const std = @import("std");
const fs = std.fs;
const os = std.posix.system;
const posix = std.posix;
const testing = std.testing;

const Error = error{
    InvalidBlockSize,
    OutOfBoundPointer,
    OutOfBoundBlock,
    SpilledBlock,
    OutOfBlocks,
};

pub const Level = enum(u8) { memory, disk };
const Location = packed struct(u64) { level: Level, index: u56 };

pub const Block = packed struct(u256) {
    free_prev: ?*Block = null,
    free_next: ?*Block = null,
    lru_prev: ?*Block = null,
    lru_next: ?*Block = null,

    fn invariants(block: *Block) void {
        if (block.free_next or block.free_prev) {
            std.debug.assert(block.free_next);
            std.debug.assert(block.free_prev);
            std.debug.assert(block.lru_next == null);
            std.debug.assert(block.lru_prev == null);
        }

        if (block.lru_next or block.lru_prev) {
            std.debug.assert(block.lru_next);
            std.debug.assert(block.lru_prev);
            std.debug.assert(block.free_next == null);
            std.debug.assert(block.free_prev == null);
        }
    }

    pub fn data(b: *Block) [*]u8 {
        const ptr: [*]Block = @ptrCast(b);
        return @ptrCast(&ptr[1]);
    }
};

test "block - data ptr" {
    var b: Block = .{};
    const ptr: [*]u8 = @ptrCast(&b);
    try testing.expectEqual(b.data(), ptr[@sizeOf(Block)..]);
}

pub const Manager = struct {
    const Options = struct {
        allocator: std.mem.Allocator,
        block_size: usize = 2 << 20,
        mem: struct { cap_bytes: usize },
        disk: struct { cap_bytes: usize, file: []const u8 = "/var/creek/spill.bin" },
    };

    const Mem = struct {
        block_size: usize,
        data_size: usize,

        count: usize = 0,
        limit: usize,
        cap: usize,

        blocks: [*]u8,
        root: Block = .{},

        fn invariants(mem: *const Mem) void {
            std.debug.assert(@popCount(mem.block_size) == 1);
            std.debug.assert(mem.data_size < mem.block_size);

            std.debug.assert(mem.count <= mem.limit);
            std.debug.assert(mem.limit <= mem.cap);

            std.debug.assert(mem.root.free_next);
            std.debug.assert(mem.root.free_prev);
            std.debug.assert(mem.root.lru_next);
            std.debug.assert(mem.root.lru_prev);
        }

        fn init(opts: Options) !Mem {
            const blocks = opts.mem.cap_bytes / opts.block_size;

            const prot = os.PROT.READ | os.PROT.WRITE;
            const flags: os.Map = .{ .ANONYMOUS = true, .POPULATE = true, .HUGETLB = true };
            const ptr = try posix.mmap(null, blocks * opts.block_size, prot, flags, -1, 0);

            const mem: Mem = .{
                .block_size = opts.block_size,
                .data_size = opts.block_size - @sizeOf(Block),
                .cap = blocks,
                .blocks = @ptrCast(ptr),
            };

            mem.root.lru_next = &mem.root;
            mem.root.lru_prev = &mem.root;

            mem.root.free_next = &try mem.block(0);
            mem.root.free_prev = &try mem.block(blocks - 1);

            (try mem.at(0)).free_prev = &mem.root;
            (try mem.at(blocks - 1)).free_next = &mem.root;

            for (0..blocks) |ix| {
                (try mem.at(ix)).free_next = &try mem.at(ix + 1);
                (try mem.at(ix)).free_prev = &try mem.at(ix - 1);
            }

            mem.invariants();
            return mem;
        }

        fn at(mem: *Mem, ix: usize) Error!*Block {
            mem.invariants();
            if (ix >= mem.cap) return Error.OutOfBoundBlock;
            if (ix >= mem.limit) return Error.SpilledBlock;
            return @ptrCast(mem.blocks[ix * mem.block_size]);
        }

        fn alloc(comptime T: type, mem: *Mem) struct { ptr: *T, spill: ?*Block } {
            mem.invariants();
            defer mem.invariants();

            const block: *Block = mem.root.free_next.?;

            var spill: ?*Block = null;
            if (block == &mem.root) {
                block = mem.root.free_prev;

                block.invariants();
                defer block.invariants();

                block.lru_prev.lru_next = &mem.root;
                mem.root.lru_prev = block.lru_prev;
                block.lru_next = null;
                block.lru_prev = null;

                spill = block;
            }

            block.invariants();
            defer block.invariants();

            mem.root.free_next = block.free_next.free_next;
            block.free_next.free_prev = &mem.root;
            block.free_next = null;
            block.free_prev = null;

            block.lru_next = mem.root.lru_next;
            block.lru_prev = &mem.root;
            mem.root.lru_next = block;
            mem.root.lru_next.lru_prev = block;

            return .{ .ptr = @ptrCast(block.data()), .spill = spill };
        }

        fn ptrToBlock(comptime T: type, mem: *const Mem, ptr: *T) !*Block {
            const p: *u8 = @ptrFromInt(@intFromPtr(ptr) & ~(mem.block_size - 1));
            if (p < mem.blocks or p > mem.blocks + mem.limit) return Error.OutOfBoundPointer;
            return @ptrCast(p);
        }

        fn free(comptime T: type, mem: *Mem, ptr: *T) !void {
            mem.invariants();
            defer mem.invariants();

            const block: *Block = try mem.ptrToBlock(ptr);

            block.invariants();
            defer block.invariants();

            @memset(block.data()[0..mem.data_size], 0);

            mem.root.free_next.free_prev = block;
            block.free_next = mem.root.free_next;
            mem.root.free_next = block;
            block.free_prev = &mem.root;

            block.lru_next.lru_prev = block.lru_prev;
            block.lru_prev.lru_next = block.lru_next;
            block.lru_next = null;
            block.lru_prev = null;
        }

        fn touch(comptime T: type, mem: *Mem, ptr: *T) !void {
            mem.invariants();
            defer mem.invariants();

            const block: *Block = try mem.ptrToBlock(ptr);

            block.invariants();
            defer block.invariants();

            block.lru_next.lru_prev = block.lru_prev;
            block.lru_prev.lru_next = block.lru_next;

            mem.root.lru_next.lru_prev = block;
            block.lru_next = mem.root.lru_next;
            block.lru_prev = &mem.root;
            mem.root.lru_next = block;
        }

        fn shrink(mem: *Mem) !?*Block {
            mem.invariants();
            defer mem.invariants();

            if (mem.root.free_prev.? != &mem.root) {
                const block: *Block = mem.root.free_prev;

                block.invariants();
                defer block.invariants();

                block.free_prev.free_next = &mem.root;
                mem.root.free_prev = block.free_prev;
                block.free_next = null;
                block.free_prev = null;

                return null;
            }

            if (mem.root.lru_prev.? != &mem.root) {
                const block: *Block = mem.root.free_prev;

                block.invariants();
                defer block.invariants();

                block.lru_prev.lru_next = &mem.root;
                mem.root.lru_prev = block.lru_prev;
                block.lru_next = null;
                block.lru_prev = null;

                return block;
            }

            return Error.OutOfBlocks;
        }
    };

    ids: u32 = 0,
    block_size: usize,
    locations: std.ArrayList(Location),
    mem: Mem,

    pub fn init(opts: Options) !Manager {
        if (@popCount(opts.block_size) != 1 or @ctz(opts.block_size) < 10)
            return Error.InvalidBlockSize;

        const mem = try Mem.init(opts);
        return .{
            .block_size = opts.block_size,
            .locations = std.ArrayList(Location).initCapacity(opts.allocator, mem.cap),
            .mem = mem,
        };
    }

    pub fn deinit(alloc: *Manager) void {
        _ = alloc;
    }
};
