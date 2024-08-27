const std = @import("std");
const testing = std.testing;

pub const Block = packed struct(u256) {
    const magic_value: u32 = 0xF0F0F0F0;

    magic: u32 = magic_value,
    lru_prev: ?*Block = null,
    lru_next: ?*Block = null,
    __pad: i96 = -1,

    pub fn data(b: *Block) *u8 {
        const ptr: [*]Block = @ptrCast(b);
        return @ptrCast(&ptr[1]);
    }
};

test "block - data ptr" {
    var b: Block = .{};
    const ptr: [*]u8 = @ptrCast(&b);
    try testing.expectEqual(b.data(), &ptr[@bitSizeOf(Block) / 8]);
}
