const std = @import("std");

pub const Status = enum(u8) {
    success,
    err,

    const Self = @This();

    pub fn fromReader(reader: *std.Io.Reader) !Self {
        return try reader.takeEnum(Self, .big); //be or le does not matter as long as it is a single byte long
    }

    pub fn is_success(self: Self) bool {
        switch (self) {
            .success => return true,
            .err => return false,
        }
    }

    pub fn toByte(self: Self) u8 {
        return @intFromEnum(self);
    }
};
