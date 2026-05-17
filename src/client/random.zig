const std = @import("std");

pub fn random_bytes(comptime N: usize, io: std.Io) [N]u8 {
    var bytes: [N]u8 = undefined;

    var random_io = std.Random.IoSource{ .io = io };

    random_io.interface().bytes(&bytes);

    return bytes;
}

pub fn random_256(io: std.Io) [32]u8 {
    return random_bytes(32, io);
}
