const std = @import("std");

pub fn read_line(io: std.Io, writer: *std.Io.Writer) !usize {
    const STDIN = std.Io.File.stdin();

    var buffer: [1024]u8 = undefined;

    var reader = STDIN.reader(io, &buffer);

    const n = try reader.interface.streamDelimiterEnding(writer, '\n');

    try writer.flush();

    return n;
}

pub fn read_line_buffer(io: std.Io, buffer: []u8) ![]u8 {
    var writer = std.Io.Writer.fixed(buffer);

    const n = try read_line(io, &writer);

    return buffer[0..n];
}

pub fn read_empty_or_fixed(comptime N: usize, io: std.Io) !?[N]u8 {
    var buffer: [N + 1]u8 = undefined;

    const slice = try read_line_buffer(io, &buffer);

    return switch (slice.len) {
        0 => null,
        N => buffer[0..N].*,
        else => error.WrongSize,
    };
}

pub fn read_fixed(comptime N: usize, io: std.Io) ![N]u8 {
    return (try read_empty_or_fixed(N, io)) orelse return error.EmptyStdin;
}

pub fn read_char(io: std.Io) !u8 {
    return (try read_fixed(1, io))[0];
}
