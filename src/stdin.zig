const std = @import("std");

pub fn read_line(io: std.Io, writer: *std.Io.Writer) !usize {
    const STDIN = std.Io.File.stdin();

    var buffer: [1024]u8 = undefined;

    var reader = STDIN.reader(io, &buffer);

    const n = try reader.interface.streamDelimiterEnding(writer, '\n');

    try writer.flush();

    return n;
}

fn get_max_int_string_len(comptime T: type) usize {
    const info = @typeInfo(T);

    switch (info) {
        .int => |int_data| {
            const max_int = std.math.maxInt(T);
            const max_unsigned_int_as_str = std.fmt.comptimePrint("{d}", .{max_int});
            if (int_data.signedness == .signed) return max_unsigned_int_as_str.len + 1 else return max_unsigned_int_as_str.len;
        },
        else => @compileError("Invalid type " ++ @typeName(T)),
    }
}

pub fn read_int(comptime T: type, io: std.Io) !T {
    const max_size = comptime get_max_int_string_len(T);

    var buffer: [max_size + 1]u8 = undefined;

    const int_str = try read_line_buffer(io, &buffer);

    return try std.fmt.parseInt(T, int_str, 10);
}

pub fn read_line_buffer(io: std.Io, buffer: []u8) ![]u8 {
    var writer = std.Io.Writer.fixed(buffer);

    const n = try read_line(io, &writer);

    return buffer[0..n];
}

pub fn read_empty_or_fixed(comptime N: usize, io: std.Io) !?[N]u8 {
    var buffer: [N + 1]u8 = undefined;

    const slice = try read_line_buffer(io, &buffer);

    if (N == 0) {
        return switch (slice.len) {
            0 => null,
            else => error.WrongSize,
        };
    } else {
        return switch (slice.len) {
            0 => null,
            N => buffer[0..N].*,
            else => error.WrongSize,
        };
    }
}

pub fn read_fixed(comptime N: usize, io: std.Io) ![N]u8 {
    return (try read_empty_or_fixed(N, io)) orelse return error.EmptyStdin;
}

pub fn read_empty(io: std.Io) !void {
    _ = try read_empty_or_fixed(0, io);
}

pub fn read_char(io: std.Io) !u8 {
    return (try read_fixed(1, io))[0];
}
