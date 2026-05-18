const std = @import("std");

pub const Color = enum(u8) {
    red = 31,
    blue = 34,
    green = 32,
    yellow = 33,

    pub fn to_rgb_string(self: Color) []const u8 {
        switch (self) {
            .red => return "38;5;196",
            .blue => return "38;5;21",
            .green => return "38;5;46",
            .yellow => return "38;5;226",
        }
    }
};

pub fn withColor(comptime text: []const u8, color: Color) []const u8 {
    switch (color) {
        inline else => |comptime_color| return std.fmt.comptimePrint("\x1b[0;{s}m{s}\x1b[0m", .{ comptime comptime_color.to_rgb_string(), text }),
    }
}
