const std = @import("std");

pub fn Mutex(comptime T: type) type {
    return struct {
        mutex: std.Io.Mutex = .init,
        data: T,

        const Self = @This();

        pub const Guard = struct {
            mutex_ptr: *std.Io.Mutex,
            data_ptr: *T,

            ///MUST ONLY BE USED ONCE
            pub fn unlock(self: *Guard, io: std.Io) void {
                self.mutex_ptr.unlock(io);
                self.* = undefined;
            }
        };

        pub fn init(data: T) Self {
            return .{ .data = data };
        }

        pub fn lock(self: *Self, io: std.Io) Guard {
            self.mutex.lockUncancelable(io);

            return .{
                .mutex_ptr = &self.mutex,
                .data_ptr = &self.data,
            };
        }
    };
}
