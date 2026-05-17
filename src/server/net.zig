const std = @import("std");

pub fn create_server(args: std.process.Args, allocator: std.mem.Allocator, io: std.Io) !std.Io.net.Server {
    const port = blk: {
        var argsIter = try args.iterateAllocator(allocator);
        defer argsIter.deinit();

        _ = argsIter.next().?;

        const port_str = argsIter.next() orelse return error.MissingPort;

        break :blk try std.fmt.parseInt(u16, port_str, 10);
    };

    var addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.unspecified(port) };
    return try addr.listen(io, .{ .reuse_address = true });
}
