const std = @import("std");
const Io = std.Io;

const crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");

pub const User = struct {
    full_pubkey: [@sizeOf(crypto.RawPubkey)]u8,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
};

pub const MutexedUser = struct {
    mutex: std.Io.Mutex,
    user: User,
};

var users: std.AutoHashMap([32]u8, *MutexedUser) = undefined;

pub fn main(init: std.process.Init) !void {
    users = .init(init.gpa);
    defer users.deinit();

    const port = blk: {
        var args = try init.minimal.args.iterateAllocator(init.gpa);
        defer args.deinit();

        _ = args.next().?;

        const port_str = args.next() orelse return error.MissingPort;

        break :blk try std.fmt.parseInt(u16, port_str, 10);
    };

    var addr = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.unspecified(port) };
    var server = try addr.listen(init.io, .{ .reuse_address = true });
    defer server.deinit(init.io);

    while (true) {
        const conn = try server.accept(init.io);

        _ = try std.Thread.spawn(.{}, handle_conn, .{ init.io, conn });
    }
}

pub fn handle_conn(io: std.Io, conn: std.Io.net.Stream) !void {
    defer conn.close(io);

    var random_io = std.Random.IoSource{ .io = io };
    const random = random_io.interface();

    var r_buffer: [1024]u8 = undefined;

    var io_reader = conn.reader(io, &r_buffer);
    var io_writer = conn.writer(io, &.{});

    var user = MutexedUser{
        .mutex = .init,
        .user = .{
            .full_pubkey = undefined,
            .reader = &io_reader.interface,
            .writer = &io_writer.interface,
        },
    };

    const reader = user.user.reader;
    const writer = user.user.writer;
    const mutex = &user.mutex;

    //handshake
    try perform_handshake(reader, writer, @ptrCast(&user.user.full_pubkey), random);

    const pubkey_hash = crypto.hash_256(&user.user.full_pubkey);

    //TODO handle "already connected" case
    try users.put(pubkey_hash, &user);
    defer _ = users.remove(pubkey_hash);

    var packet: packet_mod.Packet = undefined;

    while (true) {
        {
            try mutex.lock(io);
            defer mutex.unlock(io);
            reader.readSliceAll(@ptrCast(&packet)) catch break;
        }

        switch (packet.kind) {
            .GetPubkey => {
                const hashed_pubkey = packet.data.GetPubkey;

                const got_raw_full_pubkey = blk: {
                    //A zeroed pubkey means that the player was not found
                    const got_user = (users.get(hashed_pubkey) orelse break :blk std.mem.zeroes([crypto.RawPubkey.LENGTH]u8)).*;
                    break :blk got_user.user.full_pubkey;
                };

                const got_full_pubkey: *const crypto.RawPubkey = @ptrCast(&got_raw_full_pubkey);

                packet = .{ .kind = .Pubkey, .data = .{ .Pubkey = got_full_pubkey.* } };

                try mutex.lock(io);
                defer mutex.unlock(io);
                try writer.writeAll(@ptrCast(&packet));
            },
            .Pubkey, .ReceiveCreateGame, .ReceiveGamePacket => {},
            .SendCreateGame => {
                const create_game_data = &packet.data.SendCreateGame;

                try write_to_user(io, create_game_data.target, @ptrCast(&create_game_data.child));
            },
            .SendGamePacket => {
                const create_game_data = &packet.data.SendGamePacket;

                try write_to_user(io, create_game_data.target, @ptrCast(&create_game_data.child));
            },
        }
    }
}

pub fn perform_handshake(reader: *std.Io.Reader, writer: *std.Io.Writer, pubkey: *crypto.RawPubkey, random: std.Random) !void {
    try reader.readSliceAll(pubkey.as_bytes_mut());

    std.log.debug("Got pubkey", .{});

    var challenge: [32]u8 = undefined;
    random.bytes(&challenge);

    try writer.writeAll(&challenge);

    std.log.debug("Challenge sent", .{});

    var received_sig: [crypto.MLDSA87.Signature.encoded_length]u8 = undefined;

    try reader.readSliceAll(&received_sig);

    std.log.debug("Signature received", .{});

    const received_parsed_sig = try crypto.MLDSA87.Signature.fromBytes(received_sig);
    const parsed_pubkey = try crypto.MLDSA87.PublicKey.fromBytes(pubkey.mldsa);

    //TODO send a clear error to the user
    try received_parsed_sig.verify(&challenge, parsed_pubkey);
}

pub fn write_to_user(io: std.Io, target_hash: [32]u8, data: []const u8) !void {
    //TODO send an error to the user
    const target_user = users.get(target_hash) orelse return;

    try target_user.mutex.lock(io);
    defer target_user.mutex.unlock(io);

    try target_user.user.writer.writeAll(data);
}
