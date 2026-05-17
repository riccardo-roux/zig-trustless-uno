const std = @import("std");
const Io = std.Io;

const crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");
const net = @import("server/net.zig");
const Mutex = @import("mutex.zig").Mutex;

pub const User = struct {
    full_pubkey: crypto.RawPubkey,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
};

var users: Mutex(std.AutoHashMap([32]u8, *Mutex(User))) = undefined;

pub fn main(init: std.process.Init) !void {
    users = .init(.init(init.gpa));
    defer {
        var users_guard = users.lock(init.io);
        defer users_guard.unlock(init.io);

        users_guard.data_ptr.deinit();
    }

    var server = try net.create_server(init.minimal.args, init.gpa, init.io);
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

    var user = Mutex(User).init(.{
        .full_pubkey = undefined,
        .reader = &io_reader.interface,
        .writer = &io_writer.interface,
    });

    {
        const reader = user.data.reader;
        const writer = user.data.writer;

        //handshake
        try perform_handshake(reader, writer, &user.data.full_pubkey, random);
    }

    const pubkey_hash = crypto.hash_256(user.data.full_pubkey.as_bytes());

    //TODO handle "already connected" case
    {
        var users_guard = users.lock(io);
        defer users_guard.unlock(io);

        try users_guard.data_ptr.put(pubkey_hash, &user);
    }
    defer {
        var users_guard = users.lock(io);
        defer users_guard.unlock(io);

        _ = users_guard.data_ptr.remove(pubkey_hash);
    }

    var packet: packet_mod.Packet = undefined;

    while (true) {
        {
            var user_guard = user.lock(io);
            defer user_guard.unlock(io);

            user_guard.data_ptr.reader.readSliceAll(@ptrCast(&packet)) catch break;
        }

        std.log.debug("Received packet kind {}", .{packet.kind});

        switch (packet.kind) {
            .GetPubkey => {
                const hashed_pubkey = packet.data.GetPubkey;

                const got_full_pubkey = blk: {
                    //A zeroed pubkey means that the player was not found

                    var users_guard = users.lock(io);
                    defer users_guard.unlock(io);

                    const got_user = (users_guard.data_ptr.get(hashed_pubkey) orelse return error.PubkeyHashNotConnected);

                    std.log.debug("Got user from hashed pubkey", .{});

                    {
                        var got_user_guard = got_user.lock(io);
                        defer got_user_guard.unlock(io);

                        break :blk got_user_guard.data_ptr.full_pubkey;
                    }
                };

                std.log.debug("Got full pubkey", .{});

                packet = .{ .kind = .Pubkey, .data = .{ .Pubkey = got_full_pubkey } };

                {
                    var user_guard = user.lock(io);
                    defer user_guard.unlock(io);

                    try user_guard.data_ptr.writer.writeAll(packet.as_bytes_ptr());

                    std.log.debug("Full pubkey sent", .{});
                }
            },
            .Pubkey, .ReceiveCreateGame, .ReceiveGamePacket => {
                std.log.warn("Received invalid packet kind {}", .{packet.kind});
            },
            .SendCreateGame => {
                const old_packet_data = packet.data.SendCreateGame;

                packet = .{
                    .kind = .ReceiveCreateGame,
                    .data = .{ .ReceiveCreateGame = old_packet_data.child },
                };

                try write_to_user(io, old_packet_data.target, &packet);
            },
            .SendGamePacket => {
                const old_packet_data = packet.data.SendGamePacket;

                packet = .{
                    .kind = .ReceiveGamePacket,
                    .data = .{ .ReceiveGamePacket = old_packet_data.child },
                };

                try write_to_user(io, old_packet_data.target, &packet);
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

pub fn write_to_user(io: std.Io, target_hash: [32]u8, data: *const packet_mod.Packet) !void {
    //TODO send an error to the user
    const target_user = blk: {
        var users_guard = users.lock(io);
        defer users_guard.unlock(io);

        break :blk users_guard.data_ptr.get(target_hash) orelse {
            std.log.warn("Could not find target hash {s}", .{std.fmt.bytesToHex(&target_hash, .lower)});
            return;
        };
    };

    var target_user_guard = target_user.lock(io);
    defer target_user_guard.unlock(io);

    try target_user_guard.data_ptr.writer.writeAll(@ptrCast(data));
}
