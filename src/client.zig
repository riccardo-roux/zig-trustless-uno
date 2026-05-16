const std = @import("std");
const Io = std.Io;

const crypto = @import("crypto.zig");
const stdin = @import("stdin.zig");
const packet_mod = @import("packet.zig");
const game_packet_mod = @import("game_packet.zig");
const create_game_packet_mod = @import("create_game_packet.zig");

pub fn main(init: std.process.Init) !void {
    // var writer_buffer: [1024]u8 = undefined;
    var reader_buffer: [1024]u8 = undefined;

    var server_conn = blk: {
        var args = try init.minimal.args.iterateAllocator(init.gpa);
        defer args.deinit();

        _ = args.next().?;

        const hostname = args.next() orelse return error.MissingHostname;
        const port = blk2: {
            const port_str = args.next() orelse return error.MissingPort;
            break :blk2 try std.fmt.parseInt(u16, port_str, 10);
        };

        const parsed_hostname = try std.Io.net.HostName.init(hostname);

        break :blk try parsed_hostname.connect(init.io, port, .{ .mode = .stream, .protocol = .tcp });
    };
    defer server_conn.close(init.io);

    const keypair = crypto.KeyPair.init_random(init.io);
    const my_raw_pubkey = keypair.pubkey().raw();
    const my_hex_pubkey = std.fmt.bytesToHex(&my_raw_pubkey.hash(), .lower);

    var conn_writer = server_conn.writer(init.io, &.{});
    var conn_reader = server_conn.reader(init.io, &reader_buffer);

    try perform_handshake(&keypair, &my_raw_pubkey.to_bytes(), &conn_writer.interface, &conn_reader.interface);

    std.debug.print("Pubkey hash to share :\n{s}\n", .{&my_hex_pubkey});

    // const other_pubkey = undefined;
    {
        std.debug.print("Either :\n1) Press enter to join the game of another player\n2) Enter the hex pubkey hash of the other player to create a game\n\n", .{});

        const line = try stdin.read_empty_or_fixed(32 * 2, init.io);

        if (line) |hex_pubkey| {
            var raw_pubkey: [@divExact(hex_pubkey.len, 2)]u8 = undefined;

            _ = try std.fmt.hexToBytes(&raw_pubkey, &hex_pubkey);

            const other_pubkey_raw = try get_player_full_pubkey(&raw_pubkey, &conn_writer.interface, &conn_reader.interface);
            const other_pubkey = try other_pubkey_raw.parse();
            const other_pubkey_hash = other_pubkey_raw.hash();

            const packet_content = try create_game_packet_mod.CreateGamePacket.init_random(init.io, &keypair, &other_pubkey);

            const packet = packet_mod.Packet{
                .kind = .SendCreateGame,
                .data = .{
                    .SendCreateGame = .{
                        .target = other_pubkey_hash,
                        .child = packet_content.self,
                    },
                },
            };

            try conn_writer.interface.writeAll(packet.as_bytes_ptr());

            std.debug.print("sent random key = {s}\n", .{std.fmt.bytesToHex(&packet_content.secret_key, .lower)});
        } else {
            var packet: packet_mod.Packet = undefined;

            root: while (true) {
                std.debug.print("Accepting connections...", .{});
                try conn_reader.interface.readSliceAll(@ptrCast(&packet));

                switch (packet.kind) {
                    .ReceiveCreateGame => {
                        const packet_data = &packet.data.ReceiveCreateGame;

                        const decrypted = try packet_data.decrypt(&keypair);

                        while (true) {
                            std.debug.print("Player {s} wants to play with you, accept (y/n) ? ", .{std.fmt.bytesToHex(&decrypted.author_id, .lower)});

                            const result = std.ascii.toLower(try stdin.read_char(init.io));

                            switch (result) {
                                'y' => break,
                                'n' => continue :root,
                                else => continue,
                            }
                        }

                        const full_pubkey = try get_player_full_pubkey(&decrypted.author_id, &conn_writer.interface, &conn_reader.interface);
                        const parsed_full_pubkey = try full_pubkey.parse();

                        const random_key = try decrypted.verify_signature_and_get_content(&parsed_full_pubkey);

                        std.debug.print("received random key = {s}\n", .{std.fmt.bytesToHex(&random_key, .lower)});

                        break;
                    },
                    else => return error.InvalidPacket,
                }
            }
        }
    }
}

fn perform_handshake(keypair: *const crypto.KeyPair, pubkey: *const [crypto.RawPubkey.LENGTH]u8, writer: *std.Io.Writer, reader: *std.Io.Reader) !void {
    try writer.writeAll(pubkey);

    std.log.debug("Pubkey sent", .{});

    var challenge: [32]u8 = undefined;
    try reader.readSliceAll(&challenge);

    std.log.debug("Got challenge", .{});

    const sig = try keypair.mldsa.sign(&challenge, null);

    try writer.writeAll(&sig.toBytes());

    std.log.debug("Signature sent", .{});
}

fn get_player_full_pubkey(raw_pubkey: *const [32]u8, writer: *std.Io.Writer, reader: *std.Io.Reader) !crypto.RawPubkey {
    const packet = packet_mod.Packet{
        .kind = .GetPubkey,
        .data = .{
            .GetPubkey = raw_pubkey.*,
        },
    };

    try writer.writeAll(packet.as_bytes_ptr());

    var res: packet_mod.Packet = undefined;

    try reader.readSliceAll(@ptrCast(&res));

    return switch (res.kind) {
        .Pubkey => res.data.Pubkey,
        else => error.InvalidServerResponse,
    };
}
