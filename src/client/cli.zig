const std = @import("std");

const crypto = @import("../crypto.zig");
const State = @import("state.zig");
const stdin = @import("../stdin.zig");
const api = @import("api.zig");
const create_game_packet_mod = @import("../create_game_packet.zig");
const packet_mod = @import("../packet.zig");
const Status = @import("../server/status.zig").Status;

pub fn connect_to_server(allocator: std.mem.Allocator, io: std.Io, args: std.process.Args) !std.Io.net.Stream {
    var argsIter = try args.iterateAllocator(allocator);
    defer argsIter.deinit();

    _ = argsIter.next().?;

    const hostname = argsIter.next() orelse return error.MissingHostname;
    const port = blk2: {
        const port_str = argsIter.next() orelse return error.MissingPort;
        break :blk2 try std.fmt.parseInt(u16, port_str, 10);
    };

    const parsed_hostname = try std.Io.net.HostName.init(hostname);

    return try parsed_hostname.connect(io, port, .{ .mode = .stream, .protocol = .tcp });
}

/// Handle client->server then client->client handshakes
pub fn handle_handshakes(
    io: std.Io,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
    known_nonces: *crypto.XChaCha20Poly1305.KNOWN_NONCES_TYPE,
    allocator: std.mem.Allocator,
) !State {
    const keypair = crypto.KeyPair.init_random(io);
    const my_raw_pubkey = keypair.pubkey().raw();

    try perform_client_to_server_handshake(&keypair, &my_raw_pubkey.to_bytes(), writer, reader);

    {
        const my_hex_pubkey = std.fmt.bytesToHex(&my_raw_pubkey.hash(), .lower);
        std.debug.print("Pubkey hash to share :\n{s}\n", .{&my_hex_pubkey});
    }

    std.debug.print("Either :\n1) Press enter to join the game of another player\n2) Enter the hex pubkey hash of the other player to create a game\n\nAction : ", .{});

    const line = try stdin.read_empty_or_fixed(32 * 2, io);

    if (line) |hex_target_pubkey_hash| {
        var raw_target_pubkey_hash: [@divExact(hex_target_pubkey_hash.len, 2)]u8 = undefined;

        _ = try std.fmt.hexToBytes(&raw_target_pubkey_hash, &hex_target_pubkey_hash);

        return try connect_to_peer(io, allocator, &keypair, my_raw_pubkey, raw_target_pubkey_hash, writer, reader, known_nonces);
    } else {
        return try handle_peer_connection(io, allocator, &keypair, my_raw_pubkey, writer, reader, known_nonces);
    }
}

fn connect_to_peer(
    io: std.Io,
    allocator: std.mem.Allocator,
    keypair: *const crypto.KeyPair,
    my_pk: crypto.RawPubkey,
    raw_target_pubkey_hash: [32]u8,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
    known_nonces: *crypto.XChaCha20Poly1305.KNOWN_NONCES_TYPE,
) !State {
    const other_pubkey = blk2: {
        const other_pubkey_raw = try api.get_player_full_pubkey(&raw_target_pubkey_hash, writer, reader);
        try other_pubkey_raw.verify(raw_target_pubkey_hash);
        break :blk2 try other_pubkey_raw.parse();
    };

    std.log.info("Other pubkey validated", .{});

    const packet_content = try create_game_packet_mod.CreateGamePacket.init_random(io, keypair, &other_pubkey);

    const packet = packet_mod.Packet{
        .kind = .SendCreateGame,
        .data = .{
            .SendCreateGame = .{
                .target = raw_target_pubkey_hash,
                .child = packet_content.self,
            },
        },
    };

    try writer.writeAll(packet.as_bytes_ptr());

    std.log.info("sent random key", .{});

    const state = State{
        .allocator = allocator,
        .target_id = raw_target_pubkey_hash,
        .sk = packet_content.secret_key,
        .other_mldsa_pubkey = other_pubkey.mldsa,
        .my_keypair = keypair.mldsa,
        .my_id = my_pk.hash(),
        .known_nonces = known_nonces,
        .my_hand = .empty,
        .other_hand = .init(allocator),
    };

    try state.wait_ping_and_send_pong(io, reader, writer);

    return state;
}

pub fn handle_peer_connection(
    io: std.Io,
    allocator: std.mem.Allocator,
    keypair: *const crypto.KeyPair,
    my_pk: crypto.RawPubkey,
    writer: *std.Io.Writer,
    reader: *std.Io.Reader,
    known_nonces: *crypto.XChaCha20Poly1305.KNOWN_NONCES_TYPE,
) !State {
    var packet: packet_mod.Packet = undefined;

    root: while (true) {
        std.log.info("Accepting connections...", .{});
        try reader.readSliceAll(@ptrCast(&packet));

        switch (packet.kind) {
            .ReceiveCreateGame => {
                const packet_data = &packet.data.ReceiveCreateGame;

                const decrypted = try packet_data.decrypt(keypair, known_nonces);

                while (true) {
                    std.log.info("Player {s} wants to play with you, accept (y/n) ?", .{std.fmt.bytesToHex(&decrypted.author_id, .lower)});

                    const result = std.ascii.toLower(try stdin.read_char(io));

                    switch (result) {
                        'y' => break,
                        'n' => continue :root,
                        else => continue,
                    }
                }

                const full_pubkey = try api.get_player_full_pubkey(&decrypted.author_id, writer, reader);
                const parsed_full_pubkey = try full_pubkey.parse();

                const random_key = try decrypted.verify_signature_and_get_content(&parsed_full_pubkey.mldsa, full_pubkey.hash());

                std.log.info("received random key\n", .{});

                const state = State{
                    .allocator = allocator,
                    .target_id = full_pubkey.hash(),
                    .sk = random_key,
                    .other_mldsa_pubkey = parsed_full_pubkey.mldsa,
                    .my_keypair = keypair.mldsa,
                    .my_id = my_pk.hash(),
                    .known_nonces = known_nonces,
                    .my_hand = .empty,
                    .other_hand = .init(allocator),
                };

                try state.send_ping_and_wait_pong(io, reader, writer);

                return state;
            },
            else => return error.InvalidPacket,
        }
    }
}

fn perform_client_to_server_handshake(keypair: *const crypto.KeyPair, pubkey: *const [crypto.RawPubkey.LENGTH]u8, writer: *std.Io.Writer, reader: *std.Io.Reader) !void {
    try writer.writeAll(pubkey);

    std.log.info("Pubkey sent", .{});

    var challenge: [32]u8 = undefined;
    try reader.readSliceAll(&challenge);

    std.log.info("Got challenge", .{});

    const sig = try keypair.mldsa.sign(&challenge, null);

    try writer.writeAll(&sig.toBytes());

    std.log.info("Signature sent", .{});

    {
        const res = try Status.fromReader(reader);

        if (!res.is_success()) {
            std.log.err("Error during client->server handshake", .{});
            return error.CouldNotCompleteHandshake;
        }
    }

    std.log.info("client->server handshake succeeded", .{});
}
