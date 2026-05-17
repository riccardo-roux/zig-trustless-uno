target_id: [32]u8,
sk: [32]u8,
my_keypair: crypto.MLDSA87.KeyPair,
my_id: [32]u8,
other_mldsa_pubkey: crypto.MLDSA87.PublicKey,
known_nonces: *crypto.XChaCha20Poly1305.KNOWN_NONCES_TYPE,

const std = @import("std");
const crypto = @import("../crypto.zig");
const packet_mod = @import("../packet.zig");
const game_packet_mod = @import("../game_packet.zig");
const GenericPacket = @import("../generic_packet.zig").GenericPacket;

const Self = @This();

pub fn receive_empty_packet(self: Self, kind: game_packet_mod.GamePacketData.Kind, reader: *std.Io.Reader) !void {
    const final_packet = try self.receive_any_game_packet(reader);

    if (final_packet.kind != kind) {
        return error.MismatchingGamePacketKind;
    }
}

fn create_send_game_packet(self: Self, io: std.Io, data: game_packet_mod.GamePacketData) !packet_mod.Packet {
    const game_packet_data = try game_packet_mod.GamePacket.init_and_sign(&self.my_keypair, self.my_id, &data);

    return packet_mod.Packet{
        .kind = .SendGamePacket,
        .data = .{ .SendGamePacket = .{ .target = self.target_id, .child = .encrypt(&game_packet_data, crypto.XChaCha20Poly1305.random_nonce(io), self.sk) } },
    };
}

fn send_game_packet(self: Self, io: std.Io, data: game_packet_mod.GamePacketData, writer: *std.Io.Writer) !void {
    const final_packet = try self.create_send_game_packet(io, data);

    try writer.writeAll(final_packet.as_bytes_ptr());
}

fn send_empty_game_packet(self: Self, io: std.Io, kind: game_packet_mod.GamePacketData.Kind, writer: *std.Io.Writer) !void {
    try self.send_game_packet(io, .{ .kind = kind, .data = undefined }, writer);
}

pub fn wait_ping_and_send_pong(self: Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    std.log.debug("Waiting for ping...", .{});

    try self.receive_empty_packet(.ping, reader);

    std.log.debug("Ping received", .{});

    try self.send_empty_game_packet(io, .pong, writer);

    std.log.debug("Pong sent", .{});
}

pub fn send_ping_and_wait_pong(self: Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    try self.send_empty_game_packet(io, .ping, writer);

    std.log.debug("Ping sent, waiting for pong...", .{});

    try self.receive_empty_packet(.pong, reader);

    std.log.debug("Pong received !", .{});
}

pub fn receive_any_game_packet(self: Self, reader: *std.Io.Reader) !game_packet_mod.GamePacketData {
    var packet: packet_mod.Packet = undefined;

    try reader.readSliceAll(@ptrCast(&packet));

    if (packet.kind != .ReceiveGamePacket) {
        return error.InvalidPacket;
    }

    const data = packet.data.ReceiveGamePacket;

    const decrypted_packet = try data.decrypt(self.sk, self.known_nonces);

    const sig_verified_packet = try decrypted_packet.verify_signature_and_get_content(&self.other_mldsa_pubkey, self.target_id);

    return sig_verified_packet;
}
