const std = @import("std");
const Io = std.Io;

const crypto = @import("crypto.zig");
const stdin = @import("stdin.zig");
const packet_mod = @import("packet.zig");
const game_packet_mod = @import("game_packet.zig");
const create_game_packet_mod = @import("create_game_packet.zig");
const State = @import("client/state.zig");
const cli = @import("client/cli.zig");

pub fn main(init: std.process.Init) !void {
    var known_decrypted_nonces = crypto.XChaCha20Poly1305.KNOWN_NONCES_TYPE.init(init.gpa);
    defer known_decrypted_nonces.deinit();

    var reader_buffer: [1024]u8 = undefined;

    var server_conn = try cli.handle_server_connection(init.gpa, init.io, init.minimal.args);
    defer server_conn.close(init.io);

    var conn_writer = server_conn.writer(init.io, &.{});
    var conn_reader = server_conn.reader(init.io, &reader_buffer);

    const state = try cli.handle_client_to_client_handshake(init.io, &conn_writer.interface, &conn_reader.interface, &known_decrypted_nonces);
    _ = state;
}
