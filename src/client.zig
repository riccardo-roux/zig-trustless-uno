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

    var server_conn = try cli.connect_to_server(init.gpa, init.io, init.minimal.args);
    defer server_conn.close(init.io);

    var conn_writer = server_conn.writer(init.io, &.{});
    var conn_reader = server_conn.reader(init.io, &reader_buffer);

    var state = try cli.handle_handshakes(init.io, &conn_writer.interface, &conn_reader.interface, &known_decrypted_nonces, init.gpa);
    defer state.deinit();

    try state.generate_first_card(init.io, &conn_reader.interface, &conn_writer.interface);

    var is_my_turn = try state.choose_beginner(init.io, &conn_reader.interface, &conn_writer.interface);

    if (is_my_turn) {
        std.log.info("You begin !", .{});
    } else {
        std.log.info("The other player begins !", .{});
    }

    try state.generate_game_start_cards(init.io, &conn_reader.interface, &conn_writer.interface, is_my_turn);

    while (true) : (is_my_turn = !is_my_turn) {
        if (try state.check_win()) |i_won| {
            if (i_won) {
                std.log.info("YOU WON", .{});
            } else {
                std.log.info("YOU LOST", .{});
            }
            break;
        }

        var playable_count = try state.print_hands(is_my_turn);

        if (is_my_turn) {
            std.log.info("Your turn.", .{});

            if (playable_count == 0) {
                try state.handle_cannot_play(init.io, &conn_reader.interface, &conn_writer.interface, true);

                playable_count = try state.print_hands(true);

                if (playable_count == 0) {
                    try state.handle_cannot_play(init.io, &conn_reader.interface, &conn_writer.interface, false);
                    continue; //pass the turn
                } else {
                    //able to play, thus replay
                    is_my_turn = !is_my_turn;
                    continue;
                }
            }

            while (true) {
                std.debug.print("Action : ", .{});
                const index_to_play = try stdin.read_int(usize, init.io);
                state.play_card(&is_my_turn, index_to_play, init.io, &conn_reader.interface, &conn_writer.interface) catch |e| {
                    std.log.err("Error : {}", .{e});
                    continue;
                };
                break;
            }
        } else {
            std.log.info("The other player turn.", .{});

            for (0..2) |i| {
                const game_packet = try state.receive_any_game_packet(&conn_reader.interface);
                switch (game_packet.kind) {
                    .play => {
                        const data = game_packet.data.play;
                        try state.other_plays_card(data.chosen_color, &is_my_turn, data.revealed_value, init.io, &conn_reader.interface, &conn_writer.interface);
                        break;
                    },
                    .cannot_play => {
                        if (i == 1) break; //the other player cannot play even after drawing 1 card
                        try state.generate_other_card(init.io, &conn_reader.interface, &conn_writer.interface);
                    },
                    else => {},
                }
            }
        }
    }
}
