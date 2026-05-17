allocator: std.mem.Allocator,
target_id: [32]u8,
sk: [32]u8,
my_keypair: crypto.MLDSA87.KeyPair,
my_id: [32]u8,
other_mldsa_pubkey: crypto.MLDSA87.PublicKey,
known_nonces: *crypto.XChaCha20Poly1305.KNOWN_NONCES_TYPE,
my_hand: std.ArrayList(CardWithValueToReveal),
///key = other_hash
other_hand: std.AutoHashMap([32]u8, CommitResult),
last_card_played: Card = undefined,

const std = @import("std");
const crypto = @import("../crypto.zig");
const packet_mod = @import("../packet.zig");
const game_packet_mod = @import("../game_packet.zig");
const GenericPacket = @import("../generic_packet.zig").GenericPacket;
const Card = @import("card.zig").Card;
const deck_mod = @import("deck.zig");
const random = @import("random.zig");
const constants = @import("constants.zig");

const CardWithValueToReveal = struct {
    card: Card,
    value_to_reveal: [32]u8,
};

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

pub const CommitResult = struct {
    my_value: [32]u8,
    other_hash: [32]u8,

    pub fn get_xor_unchecked(self: CommitResult, other_value: [32]u8) [32]u8 {
        return crypto.xor_256(self.my_value, other_value);
    }
};

pub const CommitRevealValue = struct {
    my_value: [32]u8,
    other_value: [32]u8,

    pub fn get_xor(self: CommitRevealValue) [32]u8 {
        return crypto.xor_256(self.my_value, self.other_value);
    }

    /// compare `my_id XOR (my_value XOR other_value)` and `other_id XOR (my_value XOR other_value)`
    ///
    /// Returns `true` if I was the one selected (aka the smaller one in big-endian), `false` otherwise
    pub fn get_xor_smaller(self: CommitRevealValue, my_id: [32]u8, other_id: [32]u8) bool {
        const xored = self.get_xor();

        const my_xor = crypto.xor_256(xored, my_id);
        const other_xor = crypto.xor_256(xored, other_id);

        const my_xor_be = std.mem.readInt(u256, &my_xor, .big);
        const other_xor_be = std.mem.readInt(u256, &other_xor, .big);

        return my_xor_be < other_xor_be; //statistically cannot be equal, so this is fine
    }
};

pub fn commit_hashes(self: Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !CommitResult {
    const my_value = random.random_256(io);
    const my_hash = crypto.hash_256(&my_value);

    try self.send_game_packet(io, .{ .kind = .commit, .data = .{ .commit = my_hash } }, writer);

    const other_hash = blk: {
        const game_packet = try self.receive_any_game_packet(reader);
        switch (game_packet.kind) {
            .commit => break :blk game_packet.data.commit,
            else => return error.InvalidGamePacketKind,
        }
    };

    return .{
        .my_value = my_value,
        .other_hash = other_hash,
    };
}

///Get `other_value`
pub fn get_reveal(self: Self, commit_res: CommitResult, reader: *std.Io.Reader) ![32]u8 {
    const game_packet = try self.receive_any_game_packet(reader);
    switch (game_packet.kind) {
        .reveal => {
            const other_value = game_packet.data.reveal;
            if (!std.mem.eql(u8, &crypto.hash_256(&other_value), &commit_res.other_hash)) return error.OtherHashMismatch;
            return other_value;
        },
        else => return error.InvalidGamePacketKind,
    }
}

pub fn reveal(self: Self, io: std.Io, my_value: [32]u8, writer: *std.Io.Writer) !void {
    try self.send_game_packet(io, .{ .kind = .reveal, .data = .{ .commit = my_value } }, writer);
}

pub fn full_commit_reveal(self: Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !CommitRevealValue {
    const commit_res = try self.commit_hashes(io, reader, writer);
    try self.reveal(io, commit_res.my_value, writer);
    const other_value = try self.get_reveal(commit_res, reader);

    return .{ .my_value = commit_res.my_value, .other_value = other_value };
}

pub fn generate_first_card(self: *Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    const res = try self.full_commit_reveal(io, reader, writer);
    var final_value = res.get_xor();

    var card: Card = undefined;

    while (true) {
        card = deck_mod.getCardFromSeed(final_value);
        if (card.is_number()) break;

        final_value = crypto.hash_256(&final_value);
    }

    self.last_card_played = card;
}

/// Returns `true` if I was chosen, `false` otherwise
pub fn choose_beginner(self: Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !bool {
    const res = try self.full_commit_reveal(io, reader, writer);
    return res.get_xor_smaller(self.my_id, self.target_id);
}

pub fn generate_my_card(self: *Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    const res = try self.commit_hashes(io, reader, writer);
    const other_value = try self.get_reveal(res, reader);

    const seed = res.get_xor_unchecked(other_value);

    const card = CardWithValueToReveal{
        .card = deck_mod.getCardFromSeed(seed),
        .value_to_reveal = res.my_value,
    };

    try self.my_hand.append(self.allocator, card);
}

pub fn generate_other_card(self: *Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    const res = try self.commit_hashes(io, reader, writer);
    try self.reveal(io, res.my_value, writer);

    try self.other_hand.put(res.other_hash, res);
}

pub fn generate_my_cards(self: *Self, count: usize, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    for (0..count) |_| {
        try self.generate_my_card(io, reader, writer);
    }
}

pub fn generate_other_cards(self: *Self, count: usize, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    for (0..count) |_| {
        try self.generate_other_card(io, reader, writer);
    }
}

pub fn generate_game_start_cards(self: *Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer, do_i_begin: bool) !void {
    if (do_i_begin) {
        try self.generate_my_cards(constants.GAME_START_CARDS_COUNT, io, reader, writer);
        try self.generate_other_cards(constants.GAME_START_CARDS_COUNT, io, reader, writer);
    } else {
        try self.generate_other_cards(constants.GAME_START_CARDS_COUNT, io, reader, writer);
        try self.generate_my_cards(constants.GAME_START_CARDS_COUNT, io, reader, writer);
    }
}

///Returns the number of cards playable
pub fn print_hands(self: Self) !usize {
    var playable_count: usize = 0;

    std.debug.print("Your hand :\n", .{});
    for (self.my_hand.items, 0..) |my_card, i| {
        const card_json = try std.json.Stringify.valueAlloc(self.allocator, my_card.card, .{});
        defer self.allocator.free(card_json);

        const is_card_playable = my_card.card.is_playable(self.last_card_played);

        if (is_card_playable) playable_count += 1;

        std.debug.print("{d}. {s} ({s}playable)\n", .{ i, card_json, if (is_card_playable) "" else "not " });
    }
    std.debug.print("\nNumber of cards of the other player : {d}\n\n", .{self.other_hand.count()});

    {
        const card_json = try std.json.Stringify.valueAlloc(self.allocator, self.last_card_played, .{});
        defer self.allocator.free(card_json);
        std.debug.print("Last card played :\n{s}\n\n", .{card_json});
    }

    return playable_count;
}

fn handle_played_card(self: *Self, card: Card, chosen_color: ?Card.CardColor, is_my_turn: *bool, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    switch (card) {
        .Wild => {
            self.last_card_played = .{ .Wild = chosen_color orelse return error.MissingChosenColor };
        },
        .WildDrawFour => {
            self.last_card_played = .{ .WildDrawFour = chosen_color orelse return error.MissingChosenColor };
        },
        else => {
            self.last_card_played = card;
        },
    }

    switch (card) {
        .Number, .Reverse, .Wild => {},
        .Skip => {
            is_my_turn.* = !is_my_turn.*;
        },
        .DrawTwo => {
            is_my_turn.* = !is_my_turn.*;

            if (is_my_turn.*) {
                try self.generate_other_cards(2, io, reader, writer);
            } else {
                try self.generate_my_cards(2, io, reader, writer);
            }
        },
        .WildDrawFour => {
            is_my_turn.* = !is_my_turn.*;

            if (is_my_turn.*) {
                try self.generate_other_cards(4, io, reader, writer);
            } else {
                try self.generate_my_cards(4, io, reader, writer);
            }
        },
    }
}

pub fn other_plays_card(self: *Self, chosen_color: Card.CardColor, is_my_turn: *bool, revealed_value: [32]u8, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    const other_hash = crypto.hash_256(&revealed_value);

    const other_card_result = self.other_hand.get(other_hash) orelse return error.CardNotFound;

    const final_seed = other_card_result.get_xor_unchecked(revealed_value);

    const final_card = deck_mod.getCardFromSeed(final_seed);

    try self.handle_played_card(final_card, chosen_color, is_my_turn, io, reader, writer);

    _ = self.other_hand.remove(other_hash);
}

///Returns wether the player won (`false` if lost) and returns `null` if no one won yet
pub fn check_win(self: Self) !?bool {
    var result: ?bool = null;

    if (self.my_hand.items.len == 0) {
        result = true;
    }

    if (self.other_hand.count() == 0) {
        if (result == true) return error.BothWon;
        result = false;
    }

    return result;
}

pub fn handle_cannot_play(self: *Self, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer, generate_card: bool) !void {
    std.log.info("Cannot play", .{});
    try self.send_game_packet(io, .{ .kind = .cannot_play, .data = .{ .cannot_play = {} } }, writer);
    if (generate_card) {
        std.log.info("Generating new card...", .{});
        try self.generate_my_card(io, reader, writer);
    } else {
        std.log.info("Passing your turn.", .{});
    }
}

pub fn play_card(self: *Self, is_my_turn: *bool, card_index: usize, io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    if (card_index >= self.my_hand.items.len) return error.InvalidCardIndex;

    const card = self.my_hand.items[card_index];

    if (!card.card.is_playable(self.last_card_played)) return error.NotPlayableCard;

    const chosen_color = try card.card.ask_choose_color_if_needed(io);

    try self.send_game_packet(io, .{
        .kind = .play,
        .data = .{
            .play = .{
                .revealed_value = card.value_to_reveal,
                .chosen_color = chosen_color orelse undefined,
            },
        },
    }, writer);

    try self.handle_played_card(card.card, chosen_color, is_my_turn, io, reader, writer);

    _ = self.my_hand.swapRemove(card_index);
}
