const std = @import("std");
const Card = @import("card.zig").Card;

pub const DECK_CARDS = Card.generateWholeDeck();

pub fn getCardFromSeed(seed: [32]u8) Card {
    const seed_as_number = std.mem.readInt(u256, &seed, .big);
    const index: usize = @intCast(seed_as_number % DECK_CARDS.len);
    return DECK_CARDS[index];
}
