const std = @import("std");

pub const Card = union(enum) {
    Number: struct {
        color: CardColor,
        number: CardNumber,
    },
    Skip: CardColor,
    Reverse: CardColor,
    DrawTwo: CardColor,
    Wild: void,
    WildDrawFour: void,

    pub const CardColor = enum(u8) {
        red,
        blue,
        green,
        yellow,
    };

    pub const CardNumber = enum(u8) {
        zero,
        one,
        two,
        three,
        four,
        five,
        six,
        seven,
        eight,
        nine,
    };

    pub fn generateWholeDeck() [112]Card {
        var cards: [112]Card = undefined;

        var index: usize = 0;
        inline for (std.meta.tags(CardColor)) |color| {
            inline for (std.meta.tags(CardNumber)) |number| {
                const card = Card{
                    .Number = .{
                        .color = color,
                        .number = number,
                    },
                };
                cards[index] = card;
                index += 1;

                if (number != .zero) {
                    cards[index] = card;
                    index += 1;
                }
            }

            inline for (0..2) |_| {
                cards[index] = Card{
                    .Skip = color,
                };
                index += 1;
            }

            inline for (0..2) |_| {
                cards[index] = Card{
                    .Reverse = color,
                };
                index += 1;
            }

            inline for (0..2) |_| {
                cards[index] = Card{
                    .DrawTwo = color,
                };
                index += 1;
            }
        }

        inline for (0..8) |_| {
            cards[index] = Card{
                .Wild = {},
            };
            index += 1;
        }

        inline for (0..4) |_| {
            cards[index] = Card{
                .WildDrawFour = {},
            };
            index += 1;
        }

        if (index != cards.len) @compileError("Deck size mismatch");

        return cards;
    }
};
