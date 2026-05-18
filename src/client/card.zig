const std = @import("std");

const stdin = @import("../stdin.zig");
const ansi = @import("ansi.zig");

pub const Card = union(enum) {
    Number: struct {
        color: CardColor,
        number: CardNumber,
    },
    Skip: CardColor,
    Reverse: CardColor,
    DrawTwo: CardColor,
    Wild: ?CardColor,
    WildDrawFour: ?CardColor,

    pub const CardColor = enum(u8) {
        red,
        blue,
        green,
        yellow,

        pub fn to_ansi(self: CardColor) ansi.Color {
            switch (self) {
                .red => return .red,
                .blue => return .blue,
                .green => return .green,
                .yellow => return .yellow,
            }
        }

        pub fn parse_char(c: u8) ?CardColor {
            switch (c) {
                'r' => return .red,
                'b' => return .blue,
                'g' => return .green,
                'y' => return .yellow,
                else => return null,
            }
        }
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

    pub fn is_number(self: Card) bool {
        switch (self) {
            .Number => return true,
            .Skip, .Reverse, .DrawTwo, .Wild, .WildDrawFour => return false,
        }
    }

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
                .Wild = null,
            };
            index += 1;
        }

        inline for (0..4) |_| {
            cards[index] = Card{
                .WildDrawFour = null,
            };
            index += 1;
        }

        if (index != cards.len) @compileError("Deck size mismatch");

        return cards;
    }

    pub fn get_color(self: Card) ?CardColor {
        switch (self) {
            .Number => |nb| return nb.color,
            .Skip => |skip| return skip,
            .Reverse => |rev| return rev,
            .DrawTwo => |dt| return dt,
            .Wild, .WildDrawFour => |value| return value,
        }
    }

    ///MUST NOT be used in a real game, because all cards have a color (either by itself, or chosen by the one that plays it)
    pub fn is_same_color(a: Card, b: Card) bool {
        if (a.get_color()) |a_color| {
            if (b.get_color()) |b_color| {
                return a_color == b_color;
            }
        }

        return true; //if any of them has no color
    }

    ///MUST be used in a real game, because all cards have a color (either by itself, or chosen by the one that plays it)
    pub fn is_same_color_no_null(a: Card, b: Card) !bool {
        if (a.get_color()) |a_color| {
            if (b.get_color()) |b_color| {
                return a_color == b_color;
            }
        }

        return error.NullCard; //if any of them has no color
    }

    pub fn is_same_value_colorless(a: Card, b: Card) bool {
        switch (a) {
            .Number => {
                switch (b) {
                    .Number => return a.Number.number == b.Number.number,
                    else => return false,
                }
            },
            .Skip => {
                switch (b) {
                    .Skip => return true,
                    else => return false,
                }
            },
            .Reverse => {
                switch (b) {
                    .Reverse => return true,
                    else => return false,
                }
            },
            .DrawTwo => {
                switch (b) {
                    .DrawTwo => return true,
                    else => return false,
                }
            },
            .Wild => {
                switch (b) {
                    .Wild => return true,
                    else => return false,
                }
            },
            .WildDrawFour => {
                switch (b) {
                    .WildDrawFour => return true,
                    else => return false,
                }
            },
        }
    }

    pub fn is_playable(self: Card, last_card_played: Card) bool {
        return (self.is_same_color(last_card_played)) or self.is_same_value_colorless(last_card_played);
    }

    pub fn ask_choose_color_if_needed(self: Card, io: std.Io) !?CardColor {
        switch (self) {
            .Wild, .WildDrawFour => while (true) {
                std.debug.print("Choose color (r/b/g/y) : ", .{});
                const color_char = try stdin.read_char(io);
                const color = CardColor.parse_char(color_char) orelse continue;
                return color;
            },
            else => return null,
        }
    }

    pub fn to_ansi_string(self: Card) []const u8 {
        @setEvalBranchQuota(100_000);
        switch (self) {
            .Number => |number_data| {
                switch (number_data.number) {
                    inline else => |number| {
                        const number_str = std.fmt.comptimePrint("{d}", .{number});
                        return ansi.with_color_comptime(number_str, number_data.color.to_ansi());
                    },
                }
            },
            .Skip => |skip_data| {
                return ansi.with_color_comptime("skip", skip_data.to_ansi());
            },
            .Reverse => |rev| {
                return ansi.with_color_comptime("reverse", rev.to_ansi());
            },
            .DrawTwo => |draw_two| {
                return ansi.with_color_comptime("+2", draw_two.to_ansi());
            },
            .Wild => |wild| {
                if (wild) |wild_color| {
                    return ansi.with_color_comptime("wild", wild_color.to_ansi());
                } else return "wild";
            },
            .WildDrawFour => |wild_four| {
                if (wild_four) |wild_color| {
                    return ansi.with_color_comptime("wild +4", wild_color.to_ansi());
                } else return "wild +4";
            },
        }
    }

    pub fn to_string(self: Card) []const u8 {
        switch (self) {
            .Number => |number_data| {
                switch (number_data.color) {
                    inline else => |color| {
                        switch (number_data.number) {
                            inline else => |number| return std.fmt.comptimePrint("{s} {d}", .{ @tagName(color), @intFromEnum(number) }),
                        }
                    },
                }
            },
            .Skip => |skip_data| {
                switch (skip_data) {
                    inline else => |color| return std.fmt.comptimePrint("{s} skip", .{@tagName(color)}),
                }
            },
            .Reverse => |rev| {
                switch (rev) {
                    inline else => |color| return std.fmt.comptimePrint("{s} reverse", .{@tagName(color)}),
                }
            },
            .DrawTwo => |draw_two| {
                switch (draw_two) {
                    inline else => |color| return std.fmt.comptimePrint("{s} +2", .{@tagName(color)}),
                }
            },
            .Wild => |wild| {
                if (wild) |wild_color| {
                    switch (wild_color) {
                        inline else => |color| return std.fmt.comptimePrint("{s} wild", .{@tagName(color)}),
                    }
                } else return "wild";
            },
            .WildDrawFour => |wild_four| {
                if (wild_four) |wild_color| {
                    switch (wild_color) {
                        inline else => |color| return std.fmt.comptimePrint("{s} wild +4", .{@tagName(color)}),
                    }
                } else return "wild +4";
            },
        }
    }
};
