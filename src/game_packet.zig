const GenericPacket = @import("generic_packet.zig").GenericPacket;
const Card = @import("client/card.zig").Card;

pub const GamePacket = GenericPacket(GamePacketData);

pub const GamePacketData = extern struct {
    kind: Kind,
    data: Data,

    pub const Kind = enum(u8) {
        ping,
        pong,
        commit,
        reveal,
        play,
        cannot_play,
    };

    pub const Data = extern union {
        ping: void,
        pong: void,
        commit: [32]u8,
        reveal: [32]u8,
        play: Play,
        ///the player will therefore draw a card and play it if possible (if this is sent a second time, there will be no new draw, it will just become the turn of the other player)
        cannot_play: void,

        pub const Play = extern struct {
            revealed_value: [32]u8,
            ///only considered if card is a "choose color card" (aka `wild draw 4` or `wild`)
            chosen_color: Card.CardColor,
        };
    };
};
