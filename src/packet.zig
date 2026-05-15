const GamePacket = @import("game_packet.zig").GamePacket;
const crypto = @import("crypto.zig");

pub const Packet = extern struct {
    kind: Kind,
    data: Data,

    pub const Kind = enum(u8) {
        GetPubkey,
        Pubkey,
        GamePacket,
    };

    pub const Data = extern union {
        GetPubkey: void,
        Pubkey: crypto.RawPubkey,
        GamePacket: GamePacket,
    };
};
