const GenericPacket = @import("generic_packet.zig").GenericPacket;

pub const GamePacket = GenericPacket(GamePacketData);

pub const GamePacketData = extern struct {
    kind: Kind,
    data: Data,

    pub const Kind = enum(u8) {
        ping,
        pong,
        commit,
        reveal,
    };

    pub const Data = extern union {
        ping: void,
        pong: void,
        commit: [32]u8,
        reveal: [32]u8,
    };
};
