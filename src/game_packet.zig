const GenericPacket = @import("generic_packet.zig").GenericPacket;

pub const GamePacket = GenericPacket(GamePacketData);

pub const GamePacketData = extern struct {
    kind: Kind,
    data: Data,

    pub const Kind = enum(u8) {
        placeholder,
    };
    pub const Data = extern union {
        placeholder: void,
    };
};
