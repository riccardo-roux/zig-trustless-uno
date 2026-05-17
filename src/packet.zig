const GamePacket = @import("game_packet.zig").GamePacket;
const CreateGamePacket = @import("create_game_packet.zig").CreateGamePacket;
const crypto = @import("crypto.zig");

pub const Packet = extern struct {
    kind: Kind,
    data: Data,

    const Self = @This();

    pub const Kind = enum(u8) {
        ///Ask the server for the full pubkey, from its `sha3_256`
        GetPubkey,
        ///Reponse from the server
        Pubkey,
        SendCreateGame,
        ReceiveCreateGame,
        SendGamePacket,
        ReceiveGamePacket,
    };

    pub const Data = extern union {
        GetPubkey: [32]u8,
        Pubkey: crypto.RawPubkey,
        SendCreateGame: PacketWithTarget(CreateGamePacket),
        ReceiveCreateGame: CreateGamePacket,
        SendGamePacket: PacketWithTarget(GamePacket.EncryptedPacket),
        ReceiveGamePacket: GamePacket.EncryptedPacket,

        pub fn PacketWithTarget(comptime Child: type) type {
            return extern struct {
                target: [32]u8,
                child: Child,
            };
        }
    };

    pub fn to_bytes(self: Self) [@sizeOf(Self)]u8 {
        return Self.as_bytes_ptr(&self).*;
    }

    pub fn as_bytes_ptr(self: *const Self) *const [@sizeOf(Self)]u8 {
        return @ptrCast(self);
    }
};
