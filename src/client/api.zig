const std = @import("std");

const crypto = @import("../crypto.zig");
const packet_mod = @import("../packet.zig");

pub fn get_player_full_pubkey(raw_pubkey: *const [32]u8, writer: *std.Io.Writer, reader: *std.Io.Reader) !crypto.RawPubkey {
    const packet = packet_mod.Packet{
        .kind = .GetPubkey,
        .data = .{
            .GetPubkey = raw_pubkey.*,
        },
    };

    try writer.writeAll(packet.as_bytes_ptr());

    var res: packet_mod.Packet = undefined;

    try reader.readSliceAll(@ptrCast(&res));

    switch (res.kind) {
        .Pubkey => {
            const pubkey = &res.data.Pubkey;
            try pubkey.verify(raw_pubkey.*);
            return pubkey.*;
        },
        else => return error.InvalidServerResponse,
    }
}
