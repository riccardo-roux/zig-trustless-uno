const std = @import("std");

const crypto = @import("crypto.zig");

///`Child` should be an extern struct or raw bytes
pub fn GenericPacket(comptime Child: type) type {
    return extern struct {
        ///hash of the whole MLDSA+Kyber pubkey
        author_id: [32]u8,
        signature: [crypto.MLDSA87.signature_bytes]u8,
        content: Child,

        const Self = @This();

        pub const EncryptedPacket = crypto.XChaCha20Poly1305.Ciphertext(@sizeOf(Self));

        pub fn init_and_sign(keypair: *const crypto.KeyPair, content: *const Child) !Self {
            return .{
                .author_id = keypair.pubkey().raw().hash(),
                .signature = (try keypair.mldsa.sign(@ptrCast(content), null)).toBytes(),
                .content = content.*,
            };
        }

        pub fn encrypt(self: *const Self, nonce: [crypto.XChaCha20Poly1305.NONCE_LEN]u8, key: [32]u8) EncryptedPacket {
            return EncryptedPacket.encrypt(@ptrCast(self), nonce, key);
        }
    };
}
