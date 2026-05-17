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

        pub const EncryptedPacket = crypto.XChaCha20Poly1305.Ciphertext(Self);

        pub fn init_and_sign(keypair: *const crypto.MLDSA87.KeyPair, my_id: [32]u8, content: *const Child) !Self {
            return .{
                .author_id = my_id,
                .signature = (try keypair.sign(@ptrCast(content), null)).toBytes(),
                .content = content.*,
            };
        }

        pub fn verify_signature_and_get_content(self: *const Self, full_mldsa_pubkey: *const crypto.MLDSA87.PublicKey, full_pubkey_hash: [32]u8) !Child {
            if (!std.mem.eql(u8, &self.author_id, &full_pubkey_hash)) return error.PubkeyMismatch;

            const parsed_sig = try crypto.MLDSA87.Signature.fromBytes(self.signature);

            try parsed_sig.verify(@ptrCast(&self.content), full_mldsa_pubkey.*);

            return self.content;
        }

        pub fn encrypt(self: *const Self, nonce: [crypto.XChaCha20Poly1305.NONCE_LEN]u8, key: [32]u8) EncryptedPacket {
            return EncryptedPacket.encrypt(@ptrCast(self), nonce, key);
        }
    };
}
