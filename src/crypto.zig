const std = @import("std");

pub const MLDSA87 = std.crypto.sign.mldsa.MLDSA87;
pub const Kyber1024 = std.crypto.kem.kyber_d00.Kyber1024;

pub const XChaCha20Poly1305 = struct {
    const XChaCha20Poly1305Inner = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

    pub const NONCE_LEN = XChaCha20Poly1305Inner.nonce_length;
    pub const TAG_LEN = XChaCha20Poly1305Inner.tag_length;
    pub const DATA_LEN = NONCE_LEN + TAG_LEN;

    pub fn Ciphertext(comptime size: usize) type {
        return extern struct {
            nonce: [NONCE_LEN]u8,
            tag: [TAG_LEN]u8,
            encrypted_data: [size]u8,

            const Self = @This();

            pub fn encrypt(data: *const [size]u8, nonce: [NONCE_LEN]u8, key: [32]u8) Self {
                var self = Self{
                    .nonce = nonce,
                    .tag = undefined,
                    .encrypted_data = undefined,
                };

                XChaCha20Poly1305Inner.encrypt(&self.encrypted_data, &self.tag, data, "", nonce, key);

                return self;
            }

            pub fn decrypt(self: *const Self, key: [32]u8) ![size]u8 {
                var out: [size]u8 = undefined;

                try XChaCha20Poly1305Inner.decrypt(&out, &self.encrypted_data, self.tag, "", self.nonce, key);

                return out;
            }
        };
    }
};

pub fn hash_256(input: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha3.Sha3_256.hash(input, &out, .{});
    return out;
}

pub const KeyPair = struct {
    mldsa: MLDSA87.KeyPair,
    kyber: Kyber1024.KeyPair,

    const Self = @This();

    pub fn init_random(io: std.Io) Self {
        return .{
            .mldsa = .generate(io),
            .kyber = .generate(io),
        };
    }

    pub fn pubkey(self: Self) Pubkey {
        return .{
            .mldsa = self.mldsa.public_key,
            .kyber = self.kyber.public_key,
        };
    }
};

pub const Pubkey = struct {
    mldsa: MLDSA87.PublicKey,
    kyber: Kyber1024.PublicKey,

    const Self = @This();

    pub fn raw(self: Self) RawPubkey {
        return .{
            .mldsa = self.mldsa.toBytes(),
            .kyber = self.kyber.toBytes(),
        };
    }
};

pub const RawPubkey = extern struct {
    mldsa: [MLDSA87.public_key_bytes]u8,
    kyber: [Kyber1024.PublicKey.encoded_length]u8,

    const Self = @This();

    pub fn hash(self: *const Self) [32]u8 {
        return hash_256(@ptrCast(self));
    }

    pub fn verify(self: *const Self, hash_to_verify: [32]u8) !void {
        if (!std.mem.eql(u8, &self.hash(), &hash_to_verify)) {
            return error.MismatchingPubkeyHash;
        }
    }
};
