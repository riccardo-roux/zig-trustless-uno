const std = @import("std");

pub const MLDSA87 = std.crypto.sign.mldsa.MLDSA87;
pub const Kyber1024 = std.crypto.kem.kyber_d00.Kyber1024;

pub const XChaCha20Poly1305 = struct {
    const XChaCha20Poly1305Inner = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

    pub const NONCE_LEN = XChaCha20Poly1305Inner.nonce_length;
    pub const TAG_LEN = XChaCha20Poly1305Inner.tag_length;
    pub const DATA_LEN = NONCE_LEN + TAG_LEN;
    pub const KNOWN_NONCES_TYPE = std.AutoHashMap([NONCE_LEN]u8, void);

    pub fn random_nonce(io: std.Io) [NONCE_LEN]u8 {
        var nonce: [NONCE_LEN]u8 = undefined;
        var random_io = std.Random.IoSource{ .io = io };

        random_io.interface().bytes(&nonce);

        return nonce;
    }

    pub fn Ciphertext(comptime Child: type) type {
        const size = @sizeOf(Child);

        return extern struct {
            nonce: [NONCE_LEN]u8,
            tag: [TAG_LEN]u8,
            encrypted_data: [size]u8,

            const Self = @This();

            pub fn encrypt(data: *const Child, nonce: [NONCE_LEN]u8, key: [32]u8) Self {
                var self = Self{
                    .nonce = nonce,
                    .tag = undefined,
                    .encrypted_data = undefined,
                };

                XChaCha20Poly1305Inner.encrypt(&self.encrypted_data, &self.tag, @ptrCast(data), "", nonce, key);

                return self;
            }

            pub fn decrypt(self: *const Self, key: [32]u8, known_nonces: *KNOWN_NONCES_TYPE) !Child {
                var out: Child = undefined;

                if (known_nonces.contains(self.nonce)) return error.AlreadyKnownNonce;

                try XChaCha20Poly1305Inner.decrypt(@ptrCast(&out), &self.encrypted_data, self.tag, "", self.nonce, key);

                try known_nonces.put(self.nonce, {});

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

pub fn xor(comptime N: usize, a: [N]u8, b: [N]u8) [N]u8 {
    var out: [N]u8 = undefined;
    for (&out, a, b) |*out_b, a_b, b_b| {
        out_b.* = a_b ^ b_b;
    }
    return out;
}

pub fn xor_256(a: [32]u8, b: [32]u8) [32]u8 {
    return xor(32, a, b);
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

    pub const LENGTH = @sizeOf(Self);

    pub fn hash(self: *const Self) [32]u8 {
        return hash_256(@ptrCast(self));
    }

    pub fn verify(self: *const Self, hash_to_verify: [32]u8) !void {
        if (!std.mem.eql(u8, &self.hash(), &hash_to_verify)) {
            return error.MismatchingPubkeyHash;
        }
    }

    pub fn to_bytes(self: Self) [@sizeOf(Self)]u8 {
        return @as(*const [@sizeOf(Self)]u8, @ptrCast(&self)).*;
    }

    pub fn as_bytes_mut(self: *Self) *[@sizeOf(Self)]u8 {
        return @ptrCast(self);
    }

    pub fn as_bytes(self: *const Self) *const [@sizeOf(Self)]u8 {
        return @ptrCast(self);
    }

    pub fn from_bytes_ptr(bytes: *const [@sizeOf(Self)]u8) *const Self {
        return @ptrCast(bytes);
    }

    pub fn from_bytes(bytes: *const [@sizeOf(Self)]u8) Self {
        return Self.from_bytes_ptr(bytes).*;
    }

    pub fn parse(self: Self) !Pubkey {
        return .{
            .mldsa = try .fromBytes(self.mldsa),
            .kyber = try .fromBytes(&self.kyber),
        };
    }
};
