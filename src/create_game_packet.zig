const crypto = @import("crypto.zig");
const GenericPacket = @import("generic_packet.zig").GenericPacket;
const std = @import("std");

pub const CreateGamePacket = extern struct {
    kyber_ciphertext: [crypto.Kyber1024.ciphertext_length]u8,
    signed_then_encrypted_secret_key: GenericPacket([32]u8).EncryptedPacket,

    const Self = @This();

    pub const Result = extern struct {
        secret_key: [32]u8,
        self: Self,
    };

    pub fn init_random(io: std.Io, keypair: *const crypto.KeyPair, target: *const crypto.Pubkey) !Result {
        var random_io = std.Random.IoSource{ .io = io };
        const random = random_io.interface();

        const kyber_ciphertext = target.kyber.encaps(io);

        var self: Self = undefined;
        self.kyber_ciphertext = kyber_ciphertext.ciphertext;

        var random_key: [32]u8 = undefined;
        random.bytes(&random_key);

        var nonce: [crypto.XChaCha20Poly1305.NONCE_LEN]u8 = undefined;
        random.bytes(&nonce);

        const unencrypted: GenericPacket([32]u8) = try .init_and_sign(&keypair.mldsa, keypair.pubkey().raw().hash(), &random_key);

        self.signed_then_encrypted_secret_key = .encrypt(@ptrCast(&unencrypted), nonce, kyber_ciphertext.shared_secret);

        return .{ .secret_key = random_key, .self = self };
    }

    pub fn decrypt(self: Self, keypair: *const crypto.KeyPair) !GenericPacket([32]u8) {
        const kyber_key = try keypair.kyber.secret_key.decaps(&self.kyber_ciphertext);
        const decrypted = try self.signed_then_encrypted_secret_key.decrypt(kyber_key);

        const decrypted_parsed: *const GenericPacket([32]u8) = @ptrCast(&decrypted);

        return decrypted_parsed.*;
    }
};
