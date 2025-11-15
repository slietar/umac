const std = @import("std");

const openssl = @cImport({
    @cInclude("openssl/aes.h");
});

pub fn main() !void {
    const key: [32]u8 = undefined;
    const input = [_]u8{0} ** 16;
    var output = [_]u8{0} ** 16;

    // Use AES encryption from OpenSSL
    var aesKey: openssl.AES_KEY = std.mem.zeroes(openssl.AES_KEY);
    // var aesKey: openssl.AES_KEY = undefined;

    if (openssl.AES_set_encrypt_key(&key, 128, &aesKey) != 0) {
        return error.FailedToSetAESKey;
    }

    // std.debug.print("{any}\n", .{aesKey});
    std.debug.print("{any}\n", .{input});
    openssl.AES_encrypt(&input, &output, &aesKey);
    std.debug.print("{any}\n", .{output});
}
