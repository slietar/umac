const std = @import("std");

const openssl = @cImport({
    @cInclude("openssl/aes.h");
});


const BLOCK_LEN = 16;
const KEY_LEN = 16; // 16, 24 or 32


fn aesEncrypt(comptime key_len: comptime_int, key: *const [key_len]u8, input: *const [BLOCK_LEN]u8) [BLOCK_LEN]u8 {
    var output: [BLOCK_LEN]u8 = undefined;

    var aesKey: openssl.AES_KEY = std.mem.zeroes(openssl.AES_KEY);

    if (openssl.AES_set_encrypt_key(key, key_len * 8, &aesKey) != 0) {
        std.debug.panic("Failed to set AES key", .{});
    }

    openssl.AES_encrypt(input, &output, &aesKey);
    return output;
}


fn kdf(comptime key_len: comptime_int, key: *const [key_len]u8, index: u8, num_bytes: u32, output: [*]u8) void {
    const iter_count = std.math.divCeil(u32, num_bytes, BLOCK_LEN) catch unreachable;

    var cipher_input = [_]u8{0} ** BLOCK_LEN;
    cipher_input[BLOCK_LEN - 9] = index;

    for (0..iter_count) |iter_index| {
        const start_index = iter_index * BLOCK_LEN;
        const end_index = @min(start_index + BLOCK_LEN, num_bytes);

        std.debug.print("Generating block {d} from {d} to {d}\n", .{iter_index, start_index, end_index});

        std.mem.writeInt(u32, cipher_input[(BLOCK_LEN - 4)..BLOCK_LEN], @intCast(iter_index), .big);

        const block_output = aesEncrypt(key_len, key, &cipher_input);
        @memcpy(output[start_index..end_index], block_output[0..(end_index - start_index)]);
    }
}


pub fn main() !void {
    const key: [KEY_LEN]u8 = undefined;
    const input = [_]u8{0} ** BLOCK_LEN;
    _ = input;
    // var output = [_]u8{0} ** 16;

    // // Use AES encryption from OpenSSL
    // var aesKey: openssl.AES_KEY = std.mem.zeroes(openssl.AES_KEY);
    // // var aesKey: openssl.AES_KEY = undefined;

    // if (openssl.AES_set_encrypt_key(&key, 128, &aesKey) != 0) {
    //     return error.FailedToSetAESKey;
    // }

    // // std.debug.print("{any}\n", .{aesKey});
    // std.debug.print("{any}\n", .{input});
    // openssl.AES_encrypt(&input, &output, &aesKey);
    // std.debug.print("{any}\n", .{output});

    // _ = aes(key.len, &key, &input);
    var output: [64]u8 = std.mem.zeroes([64]u8);
    kdf(key.len, &key, 0, output.len, &output);
}
