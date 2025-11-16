const std = @import("std");

const fastcrypto = @cImport({
    @cInclude("umac.c");
});

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


fn kdf(comptime key_len: comptime_int, key: *const [key_len]u8, index: u8, output: []u8) void {
    const iter_count = std.math.divCeil(u32, @intCast(output.len), BLOCK_LEN) catch unreachable;

    var cipher_input = [_]u8{0} ** BLOCK_LEN;
    cipher_input[BLOCK_LEN - 9] = index;

    for (0..iter_count) |iter_index| {
        const start_index = iter_index * BLOCK_LEN;
        const end_index = @min(start_index + BLOCK_LEN, output.len);

        std.mem.writeInt(u32, cipher_input[(BLOCK_LEN - 4)..BLOCK_LEN], @intCast(iter_index), .big);

        const block_output = aesEncrypt(key_len, key, &cipher_input);
        @memcpy(output[start_index..end_index], block_output[0..(end_index - start_index)]);
    }
}


fn pdf(comptime key_len: comptime_int, key: *const [key_len]u8, nonce: []const u8, output: []u8) void {
    const tag_len = output.len;
    std.debug.assert(tag_len == 4 or tag_len == 8 or tag_len == 12 or tag_len == 16);

    var index = undefined;

    if (tag_len == 4 or tag_len == 8) {
        // TODO
        index = std.mem.readInt(u32, nonce);
    }

    var nonce_padded = [_]u8{0} ** BLOCK_LEN;
    @memcpy(&nonce_padded[0..nonce.len], nonce);

    var subkey: [KEY_LEN]u8 = undefined;
    kdf(key_len, key, 0, &subkey);
    const block = aesEncrypt(key_len, &subkey, &nonce_padded);

    if (tag_len == 4 or tag_len == 8) {
        @memcpy(output, block[(index * tag_len + 1)..(index * tag_len + tag_len)]);
    } else {
        @memcpy(output, block[0..tag_len]);
    }
}


fn nh(k: *const [1024]u8, m: []const u8) u64 {
    const t = @divExact(m.len, 4);
    var y: u64 = 0;

    var chunk_index: usize = 0;

    while (chunk_index < t) : (chunk_index += 8) {
        for (0..4) |sub_index| {
            const first_index = (chunk_index + sub_index) * 4;
            const second_index = first_index + 4 * 4;

            const m_i = std.mem.readInt(u32, m[first_index..][0..4], .little);
            const k_i = std.mem.readInt(u32, k[first_index..][0..4], .little);

            const m_i2 = std.mem.readInt(u32, m[second_index..][0..4], .little);
            const k_i2 = std.mem.readInt(u32, k[second_index..][0..4], .little);

            y +%= @as(u64, m_i +% k_i) *% @as(u64, m_i2 +% k_i2);
        }
    }

    return y;
}

test "nh" {
    var rand = std.Random.DefaultPrng.init(0);

    var k: [1024]u8 = undefined;
    std.Random.bytes(rand.random(), &k);

    var m: [32 * 5]u8 = undefined;
    std.Random.bytes(rand.random(), &m);

    const x = nh(&k, &m);

    var out = [_]u8{0} ** 8;
    fastcrypto.nh_aux(&k, &m, &out, m.len);

    const outInt = std.mem.readInt(u64, &out, .little);

    try std.testing.expect(outInt == x);
}


pub fn main() !void {
    // var rand = std.Random.DefaultPrng.init(0);

    // var k: [1024]u8 = undefined;
    // std.Random.bytes(rand.random(), &k);

    // var m: [32]u8 = undefined;
    // std.Random.bytes(rand.random(), &m);

    // const x = nh(&k, &m);
    // std.debug.print("Self {d}\n", .{x});

    // var out = [_]u8{0} ** 8;
    // fastcrypto.nh_aux(&k, &m, &out, m.len);
    // std.debug.print("Ref  {d}\n", .{std.mem.readInt(u64, &out, .big)});
    // std.debug.print("Ref  {d}\n", .{std.mem.readInt(u64, &out, .little)});
}
