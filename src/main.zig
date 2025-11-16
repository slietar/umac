const std = @import("std");

const fastcrypto = @cImport({
    @cInclude("umac.c");
});

const openssl = @cImport({
    @cInclude("openssl/aes.h");
});


const BLOCK_LEN = 16;
const KEY_LEN = 16; // 16, 24 or 32

const L1_PAD_BOUNDARY = 32;
const L1_KEY_LEN = 1024;


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

        std.mem.writeInt(u32, cipher_input[(BLOCK_LEN - 4)..BLOCK_LEN], @intCast(iter_index + 1), .big);

        const block_output = aesEncrypt(key_len, key, &cipher_input);
        @memcpy(output[start_index..end_index], block_output[0..(end_index - start_index)]);
    }
}

test "kdf" {
    var rand = std.Random.DefaultPrng.init(0);
    var key: [KEY_LEN]u8 = undefined;
    std.Random.bytes(rand.random(), &key);

    const index = 2;
    const size = 31;


    // Reference

    var output_ref: [size]u8 = undefined;

    var prf_key: fastcrypto.aes_int_key = undefined;
    fastcrypto.aes_key_setup(&key, &prf_key);
    fastcrypto.kdf(&output_ref, &prf_key, index, size);


    // Self

    var output_self: [size]u8 = undefined;

    kdf(KEY_LEN, &key, index, &output_self);


    try std.testing.expectEqualSlices(u8, &output_ref, &output_self);
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


// Input:
//   K, string of length 1024 bytes.
//   M, string with length divisible by 32 bytes.
// Output:
//   Y, string of length 8 bytes.
fn nh(k: *const [L1_KEY_LEN]u8, m: []const u8) u64 {
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

// test "nh" {
//     var rand = std.Random.DefaultPrng.init(0);

//     var k: [1024]u8 = undefined;
//     std.Random.bytes(rand.random(), &k);

//     var m: [32 * 5]u8 = undefined;
//     std.Random.bytes(rand.random(), &m);

//     const x = nh(&k, &m);

//     var out = [_]u8{0} ** 8;
//     fastcrypto.nh_aux(&k, &m, &out, m.len);

//     const outInt = std.mem.readInt(u64, &out, .little);

//     try std.testing.expect(outInt == x);
// }


// Input:
//   K, string of length 1024 bytes.
//   M, string of length less than 2^67 bits.
// Output:
//   Y, string of length (8 * ceil(bytelength(M)/L1_KEY_LEN)) bytes.
//
// TODO: Do not assume that m.len is multiple of L1_PAD_BOUNDARY
fn l1(k: *const [L1_KEY_LEN]u8, m: []const u8, output: [*]u8) void {
    const chunk_count = @max(std.math.divCeil(usize, m.len, L1_KEY_LEN) catch unreachable, 1);

    for (0..chunk_count) |chunk_index| {
        std.mem.writeInt(
            u64,
            output[(chunk_index * 8)..][0..8],
            nh(k, m[(chunk_index * L1_KEY_LEN)..@min((chunk_index + 1) * L1_KEY_LEN, m.len)]) +% (L1_KEY_LEN << 3),
            .little, // TODO: May need to swap endianess
        );
    }
}


const PRIME_36: u64 = (1 << 36) - 5;
const PRIME_64: u64 = (1 << 64) - 59;
const PRIME_128: u128 = (1 << 128) - 159;

// Input:
//   K1, string of length 64 bytes.
//   K2, string of length 4 bytes.
//   M, string of length 16 bytes.
// Output:
//   Y, string of length 4 bytes.
fn l3(k1: *const [64]u8, k2: u32, m: *const [16]u8) u32 {
    var y: u64 = 0;

    for (0..8) |i| {
        const m_i = std.mem.readInt(u16, m[(i * 2)..][0..2], .little);
        const k_i = @mod(std.mem.readInt(u64, k1[(i * 8)..][0..8], .little), PRIME_36);

        y += m_i * k_i;
    }

    const z: u32 = @truncate(@mod(y, PRIME_36));
    return z ^ k2;
}


// Input:
//   K, string of length KEYLEN bytes.
//   M, string of length less than 2^67 bits.
//   taglen, the integer 4, 8, 12 or 16.
// Output:
//   Y, string of length taglen bytes.
fn uhash(key_len: comptime_int, key: *const [key_len]u8, m: []const u8, output: []u8) void {
    const tag_len = output.len;

    const iter_count = @divExact(tag_len, 4);
    const max_iter_count: comptime_int = @divExact(16, 4);

    var l1_key: [1024 + (max_iter_count - 1) * 16]u8 = undefined;
    var l2_key: [max_iter_count * 24]u8 = undefined;
    var l3_key1: [max_iter_count * 64]u8 = undefined;
    var l3_key2: [max_iter_count * 4]u8 = undefined;

    kdf(key_len, key, 0, l1_key[0..(1024 + (iter_count - 1) * 16)]);
    kdf(key_len, key, 1, l2_key[0..(iter_count * 24)]);
    kdf(key_len, key, 2, l3_key1[0..(iter_count * 64)]);
    kdf(key_len, key, 3, l3_key2[0..(iter_count * 4)]);

    for (0..iter_count) |iter_index| {
        const l1_output_size = (std.math.divCeil(usize, m.len, L1_KEY_LEN) catch unreachable) * 8;
        const l1_output = std.heap.page_allocator.alloc(u8, l1_output_size) catch unreachable;
        defer std.heap.page_allocator.free(l1_output);

        l1(
            l1_key[(iter_index * 16)..][0..L1_KEY_LEN],
            m,
            l1_output.ptr,
        );

        var l2_output: [16]u8 = undefined;
        @memcpy(l2_output[0..8], &std.mem.zeroes([8]u8));
        @memcpy(l2_output[8..16], l1_output[0..8]);

        const iter_result = l3(
            l3_key1[(iter_index * 64)..][0..64],
            std.mem.readInt(u32, l3_key2[(iter_index * 4)..][0..4], .big),
            &l2_output,
        );

        std.mem.writeInt(
            u32,
            output[(iter_index * 4)..][0..4],
            iter_result,
            .little,
        );
    }
}


pub fn main() !void {
    var rand = std.Random.DefaultPrng.init(0);

    var key: [KEY_LEN]u8 = undefined;
    var message: [1024]u8 = undefined;
    // var result: [16]u8 = undefined; // tag_len = 16

    std.Random.bytes(rand.random(), &key);
    std.Random.bytes(rand.random(), &message);


    // // Self

    // @memset(&result, 0);
    // uhash(KEY_LEN, &key, &message, &result);

    // std.debug.print("Self {any}\n", .{result});


    // // Reference

    // @memset(&result, 0);

    // const ctx = fastcrypto.uhash_alloc(&key);
    // const status = fastcrypto.uhash(ctx, &message, message.len, &result);

    // _ = status;

    // std.debug.print("Ref  {any}\n", .{result});
}
