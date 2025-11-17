const std = @import("std");

const fastcrypto = @cImport({
    @cInclude("umac.c");
});

const openssl = @cImport({
    @cInclude("openssl/aes.h");
});


const BLOCK_LEN = 16; // At least 16 and a power of two
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


// Input:
//   K, string of length KEYLEN bytes.
//   Nonce, string of length 1 to BLOCKLEN bytes.
//   taglen, the integer 4, 8, 12 or 16.
// Output:
//   Y, string of length taglen bytes.
fn pdf(comptime key_len: comptime_int, key: *const [key_len]u8, nonce: []const u8, output: []u8) void {
    const tag_len = output.len;

    var index: usize = undefined;

    if (tag_len == 4 or tag_len == 8) {
        if (BLOCK_LEN != 16) {
            std.debug.panic("Unsupported BLOCK_LEN for tag_len 4 or 8", .{});
        }

        // log(1024/4)/log(2)
        index = nonce[nonce.len - 1] % @divExact(BLOCK_LEN, tag_len);
    } else {
        index = 0;
    }

    var padded_nonce: [BLOCK_LEN]u8 = undefined;
    @memcpy(padded_nonce[0..nonce.len], nonce);
    @memset(padded_nonce[nonce.len..], 0);

    padded_nonce[nonce.len - 1] ^= @intCast(index);

    var subkey: [KEY_LEN]u8 = undefined;
    kdf(key_len, key, 0, &subkey);
    const block = aesEncrypt(key_len, &subkey, &padded_nonce);

    @memcpy(output, block[(index * tag_len)..(index * tag_len + tag_len)]);
}


// Input:
//   K, string of length 1024 bytes.
//   M, string with length divisible by 32 bytes.
// Output:
//   Y, string of length 8 bytes.
fn nh(k: *const [L1_KEY_LEN]u8, m: []const u8) u64 {
    const chunk_count = @divExact(m.len, 4);
    var y: u64 = 0;

    var chunk_index: usize = 0;

    while (chunk_index < chunk_count) : (chunk_index += 8) {
        for (0..4) |sub_index| {
            const first_index = (chunk_index + sub_index) * 4;
            const second_index = first_index + 4 * 4;

            const m_i = std.mem.readInt(u32, m[first_index..][0..4], .little);
            const k_i = std.mem.readInt(u32, k[first_index..][0..4], .big);

            const m_i2 = std.mem.readInt(u32, m[second_index..][0..4], .little);
            const k_i2 = std.mem.readInt(u32, k[second_index..][0..4], .big);

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

//     const outInt = std.mem.readInt(u64, &out, .big);

//     try std.testing.expect(outInt == x);
// }


// Input:
//   K, string of length 1024 bytes.
//   M, string of length less than 2^67 bits.
// Output:
//   Y, string of length (8 * ceil(bytelength(M)/L1_KEY_LEN)) bytes.
//
fn l1(k: *const [L1_KEY_LEN]u8, m: []const u8, output: [*]u8) void {
    const chunk_count = @max(std.math.divCeil(usize, m.len, L1_KEY_LEN) catch unreachable, 1);

    for (0..chunk_count) |chunk_index| {
        const start_index = chunk_index * L1_KEY_LEN;
        const end_index = @min(start_index + L1_KEY_LEN, m.len);
        const chunk_size = end_index - start_index;

        var padded_chunk: []const u8 = undefined;

        if (chunk_size % L1_PAD_BOUNDARY != 0) {
            const padded_chunk_size = (std.math.divCeil(usize, chunk_size, L1_PAD_BOUNDARY) catch unreachable) * L1_PAD_BOUNDARY;
            var padded_chunk_buffer: [L1_KEY_LEN]u8 = undefined;

            @memcpy(padded_chunk_buffer[0..chunk_size], m[start_index..end_index]);
            @memset(padded_chunk_buffer[chunk_size..padded_chunk_size], 0);

            padded_chunk = padded_chunk_buffer[0..padded_chunk_size];
        } else {
            padded_chunk = m[start_index..end_index];
        }

        std.mem.writeInt(
            u64,
            output[(chunk_index * 8)..][0..8],
            nh(k, padded_chunk) +% (chunk_size << 3),
            .big,
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
        const m_i = std.mem.readInt(u16, m[(i * 2)..][0..2], .big);
        const k_i = @mod(std.mem.readInt(u64, k1[(i * 8)..][0..8], .big), PRIME_36);

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

    var l1_key: [L1_KEY_LEN + (max_iter_count - 1) * 16]u8 = undefined;
    var l2_key: [max_iter_count * 24]u8 = undefined;
    var l3_key1: [max_iter_count * 64]u8 = undefined;
    var l3_key2: [max_iter_count * 4]u8 = undefined;

    kdf(key_len, key, 1, l1_key[0..(L1_KEY_LEN + (iter_count - 1) * 16)]);
    kdf(key_len, key, 2, l2_key[0..(iter_count * 24)]);
    kdf(key_len, key, 3, l3_key1[0..(iter_count * 64)]);
    kdf(key_len, key, 4, l3_key2[0..(iter_count * 4)]);

    // std.debug.print("{any}\n", .{l3_key1[0..(iter_count * 64)]});

    // std.debug.print("{any}\n", .{L1_KEY_LEN + (iter_count - 1) * 16});
    // std.debug.print("{s}\n", .{std.fmt.bytesToHex(&l1_key, .lower)[0..((L1_KEY_LEN + (iter_count - 1) * 16) * 2)]});
    // std.debug.print("{s}\n", .{std.fmt.bytesToHex(&l2_key, .lower)[0..(iter_count * 24 * 2)]});

    for (0..iter_count) |iter_index| {
        const l1_output_size = @max(std.math.divCeil(usize, m.len, L1_KEY_LEN) catch unreachable, 1) * 8;
        const l1_output = std.heap.page_allocator.alloc(u8, l1_output_size) catch unreachable;
        defer std.heap.page_allocator.free(l1_output);

        l1(
            l1_key[(iter_index * 16)..][0..L1_KEY_LEN],
            m,
            l1_output.ptr,
        );

        // std.debug.print("{any}\n", .{m});
        // std.debug.print("{any}\n", .{l1_output});

        var l2_output: [16]u8 = undefined;
        @memset(l2_output[0..8], 0);
        @memcpy(l2_output[8..16], l1_output);

        const iter_result = l3(
            l3_key1[(iter_index * 64)..][0..64],
            std.mem.readInt(u32, l3_key2[(iter_index * 4)..][0..4], .big),
            &l2_output,
        );

        std.mem.writeInt(
            u32,
            output[(iter_index * 4)..][0..4],
            iter_result,
            .big,
        );
    }
}


// Input:
//   K, string of length KEYLEN bytes.
//   M, string of length less than 2^67 bits.
//   Nonce, string of length 1 to BLOCKLEN bytes.
//   taglen, the integer 4, 8, 12 or 16.
// Output:
//   Tag, string of length taglen bytes.
fn umac(key_len: comptime_int, key: *const [key_len]u8, m: []const u8, nonce: []const u8, output: []u8) void {
    const tag_len = output.len;
    std.debug.assert(tag_len == 4 or tag_len == 8 or tag_len == 12 or tag_len == 16);

    var uhash_output: [16]u8 = undefined;
    uhash(key_len, key, m, uhash_output[0..tag_len]);

    pdf(key_len, key, nonce, output[0..tag_len]);

    for (0..tag_len) |index| {
        output[index] ^= uhash_output[index];
    }
}


pub fn main() !void {
    const tag_len = 4; // 4, 8, 12 or 16

    var rand = std.Random.DefaultPrng.init(0);

    var key: [KEY_LEN]u8 = undefined;
    var message: [3]u8 align(8) = undefined;
    var result_self: [tag_len]u8 = undefined;
    var result_ref: [tag_len]u8 = undefined;

    // const message_len = message.len;
    const message_len = 0;

    // std.Random.bytes(rand.random(), &key);
    std.Random.bytes(rand.random(), &message);

    @memcpy(&key, "abcdefghijklmnop");
    @memcpy(&message, "aaa");


    // Self

    @memset(&result_self, 0);
    uhash(KEY_LEN, &key, message[0..message_len], &result_self);

    std.debug.print("----", .{});


    // Reference

    @memset(&result_ref, 0);

    {
        const ctx = fastcrypto.uhash_alloc(&key);
        _ = fastcrypto.uhash(ctx, &message, message_len, &result_ref);
        defer _ = fastcrypto.uhash_free(ctx);
    }


    std.debug.print("\n\nSelf {any}\n", .{result_self});
    std.debug.print("Ref  {any}\n", .{result_ref});

    std.debug.print("\n\nSelf {s}\n", .{std.fmt.bytesToHex(result_self, .lower)});
    std.debug.print("Ref  {s}\n", .{std.fmt.bytesToHex(result_ref, .lower)});


    // Full UMAC

    // var nonce align(8) = [_]u8{0x6a, 0x7b};
    var nonce: [8]u8 align(8) = undefined;
    @memcpy(&nonce, "bcdefghi");

    {
        const ctx = fastcrypto.umac_new(&key);
        _ = fastcrypto.umac(ctx, &message, message_len, &result_ref, &nonce);
        defer _ = fastcrypto.umac_delete(ctx);
    }

    umac(KEY_LEN, &key, message[0..message_len], &nonce, &result_self);

    std.debug.print("\n\nSelf {any}\n", .{result_self});
    std.debug.print("Ref  {any}\n", .{result_ref});

    std.debug.print("\n\nSelf {s}\n", .{std.fmt.bytesToHex(result_self, .lower)});
    std.debug.print("Ref  {s}\n", .{std.fmt.bytesToHex(result_ref, .lower)});
}
