const std = @import("std");

const TAG_LEN = 12;

const TAG_LEN_STR: []const u8 = blk: {
    const string = std.fmt.digits2(TAG_LEN);

    if (TAG_LEN < 10) {
        break :blk string[1..2];
    } else {
        break :blk &string;
    }
};

const fastcrypto = @cImport({
    @cDefine("UMAC_OUTPUT_LEN", TAG_LEN_STR);
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
        if (BLOCK_LEN > 1024) {
            std.debug.panic("Unsupported BLOCK_LEN for tag_len 4 or 8", .{});
        }

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
//   Y, string of length (8 * max(1, ceil(bytelength(M)/L1_KEY_LEN))) bytes.
//
fn l1(k: *const [L1_KEY_LEN]u8, m: []const u8, output: [*]u8) void {
    const chunk_count = @max(std.math.divCeil(usize, m.len, L1_KEY_LEN) catch unreachable, 1);

    for (0..chunk_count) |chunk_index| {
        const start_index = chunk_index * L1_KEY_LEN;
        const end_index = @min(start_index + L1_KEY_LEN, m.len);
        const chunk_size = end_index - start_index;

        var padded_chunk: []const u8 = undefined;

        if (chunk_size == 0) {
            // Not written in the RFC
            padded_chunk = &[_]u8{0} ** L1_PAD_BOUNDARY;
        } else if (chunk_size % L1_PAD_BOUNDARY != 0) {
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


const OFFSET_64 = 59;
const OFFSET_128 = 159;

const PRIME_36: u64 = (1 << 36) - 5;
const PRIME_64: u64 = (1 << 64) - OFFSET_64;
const PRIME_128: u128 = (1 << 128) - OFFSET_128;


// Input:
//   wordbits, the integer 64 or 128.
//   maxwordrange, positive integer less than 2^wordbits.
//   k, integer in the range 0 ... prime(wordbits) - 1.
//   M, string with length divisible by (wordbits / 8) bytes.
// Output:
//   y, integer in the range 0 ... prime(wordbits) - 1.
fn poly(comptime word_type: anytype, max_word_range: word_type, k: word_type, m: []const u8) word_type {
    const offset = if (word_type == u64) OFFSET_64 else OFFSET_128;
    const prime: word_type = if (word_type == u64) PRIME_64 else PRIME_128;
    const marker = prime - 1;

    const word_size = @sizeOf(word_type);
    const double_word_type = if (word_type == u64) u128 else u256;

    var y: word_type = 1;

    for (0..@divExact(m.len, word_size)) |word_index| {
        const word = std.mem.readInt(word_type, m[(word_index * word_size)..][0..word_size], .big);

        if (word >= max_word_range) {
            std.debug.print("!!!", .{});
            y = (k * y + marker) % prime;
            y = (k * y + (word - offset)) % prime;
        } else {
            // y = (k * y + word) % prime;
            y = @intCast((@as(double_word_type, k) * @as(double_word_type, y) + @as(double_word_type, word)) % @as(double_word_type, prime));
        }

        // std.debug.print(">>> {d}\n", .{y});
    }

    // std.debug.print("Poly accum 0 (self) {d}\n", .{y});
    // std.debug.print(">>> {d} {any}\n", .{k, m});
    // _ = 7;

    return y;
}


// Input:
//   K, string of length 24 bytes.
//   M, string of length less than 2^64 bytes.
// Output:
//   Y, string of length 16 bytes.
fn l2(k: *const [24]u8, m: []const u8, output: *[16]u8) void {
    const mask_64 = 0x01ffffff01ffffff;
    const mask_128 = 0x01ffffff01ffffff01ffffff01ffffff;

    // const mask_32 = (1 << 25) - 1;
    // const mask_64 = (mask_32 << 32) + mask_32;
    // const mask_128 = (mask_64 << 64) + mask_64;

    const k64 = std.mem.readInt(u64, k[0..8], .big) & mask_64;
    const k128 = std.mem.readInt(u128, k[8..24], .big) & mask_128;
    // std.debug.print("!!!! {d}\n", .{k64});

    const boundary = 1 << 17;
    // const boundary = (1 << 17) - 1;
    // std.debug.print("L2 boundary {d}\n", .{boundary});
    // std.debug.print("L2 m.len {d}\n", .{m.len});

    if (m.len <= boundary) {
        const y = poly(u64, (1 << 64) - (1 << 32), k64, m);
        @memset(output[0..8], 0);
        std.mem.writeInt(u64, output[8..16], y, .big); // TODO: Not sure
        // std.debug.print("!!!! small {d}\n", .{y});
    } else {
        const rest = m.len - boundary;
        const m_1 = m[0..boundary];
        // std.debug.print("L2 rest {d}\n", .{rest});

        const y1 = poly(u64, (1 << 64) - (1 << 32), k64, m_1);

        // Prefix (16) + M_2 (rest) + 0x80 (1) + padding
        const nominal_size = 16 + rest + 1;
        const padded_size = (std.math.divCeil(usize, nominal_size, 16) catch unreachable) * 16;

        var m_2 = std.heap.page_allocator.alloc(u8, padded_size) catch unreachable;
        defer std.heap.page_allocator.free(m_2);

        @memset(m_2[0..8], 0);
        std.mem.writeInt(u64, m_2[8..16], y1, .big);
        @memcpy(m_2[16..(16 + rest)], m[boundary..]);
        m_2[16 + rest] = 0x80;
        @memset(m_2[(16 + rest + 1)..], 0);

        // std.debug.print("{any}\n", .{m_2});

        const y2 = poly(u128, (1 << 128) - (1 << 64), k128, m_2);
        std.mem.writeInt(u128, output, y2, .big);
    }
}


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
        // std.debug.print(">>> m_i {d} k_i {d}\n", .{m_i, k_i});

        y += m_i * k_i;
    }

    // std.debug.print(">>> L3 pre-mod {d}\n", .{y});

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

        if (m.len <= L1_KEY_LEN) {
            @memset(l2_output[0..8], 0);
            @memcpy(l2_output[8..16], l1_output);
        } else {
            l2(
                l2_key[(iter_index * 24)..][0..24],
                l1_output,
                &l2_output,
            );
        }

        const iter_result = l3(
            l3_key1[(iter_index * 64)..][0..64],
            std.mem.readInt(u32, l3_key2[(iter_index * 4)..][0..4], .big),
            &l2_output,
        );

        // std.debug.print("Iter {d} result {d}\n", .{iter_index, iter_result});
        // _ = 1;

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
    const tag_len: usize = TAG_LEN; // 4, 8, 12 or 16

    var rand = std.Random.DefaultPrng.init(0);

    var message = std.heap.page_allocator.alloc(u8, 1 << 25) catch unreachable;

    var key: [KEY_LEN]u8 = undefined;
    // var message: [1 << 20]u8 align(8) = undefined;
    var result_self: [tag_len]u8 = undefined;
    var result_ref: [tag_len]u8 = undefined;

    // const message_len = message.len;
    const message_len = 1 << 5; // (1 << 24) + 1;

    std.Random.bytes(rand.random(), &key);
    std.Random.bytes(rand.random(), message);

    @memcpy(&key, "abcdefghijklmnop");
    @memset(message, "a"[0]);
    // @memcpy(&message, "aaa");


    // Self

    @memset(&result_self, 0);
    uhash(KEY_LEN, &key, message[0..message_len], &result_self);

    // std.debug.print("----", .{});


    // Reference

    @memset(&result_ref, 0);

    {
        const ctx = fastcrypto.uhash_alloc(&key);
        _ = fastcrypto.uhash(ctx, message.ptr, @intCast(message_len), &result_ref);
        defer _ = fastcrypto.uhash_free(ctx);
    }


    std.debug.print("\n\nSelf {any}\n", .{result_self});
    std.debug.print("Ref  {any}\n", .{result_ref});

    std.debug.print("\nSelf {s}\n", .{std.fmt.bytesToHex(result_self, .lower)});
    std.debug.print("Ref  {s}\n", .{std.fmt.bytesToHex(result_ref, .lower)});


    // Full UMAC

    // var nonce align(8) = [_]u8{0x6a, 0x7b};
    var nonce: [8]u8 align(8) = undefined;
    @memcpy(&nonce, "bcdefghi");

    {
        const ctx = fastcrypto.umac_new(&key);
        _ = fastcrypto.umac(ctx, message.ptr, @intCast(message_len), &result_ref, &nonce);
        defer _ = fastcrypto.umac_delete(ctx);
    }

    umac(KEY_LEN, &key, message[0..message_len], &nonce, &result_self);

    std.debug.print("\n\nSelf {any}\n", .{result_self});
    std.debug.print("Ref  {any}\n", .{result_ref});

    std.debug.print("\nSelf {s}\n", .{std.fmt.bytesToHex(result_self, .lower)});
    std.debug.print("Ref  {s}\n", .{std.fmt.bytesToHex(result_ref, .lower)});
}
