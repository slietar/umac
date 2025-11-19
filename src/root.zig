const std = @import("std");


const openssl = @cImport({
    @cInclude("openssl/aes.h");
});


pub const BLOCK_LEN = 16; // At least 16 and a power of two
pub const KEY_LEN = 16; // 16, 24 or 32


const OpenSSLEncryptor = struct {
    const Self = @This();

    aes_key: openssl.AES_KEY,

    fn encrypt(self: *Self, block_in: *const [BLOCK_LEN]u8, block_out: *[BLOCK_LEN]u8) void {
        openssl.AES_encrypt(@ptrCast(block_in), @ptrCast(block_out), &self.aes_key);
    }

    fn free(_: *Self) void {

    }

    fn init(self: *Self, key: *const [KEY_LEN]u8) void {
        if (openssl.AES_set_encrypt_key(key, KEY_LEN * 8, &self.aes_key) != 0) {
            @panic("Failed to set AES key");
        }
    }
};



const L1_PAD_BOUNDARY = 32;
const L1_KEY_LEN = 1024;


fn kdf(Encryptor: anytype, encryptor: *Encryptor, index: u8, output: []u8) void {
    const iter_count = std.math.divCeil(u32, @intCast(output.len), BLOCK_LEN) catch unreachable;

    var cipher_input = [_]u8{0} ** BLOCK_LEN;
    cipher_input[BLOCK_LEN - 9] = index;

    for (0..iter_count) |iter_index| {
        const start_index = iter_index * BLOCK_LEN;
        const end_index = @min(start_index + BLOCK_LEN, output.len);

        std.mem.writeInt(u32, cipher_input[(BLOCK_LEN - 4)..BLOCK_LEN], @intCast(iter_index + 1), .big);

        var block_output: [BLOCK_LEN]u8 = undefined;
        encryptor.encrypt(&cipher_input, &block_output);

        @memcpy(output[start_index..end_index], block_output[0..(end_index - start_index)]);
    }
}


// Input:
//   K, string of length KEYLEN bytes.
//   Nonce, string of length 1 to BLOCKLEN bytes.
//   taglen, the integer 4, 8, 12 or 16.
// Output:
//   Y, string of length taglen bytes.
fn pdf(Encryptor: anytype, key_encryptor: *Encryptor, nonce: []const u8, output: []u8) void {
    const tag_len = output.len;

    var index: usize = undefined;

    if (tag_len == 4 or tag_len == 8) {
        if (BLOCK_LEN > 1024) {
            @panic("Unsupported BLOCK_LEN for tag_len 4 or 8");
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
    kdf(Encryptor, key_encryptor, 0, &subkey);

    var encryptor: Encryptor = undefined;
    encryptor.init(&subkey);
    defer encryptor.free();

    var block: [BLOCK_LEN]u8 = undefined;
    encryptor.encrypt(&padded_nonce, &block);

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
            y = (k * y + marker) % prime;
            y = (k * y + (word - offset)) % prime;
        } else {
            // y = (k * y + word) % prime;
            y = @intCast((@as(double_word_type, k) * @as(double_word_type, y) + @as(double_word_type, word)) % @as(double_word_type, prime));
        }
    }

    return y;
}


// Input:
//   K, string of length 24 bytes.
//   M, string of length less than 2^64 bytes.
// Output:
//   Y, string of length 16 bytes.
fn l2(k: *const [24]u8, m: []const u8, output: *[16]u8) void {
    const mask_32 = (1 << 25) - 1;
    const mask_64 = (mask_32 << 32) + mask_32;
    const mask_128 = (mask_64 << 64) + mask_64;

    const k64 = std.mem.readInt(u64, k[0..8], .big) & mask_64;
    const k128 = std.mem.readInt(u128, k[8..24], .big) & mask_128;

    const boundary = 1 << 17;

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
fn uhash(Encryptor: anytype, key_encryptor: *Encryptor, m: []const u8, output: []u8) void {
    const tag_len = output.len;

    const iter_count = @divExact(tag_len, 4);
    const max_iter_count: comptime_int = @divExact(16, 4);

    var l1_key: [L1_KEY_LEN + (max_iter_count - 1) * 16]u8 = undefined;
    var l2_key: [max_iter_count * 24]u8 = undefined;
    var l3_key1: [max_iter_count * 64]u8 = undefined;
    var l3_key2: [max_iter_count * 4]u8 = undefined;

    kdf(Encryptor, key_encryptor, 1, l1_key[0..(L1_KEY_LEN + (iter_count - 1) * 16)]);
    kdf(Encryptor, key_encryptor, 2, l2_key[0..(iter_count * 24)]);
    kdf(Encryptor, key_encryptor, 3, l3_key1[0..(iter_count * 64)]);
    kdf(Encryptor, key_encryptor, 4, l3_key2[0..(iter_count * 4)]);

    for (0..iter_count) |iter_index| {
        const l1_output_size = @max(std.math.divCeil(usize, m.len, L1_KEY_LEN) catch unreachable, 1) * 8;
        const l1_output = std.heap.page_allocator.alloc(u8, l1_output_size) catch unreachable;
        defer std.heap.page_allocator.free(l1_output);

        l1(
            l1_key[(iter_index * 16)..][0..L1_KEY_LEN],
            m,
            l1_output.ptr,
        );

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
fn umac(Encryptor: anytype, key: *const [KEY_LEN]u8, m: []const u8, nonce: []const u8, output: []u8) void {
    const tag_len = output.len;
    std.debug.assert(tag_len == 4 or tag_len == 8 or tag_len == 12 or tag_len == 16);

    var key_encryptor: Encryptor = undefined;
    key_encryptor.init(key);
    defer key_encryptor.free();

    var uhash_output: [16]u8 = undefined;
    uhash(Encryptor, &key_encryptor, m, uhash_output[0..tag_len]);

    pdf(Encryptor, &key_encryptor, nonce, output[0..tag_len]);

    for (0..tag_len) |index| {
        output[index] ^= uhash_output[index];
    }
}


pub fn Umac(Encryptor: anytype, tag_len: comptime_int) type {
    return struct {
        const Self = @This();

        data: []u8,
        key: *const [KEY_LEN]u8,
        nonce: []const u8,

        pub fn init(key: *const [KEY_LEN]u8, nonce: []const u8) Self {
            return Self{
                .data = &[0]u8{},
                .key = key,
                .nonce = nonce,
            };
        }

        pub fn update(self: *Self, chunk: []const u8) void {
            var allocator = std.heap.page_allocator;
            var new_data = allocator.alloc(u8, self.data.len + chunk.len) catch unreachable;

            @memcpy(new_data[0..self.data.len], self.data);
            @memcpy(new_data[self.data.len..], chunk);

            allocator.free(self.data);
            self.data = new_data;
        }

        pub fn finish(self: *Self) [tag_len]u8 {
            var output: [tag_len]u8 = undefined;
            var allocator = std.heap.page_allocator;
            umac(Encryptor, self.key, self.data, self.nonce, &output);
            allocator.free(self.data);
            self.data = &[0]u8{};

            return output;
        }

        pub fn compute(
            key: *const [KEY_LEN]u8,
            nonce: []const u8,
            message: []const u8,
        ) [tag_len]u8 {
            var instance = Self.init(key, nonce);
            instance.update(message);

            return instance.finish();
        }
    };
}


test "umac" {
    const key = "abcdefghijklmnop";
    const nonce = "bcdefghi";

    const TestCase = struct {
        part: []const u8,
        repeat: usize,
        expected: [3]([]const u8),
    };

    const test_cases = [_]TestCase{
        .{
            .part = "",
            .repeat = 1,
            .expected = .{"113145FB", "6E155FAD26900BE1", "32FEDB100C79AD58F07FF764"},
        },
        .{
            .part = "a",
            .repeat = 3,
            .expected = .{"3B91D102", "44B5CB542F220104", "185E4FE905CBA7BD85E4C2DC"},
        },
        .{
            .part = "a",
            .repeat = 1 << 10,
            .expected = .{"599B350B", "26BF2F5D60118BD9", "7A54ABE04AF82D60FB298C3C"},
        },
        .{
            .part = "a",
            .repeat = 1 << 15,
            .expected = .{"58DCF532", "27F8EF643B0D118D", "7B136BD911E4B734286EF2BE"},
        },
        .{
            .part = "a",
            .repeat = 1 << 20,
            .expected = .{"DB6364D1", "A4477E87E9F55853", "F8ACFA3AC31CFEEA047F7B11"},
        },
        // .{
        //     .part = "a",
        //     .repeat = 1 << 25,
        //     .expected = .{"5109A660", "2E2DBC36860A0A5F", "72C6388BACE3ACE6FBF062D9"},
        // },
        .{
            .part = "abc",
            .repeat = 1,
            .expected = .{"ABF3A3A0", "D4D7B9F6BD4FBFCF", "883C3D4B97A61976FFCF2323"},
        },
        .{
            .part = "abc",
            .repeat = 500,
            .expected = .{"ABEB3C8B", "D4CF26DDEFD5C01A", "8824A260C53C66A36C9260A6"},
        },
    };


    // This constant must be at least as large as the largest nonrepeated message
    const CHUNK_LEN = (1 << 10) + (1 << 9);

    for (test_cases) |test_case| {
        inline for (.{4, 8, 12}, 0..) |tag_len, tag_len_index| {
            const part_len = test_case.part.len;
            const message_len = part_len * test_case.repeat;

            var chunk: [CHUNK_LEN]u8 = undefined;
            var tag: [tag_len]u8 = undefined;

            if (message_len > CHUNK_LEN) {
                var instance = Umac(OpenSSLEncryptor, tag_len).init(key, nonce);
                var repeat_index: usize = 0;

                while (repeat_index < test_case.repeat) {
                    const chunk_repeat_count = @min(@divFloor(CHUNK_LEN, part_len), test_case.repeat - repeat_index);
                    repeat_index += chunk_repeat_count;

                    for (0..chunk_repeat_count) |chunk_repeat_index| {
                        @memcpy(
                            chunk[(chunk_repeat_index * part_len)..][0..part_len],
                            test_case.part,
                        );
                    }

                    instance.update(chunk[0..(chunk_repeat_count * part_len)]);
                }

                tag = instance.finish();
            } else {
                for (0..test_case.repeat) |repeat_index| {
                    @memcpy(
                        chunk[(repeat_index * test_case.part.len)..][0..test_case.part.len],
                        test_case.part,
                    );
                }

                tag = Umac(OpenSSLEncryptor, tag_len).compute(key, nonce, chunk[0..message_len]);
            }

            var expected_tag: [tag_len]u8 = undefined;
            _ = try std.fmt.hexToBytes(&expected_tag, test_case.expected[tag_len_index]);

            try std.testing.expectEqualSlices(u8, tag[0..tag_len], expected_tag[0..tag_len]);
        }
    }
}
