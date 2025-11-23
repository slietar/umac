const std = @import("std");
const Encryptor = std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128);


pub const BLOCK_LEN = 16; // At least 16 and a power of two
pub const KEY_LEN = 16; // 16, 24 or 32
pub const MAX_TAG_LEN = 16;

const L1_PAD_BOUNDARY = 32;
const L1_KEY_LEN = 1024;
const L2_KEY_LEN = 24;
const L3_KEY1_LEN = 64;
const L3_KEY2_LEN = 4;


// Input:
//   K, string of length KEYLEN bytes.
//   index, a non-negative integer less than 2^64.
//   numbytes, a non-negative integer less than 2^64.
// Output:
//   Y, string of length numbytes bytes.
fn kdf(encryptor: *Encryptor, index: u8, output: []u8) void {
    const iter_count = std.math.divCeil(u32, @intCast(output.len), BLOCK_LEN) catch unreachable;

    var cipher_input = [_]u8{0} ** BLOCK_LEN;
    cipher_input[BLOCK_LEN - 9] = index;

    for (0..iter_count) |iter_index| {
        const start_index = iter_index * BLOCK_LEN;
        const end_index = @min(start_index + BLOCK_LEN, output.len);

        std.mem.writeInt(u32, cipher_input[(BLOCK_LEN - 4)..BLOCK_LEN], @intCast(iter_index + 1), .big);

        var block_output: [BLOCK_LEN]u8 = undefined;
        encryptor.encrypt(&block_output, &cipher_input);

        @memcpy(output[start_index..end_index], block_output[0..(end_index - start_index)]);
    }
}


// Input:
//   K, string of length KEYLEN bytes.
//   Nonce, string of length 1 to BLOCKLEN bytes.
//   taglen, the integer 4, 8, 12 or 16.
// Output:
//   Y, string of length taglen bytes.
fn pdf(key_encryptor: *Encryptor, nonce: []const u8, output: []u8) void {
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
    kdf(key_encryptor, 0, &subkey);

    var encryptor = Encryptor.init(subkey);

    var block: [BLOCK_LEN]u8 = undefined;
    encryptor.encrypt(&block, &padded_nonce);

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


const OFFSET_64 = 59;
const OFFSET_128 = 159;

const PRIME_36: u64 = (1 << 36) - 5;
const PRIME_64: u64 = (1 << 64) - OFFSET_64;
const PRIME_128: u128 = (1 << 128) - OFFSET_128;


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


const Stream = struct {
    const Self = @This();

    l1_key: *const [L1_KEY_LEN]u8,
    l2_k64: u128,
    l2_k128: u128, // Using u128 to avoid later cast
    l2_y: u128,
    l2_accum_count: usize = 0,
    l2_last_word: u64 = undefined,
    l3_key1: *const [L3_KEY1_LEN]u8,
    l3_key2: *const [L3_KEY2_LEN]u8,

    message_buffer: [L1_KEY_LEN]u8 = undefined,
    message_buffer_len: usize = 0,

    pub fn init(
        l1_key: *const [L1_KEY_LEN]u8,
        l2_key: *const [L2_KEY_LEN]u8,
        l3_key1: *const [L3_KEY1_LEN]u8,
        l3_key2: *const [L3_KEY2_LEN]u8,
    ) Self {
        const mask_32 = (1 << 25) - 1;
        const mask_64 = (mask_32 << 32) + mask_32;
        const mask_128 = (mask_64 << 64) + mask_64;

        const k64 = std.mem.readInt(u64, l2_key[0..8], .big) & mask_64;
        const k128 = std.mem.readInt(u128, l2_key[8..24], .big) & mask_128;

        return Self{
            .l1_key = l1_key,
            .l2_k64 = @intCast(k64),
            .l2_k128 = k128,
            .l2_y = 1,
            .l3_key1 = l3_key1,
            .l3_key2 = l3_key2,
        };
    }

    pub fn update(self: *Self, message_chunk: []const u8) void {
        const chunk_count = @divFloor(self.message_buffer_len + message_chunk.len, L1_KEY_LEN);

        for (0..chunk_count) |chunk_index| {
            var target: *const [L1_KEY_LEN]u8 = undefined;

            if (self.message_buffer_len == 0) {
                target = message_chunk[(chunk_index * L1_KEY_LEN)..][0..L1_KEY_LEN];
            } else if (chunk_index > 0) {
                target = message_chunk[(L1_KEY_LEN - self.message_buffer_len + (chunk_index - 1) * L1_KEY_LEN)..][0..L1_KEY_LEN];
            } else {
                @memcpy(
                    self.message_buffer[self.message_buffer_len..],
                    message_chunk[0..(L1_KEY_LEN - self.message_buffer_len)],
                );

                target = &self.message_buffer;
            }

            const word = nh(self.l1_key, target) +% (L1_KEY_LEN << 3);
            self.run_l2(word);

            self.l2_accum_count += 1;
        }

        self.message_buffer_len = (self.message_buffer_len + message_chunk.len) % L1_KEY_LEN;

        if (chunk_count == 0) {
            @memcpy(
                self.message_buffer[(self.message_buffer_len - message_chunk.len)..self.message_buffer_len],
                message_chunk,
            );
        } else {
            @memcpy(
                self.message_buffer[0..self.message_buffer_len],
                message_chunk[(message_chunk.len - self.message_buffer_len)..],
            );
        }
    }

    fn run_l2(self: *Self, word: u64) void {
        if (self.l2_accum_count == 0) {
            self.l2_y = @intCast(word);
        } else if (self.l2_accum_count < 1 << 14) {
            if (self.l2_accum_count == 1) {
                self.l2_y = (self.l2_k64 + self.l2_y) % PRIME_64;
            }

            self.l2_y = (self.l2_k64 * self.l2_y + @as(u128, word)) % PRIME_64;
        } else {
            if (self.l2_accum_count == 1 << 14) {
                self.l2_y = (self.l2_k128 + self.l2_y) % PRIME_128;
            }

            if (self.l2_accum_count % 2 == 0) {
                self.l2_last_word = word;
            } else {
                self.l2_y = @intCast(
                    (
                        (
                            @as(u256, self.l2_k128) * @as(u256, self.l2_y)
                        ) + (@as(u256, self.l2_last_word) << 64) + @as(u256, word)
                    ) % PRIME_128
                );
            }
        }
    }

    pub fn finish(self: *Self) [4]u8 {
        if (self.message_buffer_len > 0 or self.l2_accum_count == 0) {
            const padded_chunk_size = @max(1, std.math.divCeil(usize, self.message_buffer_len, L1_PAD_BOUNDARY) catch unreachable) * L1_PAD_BOUNDARY;
            @memset(self.message_buffer[self.message_buffer_len..padded_chunk_size], 0);

            const word = nh(self.l1_key, self.message_buffer[0..padded_chunk_size]) +% (self.message_buffer_len << 3);

            if (self.l2_accum_count > 0) {
                self.run_l2(word);
                self.l2_accum_count += 1;
            } else {
                self.l2_y = @intCast(word);
            }
        }

        if (self.l2_accum_count > 1 << 14) {
            self.run_l2(0x80 << (64 - 8));
            self.l2_accum_count += 1;

            if (self.l2_accum_count % 2 == 1) {
                self.run_l2(0);
            }
        }

        var l2_output: [16]u8 = undefined;
        std.mem.writeInt(u128, &l2_output, self.l2_y, .big);

        const iter_result = l3(
            self.l3_key1,
            std.mem.readInt(u32, self.l3_key2, .big),
            &l2_output,
        );

        var output: [4]u8 = undefined;
        std.mem.writeInt(u32, &output, iter_result, .big);

        return output;
    }
};


const MAX_STREAM_COUNT = @divExact(MAX_TAG_LEN, 4);

pub const Umac = struct {
    const Self = @This();

    pad: [MAX_TAG_LEN]u8 = undefined,
    streams: [MAX_STREAM_COUNT]Stream = undefined,
    stream_count: usize,

    l1_key: [L1_KEY_LEN + (MAX_STREAM_COUNT - 1) * 16]u8 = undefined,
    l2_key: [L2_KEY_LEN * MAX_STREAM_COUNT]u8 = undefined,
    l3_key1: [L3_KEY1_LEN * MAX_STREAM_COUNT]u8 = undefined,
    l3_key2: [L3_KEY2_LEN * MAX_STREAM_COUNT]u8 = undefined,

    pub fn init(tag_len: usize, key: *const [KEY_LEN]u8, nonce: []const u8) Self {
        const stream_count = @divExact(tag_len, 4);

        var self = Self{
            .stream_count = stream_count,
        };

        var key_encryptor = Encryptor.init(key.*);

        kdf(&key_encryptor, 1, self.l1_key[0..(L1_KEY_LEN + (stream_count - 1) * 16)]);
        kdf(&key_encryptor, 2, self.l2_key[0..(stream_count * L2_KEY_LEN)]);
        kdf(&key_encryptor, 3, self.l3_key1[0..(stream_count * L3_KEY1_LEN)]);
        kdf(&key_encryptor, 4, self.l3_key2[0..(stream_count * L3_KEY2_LEN)]);

        for (0..stream_count) |stream_index| {
            self.streams[stream_index] = Stream.init(
                self.l1_key[(stream_index * 16)..][0..L1_KEY_LEN],
                self.l2_key[(stream_index * L2_KEY_LEN)..][0..L2_KEY_LEN],
                self.l3_key1[(stream_index * L3_KEY1_LEN)..][0..L3_KEY1_LEN],
                self.l3_key2[(stream_index * L3_KEY2_LEN)..][0..L3_KEY2_LEN],
            );
        }

        pdf(&key_encryptor, nonce, self.pad[0..tag_len]);

        return self;
    }

    pub fn update(self: *Self, message_chunk: []const u8) void {
        for (self.streams[0..self.stream_count]) |*stream| {
            stream.update(message_chunk);
        }
    }

    pub fn finish(self: *Self, output: [*]u8) void {
        for (0.., self.streams[0..self.stream_count]) |stream_index, *stream| {
            const stream_output: [4]u8 = stream.finish();

            @memcpy(
                output[(stream_index * 4)..][0..4],
                &stream_output,
            );
        }

        for (0..(self.stream_count * 4)) |index| {
            output[index] ^= self.pad[index];
        }
    }
};



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
        .{
            .part = "a",
            .repeat = (1 << 24) - 1,
            .expected = .{"83C206C8", "FCE61C9EE7D13958", "A00D9823CD389FE1309F54F6"},
        },
        .{
            .part = "a",
            .repeat = 1 << 24,
            .expected = .{"A1B74376", "DE9359204D2ECB26", "8278DD9D67C76D9F9A3C5386"},
        },
        .{
            .part = "a",
            .repeat = (1 << 24) + 1,
            .expected = .{"6C8A252C", "13AE3F7A2D2255B8", "4F45BBC707CBF301094B6F7A"},
        },
        .{
            .part = "a",
            .repeat = 1 << 25,
            .expected = .{"85EE5CAE", "FACA46F856E9B45F", "A621C2457C0012E64F3FDAE9"},
        },
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

    for (test_cases) |test_case| {
        inline for (.{4, 8, 12}, 0..) |tag_len, tag_len_index| {
            var tag: [tag_len]u8 = undefined;
            var instance = Umac.init(tag_len, key, nonce);

            for (0..test_case.repeat) |_| {
                instance.update(test_case.part);
            }

            instance.finish(&tag);

            var expected_tag: [tag_len]u8 = undefined;
            _ = try std.fmt.hexToBytes(&expected_tag, test_case.expected[tag_len_index]);

            // const hex_output = std.fmt.bytesToHex(tag[0..4], .lower);
            // std.debug.print(">> {s} {s} \n", .{hex_output, test_case.expected[tag_len_index]});

            try std.testing.expectEqualSlices(u8, tag[0..tag_len], expected_tag[0..tag_len]);
        }
    }
}
