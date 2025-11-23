const std = @import("std");

const umac = @import("./root.zig");


const TAG_LEN = 4;

pub fn main() !void {
    const key = "abcdefghijklmnop";
    const nonce = "bcdefghi";
    var instance = umac.StreamedUmac.init(TAG_LEN, key, nonce);
    // var instance = umac.Umac.init(TAG_LEN, key, nonce);

    var timer = try std.time.Timer.start();

    const chunk_size = 1 << 4;
    const chunk_count = 1 << 16;
    const message_size = chunk_size * chunk_count;

    var buffer: [chunk_count]u8 = undefined;
    @memset(&buffer, 0);

    for (0..chunk_count) |_| {
        instance.update(&buffer);
    }

    var output: [TAG_LEN]u8 = undefined;
    instance.finish(&output);

    const duration_ns = timer.read();
    const speed: f64 = @as(f64, @floatFromInt(message_size)) / @as(f64, @floatFromInt(duration_ns)) * 1e9 / 1e6;

    std.debug.print("{d} bytes in {d} s\n", .{message_size, @as(f64, @floatFromInt(duration_ns)) * 1e-9});
    std.debug.print("Speed: {d:6.5} MB/second\n", .{speed});

    const output_hex = std.fmt.bytesToHex(output, .lower);
    std.debug.print("{s}", .{output_hex});
}
