const std = @import("std");

const umac = @import("./root.zig");


const TAG_LEN = 4;

pub fn main() !void {
    const key = "abcdefghijklmnop";
    const nonce = "bcdefghi";
    var instance = umac.Umac.init(TAG_LEN, key, nonce);

    const stdin = std.fs.File.stdin();

    var message_size: usize = 0;
    var timer = try std.time.Timer.start();

    while (true) {
        var buffer: [16_384]u8 = undefined;
        const read_count = try stdin.read(&buffer);

        if (read_count == 0) break;

        message_size += read_count;
        instance.update(buffer[0..read_count]);
    }

    var output: [TAG_LEN]u8 = undefined;
    instance.finish(&output);

    const duration_ns = timer.read();
    const speed: f64 = @as(f64, @floatFromInt(message_size)) / @as(f64, @floatFromInt(duration_ns)) * 1e9 / 1e6;

    std.debug.print("Speed: {d:6.5} MB/second\n", .{speed});

    const output_hex = std.fmt.bytesToHex(output, .lower);
    std.debug.print("{s}", .{output_hex});
}
