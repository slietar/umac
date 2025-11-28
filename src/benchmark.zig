const std = @import("std");

const umac = @import("./root.zig");

const nettle = @cImport({
    @cInclude("nettle/umac.h");
});


const tag_len = 4;

const buffer: [chunk_size]u8 = std.mem.zeroes([chunk_size]u8);

const chunk_size = 1 << 10;
const chunk_count = 1 << 15;
const message_size = chunk_size * chunk_count;

const key_value = "abcdefghijklmnop";
const nonce = "bcdefghi";


fn run_self(output: *[tag_len]u8) void {
    const key = umac.Key.init(tag_len, key_value);
    var instance = umac.Umac.init(tag_len, &key, nonce);

    for (0..chunk_count) |_| {
        instance.update(&buffer);
    }

    instance.finish(output);
}

fn run_nettle(output: *[tag_len]u8) void {
    var ctx32: nettle.umac32_ctx = undefined;
    nettle.umac32_set_key(&ctx32, key_value);
    nettle.umac32_set_nonce(&ctx32, nonce.len, nonce.ptr);

    for (0..chunk_count) |_| {
        nettle.umac32_update(&ctx32, chunk_size, &buffer);
    }

    nettle.umac32_digest(&ctx32, 4, output);
}


pub fn main() !void {
    for ([2]struct {
        name: []const u8,
        func: *const fn (output: *[tag_len]u8) void,
    } {
        .{ .name = "Self", .func = &run_self },
        .{ .name = "Nettle", .func = &run_nettle },
    }) |algorithm| {
        var timer = try std.time.Timer.start();

        var output: [tag_len]u8 = undefined;
        algorithm.func(&output);

        const duration_ns = timer.read();
        const speed: f64 = @as(f64, @floatFromInt(message_size)) / @as(f64, @floatFromInt(duration_ns)) * std.time.ns_per_s / 1e6;

        std.debug.print("[{s}]\n", .{algorithm.name});
        // std.debug.print("  {d} bytes in {d} s\n", .{message_size, @as(f64, @floatFromInt(duration_ns)) * 1e-9});
        std.debug.print("  Speed: {d:6.5} MB/second\n", .{speed});

        const output_hex = std.fmt.bytesToHex(output, .lower);
        std.debug.print("  Output: {s}\n", .{output_hex});
    }
}
