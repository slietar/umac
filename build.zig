const std = @import("std");


pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const library_module_name = "umac";
    const library_module = b.addModule(library_module_name, .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    library_module.linkSystemLibrary("openssl", .{});


    const executable_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = library_module_name, .module = library_module },
        },
    });

    executable_module.linkSystemLibrary("openssl", .{});


    const executable = b.addExecutable(.{
        .name = "umac",
        .root_module = executable_module,
    });

    b.installArtifact(executable);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(executable);

    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = library_module,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
}
