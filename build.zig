const std = @import("std");
const mem = std.mem;


fn runCommand(alloc: mem.Allocator, args: []const []const u8) std.process.Child.RunError![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = alloc,
        // .argv = &[_][]const u8{"uv", "python", "dir"},
        .argv = args,
    });

    alloc.free(result.stderr);
    return result.stdout;
}


pub fn build(b: *std.Build) !void {
    const allocator = std.heap.page_allocator;

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});


    const library_module_name = "umac";
    const library_module = b.addModule(library_module_name, .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    library_module.linkSystemLibrary("openssl", .{});


    const python_library_module_name = "umac_python";
    const python_library_module = b.addModule(python_library_module_name, .{
        .root_source_file = b.path("src/python.zig"),
        .target = target,
    });

    python_library_module.linkSystemLibrary("openssl", .{
        .preferred_link_mode = .static,
    });


    const find_python_stdout = try runCommand(allocator, &[_][]const u8{"uv", "python", "find", "3.14"});
    defer allocator.free(find_python_stdout);

    const python_bin_path = find_python_stdout[0..(find_python_stdout.len - 1)];
    const python_include_path = try runCommand(allocator, &[_][]const u8{python_bin_path, "-c", "print(__import__('sysconfig').get_path('include'), end='')"});
    defer allocator.free(python_include_path);

    python_library_module.addIncludePath(.{ .cwd_relative = python_include_path });


    const python_dynamic_library = b.addLibrary(.{
        .linkage = .dynamic,
        .name = "umac_dynamic",
        .root_module = python_library_module,
    });

    python_dynamic_library.linker_allow_shlib_undefined = true;

    b.installArtifact(python_dynamic_library);


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
