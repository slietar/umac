const std = @import("std");
const mem = std.mem;


fn runCommand(alloc: mem.Allocator, args: []const []const u8) std.process.Child.RunError![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = alloc,
        .argv = args,
    });

    alloc.free(result.stderr);
    return result.stdout;
}


pub fn build(b: *std.Build) !void {
    const allocator = std.heap.page_allocator;

    const TargetSpec = struct {
        name: []const u8,
        target: std.Build.ResolvedTarget,
    };

    const target_specs = [_]TargetSpec{
        .{
            .name = "macos-aarch64",
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .aarch64,
                .os_tag = .macos,
            }),
        },
        .{
            .name = "linux-aarch64",
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .aarch64,
                .os_tag = .linux,
            }),
        },
        .{
            .name = "linux-x86_64",
            .target = b.resolveTargetQuery(.{
                .cpu_arch = .x86_64,
                .os_tag = .linux,
            }),
        },
    };

    for (target_specs) |target_spec| {
        const target = target_spec.target;

        // const library_module_name = "umac";
        // const library_module = b.addModule(library_module_name, .{
        //     .root_source_file = b.path("src/root.zig"),
        //     .target = target,
        // });


        const python_library_module = b.createModule(.{
            .optimize = .ReleaseSmall,
            .root_source_file = b.path("src/python.zig"),
            .target = target,
        });

        python_library_module.link_libc = true;


        const find_python_stdout = try runCommand(allocator, &[_][]const u8{"uv", "python", "find", "3.14"});
        defer allocator.free(find_python_stdout);

        const python_bin_path = find_python_stdout[0..(find_python_stdout.len - 1)];
        const python_include_path = try runCommand(allocator, &[_][]const u8{python_bin_path, "-c", "print(__import__('sysconfig').get_path('include'), end='')"});
        defer allocator.free(python_include_path);

        python_library_module.addIncludePath(.{ .cwd_relative = python_include_path });


        const name = try std.fmt.allocPrint(b.allocator, "umac-{s}-{s}", .{
            @tagName(target.result.cpu.arch),
            @tagName(target.result.os.tag),
        });

        const python_dynamic_library = b.addLibrary(.{
            .linkage = .dynamic,
            .name = name,
            .root_module = python_library_module,
        });

        python_dynamic_library.linker_allow_shlib_undefined = true;

        b.installArtifact(python_dynamic_library);
    }


    const test_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = b.standardTargetOptions(.{}),
    });

    const mod_tests = b.addTest(.{
        .root_module = test_module,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
}
