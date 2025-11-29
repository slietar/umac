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

    const standard_target = b.standardTargetOptions(.{});


    // Step: python

    {
        const step = b.step("python", "Build Python extension");

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
                    .abi = .gnu,
                    .cpu_arch = .aarch64,
                    .os_tag = .linux,
                }),
            },
            .{
                .name = "linux-x86_64",
                .target = b.resolveTargetQuery(.{
                    .abi = .gnu,
                    .cpu_arch = .x86_64,
                    .os_tag = .linux,
                }),
            },
        };

        const find_python_stdout = try runCommand(allocator, &[_][]const u8{"uv", "python", "find", "3.14"});
        defer allocator.free(find_python_stdout);

        const python_bin_path = find_python_stdout[0..(find_python_stdout.len - 1)];
        const python_include_path = try runCommand(allocator, &[_][]const u8{python_bin_path, "-c", "print(__import__('sysconfig').get_path('include'), end='')"});
        defer allocator.free(python_include_path);

        for (target_specs) |target_spec| {
            const target = target_spec.target;

            const module = b.createModule(.{
                .optimize = .ReleaseSmall,
                .root_source_file = b.path("src/python.zig"),
                .target = target,
            });

            module.link_libc = true;
            module.addIncludePath(.{ .cwd_relative = python_include_path });

            const name = try std.fmt.allocPrint(b.allocator, "umac-{s}-{s}", .{
                @tagName(target.result.cpu.arch),
                @tagName(target.result.os.tag),
            });

            const library = b.addLibrary(.{
                .linkage = .dynamic,
                .name = name,
                .root_module = module,
            });

            library.linker_allow_shlib_undefined = true;

            const artifact = b.addInstallArtifact(library, .{});
            step.dependOn(&artifact.step);
        }
    }


    // Step: benchmark

    {
        const step = b.step("benchmark", "Run benchmark");

        const module = b.createModule(.{
            .optimize = .ReleaseFast,
            .root_source_file = b.path("src/benchmark.zig"),
            .target = standard_target,
        });

        module.linkSystemLibrary("nettle", .{});

        const exe = b.addExecutable(.{
            .name = "benchmark",
            .root_module = module,
        });

        const run = b.addRunArtifact(exe);
        step.dependOn(&run.step);
    }


    // Step: test

    {
        const step = b.step("test", "Run tests");

        const module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = standard_target,
        });

        const @"test" = b.addTest(.{
            .root_module = module,
        });

        const run = b.addRunArtifact(@"test");
        step.dependOn(&run.step);
    }
}
