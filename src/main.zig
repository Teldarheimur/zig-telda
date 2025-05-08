const std = @import("std");
const process = std.process;
const telda = @import("telda.zig");
const builtin = @import("builtin");

const is_debug = switch (builtin.mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};

var debug_allocator = std.heap.DebugAllocator(.{}).init;

pub fn main() !void {
    const gpa = if (is_debug)
        debug_allocator.allocator()
    else
        std.heap.smp_allocator;
    defer if (is_debug) {
        _ = debug_allocator.deinit();
    };

    var args = process.args();
    _ = args.skip();
    const path = args.next() orelse return error.NoArg;

    var bin = try telda.readBinary(gpa, path);
    defer bin.deinit();

    bin.runCode() catch |e| switch (e) {
        error.NoEntry => std.log.err("No entry", .{}),
        error.NoMagic => std.log.err("No magic", .{}),
        error.OutOfMemory => std.log.err("No alloc", .{}),
        error.UnhandledTrap => std.log.err("Unhandled trap", .{}),
        error.CouldNotPrint => std.log.err("Could not print", .{}),
    };
}

test {
    @import("std").testing.refAllDecls(@This());
}
