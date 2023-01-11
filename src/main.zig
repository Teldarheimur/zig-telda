const std = @import("std");
const process = std.process;
const telda = @import("telda.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var args = process.args();
    _ = args.skip();
    const path = args.next() orelse return error.NoArg;

    var bin = try telda.readBinary(alloc, path);
    defer bin.deinit();

    bin.runCode() catch |e| switch (e) {
        error.NoEntry => std.log.err("No entry", .{}),
        error.NoMagic => std.log.err("No magic", .{}),
        error.OutOfMemory => std.log.err("No alloc", .{}),
        error.UnhandledTrap => std.log.err("Unhandled trap", .{}),
    };
}

test {
    @import("std").testing.refAllDecls(@This());
}
