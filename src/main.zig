const std = @import("std");
const process = std.process;
const telda = @import("telda.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer arena.deinit();
    // const alloc = arena.allocator();

    var args = process.args();
    _ = args.skip();
    const path = args.next() orelse return error.NoArg;

    var bin = try telda.readBinary(alloc, path);
    defer bin.deinit();

    try bin.runCode();
}
