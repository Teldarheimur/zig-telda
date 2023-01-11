const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const builtin = @import("builtin");

inline fn splitByte(byte: u8) struct { h: u4, l: u4 } {
    return .{
        .h = @intCast(u4, byte >> 4),
        .l = @intCast(u4, byte & 0xf),
    };
}

const RuntimeState = struct {
    gprs: [20]u8 = undefined,
    rs: u16 = 0xffe0,
    rl: u16 = 0,
    rf: u16 = 0xffe0,
    rp: u16 = 0,
    rh: u16 = 0,
    rip: u16,
    rflags: packed struct {
        zero: bool = false,
        sign: bool = false,
        overflow: bool = false,
        carry: bool = false,
    } = .{},

    const Self = @This();

    pub fn init(entry: u16) Self {
        return .{
            .rip = entry,
        };
    }
    pub fn readInstruction(self: *Self, code: []const u8) []const u8 {
        const length: u16 = switch (code[self.rip]) {
            0x21...0x26 => 2,
            0x27...0x28 => 4,
            0x29...0x2a => 3,
            0x2b...0x2c => 4,
            0x2d...0x2e => 3,
            0x2f...0x3a => 3,
            0x3f => 3,
            0x40 => 4,
            0x41...0x54 => 3,
            else => 1,
        };
        const ret = code[self.rip .. self.rip + length];
        self.rip += length;
        return ret;
    }
    pub fn br(self: *Self, regnum: u4) u8 {
        const index: u8 = regnum;
        return switch (regnum) {
            0 => 0,
            1...10 => self.gprs[index - 1],
            11...15 => @truncate(u8, self.wr(regnum - 11 + 6)),
        };
    }
    pub fn setbr(self: *Self, regnum: u4, val: u8) void {
        const index: u8 = regnum;
        switch (regnum) {
            0 => {},
            1...10 => self.gprs[index - 1] = val,
            11...15 => self.setwr(regnum - 11 + 6, val),
        }
    }
    pub fn wr(self: *Self, regnum: u4) u16 {
        return switch (regnum) {
            0 => 0,
            1...10 => {
                const i: u8 = @as(u8, regnum - 1) << 1;
                return mem.readIntSliceLittle(u16, self.gprs[i .. i + 2]);
            },
            11 => self.rs,
            12 => self.rl,
            13 => self.rf,
            14 => self.rp,
            15 => self.rh,
        };
    }
    pub fn setwr(self: *Self, regnum: u4, val: u16) void {
        switch (regnum) {
            0 => {},
            1...10 => {
                const i = @as(u8, regnum - 1) << 1;
                mem.writeIntSliceLittle(u16, self.gprs[i .. i + 2], val);
            },
            11 => self.rs = val,
            12 => self.rl = val,
            13 => self.rf = val,
            14 => self.rp = val,
            15 => self.rh = val,
        }
    }
    pub inline fn setbrf(self: *Self, regnum: u4, val: u8) void {
        self.setbr(regnum, val);
        self.rflags.zero = val == 0;
        self.rflags.sign = @bitCast(i8, val) < 0;
    }
    pub inline fn setwrf(self: *Self, regnum: u4, val: u16) void {
        self.setwr(regnum, val);
        self.rflags.zero = val == 0;
        self.rflags.sign = @bitCast(i16, val) < 0;
    }
};

const Trap = error{
    Invalid,
    Halt,
    ZeroDiv,
    OutOfMemory,
    IoError,
};

fn todo(comptime description: []const u8) noreturn {
    @panic("todo: " ++ description);
}

fn runInstruction(code: []const u8, rt: *RuntimeState, memvw: *TeldaBin.MemoryView) Trap!void {
    const ins = rt.readInstruction(code);

    switch (ins[0]) {
        0x0a => return Trap.Halt,
        // NOP
        0x20 => {},
        0x21 => {
            const reg = splitByte(ins[1]).h;
            rt.rs -= 1;

            memvw.write(rt.rs, rt.br(reg)) catch return error.IoError;
        },
        0x22 => todo("push wide register"),
        0x23 => {
            const reg = splitByte(ins[1]).h;
            rt.setbr(reg, memvw.read(rt.rs) catch return error.IoError);

            rt.rs += 1;
        },
        0x24 => todo("pop wide register"),
        0x25 => {
            rt.rl = rt.rip;
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
            rt.rip = imm;
        },
        0x26 => {
            const imm = ins[1];
            rt.rip = rt.rl;
            rt.rs += imm;
        },
        0x27 => {
            const regs = splitByte(ins[1]);
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            memvw.write(imm + rt.wr(regs.h), rt.br(regs.l)) catch return error.IoError;
        },
        0x28 => todo("wide store with immediate, store wr1, w, wr2"),
        0x29 => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            memvw.write(rt.wr(regs.l) + rt.wr(regs.h), rt.br(src)) catch return error.IoError;
        },
        0x2a => todo("wide store with register, store wr1, wr2, wr3"),
        0x2b => {
            const regs = splitByte(ins[1]);
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            rt.setbr(regs.h, memvw.read(imm + rt.wr(regs.l)) catch return error.IoError);
        },
        0x2c => todo("load store with immediate, load wr1, wr2, w"),
        0x2d => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            rt.setbr(regs.h, memvw.read(rt.wr(src) + rt.wr(regs.l)) catch return error.IoError);
        },
        0x2e => todo("load store with register, load wr1, wr2, wr3"),
        0x2f => if (rt.rflags.zero) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x30 => if (rt.rflags.sign != rt.rflags.overflow) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x31 => if (rt.rflags.sign != rt.rflags.overflow and rt.rflags.zero) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x32 => if (rt.rflags.sign == rt.rflags.overflow and !rt.rflags.zero) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x33 => if (rt.rflags.sign == rt.rflags.overflow) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x34 => if (!rt.rflags.zero) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x35 => if (rt.rflags.overflow) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x36 => if (!rt.rflags.overflow) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x37 => if (rt.rflags.carry) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x38 => if (!rt.rflags.carry) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x39 => if (!rt.rflags.carry and !rt.rflags.zero) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x3a => if (rt.rflags.carry or rt.rflags.zero) {
            rt.rip = mem.littleToNative(u16, mem.bytesToValue(u16, ins[1..3]));
        },
        0x3f => {
            const dest = splitByte(ins[1]).h;
            rt.setbr(dest, ins[2]);
        },
        0x40 => {
            const ins1 = splitByte(ins[1]);
            const dest = ins1.h;
            const opt = ins1.l;
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            switch (opt) {
                0 => rt.setwr(dest, imm),
                1 => {
                    if (dest == 0) {
                        rt.rip = imm;
                    } else {
                        rt.rip = rt.wr(dest);
                    }
                },
                else => return Trap.Invalid,
            }
        },
        0x41 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            var sum: u8 = undefined;
            var isum: i8 = undefined;
            const term1 = rt.br(op1);
            const term2 = rt.br(op2);
            const carry = @addWithOverflow(u8, term1, term2, &sum);
            const overflow = @addWithOverflow(i8, @bitCast(i8, term1), @bitCast(i8, term2), &isum);
            rt.rflags.carry = carry;
            rt.rflags.overflow = overflow;
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setbr(dest, sum);
        },
        0x42 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            var sum: u16 = undefined;
            var isum: i16 = undefined;
            const term1 = rt.wr(op1);
            const term2 = rt.wr(op2);
            const carry = @addWithOverflow(u16, term1, term2, &sum);
            const overflow = @addWithOverflow(i16, @bitCast(i16, term1), @bitCast(i16, term2), &isum);
            rt.rflags.carry = carry;
            rt.rflags.overflow = overflow;
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setwr(dest, sum);
        },
        0x43 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            var sum: u8 = undefined;
            var isum: i8 = undefined;
            const term1 = rt.br(op1);
            const term2 = rt.br(op2);
            const carry = @subWithOverflow(u8, term1, term2, &sum);
            const overflow = @subWithOverflow(i8, @bitCast(i8, term1), @bitCast(i8, term2), &isum);
            rt.rflags.carry = carry;
            rt.rflags.overflow = overflow;
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setbr(dest, sum);
        },
        0x44 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            var sum: u16 = undefined;
            var isum: i16 = undefined;
            const term1 = rt.wr(op1);
            const term2 = rt.wr(op2);
            const carry = @subWithOverflow(u16, term1, term2, &sum);
            const overflow = @subWithOverflow(i16, @bitCast(i16, term1), @bitCast(i16, term2), &isum);
            rt.rflags.carry = carry;
            rt.rflags.overflow = overflow;
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setwr(dest, sum);
        },
        0x45 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, rt.br(op1) & rt.br(op2));
        },
        0x46 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) & rt.wr(op2));
        },
        0x47 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbr(dest, rt.br(op1) | rt.br(op2));
        },
        0x48 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) | rt.wr(op2));
        },
        0x49 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, rt.br(op1) ^ rt.br(op2));
        },
        0x4a => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) ^ rt.wr(op2));
        },
        0x4b => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, rt.br(op1) << @intCast(u3, rt.br(op2)));
        },
        0x4c => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) << @intCast(u4, rt.wr(op2)));
        },
        0x4d => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, @intCast(u8, @bitCast(i8, rt.br(op1)) >> @intCast(u3, rt.br(op2))));
        },
        0x4e => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, @intCast(u16, @bitCast(i16, rt.wr(op1)) >> @intCast(u4, rt.wr(op2))));
        },
        0x4f => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, rt.br(op1) >> @intCast(u3, rt.br(op2)));
        },
        0x50 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) >> @intCast(u4, rt.wr(op2)));
        },
        0x51 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const dividend = rt.br(ops.h);
            const divisor = rt.br(ops.l);

            if (divisor == 0) return Trap.ZeroDiv;

            rt.setbr(dest.h, dividend / divisor);
            rt.setbr(dest.l, dividend % divisor);
        },
        0x52 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const dividend = rt.wr(ops.h);
            const divisor = rt.wr(ops.l);

            if (divisor == 0) return Trap.ZeroDiv;

            rt.setwr(dest.h, dividend / divisor);
            rt.setwr(dest.l, dividend % divisor);
        },
        0x53 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const res = mem.nativeToLittle(u16, @as(u16, rt.br(ops.h)) * @as(u16, rt.br(ops.l)));
            const bytes = mem.asBytes(&res);

            rt.setbr(dest.l, bytes[0]);
            rt.setbr(dest.h, bytes[1]);
        },
        0x54 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const res = mem.nativeToLittle(u32, @as(u32, rt.wr(ops.h)) * @as(u32, rt.wr(ops.l)));
            const bytes = mem.asBytes(&res);

            rt.setwr(dest.l, mem.bytesToValue(u16, bytes[0..2]));
            rt.setwr(dest.h, mem.bytesToValue(u16, bytes[2..4]));
        },
        else => return Trap.Invalid,
    }
}

pub const TeldaBin = struct {
    code: []u8,
    entry: ?u16,
    alloc: Allocator,
    data: []u8,

    const Self = @This();

    pub const MemoryView = struct {
        code_len: usize,
        data: *[]u8,
        alloc: Allocator,
        pub fn init(bin: *Self) !MemoryView {
            return .{
                .code_len = bin.code.len,
                .data = &bin.data,
                .alloc = bin.alloc,
            };
        }
        pub fn read(self: *@This(), addr: u16) !u8 {
            if (addr >= 0xffe0) {
                var buf: [1]u8 = undefined;
                _ = try std.io.getStdIn().readAll(&buf);

                return buf[0];
            }

            if (addr < self.code_len) {
                return error.TriedToReadExecuteOnly;
            } else if (addr - self.code_len < self.data.len) {
                return self.data.*[addr - self.code_len];
            } else {
                return 0;
            }
        }
        pub fn write(self: *@This(), addr: u16, b: u8) !void {
            if (addr >= 0xffe0) {
                try std.io.getStdOut().writeAll(&[1]u8{b});

                return;
            }

            if (addr - self.code_len >= self.data.len) {
                const old_len = self.data.len;
                const new_size = @max(addr - self.code_len + 1, self.data.len << 1);
                self.data.* = try self.alloc.realloc(self.data.*, new_size);
                for (self.data.*[old_len..]) |*nb| nb.* = 0;
            }
            self.data.*[addr - self.code_len] = b;
        }
    };

    pub fn runCode(self: *Self) TeldaError!void {
        var rt = RuntimeState.init(self.entry orelse return error.NoEntry);
        var running = true;
        while (running) {
            var memvw = try MemoryView.init(self);
            runInstruction(self.code, &rt, &memvw) catch |e| {
                if (e == Trap.Halt) {
                    running = false;
                } else return error.UnhandledTrap;
            };
        }
    }

    pub fn deinit(self: *Self) void {
        self.alloc.free(self.code);
        self.alloc.free(self.data);
        self.code = self.code[0..0];
    }
};

pub const TeldaError = error{
    NoEntry,
    UnhandledTrap,
    NoMagic,
    OutOfMemory,
};

const aalvur_magic: *const [8]u8 = "álvur2\n";

// Remember to deinit the `TeldaBin` to free it
pub fn readBinary(alloc: Allocator, path: []const u8) !TeldaBin {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf = std.io.bufferedReader(file.reader());
    var reader = buf.reader();

    var magic_buf: [aalvur_magic.len]u8 = undefined;

    _ = try reader.readAll(&magic_buf);

    if (!mem.eql(u8, &aalvur_magic.*, &magic_buf)) return TeldaError.NoMagic;

    var entry: ?u16 = null;
    var code = std.ArrayList(u8).init(alloc);
    defer code.deinit();

    while (true) {
        const section_name = try reader.readUntilDelimiterAlloc(alloc, 0, 0xffff);
        defer alloc.free(section_name);
        if (section_name.len == 0) break;
        const size = try reader.readIntLittle(u16);

        if (mem.eql(u8, section_name, "_entry")) {
            std.debug.assert(size == 3);
            // segment type
            _ = try reader.readIntLittle(u8);
            const addr = try reader.readIntLittle(u16);
            entry = addr;
        } else if (mem.eql(u8, section_name, "_seg")) {
            const offset = try reader.readIntLittle(u16);
            const stype = try reader.readIntLittle(u8);
            _ = stype;
            const length = size - 3;
            var seg_data = try alloc.alloc(u8, length);
            defer alloc.free(seg_data);
            _ = try reader.readAll(seg_data);
            const old_len = code.items.len;
            if (old_len < offset + length) {
                try code.resize(offset + length);
                for (code.items[old_len..]) |*b| b.* = 0;
            }
            try code.replaceRange(offset, length, seg_data);
        }
    }
    return .{
        .alloc = alloc,
        .code = code.toOwnedSlice(),
        .data = try alloc.alloc(u8, 0),
        .entry = entry,
    };
}

test "register byte->wide" {
    var rt = RuntimeState.init(0);
    {
        var i: u4 = 1;
        while (i != 0) {
            rt.setbr(i, i);
            i +%= 1;
        }
    }
    try std.testing.expectEqual(@as(u16, 0x0201), rt.wr(0x1));
    try std.testing.expectEqual(@as(u16, 0x0403), rt.wr(0x2));
    try std.testing.expectEqual(@as(u16, 0x0605), rt.wr(0x3));
    try std.testing.expectEqual(@as(u16, 0x0807), rt.wr(0x4));
    try std.testing.expectEqual(@as(u16, 0x0a09), rt.wr(0x5));
    try std.testing.expectEqual(@as(u16, 0x000b), rt.wr(0x6));
    try std.testing.expectEqual(@as(u16, 0x000c), rt.wr(0x7));
    try std.testing.expectEqual(@as(u16, 0x000d), rt.wr(0x8));
    try std.testing.expectEqual(@as(u16, 0x000e), rt.wr(0x9));
    try std.testing.expectEqual(@as(u16, 0x000f), rt.wr(0xa));
}
test "register wide" {
    var rt = RuntimeState.init(0);
    {
        var i: u4 = 1;
        while (i != 0) {
            const v = @as(u16, i);
            rt.setwr(i, ((v << 12) | (v << 8) | (v << 4) | (v << 0)) - 1);
            i +%= 1;
        }
    }
    try std.testing.expectEqual(@as(u16, 0x1110), rt.wr(0x1));
    try std.testing.expectEqual(@as(u16, 0x2221), rt.wr(0x2));
    try std.testing.expectEqual(@as(u16, 0x3332), rt.wr(0x3));
    try std.testing.expectEqual(@as(u16, 0x4443), rt.wr(0x4));
    try std.testing.expectEqual(@as(u16, 0x5554), rt.wr(0x5));
    try std.testing.expectEqual(@as(u16, 0x6665), rt.wr(0x6));
    try std.testing.expectEqual(@as(u16, 0x7776), rt.wr(0x7));
    try std.testing.expectEqual(@as(u16, 0x8887), rt.wr(0x8));
    try std.testing.expectEqual(@as(u16, 0x9998), rt.wr(0x9));
    try std.testing.expectEqual(@as(u16, 0xaaa9), rt.wr(0xa));
    try std.testing.expectEqual(@as(u16, 0xbbba), rt.wr(0xb));
    try std.testing.expectEqual(@as(u16, 0xcccb), rt.wr(0xc));
    try std.testing.expectEqual(@as(u16, 0xdddc), rt.wr(0xd));
    try std.testing.expectEqual(@as(u16, 0xeeed), rt.wr(0xe));
    try std.testing.expectEqual(@as(u16, 0xfffe), rt.wr(0xf));
}
test "register wide->byte" {
    var rt = RuntimeState.init(0);
    {
        var i: u4 = 1;
        while (i <= 10) {
            const v = @as(u16, i);
            rt.setwr(i, ((v << 12) | (v << 8) | (v << 4) | (v << 0)) - 1);
            i += 1;
        }
    }
    try std.testing.expectEqual(@as(u8, 0x10), rt.br(0x1));
    try std.testing.expectEqual(@as(u8, 0x11), rt.br(0x2));
    try std.testing.expectEqual(@as(u8, 0x21), rt.br(0x3));
    try std.testing.expectEqual(@as(u8, 0x22), rt.br(0x4));
    try std.testing.expectEqual(@as(u8, 0x32), rt.br(0x5));
    try std.testing.expectEqual(@as(u8, 0x33), rt.br(0x6));
    try std.testing.expectEqual(@as(u8, 0x43), rt.br(0x7));
    try std.testing.expectEqual(@as(u8, 0x44), rt.br(0x8));
    try std.testing.expectEqual(@as(u8, 0x54), rt.br(0x9));
    try std.testing.expectEqual(@as(u8, 0x55), rt.br(0xa));
    try std.testing.expectEqual(@as(u8, 0x65), rt.br(0xb));
    try std.testing.expectEqual(@as(u8, 0x76), rt.br(0xc));
    try std.testing.expectEqual(@as(u8, 0x87), rt.br(0xd));
    try std.testing.expectEqual(@as(u8, 0x98), rt.br(0xe));
    try std.testing.expectEqual(@as(u8, 0xa9), rt.br(0xf));
}
