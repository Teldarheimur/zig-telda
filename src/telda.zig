const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const builtin = @import("builtin");
const littleEndian = std.builtin.Endian.little;

const Int = std.meta.Int;

fn signed(comptime int: type) type {
    return Int(.signed, @typeInfo(int).Int.bits);
}

// return signed version of type
inline fn sign(unsigned: anytype) signed(@TypeOf(unsigned)) {
    return @bitCast(unsigned);
}

inline fn splitByte(byte: u8) struct { h: u4, l: u4 } {
    return .{
        .h = @intCast(byte >> 4),
        .l = @intCast(byte & 0xf),
    };
}

inline fn getWide(slice: []u8, index: usize) u16 {
    std.debug.assert(slice.len > 2);
    return mem.readInt(u16, slice[index..][0..2], littleEndian);
}
inline fn setWide(slice: []u8, index: usize, wide: u16) void {
    std.debug.assert(slice.len > 2);
    mem.writeInt(u16, slice[index..][0..2], wide, littleEndian);
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
            0x21...0x24,
            0x26 => 2,
            0x25,
            0x2d...0x2e,
            0x29...0x2a,
            0x2f...0x3a,
            0x3f,
            0x41...0x54 => 3,
            0x27...0x28,
            0x2b...0x2c,
            0x40 => 4,
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
            11...15 => @truncate(self.wr(regnum - 11 + 6)),
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
                return getWide(&self.gprs, i);
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
                setWide(&self.gprs, i, val);
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
        self.rflags.sign = @as(i8, @bitCast(val)) < 0;
    }
    pub inline fn setwrf(self: *Self, regnum: u4, val: u16) void {
        self.setwr(regnum, val);
        self.rflags.zero = val == 0;
        self.rflags.sign = @as(i16, @bitCast(val)) < 0;
    }
};

const Trap = error{
    Invalid,
    Halt,
    ZeroDiv,
    OutOfMemory,
    IoError,
};

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
        0x22 => {
            const reg = splitByte(ins[1]).h;
            rt.rs -= 2;

            memvw.writew(rt.rs, rt.wr(reg)) catch return error.IoError;
        },
        0x23 => {
            const reg = splitByte(ins[1]).h;
            rt.setbr(reg, memvw.read(rt.rs) catch return error.IoError);

            rt.rs += 1;
        },
        0x24 => {
            const reg = splitByte(ins[1]).h;

            const val = memvw.readw(rt.rs) catch return error.IoError;
            rt.setwr(reg, val);
            rt.rs += 2;
        },
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
        0x28 => {
            const regs = splitByte(ins[1]);
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            memvw.writew(imm + rt.wr(regs.h), rt.wr(regs.l)) catch return error.IoError;
        },
        0x29 => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            memvw.write(rt.wr(regs.l) + rt.wr(regs.h), rt.br(src)) catch return error.IoError;
        },
        0x2a => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            memvw.writew(rt.wr(regs.l) + rt.wr(regs.h), rt.wr(src)) catch return error.IoError;
        },
        0x2b => {
            const regs = splitByte(ins[1]);
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            rt.setbr(regs.h, memvw.read(imm + rt.wr(regs.l)) catch return error.IoError);
        },
        0x2c => {
            const regs = splitByte(ins[1]);
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            rt.setwr(regs.h, memvw.readw(imm + rt.wr(regs.l)) catch return error.IoError);
        },
        0x2d => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            rt.setbr(regs.h, memvw.read(rt.wr(src) + rt.wr(regs.l)) catch return error.IoError);
        },
        0x2e => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            rt.setwr(regs.h, memvw.readw(rt.wr(src) + rt.wr(regs.l)) catch return error.IoError);
        },
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

            const term1 = rt.br(op1);
            const term2 = rt.br(op2);
            const sum, const carry = @addWithOverflow(term1, term2);
            const isum, const overflow = @addWithOverflow(sign(term1), sign(term2));

            rt.rflags.carry = @bitCast(carry);
            rt.rflags.overflow = @bitCast(overflow);
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setbr(dest, sum);
        },
        0x42 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            const term1 = rt.wr(op1);
            const term2 = rt.wr(op2);
            const sum, const carry = @addWithOverflow(term1, term2);
            const isum, const overflow = @addWithOverflow(sign(term1), sign(term2));

            rt.rflags.carry = @bitCast(carry);
            rt.rflags.overflow = @bitCast(overflow);
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setwr(dest, sum);
        },
        0x43 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            const term1 = rt.br(op1);
            const term2 = rt.br(op2);
            const sum, const carry = @subWithOverflow(term1, term2);
            const isum, const overflow = @subWithOverflow(sign(term1), sign(term2));

            rt.rflags.carry = @bitCast(carry);
            rt.rflags.overflow = @bitCast(overflow);
            rt.rflags.zero = sum == 0;
            rt.rflags.sign = isum < 0;

            rt.setbr(dest, sum);
        },
        0x44 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;

            const term1 = rt.wr(op1);
            const term2 = rt.wr(op2);
            const sum, const carry = @subWithOverflow(term1, term2);
            const isum, const overflow = @subWithOverflow(sign(term1), sign(term2));

            rt.rflags.carry = @bitCast(carry);
            rt.rflags.overflow = @bitCast(overflow);
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
            rt.setbrf(dest, rt.br(op1) << @intCast(rt.br(op2)));
        },
        0x4c => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) << @intCast(rt.wr(op2)));
        },
        0x4d => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, @intCast(sign(rt.br(op1)) >> @intCast(rt.br(op2))));
        },
        0x4e => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, @intCast(sign(rt.wr(op1)) >> @intCast(rt.wr(op2))));
        },
        0x4f => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setbrf(dest, rt.br(op1) >> @intCast(rt.br(op2)));
        },
        0x50 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.setwrf(dest, rt.wr(op1) >> @intCast(rt.wr(op2)));
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

pub const MEM_SIZE = 256*256-0x20;

pub const TeldaBin = struct {
    memory: *[MEM_SIZE]u8,
    entry: ?u16,
    alloc: Allocator,

    const Self = @This();


    const MemvwStdout = std.io.BufferedWriter(4096, std.fs.File.Writer).Writer;
    const MemvwStdin = std.io.BufferedReader(4096, std.fs.File.Reader).Reader;

    pub const MemoryView = struct {
        data: *[MEM_SIZE]u8,
        stdout: MemvwStdout,
        stdin: MemvwStdin,

        pub fn init(bin: *Self, stdout: MemvwStdout, stdin: MemvwStdin) @This() {
            return .{
                .data = bin.memory,
                .stdout = stdout,
                .stdin = stdin,
            };
        }
        pub fn read(self: *@This(), addr: u16) !u8 {
            if (addr >= 0xffe0) {
                var buf: [1]u8 = undefined;
                _ = try self.stdin.readAll(&buf);

                return buf[0];
            }

            return self.data.*[addr];
        }
        pub fn write(self: *@This(), addr: u16, b: u8) !void {
            if (addr >= 0xffe0) {
                try self.stdout.writeAll(&[1]u8{b});

                return;
            }

            self.data.*[addr] = b;
        }
        pub fn readw(self: *@This(), addr: u16) !u16 {
            const bytes = [_]u8 {
                try self.read(addr),
                try self.read(addr+1)
            };
            return mem.readInt(u16, &bytes, littleEndian);
        }
        pub fn writew(self: *@This(), addr: u16, val: u16) !void {
            const bytes = mem.asBytes(&mem.nativeToLittle(u16, val));
            try self.write(addr, bytes[0]);
            try self.write(addr+1, bytes[1]);
        }
    };

    pub fn runCode(self: *Self) TeldaError!void {
        var rt = RuntimeState.init(self.entry orelse return error.NoEntry);
        var running = true;
        var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
        var stdin = std.io.bufferedReader(std.io.getStdIn().reader());
        while (running) {
            var memvw = MemoryView.init(self, stdout.writer(), stdin.reader());
            runInstruction(self.memory, &rt, &memvw) catch |e| {
                if (e == Trap.Halt) {
                    running = false;
                } else return error.UnhandledTrap;
            };
        }
        stdout.flush() catch return TeldaError.CouldNotPrint;
    }

    pub fn deinit(self: *Self) void {
        self.alloc.destroy(self.memory);
    }
};

pub const TeldaError = error{
    NoEntry,
    UnhandledTrap,
    NoMagic,
    OutOfMemory,
    CouldNotPrint,
};

const aalvur_magic: *const [8]u8 = "álvur2\n";

// skips shebang up to 1KiB long
fn skipSheBang(file: *std.fs.File) !void {
    var buffer: [1024]u8 = undefined;
    const n = try file.readAll(&buffer);
    const bytes = buffer[0..n];
    if (mem.eql(u8, bytes[0..2], "#!")) {
        for (bytes[2..], 2..) |b, i| {
            if (b == '\n') {
                try file.seekTo(i);
                return;
            }
        }
        // TODO: support longer shebang headers?
        return error.SheBangTooLong;
    } else {
        try file.seekTo(0);
    }
}

// Remember to deinit the `TeldaBin` to free it
pub fn readBinary(alloc: Allocator, path: []const u8) !TeldaBin {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    try skipSheBang(&file);

    var buf = std.io.bufferedReader(file.reader());
    var reader = buf.reader();

    var magic_buf: [aalvur_magic.len]u8 = undefined;

    _ = try reader.readAll(&magic_buf);

    if (!mem.eql(u8, &aalvur_magic.*, &magic_buf)) {
        try reader.skipUntilDelimiterOrEof('\n');
    }

    var entry: ?u16 = null;
    var code = try alloc.create([MEM_SIZE]u8);
    @memset(code, 0);
    // var code = [1]u8{0} ** (256*256-0x20); // is this safe?

    while (true) {
        const section_name = try reader.readUntilDelimiterAlloc(alloc, 0, 0xffff);
        defer alloc.free(section_name);
        if (section_name.len == 0) break;
        const size = try reader.readInt(u16, littleEndian);

        if (mem.eql(u8, section_name, "_entry")) {
            std.debug.assert(size == 3);
            // segment type
            _ = try reader.readInt(u8, littleEndian);
            const addr = try reader.readInt(u16, littleEndian);
            entry = addr;
        } else if (mem.eql(u8, section_name, "_seg")) {
            const offset = try reader.readInt(u16, littleEndian);
            const stype = try reader.readInt(u8, littleEndian);
            _ = stype;
            const length = size - 3;
            _ = try reader.readAll(code[offset..offset+length]);
        }
    }
    return .{
        .memory = code,
        .entry = entry,
        .alloc = alloc,
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
