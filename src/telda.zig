const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

inline fn splitByte(byte: u8) struct {h: u4, l: u4} {
    return .{
        .h = @intCast(u4, byte >> 4),
        .l = @intCast(u4, byte & 0xf),
    };
}

const RuntimeState = struct {
    gprs: [10]u16 = undefined,
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
            0x41...0x54 => 4,
            else => 1,
        };
        const ret = code[self.rip..self.rip+length];
        self.rip += length;
        return ret;
    }
    pub fn br(self: *Self, regnum: u4, zero: *u8) *u8 {
        return switch (regnum) {
            0 => zero,
            1...10 => &@ptrCast([*]u8, &self.gprs)[regnum-1],
            11...15 => &@ptrCast([*]u8, &self.gprs)[(regnum-11)<<1],
        };
    }
    pub fn wr(self: *Self, regnum: u4, zero: *u16) *u16 {
        return switch (regnum) {
            0 => zero,
            1...10 => &self.gprs[regnum-1],
            11 => &self.rs,
            12 => &self.rl,
            13 => &self.rf,
            14 => &self.rp,
            15 => &self.rh,
        };
    }
};

const Trap = error {
    Invalid,
    Halt,
    ZeroDiv,
    OutOfMemory,
    IoError,
};

fn widesUnsupported() noreturn {
    @panic("wide reads and writes are not supported yet");
}

fn runInstruction(code: []const u8, rt: *RuntimeState, memvw: anytype) Trap!void {
    var z: u8 = 0;
    var c: u16 = 0;
    const ins = rt.readInstruction(code);
    switch (ins[0]) {
        0x0a => return Trap.Halt,
        // NOP
        0x20 => {},
        0x21 => {
            const reg = splitByte(ins[1]).h;
            rt.rs -= 1;

            memvw.write(rt.rs, rt.br(reg, &z).*) catch return error.IoError;
        },
        0x22 => widesUnsupported(),
        0x23 => {
            const reg = splitByte(ins[1]).h;
            rt.br(reg, &z).* = memvw.read(rt.rs) catch return error.IoError;

            rt.rs += 1;
        },
        0x24 => widesUnsupported(),
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

            memvw.write(imm+rt.wr(regs.h, &c).*, rt.br(regs.l, &z).*) catch return error.IoError;
        },
        0x28 => widesUnsupported(),
        0x29 => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            memvw.write(rt.wr(regs.l, &c).*+rt.wr(regs.h, &c).*, rt.br(src, &z).*) catch return error.IoError;
        },
        0x2a => widesUnsupported(),
        0x2b => {
            const regs = splitByte(ins[1]);
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            rt.br(regs.h, &z).* = memvw.read(imm+rt.wr(regs.l, &c).*) catch return error.IoError;
        },
        0x2c => widesUnsupported(),
        0x2d => {
            const regs = splitByte(ins[1]);
            const src = splitByte(ins[2]).h;

            memvw.write(rt.wr(regs.h, &c).*+rt.wr(regs.l, &c).*, rt.br(src, &z).*) catch return error.IoError;
        },
        0x2e => widesUnsupported(),
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
            rt.br(dest, &z).* = ins[2];
        },
        0x40 => {
            const ins1 = splitByte(ins[1]);
            const dest = ins1.h;
            const opt = ins1.l;
            const imm = mem.littleToNative(u16, mem.bytesToValue(u16, ins[2..4]));

            switch (opt) {
                0 => rt.wr(dest, &c).* = imm,
                1 => {
                    if (dest == 0) {
                        rt.rip = imm;
                    } else {
                        rt.rip = rt.wr(dest, &c).*;
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
            rt.br(dest, &z).* = rt.br(op1, &z).* +% rt.br(op2, &z).*;
        },
        0x42 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* +% rt.wr(op2, &c).*;
        },
        0x43 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = rt.br(op1, &z).* -% rt.br(op2, &z).*;
        },
        0x44 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* -% rt.wr(op2, &c).*;
        },
        0x45 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = rt.br(op1, &z).* & rt.br(op2, &z).*;
        },
        0x46 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* & rt.wr(op2, &c).*;
        },
        0x47 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = rt.br(op1, &z).* | rt.br(op2, &z).*;
        },
        0x48 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* | rt.wr(op2, &c).*;
        },
        0x49 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = rt.br(op1, &z).* ^ rt.br(op2, &z).*;
        },
        0x4a => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* ^ rt.wr(op2, &c).*;
        },
        0x4b => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = rt.br(op1, &z).* << @intCast(u3, rt.br(op2, &z).*);
        },
        0x4c => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* << @intCast(u4, rt.wr(op2, &c).*);
        },
        0x4d => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = @intCast(u8, @intCast(i8, rt.br(op1, &z).*) >> @intCast(u3, rt.br(op2, &z).*));
        },
        0x4e => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = @intCast(u16, @intCast(i16, rt.wr(op1, &c).*) >> @intCast(u4, rt.wr(op2, &c).*));
        },
        0x4f => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.br(dest, &z).* = rt.br(op1, &z).* >> @intCast(u3, rt.br(op2, &z).*);
        },
        0x50 => {
            const regs1 = splitByte(ins[1]);
            const dest = regs1.h;
            const op1 = regs1.l;
            const op2 = splitByte(ins[2]).h;
            rt.wr(dest, &c).* = rt.wr(op1, &c).* >> @intCast(u4, rt.wr(op2, &c).*);
        },
        0x51 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const dividend = rt.br(ops.h, &z).*;
            const divisor  = rt.br(ops.l, &z).*;

            if (divisor == 0) return Trap.ZeroDiv;

            rt.br(dest.h, &z).* = dividend / divisor;
            rt.br(dest.l, &z).* = dividend % divisor;
        },
        0x52 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const dividend = rt.wr(ops.h, &c).*;
            const divisor  = rt.wr(ops.l, &c).*;

            if (divisor == 0) return Trap.ZeroDiv;

            rt.wr(dest.h, &c).* = dividend / divisor;
            rt.wr(dest.l, &c).* = dividend % divisor;
        },
        0x53 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const res = mem.nativeToLittle(u16, @intCast(u16, rt.br(ops.h, &z).*) * @intCast(u16, rt.br(ops.l, &z).*));
            const bytes = mem.asBytes(&res);

            rt.br(dest.l, &z).* = bytes[0];
            rt.br(dest.h, &z).* = bytes[1];
        },
        0x54 => {
            const dest = splitByte(ins[1]);
            const ops = splitByte(ins[2]);
            const res = mem.nativeToLittle(u32, @intCast(u32, rt.wr(ops.h, &c).*) * @intCast(u32, rt.wr(ops.l, &c).*));
            const bytes = mem.asBytes(&res);

            rt.wr(dest.l, &c).* = mem.bytesToValue(u16, bytes[0..2]);
            rt.wr(dest.h, &c).* = mem.bytesToValue(u16, bytes[2..4]);
        },
        else => return Trap.Invalid,
    }
}

pub const TeldaBin = struct {
    code: []u8,
    entry: ?u16,
    alloc: Allocator,
    data: ?[]u8 = null,

    const Self = @This();

    pub const MemoryView = struct {
        code_len: usize,
        data: []u8,
        alloc: Allocator,
        pub fn init(bin: *Self) !MemoryView {
            var dat: []u8 = undefined;
            if (bin.data) |dt| {
                dat = dt;
            } else {
                dat = try bin.alloc.alloc(u8, 256);
                bin.data = dat;
            }

            return .{
                .code_len = bin.code.len,
                .data = dat,
                .alloc = bin.alloc,
            };
        }
        pub fn read(self: *@This(), addr: u16) !u8 {
            if (addr >= 0xffe0) {
                var buf: [1]u8 = undefined;
                _ = try std.io.getStdIn().readAll(&buf);

                return buf[0];
            }

            if (addr - self.code_len < self.data.len) {
                return self.data[addr-self.code_len];
            } else {
                return 0;
            }
        }
        pub fn write(self: *@This(), addr: u16, b: u8) !void {
            if (addr >= 0xffe0) {
                try std.io.getStdOut().writeAll(&[1]u8 {b});

                return;
            }

            if (addr - self.code_len >= self.data.len) {
                const old_len = self.data.len;
                const new_size = @max(addr - self.code_len + 1, self.data.len << 1);
                self.data = try self.alloc.realloc(self.data, new_size);
                for (self.data[old_len..]) |*nb| nb.* = 0;
            }
            self.data[addr-self.code_len] = b;
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
        self.code = self.code[0..0];
        if (self.data) |dat| {
            self.alloc.free(dat);
        }
    }
};

pub const TeldaError = error {
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
            const length = size-3;
            var seg_data = try alloc.alloc(u8, length);
            defer alloc.free(seg_data);
            _ = try reader.readAll(seg_data);
            const old_len = code.items.len;
            if (old_len < offset+length) {
                try code.resize(offset+length);
                for (code.items[old_len..]) |*b| b.* = 0;
            }
            try code.replaceRange(offset, length, seg_data);
        }
    }
    return .{.alloc = alloc, .code = code.toOwnedSlice(), .entry = entry };
}
