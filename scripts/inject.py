#!/usr/bin/env python3
"""向 Mach-O 注入 LC_LOAD_DYLIB 加载命令（纯 Python 实现，零第三方依赖）。

用法:
    inject.py <macho_path> <dylib_install_path>

行为:
  - 支持 thin 与 fat/universal（含 fat64）二进制，逐架构处理
  - 已存在相同 dylib 路径时跳过该架构（幂等）
  - 注入前移除旧的 LC_CODE_SIGNATURE，交由后续 ldid 重新签名
  - 只写入文件头部的空闲填充区，不改变文件大小与各架构偏移
  - 头部空间不足时报错退出，绝不写出半成品

退出码: 0 成功（含"已注入过"）；1 失败；2 用法错误
"""
import os
import stat
import struct
import sys
import tempfile

# ---------- Mach-O 常量 ----------
MH_MAGIC, MH_CIGAM = 0xFEEDFACE, 0xCEFAEDFE
MH_MAGIC_64, MH_CIGAM_64 = 0xFEEDFACF, 0xCFFAEDFE
FAT_MAGIC, FAT_CIGAM = 0xCAFEBABE, 0xBEBAFECA
FAT_MAGIC_64, FAT_CIGAM_64 = 0xCAFEBABF, 0xBFBAFECA

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_SYMSEG = 0x3
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D
LC_LAZY_LOAD_DYLIB = 0x20
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_ENCRYPTION_INFO_64 = 0x2C
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034

DYLIB_CMDS = {
    LC_LOAD_DYLIB,
    LC_LOAD_WEAK_DYLIB,
    LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
}
# 只含一个 file offset 的 linkedit_data_command 类加载命令
LINKEDIT_DATA_CMDS = {
    LC_CODE_SIGNATURE,
    LC_FUNCTION_STARTS,
    LC_DATA_IN_CODE,
    LC_DYLIB_CODE_SIGN_DRS,
    LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
}

CPU_NAMES = {
    7: "i386",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}

CODE_SIGNATURE_CMDSIZE = 16  # linkedit_data_command 固定 16 字节


def log(msg):
    print(msg, flush=True)


def die(msg):
    print(f"[inject][FATAL] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def u32_at(buf, off, endian):
    return int.from_bytes(buf[off:off + 4], endian)


class MachOSlice:
    """单个 Mach-O 架构切片（fat 中的一片，或整个 thin 文件）"""

    def __init__(self, buf, offset):
        self.buf = buf
        self.offset = offset
        magic = int.from_bytes(buf[offset:offset + 4], "little")
        if magic in (MH_MAGIC, MH_MAGIC_64):
            self.endian = "<"
            self.byteorder = "little"
            self.is64 = magic == MH_MAGIC_64
        elif magic in (MH_CIGAM, MH_CIGAM_64):
            self.endian = ">"
            self.byteorder = "big"
            self.is64 = magic == MH_CIGAM_64
        else:
            raise ValueError(f"不是 Mach-O 头（magic=0x{magic:08x}）")
        self.header_size = 32 if self.is64 else 28
        self.cputype = self.u32(offset + 4)
        self.ncmds = self.u32(offset + 16)
        self.sizeofcmds = self.u32(offset + 20)
        if self.ncmds == 0 or self.sizeofcmds == 0:
            raise ValueError("ncmds/sizeofcmds 为 0，疑似非法 Mach-O")
        self.commands = self._parse_commands()

    # ----- 基础读取 -----
    def u32(self, off):
        return int.from_bytes(self.buf[off:off + 4], self.byteorder)

    def u64(self, off):
        return int.from_bytes(self.buf[off:off + 8], self.byteorder)

    @property
    def arch_name(self):
        return CPU_NAMES.get(self.cputype, f"cpu=0x{self.cputype:x}")

    def _parse_commands(self):
        p = self.offset + self.header_size
        end = p + self.sizeofcmds
        if end > len(self.buf):
            raise ValueError("sizeofcmds 越界，文件可能被截断")
        cmds = []
        for _ in range(self.ncmds):
            if p + 8 > end:
                raise ValueError("load command 区域越界")
            cmd = self.u32(p)
            cmdsize = self.u32(p + 4)
            if cmdsize < 8 or p + cmdsize > end:
                raise ValueError(f"非法 cmdsize={cmdsize}（cmd=0x{cmd:x}）")
            cmds.append((cmd, cmdsize, p))
            p += cmdsize
        return cmds

    # ----- 信息提取 -----
    def dylib_paths(self):
        paths = []
        for cmd, cmdsize, p in self.commands:
            if cmd in DYLIB_CMDS:
                name_off = self.u32(p + 8)
                if 0 < name_off < cmdsize:
                    raw = bytes(self.buf[p + name_off:p + cmdsize])
                    paths.append(raw.split(b"\0", 1)[0].decode("utf-8", "replace"))
        return paths

    def has_code_signature(self):
        return any(cmd == LC_CODE_SIGNATURE for cmd, _, _ in self.commands)

    def data_start(self):
        """头部之后第一个真实数据（段内容/节内容/链接信息）的偏移（相对切片起始）"""
        cands = []

        def add(v):
            if v > 0:
                cands.append(v)

        for cmd, cmdsize, p in self.commands:
            if cmd == LC_SEGMENT_64:
                add(self.u64(p + 40))  # fileoff
                nsects = self.u32(p + 64)
                sec = p + 72
                for i in range(nsects):
                    s = sec + i * 80
                    if s + 80 > p + cmdsize:
                        break
                    add(self.u32(s + 48))  # section.offset
            elif cmd == LC_SEGMENT:
                add(self.u32(p + 32))  # fileoff
                nsects = self.u32(p + 48)
                sec = p + 56
                for i in range(nsects):
                    s = sec + i * 68
                    if s + 68 > p + cmdsize:
                        break
                    add(self.u32(s + 40))  # section.offset
            elif cmd == LC_SYMTAB:
                add(self.u32(p + 8))   # symoff
                add(self.u32(p + 16))  # stroff
            elif cmd == LC_SYMSEG:
                add(self.u32(p + 8))
            elif cmd == LC_DYSYMTAB:
                for off in (32, 40, 48, 56, 64, 72):
                    add(self.u32(p + off))
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                for off in (8, 16, 24, 32, 40):
                    add(self.u32(p + off))
            elif cmd in LINKEDIT_DATA_CMDS:
                add(self.u32(p + 8))   # dataoff
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                add(self.u32(p + 8))   # cryptoff
        if not cands:
            raise ValueError("无法确定头部可用空间上界")
        return min(cands)

    def cmds_end(self):
        return self.offset + self.header_size + self.sizeofcmds

    # ----- 注入 -----
    def inject(self, dylib_path):
        if dylib_path in self.dylib_paths():
            return False

        raw_name = dylib_path.encode() + b"\0"
        align = 8 if self.is64 else 4
        cmdsize = 24 + len(raw_name)
        cmdsize = (cmdsize + align - 1) // align * align
        new_cmd = (
            struct.pack(f"{self.endian}IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 2, 0x10000, 0x10000)
            + raw_name
        ).ljust(cmdsize, b"\0")

        has_sig = self.has_code_signature()
        # 注入时移除旧签名命令；随后 ldid 会重新写入 16 字节 LC_CODE_SIGNATURE
        reserve = 0 if has_sig else CODE_SIGNATURE_CMDSIZE
        avail = self.data_start() - (self.header_size + self.sizeofcmds)
        need = len(new_cmd) + reserve
        if avail < need:
            raise ValueError(
                f"头部空闲空间不足：需要 {need} 字节，可用 {avail} 字节"
                f"（该二进制未预留 headerpad，可用 insert_dylib/optool 手工处理）"
            )

        kept = [(cmd, cmdsize_, p) for cmd, cmdsize_, p in self.commands
                if cmd != LC_CODE_SIGNATURE]
        blob = b"".join(bytes(self.buf[p:p + cs]) for _, cs, p in kept) + new_cmd

        start = self.offset + self.header_size
        wipe = max(self.sizeofcmds, len(blob))
        self.buf[start:start + wipe] = b"\0" * wipe
        self.buf[start:start + len(blob)] = blob

        struct.pack_into(f"{self.endian}I", self.buf, self.offset + 16, len(kept) + 1)
        struct.pack_into(f"{self.endian}I", self.buf, self.offset + 20, len(blob))
        return True


def iter_slices(buf):
    """返回 [(offset, size), ...]，按文件中的顺序"""
    if len(buf) < 8:
        raise ValueError("文件过小，不是 Mach-O")
    magic = int.from_bytes(buf[0:4], "big")
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        byteorder = "big"
        is64 = magic == FAT_MAGIC_64
    elif magic in (FAT_CIGAM, FAT_CIGAM_64):
        byteorder = "little"
        is64 = magic == FAT_CIGAM_64
    else:
        return [(0, len(buf))]
    nfat = int.from_bytes(buf[4:8], byteorder)
    entry_size = 32 if is64 else 20
    if not 1 <= nfat <= 64 or 8 + nfat * entry_size > len(buf):
        raise ValueError(f"非法 fat 头（nfat={nfat}）")
    slices = []
    for i in range(nfat):
        p = 8 + i * entry_size
        if is64:
            off = int.from_bytes(buf[p + 8:p + 16], byteorder)
            size = int.from_bytes(buf[p + 16:p + 24], byteorder)
        else:
            off = int.from_bytes(buf[p + 8:p + 12], byteorder)
            size = int.from_bytes(buf[p + 12:p + 16], byteorder)
        if off + size > len(buf):
            raise ValueError(f"fat 架构 {i} 越界（off={off}, size={size}）")
        slices.append((off, size))
    return slices


def write_atomic(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".inject-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        os.chmod(tmp, mode | 0o200)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    target, dylib_path = sys.argv[1], sys.argv[2]

    with open(target, "rb") as f:
        data = bytearray(f.read())

    try:
        slices = iter_slices(data)
        injected = skipped = 0
        for i, (off, _size) in enumerate(slices):
            sl = MachOSlice(data, off)
            if sl.inject(dylib_path):
                injected += 1
                log(f"[+] arch {i} ({sl.arch_name}): 注入 LC_LOAD_DYLIB -> {dylib_path}")
            else:
                skipped += 1
                log(f"[skip] arch {i} ({sl.arch_name}): 已存在 -> {dylib_path}")

        if injected:
            write_atomic(target, data)
            log(f"[ok] 已写回 {target}（注入 {injected} 个架构，跳过 {skipped} 个）")
        else:
            log(f"[ok] 无需修改（{skipped} 个架构均已包含该加载命令）")

        # 校验：重新解析最终文件
        with open(target, "rb") as f:
            final = bytearray(f.read())
        for i, (off, _size) in enumerate(iter_slices(final)):
            sl = MachOSlice(final, off)
            if dylib_path not in sl.dylib_paths():
                die(f"校验失败: arch {i} ({sl.arch_name}) 未包含 {dylib_path}")
        log(f"[ok] 校验通过: 全部 {len(slices)} 个架构均包含 {dylib_path}")
    except ValueError as exc:
        die(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())