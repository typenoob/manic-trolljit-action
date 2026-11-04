#!/usr/bin/env python3
"""scripts/inject.py 的自检用例。

不依赖 macOS、不依赖第三方库：用代码合成结构合法的 Mach-O 夹具，
验证 thin / fat 注入、幂等、以及头部空间不足时的失败行为。

运行: python3 tests/test_inject.py
"""
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
INJECT_PY = os.path.join(os.path.dirname(HERE), "scripts", "inject.py")

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_MAIN = 0x80000028
MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 2
CPU_ARM64 = 0x0100000C
CPU_ARM64E = 0x0100000C

TEXT_OFFSET = 0x4000
TEXT_BYTES = bytes(range(256)) * 4  # 1KB 可校验内容


def _load_inject_module():
    spec = importlib.util.spec_from_file_location("inject_mod", INJECT_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inject_mod = _load_inject_module()


# ---------- Mach-O 夹具构造 ----------
def _seg64(name, vmaddr, vmsize, fileoff, filesize, prot, sections=()):
    cmdsize = 72 + 80 * len(sections)
    out = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64, cmdsize, name.encode(), vmaddr, vmsize,
        fileoff, filesize, prot, prot, len(sections), 0,
    )
    for sectname, addr, size, offset in sections:
        out += struct.pack(
            "<16s16sQQIIIIIIII",
            sectname.encode(), name.encode(), addr, size, offset,
            0, 0, 0, 0, 0, 0, 0,
        )
    return out


def _dylib_cmd(path):
    raw = path.encode() + b"\0"
    cmdsize = (24 + len(raw) + 7) // 8 * 8
    return (
        struct.pack("<IIIIII", LC_LOAD_DYLIB, cmdsize, 24, 2, 0x10000, 0x10000) + raw
    ).ljust(cmdsize, b"\0")


def build_macho(cputype=CPU_ARM64, text_offset=TEXT_OFFSET, with_signature=True, text_size=None):
    """构造一个 arm64 可执行文件切片（含 __PAGEZERO/__TEXT/LC_MAIN/LC_LOAD_DYLIB[/LC_CODE_SIGNATURE]）"""
    text_size = len(TEXT_BYTES) if text_size is None else text_size
    cmds = b"".join([
        _seg64("__PAGEZERO", 0, 0x100000000, 0, 0, 0),
        _seg64("__TEXT", 0x100000000, text_offset, 0, text_offset, 5,
               [("__text", 0x100000000 + text_offset, text_size, text_offset)]),
        struct.pack("<IIQQ", LC_MAIN, 24, text_offset, 0),
        _dylib_cmd("/usr/lib/libSystem.B.dylib"),
    ])
    header_size = 32
    if with_signature:
        cmds += struct.pack("<IIII", LC_CODE_SIGNATURE, 16, 0, 0)  # dataoff 稍后回填
    ncmds = 4 + (1 if with_signature else 0)
    header = struct.pack(
        "<IiiIIIII", MH_MAGIC_64, cputype, 0, MH_EXECUTE, ncmds, len(cmds), 0x00200085, 0,
    )
    body = bytearray(header + cmds)
    body += b"\0" * (text_offset - len(body))
    body += TEXT_BYTES
    if with_signature:
        sig_off = len(body)
        body += b"\x5a" * 32
        # 回填 LC_CODE_SIGNATURE 的 dataoff/datasize
        pos = header_size + len(cmds) - 16
        struct.pack_into("<II", body, pos + 8, sig_off, 32)
    return bytes(body)


def build_fat(slices, align=0x4000):
    """构造 fat 二进制（大端 fat 头 + fat_arch 32）"""
    nfat = len(slices)
    header = struct.pack(">II", 0xCAFEBABE, nfat)
    entries = b""
    offset = 0x4000
    placed = []
    for cputype, data in slices:
        entries += struct.pack(">iiIII", cputype, 0, offset, len(data), 14)
        placed.append((offset, data))
        offset += (len(data) + align - 1) // align * align
    out = bytearray(header + entries)
    for off, data in placed:
        if len(out) < off:
            out += b"\0" * (off - len(out))
        out[off:off + len(data)] = data
    return bytes(out)


# ---------- 用例 ----------
class InjectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="inject-test-")
        self.dylib = "@executable_path/Frameworks/TrollStoreJITEnabler.dylib"

    def tearDown(self):
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def _run(self, path, dylib=None):
        return subprocess.run(
            [sys.executable, INJECT_PY, path, dylib or self.dylib],
            capture_output=True, text=True,
        )

    def _slices(self, path):
        with open(path, "rb") as f:
            data = bytearray(f.read())
        return data, [inject_mod.MachOSlice(data, off) for off, _ in inject_mod.iter_slices(data)]

    def test_thin_inject(self):
        original = build_macho()
        path = self._write("thin", original)
        res = self._run(path)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("注入 LC_LOAD_DYLIB", res.stdout)

        data, slices = self._slices(path)
        self.assertEqual(len(slices), 1)
        sl = slices[0]
        self.assertIn(self.dylib, sl.dylib_paths())
        self.assertIn("/usr/lib/libSystem.B.dylib", sl.dylib_paths())
        self.assertFalse(sl.has_code_signature(), "旧 LC_CODE_SIGNATURE 应被移除")
        self.assertEqual(len(data), len(original), "文件大小不应改变")
        # __text 内容未被破坏
        self.assertEqual(bytes(data[TEXT_OFFSET:TEXT_OFFSET + len(TEXT_BYTES)]), TEXT_BYTES)
        # 保留的加载命令仍然可解析（ncmds 与 sizeofcmds 自洽）
        self.assertEqual(sl.ncmds, len(sl.commands))

    def test_idempotent(self):
        path = self._write("thin", build_macho())
        self.assertEqual(self._run(path).returncode, 0)
        with open(path, "rb") as f:
            once = f.read()
        res = self._run(path)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("无需修改", res.stdout)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), once, "二次注入不应修改文件")

    def test_fat_inject(self):
        fat = build_fat([(CPU_ARM64, build_macho(CPU_ARM64)),
                         (CPU_ARM64E, build_macho(CPU_ARM64E))])
        path = self._write("fat", fat)
        res = self._run(path)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("全部 2 个架构", res.stdout)

        data, slices = self._slices(path)
        self.assertEqual(len(slices), 2)
        self.assertEqual(len(data), len(fat), "fat 文件大小不应改变")
        # fat 头中的架构偏移/大小保持不变
        before = [struct.unpack_from(">II", fat, 8 + 20 * i + 8) for i in range(2)]
        after = [struct.unpack_from(">II", data, 8 + 20 * i + 8) for i in range(2)]
        self.assertEqual(after, before, "fat 架构偏移/大小不应改变")
        for sl in slices:
            self.assertIn(self.dylib, sl.dylib_paths())

    def test_no_space(self):
        # __text 紧贴头部，无 headerpad
        tight = build_macho(text_offset=0x180)
        path = self._write("tight", tight)
        res = self._run(path)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("头部空闲空间不足", res.stderr)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), tight, "失败时不应修改文件")

    def test_bad_args(self):
        res = subprocess.run([sys.executable, INJECT_PY], capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)

    def test_not_macho(self):
        path = self._write("notmacho", b"hello world, definitely not mach-o")
        res = self._run(path)
        self.assertEqual(res.returncode, 1)
        self.assertIn("不是 Mach-O", res.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)