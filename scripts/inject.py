#!/usr/bin/env python3
"""向 Mach-O 二进制注入 LC_LOAD_DYLIB 加载命令（基于 LIEF，纯 Python，跨平台）。

用法: inject.py <binary> <dylib_install_path>

- 支持 fat/universal 二进制，逐架构处理
- 已存在相同加载路径时跳过（幂等）
- 写入临时文件后原子替换
"""
import os
import sys
import tempfile

import lief


def get_binaries(path):
    parsed = lief.MachO.parse(path)
    # 新版本 parse 始终返回 FatBinary（可迭代），旧版本可能直接返回 Binary
    try:
        binaries = list(parsed)
    except TypeError:
        binaries = [parsed]
    if not binaries:
        raise RuntimeError(f"未能从 {path} 解析出任何 Mach-O 架构")
    return binaries


def write_all(path):
    """整体写出（FatBinary.write 会写出全部架构，Binary.write 写出单架构）"""
    parsed = lief.MachO.parse(path)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)),
                                        prefix=".inject-", suffix=".tmp")
    os.close(tmp_fd)
    try:
        parsed.write(tmp_path)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    target, dylib_path = sys.argv[1], sys.argv[2]
    binaries = get_binaries(target)

    injected = skipped = 0
    for i, b in enumerate(binaries):
        arch = b.header.cpu_type
        if dylib_path in b.libraries:
            print(f"[skip] arch {i} ({arch}): LC_LOAD_DYLIB 已存在 -> {dylib_path}")
            skipped += 1
            continue
        b.add_library(dylib_path)
        print(f"[+] arch {i} ({arch}): 已注入 LC_LOAD_DYLIB -> {dylib_path}")
        injected += 1

    if injected > 0:
        write_all(target)
        print(f"[ok] 已写回 {target}（注入 {injected} 个架构，跳过 {skipped} 个）")
    else:
        print(f"[ok] 无需修改（{skipped} 个架构均已注入过）")

    # 校验
    for i, b in enumerate(get_binaries(target)):
        assert dylib_path in b.libraries, f"校验失败: arch {i} 未找到加载命令"
    print(f"[ok] 校验通过: 全部架构均包含 {dylib_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
