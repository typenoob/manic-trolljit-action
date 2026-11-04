#!/usr/bin/env bash
# 把一个 SideloadJIT 版 ipa 改包为 TrollStore 永久 JIT 版 ipa：
#   1. 下载输入 ipa 并解包
#   2. 整份替换主二进制 entitlements（ldid -S，去 iCloud、加 no-sandbox/platform-application/...）
#   3. 下载预编译 TrollStoreJITEnabler.dylib 放入 Frameworks/ 并注入 LC_LOAD_DYLIB
#   4. ldid 重新 ad-hoc 签名主二进制与 dylib，删除 embedded.mobileprovision
#   5. 重新 zip 为 *.TrollStoreJIT.ipa
#
# 环境变量:
#   IPA_URL       (必填) 输入 ipa 的下载 URL
#   DYLIB_URL     (可选) TrollStoreJITEnabler.dylib 下载地址
#   OUTPUT_NAME   (可选) 输出文件名；缺省从 URL 推导（SideloadJIT -> TrollStoreJIT）
#   IPA_SHA256    (可选) 输入 ipa 的 sha256 校验值
#   WORK_DIR      (可选) 工作目录，默认 ./build
#   OUT_DIR       (可选) 产物目录，默认 ./output
set -euo pipefail

log() { printf '[repkg] %s\n' "$*"; }
die() { printf '[repkg][FATAL] %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IPA_URL="${IPA_URL:?IPA_URL is required}"
DYLIB_URL="${DYLIB_URL:-https://github.com/Rednick16/TrollStoreJITEnabler/releases/download/1.1.0/TrollStoreJITEnabler.dylib}"
OUTPUT_NAME="${OUTPUT_NAME:-}"
IPA_SHA256="${IPA_SHA256:-}"
WORK_DIR="${WORK_DIR:-$PWD/build}"
OUT_DIR="${OUT_DIR:-$PWD/output}"

LDID_VERSION="v2.1.5-procursus7"
# Windows（Git Bash/MSYS）本地调试时可覆盖：
#   LDID_ASSET=ldid_w64_x86_64.exe LDID_NAME=ldid.exe
LDID_ASSET="${LDID_ASSET:-ldid_linux_x86_64}"
LDID_NAME="${LDID_NAME:-ldid}"
LDID_URL="https://github.com/ProcursusTeam/ldid/releases/download/${LDID_VERSION}/${LDID_ASSET}"
JIT_DYLIB_NAME="TrollStoreJITEnabler.dylib"
DYLIB_INSTALL_PATH="@executable_path/Frameworks/${JIT_DYLIB_NAME}"

# ---------- 依赖检查 ----------
command -v curl >/dev/null || die "需要 curl"
command -v unzip >/dev/null || die "需要 unzip"
PYTHON_BIN="${PYTHON_BIN:-python3}"
command -v "$PYTHON_BIN" >/dev/null || PYTHON_BIN=python
command -v "$PYTHON_BIN" >/dev/null || die "需要 python3 或 python"
# 注入器为纯 Python 实现（无第三方依赖），仅需标准库
"$PYTHON_BIN" -c 'import struct, plistlib, zipfile' || die "python 标准库不完整"

# ---------- 准备目录与工具 ----------
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/payload" "$OUT_DIR"
TOOLS_DIR="$WORK_DIR/tools"
mkdir -p "$TOOLS_DIR"
LDID="$TOOLS_DIR/$LDID_NAME"
if [ ! -x "$LDID" ]; then
  log "下载 ldid ${LDID_VERSION}"
  curl -fsSL --retry 3 -o "$LDID" "$LDID_URL"
  chmod +x "$LDID"
fi

# ---------- 下载并解包 ipa ----------
IPA_FILE="$WORK_DIR/input.ipa"
log "下载 ipa: $IPA_URL"
curl -fL --retry 3 -o "$IPA_FILE" "$IPA_URL" || die "下载 ipa 失败: $IPA_URL"
if [ -n "$IPA_SHA256" ]; then
  echo "${IPA_SHA256}  $IPA_FILE" | sha256sum -c - || die "ipa sha256 校验失败"
  log "ipa sha256 校验通过"
fi
unzip -q "$IPA_FILE" -d "$WORK_DIR/payload"

APP_DIR="$(find "$WORK_DIR/payload/Payload" -maxdepth 2 -type d -name '*.app' | head -n 1)"
[ -n "$APP_DIR" ] || die "未找到 Payload/*.app"
APP_DIR="$(cd "$APP_DIR" && pwd)"
APP_NAME="$(basename "$APP_DIR")"
log "定位到 app: $APP_NAME"

# 通过 Info.plist 的 CFBundleExecutable 定位主二进制（不硬编码 app 名）
EXEC_NAME="$("$PYTHON_BIN" - "$APP_DIR/Info.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    info = plistlib.load(f)
exe = info.get("CFBundleExecutable") or info.get("CFBundleName")
if not exe:
    sys.exit("Info.plist 中缺少 CFBundleExecutable/CFBundleName")
print(exe)
PY
)"
MAIN_BIN="$APP_DIR/$EXEC_NAME"
[ -f "$MAIN_BIN" ] || die "主二进制不存在: $MAIN_BIN"
log "主二进制: $EXEC_NAME"

# ---------- 注入 TrollStoreJITEnabler.dylib ----------
log "下载 dylib: $DYLIB_URL"
curl -fL --retry 3 -o "$APP_DIR/Frameworks/$JIT_DYLIB_NAME" --create-dirs "$DYLIB_URL" \
  || die "下载 dylib 失败: $DYLIB_URL"

log "注入 LC_LOAD_DYLIB: $DYLIB_INSTALL_PATH"
"$PYTHON_BIN" "$SCRIPT_DIR/inject.py" "$MAIN_BIN" "$DYLIB_INSTALL_PATH"

# ---------- ldid 重签（注入完成后再签名，保证签名覆盖最终内容） ----------
log "ldid 整份替换 entitlements: $SCRIPT_DIR/entitlements.plist"
"$LDID" -S"$SCRIPT_DIR/entitlements.plist" "$MAIN_BIN"
log "ldid ad-hoc 签名 dylib"
"$LDID" -S "$APP_DIR/Frameworks/$JIT_DYLIB_NAME"

# ---------- 清理 provisioning profile（TrollStore 不需要，且会带来 entitlements 冲突） ----------
rm -f "$APP_DIR/embedded.mobileprovision"
log "已删除 embedded.mobileprovision"

# ---------- 推导输出名并打包 ----------
if [ -z "$OUTPUT_NAME" ]; then
  BASE_NAME="$(basename "$IPA_URL")"
  OUTPUT_NAME="$("$PYTHON_BIN" - "$BASE_NAME" <<'PY'
import sys
name = sys.argv[1]
if not name.endswith(".ipa"):
    sys.exit(f"输入 URL 文件名不是 .ipa: {name}")
if "SideloadJIT" not in name:
    sys.exit(f"文件名不含 SideloadJIT，无法自动推导输出名: {name}（请用 OUTPUT_NAME 显式指定）")
print(name.replace("SideloadJIT", "TrollStoreJIT"))
PY
)"
fi
case "$OUTPUT_NAME" in
  *.ipa) ;;
  *) OUTPUT_NAME="${OUTPUT_NAME}.ipa" ;;
esac

OUT_FILE="$OUT_DIR/$OUTPUT_NAME"
log "打包: $OUT_FILE"
( cd "$WORK_DIR/payload" && "$PYTHON_BIN" - "$OUT_FILE" <<'PY'
import os, sys, zipfile
out = os.path.abspath(sys.argv[1])
if os.path.exists(out):
    os.remove(out)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    # ipa 规范：根目录为 Payload/，统一使用正斜杠
    for root, dirs, files in os.walk("Payload"):
        for name in files:
            p = os.path.join(root, name)
            z.write(p, p.replace(os.sep, "/"))
PY
)

[ -s "$OUT_FILE" ] || die "打包产物为空"
log "完成: $OUT_FILE ($(du -h "$OUT_FILE" | cut -f1))"

# ---------- 暴露给 CI ----------
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "ipa_path=$OUT_FILE"
    echo "ipa_name=$OUTPUT_NAME"
  } >> "$GITHUB_OUTPUT"
fi
