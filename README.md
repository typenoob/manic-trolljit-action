# manic-trolljit-action

一个 GitHub Action：把 **SideloadJIT 版 ipa** 改包为 **TrollStore 永久 JIT 版 ipa**。

以 ManicEMU 为例，输入：

```
https://github.com/Manic-EMU/ManicEMU/releases/download/v2.0.2/ManicEMU.v2.0.2.SideloadJIT.ipa
```

产出对应版本：

```
ManicEMU.v2.0.2.TrollStoreJIT.ipa
```

## 原理

在打包阶段完成改包（不依赖 TrollFools 事后补签）：

1. **下载解包** 输入 ipa，通过 `Info.plist` 的 `CFBundleExecutable` 自动定位主二进制（不硬编码 app 名）。
2. **ldid 整份替换 entitlements**（`ldid -S<plist>`，非合并），移除会在 TrollStore 下报错的 iCloud 各项，写入：
   - `com.apple.private.security.no-container = true`
   - `com.apple.private.security.no-sandbox = true`
   - `platform-application = true`
   - `get-task-allow = true`
   - `com.apple.private.memorystatus = true`
   - `com.apple.security.iokit-user-client-class` = AGX 5 项（AGXDeviceUserClient / V1 / V2 / V3 / AGXSharedUserClient）
3. **注入 JIT Enabler**：下载 [Rednick16/TrollStoreJITEnabler](https://github.com/Rednick16/TrollStoreJITEnabler) 预编译 dylib（v1.1.0）放入 `Frameworks/`，向主二进制注入 `LC_LOAD_DYLIB` 加载命令（基于 [LIEF](https://github.com/lief-project/LIEF) 纯 Python Mach-O 编辑，支持 fat 二进制，Linux 可跑）。
4. **重签与清理**：`ldid` 对主二进制（含 entitlements）与 dylib 重新 ad-hoc 签名；删除 `embedded.mobileprovision`（TrollStore 忽略签名，保留反而可能引起 entitlements 冲突）。
5. **重新打包** zip 为 `*.TrollStoreJIT.ipa` 并上传 Artifact。

## 使用

### 方式一：手动触发内置工作流

1. Fork / 推送本仓库到 GitHub；
2. 进入 **Actions → Build TrollStore JIT IPA → Run workflow**；
3. 填入 `ipa_url`（默认已填 ManicEMU v2.0.2 SideloadJIT），点击运行；
4. 运行完成后在 Artifact 中下载 `*.TrollStoreJIT.ipa`，导入 TrollStore 安装。

### 方式二：在其他工作流中引用

```yaml
- uses: <owner>/manic-trolljit-action@main
  with:
    ipa_url: https://github.com/Manic-EMU/ManicEMU/releases/download/v2.0.2/ManicEMU.v2.0.2.SideloadJIT.ipa
```

## 参数

| 输入 | 必填 | 默认 | 说明 |
| --- | --- | --- | --- |
| `ipa_url` | 是 | - | SideloadJIT ipa 的下载 URL |
| `dylib_url` | 否 | TrollStoreJITEnabler v1.1.0 | JIT Enabler dylib 下载地址 |
| `output_name` | 否 | 自动推导 | 输出文件名；缺省时把 URL 文件名中的 `SideloadJIT` 替换为 `TrollStoreJIT`，推导失败则报错 |
| `ipa_sha256` | 否 | 空 | 可选的输入 ipa sha256 校验值 |
| `upload_artifact` | 否 | `true` | 是否上传 Artifact |

| 输出 | 说明 |
| --- | --- |
| `ipa_path` | 生成的 ipa 文件路径 |
| `ipa_name` | 生成的 ipa 文件名 |

## 本地调试

脚本可在任意 Linux / macOS（含 WSL）环境独立运行：

```bash
export IPA_URL="https://github.com/Manic-EMU/ManicEMU/releases/download/v2.0.2/ManicEMU.v2.0.2.SideloadJIT.ipa"
./scripts/repkg.sh
# 产物位于 ./output/
```

依赖：`curl`、`unzip`、`zip`、`python3` + `lief==0.14.1`（脚本会自动 pip 安装）；`ldid`（自动下载 ProcursusTeam 静态二进制）。

## 目录结构

```
├── action.yml                    # composite action
├── .github/workflows/build.yml   # workflow_dispatch 手动触发入口
└── scripts/
    ├── repkg.sh                  # 核心改包脚本
    ├── inject.py                 # LC_LOAD_DYLIB 注入（LIEF）
    └── entitlements.plist        # TrollStore 永久 JIT entitlements 模板
```

## 说明

- 仅支持 TrollStore 环境（iOS 14.0–16.6.1 / 17.0 及 TrollStore 支持范围），dylib 在非 TrollStore 环境下不会生效。
- 本工具仅用于对**你合法拥有且允许修改的 ipa**（如开源项目发布包）做个人设备改包，请遵守上游许可证。
