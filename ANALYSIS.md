# 完整技术分析：Update_ILCE7M3V404.exe

> 本文为 [README](README.md) 所述免责声明约束下的研究记录。
> 内容仅描述封装与容器格式，不包含密钥、解密方法或可刷写镜像。

**样本**：Update_ILCE7M3V404.exe
**尺寸**：339,275,208 字节
**SHA-256**：8c356688a70946a855191e99fd4d9096a5c3d4263f3f11065605eaea45639d57
**PE**：PE32 / i386 / 5 节 / ImageBase 0x400000
**性质**：Sony Sony Packaging Tool (Packman) 自解压器 + 相机固件更新器

---

## 1. 整体封装链

| 层 | 位置 | 变换 | 结果 |
|---|---|---|---|
| PE 本体 | 0x000000–0x0711FF | — | 解包器（MFC） |
| Packman 条目表 | 0x071200 起 | 明文 + UTF-16LE | 指向 Settings.ini 与 .cab |
| Settings.ini | 0x0712FA，1834 B | UTF-16LE 明文 | 包配置 |
| 固件包 cab | 0x071A24，338,799,086 B | 逐字节 XOR 0xFF | 标准 MSCF cab |
| Authenticode | 0x1438C412，10,678 B | PKCS#7 | 签名 |
| ├ FirmwareData_ILCE7M3V404.dat | cab 内 | — | 335,395,240 B 固件容器 |
| └ 其余 44 个文件 | cab 内 | — | MFC 运行库、语言 XML、更新器 |

### 1.1 唯一的"加密"：XOR 0xFF

解包器用 Cabinet.dll 展开 cab（延迟导入 FDICreate/FDICopy/FDIDestroy），
写盘回调 FUN_00407bf0 → FUN_00407cf0 → FUN_00407f30：

    逐字节取反，0x40 字节一块：
        *param_1 = ~*param_1;  ... param_1[0xf] = ~param_1[0xf];

只有名字为 E8FF0748-2339-49f9-9A79-824D7561736C.cab 的条目被取反，其余文件原样拷贝。
取反后 0x071A24 首 4 字节 = 4D 53 43 46 = MSCF，cbCabinet = 0x1431A9EE。

> 教训：一开始被 8.000 的熵误导去找 AES；Cabinet.dll 的存在本应第一时间提示
> "最终产物就是标准 CAB"，只需搜索 MSCF 的取反形态。

### 1.2 Settings.ini（明文）

    [Package]  ProductName = Update_ILMEFX6V200
               PackageDateTime = 2026-02-09T10:44:38.346Z
               Compression = True
               TotalFileSize = 344321724
    [Restriction] CheckDigitalSignature = False
                  CheckManufacturer = False
                  ExtractorArchitecture = 1
    [Execution_x64] FileName = FirmwareUpdaterEg.exe  WaitMode = 1  WaitTimeout = 1500

（ProductName 写着 ILMEFX6V200，与文件名 ILCE7M3V404 不符 —— 打包机模板残留，
不影响包内容。）

---

## 2. UFU 固件容器格式

文件头 8 字节魔数 89 55 46 55 0D 0A 1A 0A（"\x89UFU\r\n\x1a\n"，仿 PNG 风格）。

其后的全部内容是一条 TLV 链：

    struct chunk {
        uint32_be length;      // 载荷长度
        char      tag[4];      // ASCII
        uint8     payload[length];
    };

实测链（闭合，无余量）：

| # | 偏移 | tag | 长度 | 载荷范围 | 含义 |
|---|---|---|---|---|---|
| 1 | 0x00000008 | DATV | 4 | 0x10–0x14 | 数据格式版本 = 1 |
| 2 | 0x00000014 | PROV | 4 | 0x1C–0x20 | 协议版本 = 1 |
| 3 | 0x00000020 | UDID | 92 | 0x28–0x84 | 目标机型/VID/PID 白名单 |
| 4 | 0x00000084 | FDAT | 335,395,088 | 0x8C–0x13FDB99C | 固件镜像（加密） |
| 5 | 0x13FDB99C | DEND | 4 | 0x13FDB9A4–0x13FDB9A8 | CRC-32 |

链终点 0x13FDB9A8 = 文件长度，slack = 0。

### 2.1 DEND 校验 = 标准 CRC-32

    CRC32(bytes[0 .. 0x13FDB99C)) = 0xEF01A1DA   ← 与 DEND 载荷完全一致

即 IEEE 802.3 / zlib 多项式，大端存储，覆盖从魔数到 FDAT 载荷末尾的全部字节。
（对应更新器里的日志格式串："Firm CRC=[%x] Chunk=[%c%c%c%c], PC CRC=[%x]"）

### 2.2 UDID 表 = 11 个目标机型

    struct udid {
        uint32_be count;                 // = 11
        struct { uint16_be modelCode;
                 uint16_be usbVid;       // 恒为 0x054C = Sony
                 uint16_be usbPid;
                 uint16_be flags; } e[count];
    };

| # | modelCode | usbVid | usbPid |
|---|---|---|---|
| 0 | 0x0448 | 0x054C | 0x0100 |
| 1 | 0x047D | 0x054C | 0x0100 |
| 2 | 0x07C7 | 0x054C | 0x0100 |
| 3 | 0x07C8 | 0x054C | 0x0100 |
| 4 | 0x0BEE | 0x054C | 0x0100 |
| 5 | 0x0BEF | 0x054C | 0x0100 |
| 6 | 0x0BFE | 0x054C | 0x0100 |
| 7 | 0x0BFF | 0x054C | 0x0100 |
| 8 | 0x0C01 | 0x054C | 0x0100 |
| 9 | 0x0C02 | 0x054C | 0x0100 |
| 10 | 0x03E2 | 0x054C | 0x0200 |

型号成对出现（7C7/7C8、BEE/BEF、BFE/BFF、C01/C02），典型的"正常运行模式 /
固件更新模式"双 PID 组合。0x03E2 单独走 0x0200。

---

## 3. FDAT 载荷：16 字节块加密，PC 端不参与解密

证据链：

1. 全长恰为 16 的倍数：335,395,088 / 16 = 20,962,193（整除）。
2. 熵恒为 8.000：40 个 8 MB 块全部 8.0000，无任何低熵区，无字符串、无结构。
3. 几乎无重复块：20,962,096 个 16 B 块中只有 1 组重复（25 份），
   对应载荷开头约 400 字节的规则填充区 —— 与 ECB 模式下重复明文块的表现一致。
4. 常规压缩（LZMA/LZX/deflate/BZip2/XZ）均被高熵 + 无重复性排除。

### 3.1 更新器不碰这段数据（决定性证据）

FirmwareUpdaterEg.exe 的 chunk 分派代码（capstone 反汇编）：

    0x401845  read 12 bytes into [ebp-0x2014]        ; 读 8 字节魔数 + 12 字节 chunk 头
    0x40185A  cmp  dword [buf], 0x56544144           ; "DATV"
    0x4018E0  cmp  dword [buf], 0x564F5250           ; "PROV"
    0x401A92  cmp  dword [buf], 0x54414446           ; "FDAT"   <<<
    0x401AA4  call [vtable+0x14]                     ; GetPosition()
    0x401AA9  add  eax, -8                           ; 载荷起始偏移
    0x401AB2  mov  [ebx+0x14], eax                   ; 只保存 offset
    0x401AC5  mov  eax, [ebp-0x2014]                 ; 读到的长度
    0x401AD6  mov  [ebx+0x10], eax                   ; 只保存 size
    0x401AD9  call [edx+0x34]  (size, 0, 1)          ; Seek 直接跳过载荷！

FDAT 分支只记录 offset / size 两个字段，然后 Seek 越过，全程不读、不校验、
不变换。真正的数据搬运发生在后续传输阶段，按 m_maxFirmDataSize 窗口直接从文件
读原始密文，经 USB 命令包发给相机；相机端回传 CRC 与 PC 端计算的 CRC 比对
（"Firm CRC=… PC CRC=…"）。

同时，三个二进制里都没有 AES S-box、逆 S-box、CRC32 查表、SHA-256 常量，
导入表里也没有任何 Crypt* / bcrypt 函数。

> 结论：固件镜像的解密与完整性验证发生在相机内部（机身安全区 / 引导 ROM），
> 更新器只是把 335 MB 密文按窗口转发。PC 侧不存在可提取的密钥或算法。

---

## 4. 产物清单

    
    ├── payload.cab                 338,799,086 B  取反后的标准 cab
    ├── sony_fw_unpack.py                          一键复现脚本
    └── extract/                    344,321,724 B  cab 解开后的 45 个文件
        ├── FirmwareData_ILCE7M3V404.dat   335,395,240 B  ← 固件容器
        ├── FirmwareUpdaterEg.exe              120,240 B  ← MFC USB 更新器
        ├── FirmwareUpdaterImg.dll             107,952 B  ← 资源 DLL
        ├── ModelName.ini / Str*.xml（15 语言）
        ├── mfc140u / msvcp* / msvcr* / ucrtbase / vcruntime140
        └── api-ms-win-*.dll ×18、XpStorageDevice_WinXp2k.dll

## 5. 复现

    python sony_fw_unpack.py [路径\Update_ILCE7M3V404.exe]

脚本自动完成：定位 Packman 表 → 取反提取 cab → 7z 解包 → 解析 UFU chunk 链 →
校验 DEND CRC-32 → 列出 UDID 机型表 → 统计 FDAT 块重复。

## 6. 若要继续深入

- 不要指望从 PC 侧解出固件：密钥不在样本里。
- 可行的下一步只有硬件/运行时方向：
  1. 相机 USB 抓包（更新模式 PID 0x0100），看命令协议里是否有明文窗口；
  2. 从相机 dump 引导区，找 AES 密钥槽；
  3. 拿一份"已解密"的同代固件做已知明文攻击（若为 ECB 且存在已知固定块）。
- 也可以横向利用已解出的 44 个普通文件做版本比对（FirmwareUpdaterEg.exe 版本
  3.2.00.06230，2021-06-23 构建）。
