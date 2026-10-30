# DSM Root Partition Recovery Checklist (Prevent Boot Loops)

[English](#english) | [繁體中文](#繁體中文)

---

## English

### Background
During an active C3RB3R attack on Synology DSM, the malware traverses the root partition (`/` on `/dev/md0`) in addition to storage pools (`/volume1` ~ `/volumeN`).
If a victim decrypts only their storage volumes and hastily reboots the NAS, the machine will fail to boot and enter a permanent boot loop due to damaged kernel images and system ramdisks.

### Critical System Files to Inspect & Restore

Before rebooting DSM, execute the following audit in the root partition:

```bash
# 1. Search for any locked system files in root partition
find / -maxdepth 4 -name "*.L0CK3D" 2>/dev/null
```

Pay special attention to these mission-critical files:
1. **Linux Kernel Image**: `/.syno/patch/zImage.L0CK3D` -> must restore to `/.syno/patch/zImage`
2. **DSM Ramdisk**: `/.syno/patch/rd.gz.L0CK3D` -> must restore to `/.syno/patch/rd.gz`
3. **DSM Version & Platform Configs**:
   - `/etc/VERSION.L0CK3D`
   - `/.syno/patch/VERSION.L0CK3D`
   - `/.syno/patch/platform.ini.L0CK3D`
   - `/.syno/patch/updater.L0CK3D`
4. **Bootloader & BIOS**:
   - `/.syno/patch/bios.ROM.L0CK3D`
   - `/.syno/patch/GRUB_VER.L0CK3D`

### Verification Commands
```bash
# Verify rd.gz is valid gzip/cpio archive:
gzip -t /.syno/patch/rd.gz && echo "rd.gz OK"

# Verify zImage has valid Linux kernel signature:
file /.syno/patch/zImage
```

---

## 繁體中文

### 背景說明
在群暉 DSM 遭受 C3RB3R 勒索攻擊時，病毒不僅會加密數據儲存池（`/volume1` ~ `/volumeN`），還會深入系統根分區（`/dev/md0` 掛載於 `/`）。
如果受害者僅解密了數據盤上的檔案就匆忙重啟 NAS，系統會因為開機內核（Kernel）和 Ramdisk 損壞而直接陷入 **無法開機的死循環（Boot Loop）**。

### 必檢核心系統檔案清單

在重啟群暉之前，務必在 root 權限下執行全盤掃描：

```bash
# 1. 檢索根目錄分區下的所有被鎖定檔案
find / -maxdepth 4 -name "*.L0CK3D" 2>/dev/null
```

重點排查並原地解密以下核心檔案：
1. **Linux 核心映像**：`/.syno/patch/zImage.L0CK3D` -> 必須原地解密為 `/.syno/patch/zImage`
2. **DSM 開機 Ramdisk**：`/.syno/patch/rd.gz.L0CK3D` -> 必須原地解密為 `/.syno/patch/rd.gz`
3. **版本與硬體平台配置**：
   - `/etc/VERSION.L0CK3D`
   - `/.syno/patch/VERSION.L0CK3D`
   - `/.syno/patch/platform.ini.L0CK3D`
   - `/.syno/patch/updater.L0CK3D`
4. **引導韌體與 GRUB**：
   - `/.syno/patch/bios.ROM.L0CK3D`
   - `/.syno/patch/GRUB_VER.L0CK3D`

### 驗證指令
```bash
# 驗證 rd.gz 是否為完整未損壞的壓縮檔案：
gzip -t /.syno/patch/rd.gz && echo "rd.gz 正常"

# 驗證 zImage 核心識別碼：
file /.syno/patch/zImage
```
