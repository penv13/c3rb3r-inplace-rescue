# Real-World Incident Case Study & Granular Timeline

[English](#english) | [繁體中文](#繁體中文)

---

<a name="english"></a>
## English

This document provides a factual, granular, minute-by-minute retrospective of a full-scale C3RB3R (.L0CK3D) ransomware incident on an enterprise-grade virtualized Synology DSM environment (ESXi 7.0, 7 Storage Pools, >70 TB total capacity). All timestamps are in **UTC+8**.

---

### Incident Summary Dashboard

| Metric | Recorded Value |
| :--- | :--- |
| **Target System** | Synology DSM 7.2 (x86_64 Virtual Machine on ESXi 7.0, Dedicated 16 GB RAM, Passthrough Disks) |
| **Storage Architecture** | 7 Storage Pools (`/volume1` ~ `/volume7`), Total raw capacity >70 TB |
| **Malware Profile** | C3RB3R (Linux Cerber variant), UPX 3.95 packed ELF 64-bit |
| **Concurrency** | 306 parallel worker threads |
| **Total Files Restored** | **3,863 files** (100% success rate, 0 permanent data loss) |
| **Total Volume of Decrypted Data** | **~2.32 TB** (Media archives, database engines, container configs, OS kernel) |
| **Ransom Notes Cleaned** | **>12,000+** `read-me3.txt` files wiped across all recovery phases |
| **Extra Disk Space Overhead** | **0 Bytes** (100% In-Place Decrypt & Truncate) |
| **Key Retrieval Duration** | **2.8 Seconds** (via Hardware AES-NI Nonce sliding window match) |

---

### Comprehensive Volume-by-Volume Damage & Recovery Breakdown

> **Crucial Forensic Note on Hidden System Folders (`@`)**:  
> In addition to standard shared folders, C3RB3R traversed Synology DSM internal system metadata directories located at the root of every storage pool (e.g., `@database`, `@appdata`, `@appstore`, `@appconf`, `@eaDir`, `@synoattr`, `@synoquota`, `@SynoFinder-log`, and `@tmp`). Fully decrypting and restoring these hidden system directories was mission-critical for DSM packages and database services to come back online cleanly.

| Volume / Target | File Count | Data Size | Data Types & Categorization | Ransom Notes Removed | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Root Partition (`/dev/md0` on `/`)** | 192 files | ~1.5 GB | **OS Boot & Kernel Files**: `zImage`, `rd.gz`, `updater`, `VERSION`, `bios.ROM`, `platform.ini` | 2,646 | **100% Restored (Prevented Boot Loop)** |
| **`/volume1`** | 2 files + system configs | ~12 MB | **System Attributes & Core Packages**: `@synoattr`, `@synoquota`, WebStation, Docker configs (`dockerd.json`), PostgreSQL core configs | 100+ | **100% Restored** |
| **`/volume2`** | 807 files | **~2.08 TB** | **Video Media, System Backups & Personal Data**: Video archives, system backups, media data, `@appdata` | 1,800+ | **100% Restored** |
| **`/volume3`** | 10 files | 39.40 GB | **Video Media & Databases**: Video files, metadata databases, `@` directories | 30+ | **100% Restored** |
| **`/volume4`** | 15 files | 44.46 GB | **Video Media, Documents & Databases**: Video files, document archives, personal databases | 40+ | **100% Restored** |
| **`/volume5`** | **2,776 files** | **160.20 GB** | **Photos, Video Recordings, Books, Scanned Docs & Personal Data**: Photo libraries, video recordings, document archives, scanned books, personal files | 6,030 | **100% Restored** |
| **`/volume6`** | 11 files | ~150 MB | **Video Media, Subtitles & Databases**: Video files, subtitle files, database indexes, `@` cache | 25+ | **100% Restored** |
| **`/volume7`** | 62 files | 38.60 GB | **Video Media & Databases**: Video archives, subtitle files, index databases | 150+ | **100% Restored** |
| **TOTAL** | **3,863 files** | **~2.32 TB** | Multi-terabyte production data & system metadata | **>12,000+** | **100% Success (0 Failures)** |

---

### Granular Minute-by-Minute Timeline (All Times UTC+8)

#### Phase 1: Attack Outbreak & Emergency Freezing (Oct 28, 2026)
* **14:42 (UTC+8)**: Attack commences. The attacker executes the dropper under `/lost+found/` exploiting DSM remote authentication vulnerabilities (CVE-2024-10441 / SA-24:20). The process spawns 306 parallel worker threads (`/lost+found/libgittcb.bat -n 306`) and deletes its on-disk binary immediately. Earliest `.L0CK3D` files recorded with this timestamp.
* **14:42 - 14:50 (UTC+8)**: The malware traverses the root partition (`/dev/md0`) and storage volumes, appending `.L0CK3D` and leaving `read-me3.txt`.
* **15:00 (UTC+8)**: The system Docker daemon crashes because `dockerd.json` was encrypted. PostgreSQL connection fails due to encrypted configuration files.
* **17:35 (UTC+8)**: Administrator discovers abnormal files with `.L0CK3D` extensions appearing across web and storage directories.
* **17:43 (UTC+8)**: Administrator initiates emergency incident response session.
* **17:45 - 17:50 (UTC+8)**: Rapid triage locates active PID `27433` actively encrypting files in `/volume2/...`.
* **17:50:26 (UTC+8) [CRITICAL TRIAGE]**: Executed `kill -STOP 27433`. The encryptor process is immediately frozen in RAM! Over 60+ TB of media and database storage is saved from further encryption.
* **17:51 - 17:54 (UTC+8)**: Volatile capture: Dumped process executable via `/proc/27433/exe` (`recovered_malware.bin`, UPX 3.95, SHA256: `802ac85d...`).
* **18:02 (UTC+8)**: Volatile capture: Dumped process memory image into `/root/mem_dump.bin` (65,761,280 bytes = 62.71 MB).
* **18:06 (UTC+8)**: Confirmed assets preserved; executed `kill -9 27433` to eliminate background execution risks. Initial recovery restored PostgreSQL and WebStation configuration templates.
* **21:00 - 23:45 (UTC+8)**: Damage analysis across storage volumes. Identified damaged video and document archives in `/volume2` and `/volume7`, wiping thousands of ransom notes in affected directories during initial triage.

#### Phase 2: The Physical Memory Detour & Alternative Carving (Oct 29, 2026)
* **01:49 (UTC+8)**: Analysis of file damage patterns. Identified that C3RB3R utilizes partial/interleaved encryption (Mode 0x25, dividing large files into discrete encrypted segments across head, middle, and end, totaling e.g. ~10.2 MB for ~100MB files). Successful prototype repair of video moov atoms.
* **13:54 (UTC+8)**: Review of community bulletins (soimy/c3rb3r-rescue, REA/ASTRA). Community report specifies: *"Master key recovered from PAUSED process memory via virtual address pointer 0x5427f8"*.
* **14:03 (UTC+8) (Cognitive Detour)**: Because the process was killed on Day 1, the team assumed process virtual address space was discarded by the kernel. The team attempted to search the host's entire physical RAM:
  * Dumped 16.00 GiB physical memory from `/proc/kcore` (`synology_ram_16gb.raw`, 17,178,836,992 bytes).
  * Dumped 9.37 GiB ZRAM swap partition (`synology_zram0.raw`).
* **15:00 - 18:00 (UTC+8)**: Multi-threaded scanning over 16 GB raw physical memory yielded no clean matches due to unpaged fragmentation, swap noise, and alignment shifts. Concurrently built a Btrfs CoW block carver (`c3r_btrfs.py`) to salvage unallocated extents.

#### Phase 3: The 3-Second Breakthrough & Multi-Terabyte In-Place Restoration (Oct 30, 2026)
* **19:50 (UTC+8)**: Re-evaluating the evidence chain. Realized that on Day 1 (before issuing `kill -9`), the team had **already captured the clean 62.7 MB process memory dump (`mem_dump.bin`)**!
* **19:52 (UTC+8)**: Formulated the **Nonce Invariant**: The last 48 bytes of the 588-byte footer decrypt via AES-256-CBC to reveal a duplicated 8-byte nonce: `pt[32..40] == pt[40..48]`.
* **19:54 (UTC+8)**: Implemented hardware-accelerated sliding window search in C (`scan_master.c`).
* **19:54:30 (UTC+8) [BREAKTHROUGH]**: **Master Key Found in 2.8 seconds at offset `0x21a00`!**
  * `Master IV (16B):  50ba37a8b945... [REDACTED]`
  * `Master Key (32B): 935010c1459c... [REDACTED]`
* **20:30 (UTC+8)**: Built `inplace_restore_linux` (Go 8-worker native engine).
* **21:00 - 23:55 (UTC+8)**: Full-speed in-place restoration:
  * `/volume7`: 62 video media files (38.6 GB) restored in 42 seconds.
  * `/volume6`: 11 video media and subtitle files restored in 8 seconds.
  * `/volume5`: 2,776 photo, video recording, document and book files (160.2 GB) restored in 4 minutes 12 seconds.
  * `/volume4` & `/volume3`: 25 video media and document files (83.8 GB) restored.
  * `/volume2`: 807 video media and system backup files (2.08 TB) restored in 18 minutes.
  * `/dev/md0` (Root): 192 critical system/kernel files restored, 2,646 ransom notes wiped.

#### Phase 4: Hidden Damage Audit & System Hardening (Oct 31, 2026)
* **01:00 - 03:00 (UTC+8)**: Deep system audit for latent post-attack anomalies:
  * **Download Clients**: Removed stale `lockfile`, `session.lock`, `ipc-socket` left behind from abrupt shutdown; WebUI restored.
  * **Cloud Services**: Aborted hung FUSE connection (id 496 in kernel D-state) that was locking port 19798 and causing `df -h` to hang; updated package sha256 hash.
  * **Database Validation**: Checked 38 Docker SQLite databases and 13 DSM system databases via `PRAGMA integrity_check` -> **0 corruption**.
  * **Storage Health**: Btrfs device stats verified 0 corruption and 0 I/O errors across all 7 volumes.

---

<a name="繁體中文"></a>
## 繁體中文

本文件詳細記錄了一起發生在企業級虛擬化 Synology DSM 環境（ESXi 7.0、7 個儲存池、總容量逾 70 TB）中遭遇 C3RB3R (.L0CK3D) 勒索病毒攻擊的**精確到分鐘的實戰救災時間線與數據統計**。時區統一採用 **UTC+8**。

---

### 受損與修復總覽

| 統計維度 | 實測數值 |
| :--- | :--- |
| **目標系統** | Synology DSM 7.2（ESXi 7.0 虛擬機，16 GB 獨占記憶體，直通硬碟） |
| **儲存架構** | 7 個儲存池（`/volume1` ～ `/volume7`），裸容量逾 70 TB |
| **勒索病毒特徵** | C3RB3R（Linux 版 Cerber 變種），UPX 3.95 加殼 64 位二進位 |
| **併發威脅** | 306 個加密執行緒並行破壞 |
| **成功解密檔案總數** | **3,863 個檔案**（成功率 100%，0 數據丟失） |
| **成功解密數據量** | **約 2.32 TB**（包含影音檔案、資料庫、容器配置、DSM 核心開機檔） |
| **清理勒索信數量** | **逾 12,000+ 份** `read-me3.txt` |
| **額外磁碟開銷** | **0 位元組**（全原位原地解密覆寫 + `ftruncate` 截斷） |
| **金鑰檢索耗時** | **2.8 秒**（基於 Nonce 恆等自校驗 + 硬體 AES-NI） |

---

### 各分區業務定位與受損/修復詳細統計

> **關鍵取證細節：關於每個儲存池的 `@` 系統底層目錄**：  
> 勒索病毒在掃描各磁碟時，會深入每個 Volume 根部的 `@` 系統隱藏目錄（例如 `@database`, `@appdata`, `@appstore`, `@appconf`, `@eaDir`, `@synoattr`, `@synoquota`, `@SynoFinder-log`, `@tmp`）。全量深入並原地解密這些隱藏中繼資料，是確保群暉套件在災後能夠無縫開機、不報錯重啟的**核心生命線**。

| 分區 / 目錄 | 受損檔案數 | 數據總量 | 檔案類型與內容概述 | 清理勒索信數 | 修復結果 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **系統根分區 (`/dev/md0` 於 `/`)** | 192 個 | ~1.5 GB | **系統開機核心與韌體**：`zImage` (Kernel), `rd.gz` (Ramdisk), `updater`, `VERSION`, `bios.ROM`, `platform.ini` | 2,646 份 | **100% 原位解密（防 Boot Loop 變磚）** |
| **`/volume1`** | 2 個 + 系統底層配置 | ~12 MB | **系統底層屬性與核心套件**：`@synoattr`, `@synoquota`, WebStation, Docker 核心配置 (`dockerd.json`), PostgreSQL 核心配置 | 100+ 份 | **100% 原位解密** |
| **`/volume2`** | 807 個 | **約 2.08 TB** | **影音檔案、系統備份與個人資料**：影音存檔、中繼快取、系統備份、個人資料檔案、`@appdata` | 1,800+ 份 | **100% 原位解密** |
| **`/volume3`** | 10 個 | 39.40 GB | **影音檔案與資料庫**：影音存檔、視頻資料庫、`@` 索引中繼資料 | 30+ 份 | **100% 原位解密** |
| **`/volume4`** | 15 個 | 44.46 GB | **影音檔案、文檔與資料庫**：影音檔案、文字檔案、個人資料庫 | 40+ 份 | **100% 原位解密** |
| **`/volume5`** | **2,776 個** | **160.20 GB** | **圖片檔案、錄像檔案、書籍檔案、掃描檔案與個人資料**：照片檔案、錄像檔案、文字文檔、掃描檔案、書籍檔案 | 6,030 份 | **100% 原位解密** |
| **`/volume6`** | 11 個 | ~150 MB | **影音檔案、字幕與資料庫**：影音檔案、字幕檔案、資料庫索引、`@` 快取 | 25+ 份 | **100% 原位解密** |
| **`/volume7`** | 62 個 | 38.60 GB | **影音檔案與資料庫**：影音存檔、字幕檔案、索引資料庫 | 150+ 份 | **100% 原位解密** |
| **總計** | **3,863 個** | **約 2.32 TB** | 數十 TB 核心生產力、影音存檔與個人資產 | **逾 12,000+ 份** | **100% 成功還原（0 失敗）** |

---

### 詳細實戰時序記錄（精確到分鐘，時區 UTC+8）

#### 第一階段：病毒爆發與緊急止血（2026-10-28）
* **14:42 (UTC+8)**：勒索攻擊爆發。攻擊者利用 DSM 認證組件漏洞（CVE-2024-10441）植入木馬，於 `/lost+found/` 啟動惡意程式 `/lost+found/libgittcb.bat -n 306`，開啟 306 個執行緒並行掃描硬碟，並立即在硬碟上刪除了自身的二進位實體。磁碟上記錄到首批檔案遭改寫的時間戳正是 14:42。
* **14:42 - 14:50 (UTC+8)**：病毒瘋狂遍歷系統根分區 `/` 及各個儲存池，將檔案重命名為 `.L0CK3D` 並留下勒索信 `read-me3.txt`。
* **15:00 (UTC+8)**：由於容器核心設定檔 `dockerd.json` 被加密，Docker 服務崩潰；PostgreSQL 因配置被鎖停止連線。
* **17:35 (UTC+8)**：管理員在登錄系統維護時，發現檔案目錄中出現大量奇奇怪怪的 `.L0CK3D` 未知檔案。
* **17:43 (UTC+8)**：管理員正式啟動應急處置求助與調查。
* **17:45 - 17:50 (UTC+8)**：快速排查鎖定後台惡意 PID `27433` 正在瘋狂並行讀寫 `/volume2/...`。
* **17:50:26 (UTC+8) [關鍵止血操作]**：果斷執行 `kill -STOP 27433`！勒索進程被瞬間凍結，成功保住了剩下超過 60+ TB 未被波及的珍貴數據！
* **17:51 - 17:54 (UTC+8)**：取證提取：從 Linux `/proc/27433/exe` 救回被刪除的惡意主體（`/root/recovered_malware.bin`，UPX 加殼）。
* **18:02 (UTC+8)**：記憶體保全：將該進程的獨立記憶體完整轉儲至 `/root/mem_dump.bin`（大小 65,761,280 位元組 = 62.71 MB）。
* **18:06 (UTC+8)**：確認資產留存後，執行 `kill -9 27433` 徹底終止進程。初步修復 PostgreSQL 和 WebStation。
* **21:00 - 23:45 (UTC+8)**：針對受損目錄進行排查，確認 `/volume2` 與 `/volume7` 等分區中的影音與存檔檔案受損，並在初期快速清理了受災目錄下數千份勒索信。

#### 第二階段：思維定勢的彎路與替代雕刻（2026-10-29）
* **01:49 (UTC+8)**：逆向分析檔案損壞特徵，確認 C3RB3R 採取了多分段間隔加密（Mode 0x25，將大檔案分散切出頭部、中部、尾部等受損區塊，例如百兆檔案分散加密共約 10.2 MB）。測試成功利用 FFmpeg 重建視頻頭修復 MP4。
* **13:54 (UTC+8)**：獲取社群前沿情報（soimy/c3rb3r-rescue、REA/ASTRA 報告）。情報指出：*“Master Key 提取的前提是惡意進程處於暫停狀態，讀取虛擬地址指針 0x5427f8”*。
* **14:03 (UTC+8)（陷入思維定勢）**：團隊誤以為「既然進程在第一天已被 kill -9，進程空間已銷毀，只能去整機物理記憶體大海撈針」：
  * 從 `/proc/kcore` 導出 16.00 GiB 整機物理記憶體（`synology_ram_16gb.raw`，17,178,836,992 位元組）。
  * 導出 9.37 GiB ZRAM 交換分區（`synology_zram0.raw`）。
* **15:00 - 18:00 (UTC+8)**：在 16 GB 龐大且混亂的物理內存碎片中搜尋，因分頁打散和噪聲干擾始終無法命中。期間編寫了 Btrfs 底層塊雕刻工具（`c3r_btrfs.py`）嘗試利用 CoW 歷史快照救回部分非連續數據。

#### 第三階段：3 秒破局與數 TB 原地極限還原（2026-10-30）
* **19:50 (UTC+8)**：重新審視取證鏈條，猛然醒悟：**第一天在執行 `kill -9` 前，我們早就完整封存了該進程最純淨的 62.7 MB 獨立記憶體鏡像（`mem_dump.bin`）！**
* **19:52 (UTC+8)**：深入掌握 **Nonce 恆等式**：588 位元組 Footer 的最後 48 位元組經 AES-256-CBC 解密後，明文必然在 `[32..40]` 與 `[40..48]` 出現兩次重複的 8 位元組 Nonce。
* **19:54 (UTC+8)**：編寫硬體加速滑動窗口檢索工具 `scan_master.c`。
* **19:54:30 (UTC+8)（重大突破！）**：**僅耗時 2.8 秒，在偏移量 `0x21a00` 精確命中 Master Key！**
  * `Master IV (16B):  50ba37a8b945... [REDACTED]`
  * `Master Key (32B): 935010c1459c... [REDACTED]`
* **20:30 (UTC+8)**：開發完成 8 執行緒原生 Go 原位還原引擎（`inplace_restore_linux`）。
* **21:00 - 23:55 (UTC+8)**：開啟全速原地還原：
  * `/volume7`：62 個影音檔案（38.6 GB）於 42 秒內 100% 還原；
  * `/volume6`：11 個影音與字幕檔案於 8 秒內還原；
  * `/volume5`：2,776 個圖片檔案、錄像檔案、書籍檔案與個人資料（160.2 GB）於 4 分 12 秒內 100% 還原；
  * `/volume4` 與 `/volume3`：25 個影音與文檔檔案（83.8 GB）順利還原；
  * `/volume2`：807 個影音檔案與系統備份（2.08 TB）於 18 分鐘內 100% 還原；
  * `/dev/md0` 系統根分區：192 個核心引導檔案原地覆寫還原，清理 2,646 份勒索信。

#### 第四階段：暗傷排查與內核除障（2026-10-31）
* **01:00 - 03:00 (UTC+8)**：針對強制中斷遺留的「隱蔽內傷」進行全盤體檢：
  * **下載服務**：清理異常中斷遺留的 `lockfile`、`session.lock`、`ipc-socket`，WebUI 恢復正常。
  * **雲端掛載**：中止卡死在 Linux 內核 D-State 的 FUSE 懸死連線（id 496，該連線導致全系統 `df -h` 卡死），更新套件 SHA-256 校驗碼，雲盤掛載秒開。
  * **資料庫校驗**：遍歷 `/volume1/docker` 下 38 個 SQLite 資料庫及 13 個系統資料庫執行 `PRAGMA integrity_check`，**0 損壞**。
  * **底層健康**：Btrfs device stats 確認全部 7 個儲存池 0 錯誤。
