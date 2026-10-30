# Technical Architecture: C3RB3R (.L0CK3D) File Format & Cryptographic Layout

[English](#english) | [繁體中文](#繁體中文)

---

## English

### 1. Overall Encryption Structure

C3RB3R employs a two-tier hybrid encryption scheme:
* **File Encryption**: ChaCha8 stream cipher. Depending on file size and mode, encrypts either the entire file (small files < 1 MB), the first 1 MB (medium files), or interleaved segments across head, middle, and end (large files > 10 MB). See Section 4 for complete rules and concrete examples.
* **Key Encryption**: AES-256-CBC. Each file's 32-byte ChaCha8 key and 8-byte nonce are wrapped inside a 48-byte Session Block appended to the file.
* **Footer Append**: A fixed 588-byte metadata trailer is appended to the end of every `.L0CK3D` file:
  $$\text{EncryptedFileSize} = \text{OriginalFileSize} + 588$$

```
+-------------------------------------------------------------+---------------------+
|                  Encrypted File Body                        |   Footer (588 B)    |
| (Segments 0..N encrypted with ChaCha8 using FileKey & Nonce)|                     |
+-------------------------------------------------------------+---------------------+
                                                               ^                     ^
                                                               |                     |
                                                        Offset: Size - 588     Offset: Size
```

### 2. 588-Byte Footer Layout

| Byte Offset (from Footer start) | Length | Field Description |
| :--- | :--- | :--- |
| `0x000` - `0x02F` (`[0..48]`) | 48 B | **Encrypted Session Key Record** (AES-256-CBC wrapped) |
| `0x030` - `0x23B` (`[48..572]`) | 524 B | Encrypted Metadata / Ransom identifiers |
| `0x23C` (`572`) | 1 B | **Encryption Mode** (`0x24`: Full, `0x25`: Percent, `0x26`: 1MB Header) |
| `0x23D` (`573`) | 1 B | **Percent Factor** (e.g. 10, 20, 50, or 0) |
| `0x23E` (`574`) | 1 B | **Crypto Engine Identifier** (Expected: `0x20` for ChaCha8) |
| `0x23F` - `0x243` (`[575..579]`) | 5 B | Reserved / Padding |
| `0x244` - `0x24B` (`[580..588]`) | 8 B | **Original File Size** (64-bit Little-Endian uint64) |

### 3. Session Key Unwrap & The Nonce Invariant

The 48-byte record is decrypted using AES-256-CBC with the **Master Key Material** (`IV: 16 B, Key: 32 B`):
```text
Plaintext (48 B) = AES-256-CBC-Decrypt(MasterKey[16..48], MasterIV[0..16], Ciphertext[0..48])
```

Decrypted plaintext layout:
* `pt[0..32]`: 32-byte ChaCha8 File Key
* `pt[32..40]`: 8-byte ChaCha8 Nonce
* `pt[40..48]`: **Duplicated 8-byte ChaCha8 Nonce**

> **The Nonce Invariant**: `memcmp(pt + 32, pt + 40, 8) == 0`.  
> This mathematical invariant allows 100% false-positive-free brute-force search across volatile memory dumps in seconds.

### 4. Segmented / Interleaved Encryption Mechanics (Mode `0x25`)

For larger files, C3RB3R does not only encrypt the beginning; it distributes encrypted blocks across the entire file body (head, middle, and end) to maximize destruction speed while ensuring recovery without the key is mathematically impossible.

#### Segment Calculation Rules
The footer specifies `mode` at offset 572 and `percent` at offset 573:

1. **Mode `0x24` (Full Encryption)**:
   * Condition: `percent == 0`
   * Single segment: `[{ Offset: 0, Length: origSize }]`
2. **Mode `0x26` (Header-only)**:
   * Single segment: `[{ Offset: 0, Length: min(origSize, 1024 * 1024) }]` (First 1 MB)
3. **Mode `0x25` (Interleaved Segments across Head, Middle & End)**:
   * **Factor lookup table by percentage**:
     | Percent | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 50 | 60 | 70 | 80 |
     | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
     | Factor | 4 | 5 | 7 | 9 | 10 | 12 | 14 | 10 | 20 | 23 | 27 |
   * **Segment Length**:
     `Length = (origSize / 100) * Factor`
   * **Segment Count**:
     * If `percent == 50`: `Count = 5`
     * All other percentages: `Count = 3`
   * **Gap between Segments**:
     * If `percent == 50`: `Gap = Length`
     * All other percentages: `Gap = (origSize - 3 * Length) / 2`
   * **Segment Starting Offsets**:
     * Segment 0 (Head): `Offset_0 = 0`, length: `Length`
     * Segment 1 (Middle): `Offset_1 = Length + Gap`, length: `Length`
     * Segment 2 (End): `Offset_2 = 2 * (Length + Gap)`, length: `Length`
     * *(For 50% mode with 5 segments: `Offset_i = i * (Length + Gap)` for `i = 0..4`)*

```text
+----------------+--------------+----------------+--------------+----------------+--------------+
|Segment 0 (Head)|Gap 0 (Intact)|Segment 1 (Mid) |Gap 1 (Intact)|Segment 2 (End) |Footer (588 B)|
|  [Encrypted]   |  [Raw Data]  |  [Encrypted]   |  [Raw Data]  |  [Encrypted]   |  [AES Meta]  |
+----------------+--------------+----------------+--------------+----------------+--------------+
^                ^              ^                ^              ^                ^              ^
0             Length        Offset_1       Offset_1+Len     Offset_2         origSize         EOF
```

* **Segment 0 (Head)**: `0` to `Length`, encrypted with ChaCha8 stream cipher.
* **Gap 0 (Untouched Raw Data)**: `Length` to `Offset_1`, 100% unencrypted intact data.
* **Segment 1 (Middle)**: `Offset_1` to `Offset_1 + Length`, encrypted with ChaCha8 stream cipher.
* **Gap 1 (Untouched Raw Data)**: `Offset_1 + Length` to `Offset_2`, 100% unencrypted intact data.
* **Segment 2 (End)**: `Offset_2` to `origSize`, encrypted with ChaCha8 stream cipher.
* **Footer (588 B Metadata)**: `origSize` to `EOF`, containing AES-wrapped session record and parameters; removed atomically via `ftruncate(origSize)`.

#### File Sizing Strategies & Concrete Real-World Examples

C3RB3R adaptively chooses its encryption strategy based on file size to balance encryption throughput with irreversible damage:

| File Category | Size Threshold | Encryption Mode | Observed Behavior & Examples |
| :--- | :--- | :--- | :--- |
| **Small Files** | `< 1 MB` (Configs, Scripts, Databases) | **Mode `0x24` (Full)** | **100% Fully Encrypted**. Configuration files (`dockerd.json`, `.conf`), database headers, shell scripts, and auth tokens are completely scrambled from byte 0 to EOF. |
| **Medium Files** | `1 MB ~ 10 MB` | **Mode `0x26` (Header-only)** | **First 1 MB Encrypted**. Encrypts byte 0 to 1,048,576 (`min(origSize, 1MB)`), destroying file headers while leaving the remaining payload untouched. |
| **Large Files** | `> 10 MB` (Videos, Virtual Disks, Archives) | **Mode `0x25` (Interleaved)** | **Disjoint Multi-Segment Encryption (3 or 5 blocks across Head, Middle, End)**. Disperses corruption across the entire file so containers and media players fail completely. |

##### Concrete Real-World Calculations for Large Files (Mode `0x25`):
* **Example A: ~256 MB Video File (Observed in Incident, `Percent = 10%`, Factor = 4)**:
  * Single Segment Length: `Length = (255.9 MB / 100) * 4 ≈ 10.2 MB`
  * Layout:
    * Segment 0 (Head): `0` to `10.2 MB` (10.2 MB encrypted)
    * Gap 0 (Untouched): `10.2 MB` to `122.7 MB` (112.5 MB raw intact data)
    * Segment 1 (Middle): `122.7 MB` to `132.9 MB` (10.2 MB encrypted)
    * Gap 1 (Untouched): `132.9 MB` to `245.4 MB` (112.5 MB raw intact data)
    * Segment 2 (End): `245.4 MB` to `255.9 MB` (10.2 MB encrypted)
  * Total Encrypted: `3 * 10.2 MB ≈ 30.6 MB` (~12% of the file).
  * Untouched Raw Data: `~225.3 MB` (~88% of the file completely intact).
  * *(Note: This reveals the true origin of "~10.2 MB" recorded in early incident triage: each single encrypted segment was ~10.2 MB!)*
* **Example B: 50 GB 4K High-Bitrate Video Archive (`Percent = 10%`, Factor = 4)**:
  * Single Segment Length: `Length = (50 GB / 100) * 4 = 2 GB`
  * Layout:
    * Segment 0 (Head): `0` to `2 GB` (2 GB encrypted)
    * Gap 0 (Untouched): `2 GB` to `24 GB` (22 GB raw intact data)
    * Segment 1 (Middle): `24 GB` to `26 GB` (2 GB encrypted)
    * Gap 1 (Untouched): `26 GB` to `48 GB` (22 GB raw intact data)
    * Segment 2 (End): `48 GB` to `50 GB` (2 GB encrypted)
  * Total Encrypted: `3 * 2 GB = 6 GB` (12% of the file).
  * Untouched Raw Data: `44 GB` (88% of the file completely intact).
  * **The In-Place Advantage**: Traditional copy-restore scripts require **50 GB of free space** and must write 50 GB to disk. `inplace_restore` only touches the 6 GB of damaged blocks in-place and calls `ftruncate`, restoring the 50 GB file in seconds with **0 bytes extra space**!

#### Why In-Place Decryption is 100x Faster and Requires 0 Extra Space:
Traditional recovery scripts (`decrypt_copy.py`) sequentially read the entire multi-gigabyte file from start to finish, copying unaffected gaps to a new duplicate file on disk (requiring 1:1 free storage).

`inplace_restore` achieves **Zero Extra Space** and near-instant completion:
1. **Disjoint Segment Overwriting**: Using POSIX `ReadAt(chunk, Offset)` and `WriteAt(chunk, Offset)`, the tool ONLY reads and rewrites the exact encrypted bytes of Segments 0, 1, and 2 directly inside the original file.
2. **Untouched Gaps**: Gigabytes of raw untouched data in `Gap 0` and `Gap 1` are **never copied or relocated on disk**.
3. **Atomic Truncation**: Once all segments are restored, calling `ftruncate(origSize)` immediately drops the 588-byte metadata footer from the inode without moving blocks.
4. **Counter Continuity**: ChaCha8 keystream blocks are incremented monotonically across segments (`counter += (take + 63) / 64`), matching the ransomware's internal cipher stream state.

---

## 繁體中文

### 1. 整體加密架構

C3RB3R 採用兩層混合加密機制：
* **檔案層級加密**：ChaCha8 流加密。根據檔案大小與設定模式，進行全量加密（< 1 MB 小型檔案）、前綴加密（中型檔案）或頭中尾多分段間隔切片加密（> 10 MB 大型檔案）。詳見第 4 節的規格與實例對比。
* **金鑰層級包裝**：AES-256-CBC。每個檔案獨立的 32 位元組 ChaCha8 Key 與 8 位元組 Nonce 被封裝進檔案尾部的 48 位元組 Session 結構。
* **Footer 尾部結構**：在所有 `.L0CK3D` 檔案末尾固定追加 588 位元組的中繼資料（Footer）：
  $$\text{加密檔案大小} = \text{原始檔案大小} + 588$$

### 2. 588 位元組 Footer 記憶體佈局

| 偏移量（自 Footer 開頭） | 長度 | 欄位說明 |
| :--- | :--- | :--- |
| `0x000` - `0x02F` (`[0..48]`) | 48 B | **加密的 Session Key 記錄**（由 Master Key 經 AES-256-CBC 加密） |
| `0x030` - `0x23B` (`[48..572]`) | 524 B | 加密中繼資料 / 勒索識別碼 |
| `0x23C` (`572`) | 1 B | **加密模式** (`0x24`: 全量, `0x25`: 百分比切片, `0x26`: 1MB 頭部) |
| `0x23D` (`573`) | 1 B | **切片因子** (例如 10, 20, 50, 或 0) |
| `0x23E` (`574`) | 1 B | **演算法標識** (預期值為 `0x20`，代表 ChaCha8) |
| `0x23F` - `0x243` (`[575..579]`) | 5 B | 保留 / 對齊填充 |
| `0x244` - `0x24B` (`[580..588]`) | 8 B | **原始檔案大小**（64 位元 Little-Endian 整數） |

### 3. 金鑰解密與 Nonce 恆等驗證

使用 48 位元組的 **Master Key Material**（前 16 位元組 IV + 後 32 位元組 Key）執行 AES-256-CBC 解密：
```text
Plaintext (48 B) = AES-256-CBC-Decrypt(MasterKey[16..48], MasterIV[0..16], Ciphertext[0..48])
```

解密後的明文佈局：
* `pt[0..32]`：該檔案專屬的 32 位元組 ChaCha8 Key
* `pt[32..40]`：8 位元組 ChaCha8 Nonce
* `pt[40..48]`：**重複的 8 位元組 ChaCha8 Nonce**

> **Nonce 恆等不變量**：`memcmp(pt + 32, pt + 40, 8) == 0`。  
> 這個自校驗特徵使得我們可以在幾十 MB 的進程記憶體 dump 中進行 1 位元組滑動比對，**零誤報、且 3 秒內秒級命中真實 Master Key**。

### 4. 多分段間隔切片加密與原位修復原理（Mode `0x25`）

針對大檔案（如影音存檔、資料庫檔案），C3RB3R 並非只加密頭部，而是將加密區塊分散在檔案的**開頭（Head）、中間（Middle）與後半部（End）**，在極大化加密破壞效率的同時，防止受害者透過修復單一頭部恢復數據。

#### 分段計算規則
Footer 偏移量 572 記載 `mode`，偏移量 573 記載 `percent`：

1. **模式 `0x24`（全量加密）**：
   * 條件：`percent == 0`
   * 單一分段：`[{ Offset: 0, Length: origSize }]`
2. **模式 `0x26`（頭部加密）**：
   * 單一分段：`[{ Offset: 0, Length: min(origSize, 1024 * 1024) }]`（前 1 MB）
3. **模式 `0x25`（頭、中、尾多分段切片加密）**：
   * **切片因子查詢表（`partialFactors`）**：
     | 百分比 (Percent) | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 50 | 60 | 70 | 80 |
     | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
     | 因子 (Factor) | 4 | 5 | 7 | 9 | 10 | 12 | 14 | 10 | 20 | 23 | 27 |
   * **單段長度 (Length)**：
     `Length = (origSize / 100) * Factor`
   * **分段數量 (Count)**：
     * 若 `Percent == 50`：`Count = 5`
     * 其他百分比：`Count = 3`
   * **分段間隙 (Gap)**：
     * 若 `Percent == 50`：`Gap = Length`
     * 其他百分比：`Gap = (origSize - 3 * Length) / 2`
   * **各分段起始偏移量 (Starting Offsets)**：
     * 第 0 段（頭部）：`Offset_0 = 0`，長度為 `Length`
     * 第 1 段（中部）：`Offset_1 = Length + Gap`，長度為 `Length`
     * 第 2 段（尾部）：`Offset_2 = 2 * (Length + Gap)`，長度為 `Length`
     * *（若為 50% 模式切為 5 段，則公式通用為：`Offset_i = i * (Length + Gap)`，其中 `i` 為 0 到 4）*

```text
+----------------+--------------+----------------+--------------+----------------+--------------+
|Segment 0 (Head)|Gap 0 (Intact)|Segment 1 (Mid) |Gap 1 (Intact)|Segment 2 (End) |Footer (588 B)|
|  [Encrypted]   |  [Raw Data]  |  [Encrypted]   |  [Raw Data]  |  [Encrypted]   |  [AES Meta]  |
+----------------+--------------+----------------+--------------+----------------+--------------+
^                ^              ^                ^              ^                ^              ^
0             Length        Offset_1       Offset_1+Len     Offset_2         origSize         EOF
```

* **分段 0（頭部 Segment 0）**：`0` ～ `Length`，受 ChaCha8 演算法加密。
* **間隙 0（原始數據 Gap 0）**：`Length` ～ `Offset_1`，**完全未受損**的原始數據。
* **分段 1（中部 Segment 1）**：`Offset_1` ～ `Offset_1 + Length`，受 ChaCha8 演算法加密。
* **間隙 1（原始數據 Gap 1）**：`Offset_1 + Length` ～ `Offset_2`，**完全未受損**的原始數據。
* **分段 2（尾部 Segment 2）**：`Offset_2` ～ `origSize`，受 ChaCha8 演算法加密。
* **Footer（588 位元組中繼區）**：`origSize` ～ `EOF`，包含 AES 加密的 Session Key 及原始元數據，原位修復完畢後調用 `ftruncate(origSize)` 直接從 inode 抹除。

#### 檔案尺寸分級加密行為與實戰案例對比

C3RB3R 會根據檔案大小動態選擇加密模式，以在「最快破壞時間」與「不可逆破壞」之間取得平衡：

| 檔案類型 | 尺寸規模 | 加密模式 | 實際破壞行為與實戰案例 |
| :--- | :--- | :--- | :--- |
| **小型檔案** | `< 1 MB`（設定檔、腳本、微型資料庫） | **模式 `0x24`（全量加密）** | **100% 全量覆蓋**。包括容器配置（`dockerd.json`、`.conf`）、系統授權 Token、SQLite 資料庫元數據等，從第 0 位元組至末尾全數加密。 |
| **中型檔案** | `1 MB ~ 10 MB` | **模式 `0x26`（前綴加密）** | **僅加密前 1 MB**。僅改寫檔案開頭的 1,048,576 位元組（`min(origSize, 1MB)`），摧毀檔案頭結構。 |
| **大型檔案** | `> 10 MB`（4K 影音、大資料庫、虛擬磁碟） | **模式 `0x25`（分段切片）** | **頭、中、尾離散切片（分散為 3 或 5 個受損區塊）**。實測詳情見下方實例。 |

##### 大型檔案分段計算實例（Mode `0x25`）：
* **實例 1：約 256 MB 實戰影音檔案（救災現場實錄，`Percent = 10%`，Factor = 4）**：
  * 單段長度：`Length = (255.9 MB / 100) * 4 ≈ 10.2 MB`
  * 實體佈局：
    * 分段 0（頭部）：`0` ～ `10.2 MB`（加密 10.2 MB）
    * 間隙 0（完好）：`10.2 MB` ～ `122.7 MB`（未加密原始數據約 112.5 MB）
    * 分段 1（中部）：`122.7 MB` ～ `132.9 MB`（加密 10.2 MB）
    * 間隙 1（完好）：`132.9 MB` ～ `245.4 MB`（未加密原始數據約 112.5 MB）
    * 分段 2（尾部）：`245.4 MB` ～ `255.9 MB`（加密 10.2 MB）
  * 受損數據總量：`3 * 10.2 MB ≈ 30.6 MB`（佔檔案約 12%）。
  * 完好原始數據：約 `225.3 MB`（高達 88% 的內容根本未被碰觸）。
  * *（註：這正是救災初期取證記錄中「大檔案受損約 10.2 MB」的真實物理來源——單個切片的長度剛好就是約 10.2 MB！）*
* **實例 2：50 GB 4K 超高碼率影音檔案（`Percent = 10%`，Factor = 4）**：
  * 單段長度：`Length = (50 GB / 100) * 4 = 2 GB`
  * 實體佈局：
    * 分段 0（頭部）：`0` ～ `2 GB`（加密 2 GB）
    * 間隙 0（完好）：`2 GB` ～ `24 GB`（未加密原始數據 22 GB）
    * 分段 1（中部）：`24 GB` ～ `26 GB`（加密 2 GB）
    * 間隙 1（完好）：`26 GB` ～ `48 GB`（未加密原始數據 22 GB）
    * 分段 2（尾部）：`48 GB` ～ `50 GB`（加密 2 GB）
  * 受損數據總量：`3 * 2 GB = 6 GB`（佔檔案 12%）。
  * 完好原始數據：**高達 44 GB 的未加密原始數據保持完好**（佔 88%）！
  * **原位解密（In-Place）的降維打擊**：社群傳統複製腳本需要 **50 GB 額外硬碟空間** 且需全盤搬運 50 GB；而 `inplace_restore` 僅在原檔案原地讀寫這 6 GB 受損塊並執行 `ftruncate` 截斷，**0 位元組額外開銷**，數秒內即可 100% 救回！

#### 原位解密（In-Place）比傳統複製快 100 倍且 0 額外空間的技術核心：
社群傳統工具（如 `decrypt_copy.py`）需要從頭到尾順序讀取整個幾十 GB 的檔案，把未受損的數據也完整複製到新檔案中，這在硬碟容量已滿時會直接引發 `ENOSPC`（磁碟空間不足）崩潰。

`inplace_restore` 的原位解密技術：
1. **離散分段原地覆寫**：利用底層系統調用 `f.ReadAt(chunk, Offset)` 與 `f.WriteAt(chunk, Offset)`，**精準只讀取並原地覆寫分段 0、1、2 這幾處受損塊**。
2. **未受損 Gap 零拷貝**：間隔 0 與間隔 1 中數十 GB 的原始數據在磁碟物理塊上**完全不動、零拷貝**。
3. **原子截斷**：所有受損分段修復完畢後，執行 `ftruncate(origSize)` 瞬間抹除檔案尾部 588 位元組的 Footer，還原真實大小。
4. **計數器嚴格連續**：跨分段保持 ChaCha8 流計數器單調遞增（`counter += (take + 63) / 64`），與病毒加密時的內部狀態完全吻合。
