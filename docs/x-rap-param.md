# `x-rap-param` 实现说明与扩展指南

本文档记录 `xhshow.RapParamSigner` 当前的实现策略，以及将来若需要在 payload 里
注入真实交互事件（鼠标/键盘/滚轮/焦点）时如何扩展。

适用 SDK 版本：**10201**（`mark = [7, 36, 1, salt_len]`）。

---

## 1. 目录索引

- [整体结构回顾](#2-整体结构回顾)
- [当前实现填了什么](#3-当前实现填了什么)
- [事件序列字段族说明](#4-事件序列字段族说明)
- [扩展事件支持的具体改动](#5-扩展事件支持的具体改动)
- [事件序列的合理性约束](#6-事件序列的合理性约束)
- [何时需要扩展](#7-何时需要扩展)

---

## 2. 整体结构回顾

`x-rap-param` 是一个 base64 字符串，解码后分两层：

```
outer (36 byte 固定包头 + 变长包体)
  [0:4]    mark = [7, 36, 1, salt_len]
  [4:8]    proto_version = 1
  [8:12]   key_len = 20
  [12:16]  cipher_len
  [16:20]  xxhash32(包体)
  [20:24]  sdk_version = 10201
  [24:28]  outer_cost_ms
  [28:36]  reserved (8 字节 0)
  [36 : 36+salt_len]                   salt
  [.. : .. + 16]                       AES-ECB(IV)
  [.. : .. + 4]                        [0,0,0,16]
  [.. : .. + cipher_len-4]             cipher
  [.. : .. + 4]                        gzip 前明文长度

inner plaintext (gzip 解压后的字节流)
  [0:4]    PAYLOAD_HEADER = [3, 232, 0, 0]   (= field 1000 + 长度占位)
  [4:10]   6 字节 BE 时间戳
  [10:12]  XOR_MARKER = [3, 233]
  [12:16]  xxhash32(xor_key_char)            BE
  [16:..]  字段流（XOR-decoded with xor_key）
```

字段流里**每个字段以 2 字节 BE field_id 开头**，长度由 field_id 决定。

---

## 3. 当前实现填了什么

### 3.1 真实计算的字段（不能简化）

| field_id | 含义 | 当前实现 |
|---|---|---|
| 1000 | Timestamp | `int(time.time() * 1000)`，6 字节 BE |
| 1001 | XorKeyVerify | 从 `0-9a-z` 随机抽 1 字符 → `xxhash32(char)` |
| 1002 | Uuid | 16 字符随机 alphanum，每次调用刷新 |
| 1003 | RequestHash | `xxhash32("//{host}{uri}{body}")` —— host 默认 `edith.xiaohongshu.com` |
| 1095 | PageLoadTime | signer **实例创建**时一次性算好（`now - random(10ms..30s)`），整个实例生命期内复用，模仿 JSVMP 模块初始化时间戳 |
| 1091 | SignCostTime | `[const4=4, cost_ms=随机8..14, 0xFFFF]` 共 8 字节 |
| outer body xxhash | — | 外层 36 字节后整段做 xxhash32 |
| outer cost_ms | — | 随机 8-14 ms |
| AES IV | — | 16 字节随机 alphanum，AES-ECB 加密后写入 |
| salt | — | 4-6 字节随机 alphanum |
| gzip | — | pako 兼容（FLG=0, OS=3） |

### 3.2 硬编码常量字段

| field_id | 含义 | 写入字节 |
|---|---|---|
| 1051..1065 | 自动化检测器 V1（Phantomjs / Chromedriver / CDP / UndetectedCD / Playwright / Crawlee / Cef / Pupp / Selenium） | `flag = 0` |
| 1070 | BrowserUseV1 | `flag = 0` |
| 1066..1069 | DrissionRunV1 / AnonymousReadyStateV1 / DrissionAutomationV1 / V2 | `flag = 0` |
| 1100 | FieldAbnormal | 4 字节 0 |
| 1071 | isStealthV1 | `flag = 0` |
| 1072 | isCodeBeautify | `flag = 0` |
| 1073 | stealthJs | `flag = 0` |
| 1078 | MouseData | 4 字节 0（无事件） |
| 1082 | TouchData | 4 字节 0 |
| 1084 | KeyboardData | 4 字节 0 |
| 1088 | WheelData | 4 字节 0 |
| 1090 | FocusData | 4 字节 0 |
| 1092 | InnerWidth | `RapParamConfig.DEFAULT_INNER_WIDTH = 1920` |
| 1094 | InnerHeight | `RapParamConfig.DEFAULT_INNER_HEIGHT = 1080` |
| 1093 | reserved | 4 字节 0 |
| 1151..1156 | HpClick events | `flag = 0` |

**当前 payload 固定为 205 字节**（无任何交互事件）。

### 3.3 没有写入的字段

以下字段在 SDK 10201 下**只在有真实事件时才出现**，当前实现一律省略：

| field_id | 含义 | 配对的 *Data 字段 |
|---|---|---|
| 1077 | MouseBaseTime | 1078 MouseData |
| 1081 | TouchBaseTime | 1082 TouchData |
| 1083 | KeyboardBaseTime | 1084 KeyboardData |
| 1087 | WheelBaseTime | 1088 WheelData |
| 1089 | FocusBaseTime | 1090 FocusData |

---

## 4. 事件序列字段族说明

每一对 `*BaseTime` + `*Data` 实际编码格式如下（以鼠标为例，焦点等同构）：

### 4.1 BaseTime 字段（10 字节）

```
[2 bytes] field_id BE  (例如 1077 = [4, 53])
[2 bytes] padding 0x00 0x00
[6 bytes] base_timestamp_ms BE
```

`base_timestamp_ms` 是**第一条事件**的绝对时间戳，后续事件用相对它的 `delta_ms`
节省字节。

### 4.2 Data 字段（变长）

```
[2 bytes] field_id BE
[4 bytes] random_seed BE  (rand_uint32, 仅作扰动)
[N × 3 bytes] events: 每条事件 = [flag_u8, delta_ms_BE16]
```

每条事件 3 字节：

- `flag` (1 字节): 事件类型/状态。FocusData 见过 `0x01 = focus_in`，`0x00 = focus_out`；
  其它事件族的 flag 编码在抓到更多样本前**未知**，建议先按真实抓包样本回放。
- `delta_ms` (2 字节 BE): `event_ts - base_timestamp_ms`，限制在 0..0xFFFF（最大 65.5 秒）。
  超过 65.5 秒的事件需要切到下一个 BaseTime 段。

### 4.3 解析时如何切割 *Data

由于 *Data 字段长度未声明（无 length 前缀），解码侧必须**前探**：从 `Data` 起每读
3 字节就检查后续 2 字节能否解码出**已知** field_id；能解出则停止读 *Data，否则
继续读 3 字节。

参考实现：`claude_own/x_rap_param/decode_real_sample.py:_walk_fields` 的 `DATA_PAIR`
分支。

### 4.4 真实抓包对照

来自第二次会话给的真实样本（`outer_cost=1235ms` 的那条）：

```
fid=1089 FocusBaseTime    base_ts = 1778122019330 (19:46:59.330)
fid=1090 FocusData        rand=9 events=3:
  event #0: flag=0x01 dt=+0ms     ts=1778122019330  ← focus in
  event #1: flag=0x00 dt=+1554ms  ts=1778122020884  ← focus out
  event #2: flag=0x01 dt=+2482ms  ts=1778122021812  ← focus in
```

---

## 5. 扩展事件支持的具体改动

下面给出"加入事件支持"时的最小改动建议。当前实现**没有**这些代码。

### 5.1 数据结构

```python
# src/xhshow/core/x_rap.py

from dataclasses import dataclass
from typing import Literal

EventKind = Literal["mouse", "touch", "keyboard", "wheel", "focus"]

@dataclass(frozen=True)
class InteractionEvent:
    """A single user interaction event."""
    kind: EventKind          # which *Data family this belongs to
    flag: int                # 0..255, semantics depend on kind
    timestamp_ms: int        # absolute Unix ms
```

### 5.2 字段 ID 映射

```python
_BASE_TIME_FID = {
    "mouse":    1077,
    "touch":    1081,
    "keyboard": 1083,
    "wheel":    1087,
    "focus":    1089,
}
_DATA_FID = {
    "mouse":    1078,
    "touch":    1082,
    "keyboard": 1084,
    "wheel":    1088,
    "focus":    1090,
}
```

### 5.3 编码函数

```python
def _encode_event_pair(
    kind: EventKind, events: list[InteractionEvent], rng: random.Random,
) -> tuple[bytes, bytes]:
    """Return (base_time_block, data_block) — both already field-id-prefixed,
    NOT yet xor-encoded. Caller is responsible for XOR-with-key.

    If `events` is empty, returns (b"", data_block_with_zero_payload) so the
    Data field still appears (4-byte zero) but no BaseTime is emitted —
    matching the no-interaction layout.
    """
    if not events:
        data_block = _be(_DATA_FID[kind], 2) + b"\x00\x00\x00\x00"
        return b"", data_block

    sorted_events = sorted(events, key=lambda e: e.timestamp_ms)
    base_ts = sorted_events[0].timestamp_ms

    # BaseTime field: 10 bytes total
    base_block = _be(_BASE_TIME_FID[kind], 2) + b"\x00\x00" + _be(base_ts, 6)

    # Data field: 2-byte fid + 4-byte random + N × 3-byte events
    seed = rng.randint(1, 100)
    body = bytearray(_be(seed, 4))
    for ev in sorted_events:
        delta = ev.timestamp_ms - base_ts
        if not 0 <= delta <= 0xFFFF:
            raise ValueError(
                f"event delta {delta}ms exceeds 65.5s — split into a new BaseTime segment"
            )
        body.append(ev.flag & 0xFF)
        body.append((delta >> 8) & 0xFF)
        body.append(delta & 0xFF)
    data_block = _be(_DATA_FID[kind], 2) + bytes(body)
    return base_block, data_block
```

### 5.4 公共 API 改动

```python
class RapParamSigner:
    def sign(
        self,
        method: ...,
        uri: ...,
        payload: ...,
        *,
        host: str | None = None,
        timestamp: float | None = None,
        page_load_timestamp_ms: int | None = None,
        events: list[InteractionEvent] | None = None,   # NEW
    ) -> str:
        ...
```

`_build_payload` 内部按字段流插入顺序处理：

```python
events = events or []
by_kind: dict[EventKind, list[InteractionEvent]] = {k: [] for k in _DATA_FID}
for ev in events:
    by_kind[ev.kind].append(ev)

# 插入顺序：MouseBaseTime/MouseData → Touch... → Keyboard... → Wheel... → Focus...
# 仅当对应 events 非空时插入 BaseTime；Data 无论是否有事件都要插入
order: list[EventKind] = ["mouse", "touch", "keyboard", "wheel", "focus"]
for kind in order:
    base_block, data_block = _encode_event_pair(kind, by_kind[kind], self._rng)
    body += _xor_bytes(base_block, xk)   # 只在有事件时非空
    body += _xor_bytes(data_block, xk)
```

### 5.5 测试新增建议

- 全空：`events=None` → 输出长度仍为 205 字节，与现有实现一致。
- 单 focus 事件：检查 1089 BaseTime 出现，1090 Data 含 1 条 3 字节事件。
- 跨域 delta：构造一条 delta=70_000ms 的事件，应抛 ValueError。
- 抓包回放：用真实样本里的 events 列表（base_ts=19:46:59.330 + 3 条 focus）作为
  fixture，编码后比较得到的 `[1089...1090...]` 字节段是否完全一致。

---

## 6. 事件序列的合理性约束

将来注入伪造事件时，**最容易翻车的是"事件不像真人"**。即使字节格式对，服务端
若有时间分布异常检测（如机器学习模型）依然可能拒绝。需要遵守：

| 维度 | 真人特征 | 风险阈值 |
|---|---|---|
| 事件总数 | 一次签名前 5-30 条 | < 3 条或 > 200 条都奇怪 |
| 事件间隔 | 鼠标移动 16-50ms，键盘键间 80-300ms | < 10ms 太机器 |
| Mouse 轨迹 | 连续坐标，加速度有变化 | 直线 / 等距点必死 |
| Focus 模式 | 偶尔 in/out，不会高频切换 | 1 秒内 > 3 次切换异常 |
| BaseTime 与 Inner Timestamp 关系 | BaseTime ≤ Inner ts，差值 < 30 秒 | 反过来或差值过大异常 |
| Data field rand 字段 | 真实 JSVMP 用某种伪随机源 | 用 `random.Random(seed)` 可能可被识别，用 `secrets` 或系统熵更好 |

**经验建议**：除非有特定接口必须带事件，否则**保持当前空实现**。一旦伪造事件
容易引入额外检测面，且发现问题难以归因。

---

## 7. 何时需要扩展

到目前为止已知的接口表现：

| 接口 | 是否需要 x-rap-param | 是否对事件序列敏感 |
|---|---|---|
| `/api/sns/web/v1/feed` | **是**（feed_test.py 已验证 200 + 数据） | 否（空 events 工作） |
| `/api/sns/web/v1/search/notes` | 否（seach_test.py 显示加不加都 200） | 不适用 |
| `/api/sns/web/v1/homefeed` | 未在本仓库验证，参考已有协议应类似 feed | 未知 |
| 写操作（`/like`、`/comment/post` 等） | **未验证** | **未知，可能要求事件** |

**触发扩展工作的信号**：

1. 某个新接口稳定返回非 200 / 业务错误码（例如 `461`、`406`），且检查发现去掉
   x-rap-param 一切正常，加上 x-rap-param 反而失败 —— 说明服务端对 events 有最
   小数量校验。
2. 某接口接受签名但**结果质量降级**（命中数为 0 / 字段被脱敏） —— 说明服务端识
   别为"无人在场"做了静默降权，需要伪造 events 提升可信度。
3. JSVMP 升级（mark[3] 之外的字节、sdk_version、字段 ID 变化）。届时优先用
   `claude_own/x_rap_param/decode_real_sample.py` 解新抓包，对照本文档第 4 节确
   认 BaseTime/Data 编码是否仍兼容。

如果只是 cookies 过期，不要先怀疑事件层 —— 先换账号。
