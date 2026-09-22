# Forensic PKI Adjudication Service（隔离网络离线 PKI 取证裁决服务）

纯后端服务，面向隔离网络中的数字取证团队。团队把在**不同时间**归档的证书、
交叉签发证书、完整 CRL、delta CRL 和 OCSP 响应上传到不可变的“证据集”，
服务对“某制品在 `signed_at` 时刻是否由某叶证书在给定信任锚与策略下有效签署”
作出**可独立复核**的密码学裁决。

服务**不访问网络**补取任何证书或撤销信息，**不把系统当前时间**混入裁决结果，
没有任何前端，也不内置任何测试夹具指纹。

---

## 1. 快速开始（克隆后仅依赖 Docker）

```bash
# 构建并启动两个共享同一持久化卷的 API 实例（宿主端口由 API_PORT 控制）
export API_PORT=8080
docker compose build
docker compose up -d api1 api2

# 运行一次性验收服务（容器名 verify），跑完即退出
docker compose run --build verify
# 期望最后一行：acceptance: 14/14 passed
```

- 健康检查：`curl -fsS http://127.0.0.1:${API_PORT}/healthz`
- 两个实例 `api1`/`api2` 挂载**同一个命名卷** `forensic-data`，
  用于验证跨实例并发、封存与幂等语义。
- 数据、SQLite WAL 与证据包都写入持久化卷 `/data`。

不使用 Docker 的本地方式（需要 Python 3.11）：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest
DATA_DIR=./data API_PORT=8091 python -m app.main          # 实例1
DATA_DIR=./data API_PORT=8092 python -m app.main          # 实例2（另一个终端）
API1_URL=http://127.0.0.1:8091 API2_URL=http://127.0.0.1:8092 \
    python acceptance/run_acceptance.py
python -m pytest -q
```

---

## 2. 版本化 HTTP API

所有路径以 `/api/v1` 前缀。所有请求/响应体均为规范 JSON（见 §6）。
变更类请求必须带 `client_request_id`（或 `Idempotency-Key` 头）。

| 方法 | 路径 | 说明 |
|-----|------|------|
| POST | `/api/v1/evidence-sets` | 创建证据集（幂等） |
| POST | `/api/v1/evidence-sets/{id}/items` | 批量加入 DER 证书 / 完整 CRL / delta CRL / OCSP |
| POST | `/api/v1/evidence-sets/{id}/seal` | 原子封存；封存后不可变 |
| GET  | `/api/v1/evidence-sets/{id}` | 读取状态与内容摘要 |
| POST | `/api/v1/evidence-sets/{id}/adjudications` | 提交裁决请求（幂等） |
| GET  | `/api/v1/evidence-sets/{id}/adjudications/{adj_id}` | 读取裁决 |
| GET  | `/api/v1/evidence-sets/{id}/packages/{adj_id}` | 下载 ZIP 证据包 |
| GET  | `/healthz` | 健康检查 |

### 上传条目

```jsonc
POST /api/v1/evidence-sets/{id}/items
{
  "client_request_id": "batch-2024-05-01-01",
  "received_at": "2024-05-01T09:00:00Z",   // 取证方实际掌握该证据的时间
  "items": [
    {"client_ref": "leaf-001", "type": "certificate", "content_base64": "MIID..."},
    {"client_ref": "crl-007",  "type": "crl",         "content_hex": "3082..."},
    {"client_ref": "ocsp-003", "type": "ocsp",        "content_base64": "..."}
  ]
}
```

- 内容用 `content_base64`（标准 base64）或 `content_hex` 提供，二者皆可。
- `received_at` 是**取证元数据**（证据归档/掌握时刻），由客户端提供；
  服务端时钟不影响任何裁决。
- 相同 `client_ref` + 相同规范化内容重试 → 返回原结果；
  相同 `client_ref` + **不同**内容 → `409 CONFLICT`。

### 裁决请求

```jsonc
POST /api/v1/evidence-sets/{id}/adjudications
{
  "client_request_id": "adj-0001",
  "artifact_digest": "<hex 或 base64 的制品摘要>",
  "signature": "<制品原始签名>",
  "signature_algorithm": "1.2.840.10045.4.3.2",      // ECDSA-P256-SHA256
  "signed_at": "2023-11-14T22:13:20Z",
  "knowledge_cutoff": "2023-12-01T00:00:00Z",
  "leaf_certificate_sha256": "<64 hex>",
  "initial_policies": ["2.5.29.32.0"],
  "trust_anchors": ["<64 hex 锚证书 DER sha256>"]
}
```

`adjudication_id` 等于规范化裁决请求的 SHA-256。裁决固定到封存集的
`content_digest`；裁决期间其他上传/封存不可能混入（封存集不可变）。

---

## 3. 支持的 RFC 5280 配置文件（profile v1）

不在配置文件内的编码或算法一律返回结构化 `422`，错误体
`{"error":{"code":"UNSUPPORTED", ...}}`，**绝不降级接受**。

### 3.1 公钥与签名算法

| 类别 | 接受 |
|------|------|
| 证书 / CRL / OCSP 签名 | RSASSA-PSS（SHA-256/384/512，MGF1 同哈希、salt 长度=摘要长度、trailer=1）；RSA PKCS#1 v1.5（SHA-256/384/512）；ECDSA P-256（SHA-256/384/512）；纯 Ed25519 |
| 公钥 | RSA 2048/3072/4096；EC **仅 P-256**（secp256r1）；Ed25519 |
| 哈希 | SHA-256 / SHA-384 / SHA-512（OCSP certID 另允许 SHA-1） |
| 证书版本 | 仅 X.509 v3 |
| 时间编码 | UTCTime `YYMMDDHHMMSSZ`（1950–2049）或 GeneralizedTime `YYYYMMDDHHMMSSZ`，秒级、无小数、必须 `Z` |

制品签名同样真实校验：PKCS#1 v1.5 按 RFC 8017 校验 DER `DigestInfo`；
RSA-PSS/ECDSA 校验预哈希（prehashed）摘要；Ed25519 校验 SHA-512 摘要。

### 3.2 必做的层级与扩展校验

- **Basic Constraints**：CA 必须 `cA=true`（扩展必须 critical）；
  `pathLenConstraint` 按 RFC 5280 逐跳计数（自签发证书不占层数）。
- **Key Usage**：签发证书需 `keyCertSign`；签发 CRL 需 `cRLSign`；
  叶证书需 `digitalSignature`。
- **Extended Key Usage**：叶证书必须含 `id-kp-codeSigning (1.3.6.1.5.5.7.3.3)`；
  任一 CA 若带 EKU 也必须包含 codeSigning。
- **Name Constraints**：支持 DNS 与 URI（仅这两类 GeneralName，ASCII、
  大小写不敏感）。permitted/excluded 子树按 RFC 5280 对叶的 SAN
  （无 SAN 时回退 subject CN）逐跳应用；URI 约束匹配其 host 组件。
  其它 GeneralName 类型（email、IP、directoryName 等）→ `UNSUPPORTED`。
- **证书策略**：完整实现 RFC 5280 §6.1.x 策略树：
  - `certificatePolicies` 逐层交集；
  - `anyPolicy (2.5.29.32.0)` 及其经 `inhibitAnyPolicy` 的逐层抑制；
  - `policyMappings`（issuer→subject）在 `inhibitPolicyMapping` 未生效时
    逐层传播，生效时禁止；映射不允许涉及 anyPolicy；
  - `requireExplicitPolicy` / `policyConstraints` /
    `inhibitAnyPolicy` 计数器按 RFC 顺序（匹配→递减→采纳本证书扩展）；
  - 最终与请求的 `initial_policies` 做 wrap-up 交集。
- **撤销证据自身**：CRL/OCSP 的 TBS 签名都用证据集内真实签发者公钥校验，
  从不相信证据里自述的字段。

---

## 4. 双时间轴口径（关键语义）

存在两条相互独立的时间轴：

- `signed_at`：制品被声称签署的**历史时刻**；
- `knowledge_cutoff`：取证方“当时已经掌握证据”的**知识截止时刻**。

规则：

1. 每份证据上传时带不可变的 `received_at`。只有
   `received_at <= knowledge_cutoff` 的证据**可被采用**；
   事后才归档的响应无法冒充当时已知信息（在 `considered_evidence` 中记为
   `not_received_by_knowledge_cutoff`）。
2. **撤销结论以 `signed_at` 判断**，绝不用 `knowledge_cutoff` 或服务器时间。
3. 证明“清白/GOOD”的证据（无撤销条目的 CRL、GOOD 的 OCSP）必须在
   `signed_at` 时刻处于有效期窗口：`this_update <= signed_at <= next_update`。
4. 记录“撤销事件”的证据是**档案性记录**：OCSP/CRL 条目的
   `revocation_date <= signed_at` 时，即使该响应**产生于** `signed_at` 之后，
   只要它在 `knowledge_cutoff` 前已被掌握，仍必须影响历史裁决（REVOKED）。
5. 撤销事件晚于 `signed_at` 的 REVOKED 响应，在该时刻按 GOOD 处理。
6. 时间窗口已过期、无法在 `signed_at` 证明有效的撤销材料给出 `STALE`。

撤销结论取值：`GOOD` / `REVOKED` / `UNKNOWN` / `STALE` /
`MALFORMED_EVIDENCE`。每一份被考虑的证据都会在结果中记录
**采用（USED）或排除原因**（未在截止前收到、签名/签发者未验证、
certID 不匹配、scope 不符、窗口过期等）。

### 4.1 CRL / delta CRL 合并规则

- delta CRL 只能与满足**全部**相容性条件的完整 CRL 合并：
  相同 issuer、相同 AKI、相同 IDP 分发点（URI）、
  base 的 `cRLNumber == delta 的 baseCRLNumber`，且 delta 编号更大；
  同一 base 取编号最大（并列取指纹最小）的 delta。
- 合并时支持 `removeFromCRL`：delta 中的该 reason 条目删除 base 撤销项。
- `onlyContainsUserCerts` / `onlyContainsCACerts` 与证书角色匹配；
  indirect CRL、`onlySomeReasons` 分区、属性证书 CRL 均在配置外 →
  `UNSUPPORTED`。

### 4.2 OCSP 规则

- certID 用签发者 Name DER 与 SubjectPublicKey 位串**重新计算**
  nameHash/keyHash（支持 SHA-1/256/384/512），密码学比对序列号。
- 直接 CA 响应：必须由签发该证书的 CA 私钥签署。
- 委托响应者：内嵌响应者证书必须链到该 CA、含 `id-kp-OCSPSigning`、
  非 CA、具备 `digitalSignature`、在 `signed_at` 有效
  （或带 `id-pk-OCSP-nocheck`），响应 TBS 再用其公钥真实验签。

### 4.3 证据选择（确定性）

在所有**可采用且验签通过、范围匹配**的决定性证据中：

1. 取“生成时刻”最新者（OCSP 取 `thisUpdate`，CRL/delta 组合取
   delta 的 `thisUpdate`/`lastUpdate`，否则 base）；
2. 并列时优先 OCSP，再其次按证据 SHA-256 指纹升序。

---

## 5. 证书图、路径构建与决胜

- 节点 = 不同 DER（以 SHA-256 为身份）；交叉签发、重复对象、图环都是
  图的自然组成。子→父边要求 issuer DN/AKI 身份匹配**且**真实签名验证通过。
- 路径搜索在**整图**上进行（迭代加深：先最短证书数，再按
  叶→根指纹序列字典序），但**不会先固定最短链再查撤销**：
  每条到达锚的完整路径都要同时通过密码学、层级、pathLen、名称约束、
  策略、EKU 和**双时态撤销**裁决。
- 环用“路径上集合”阻断；不枚举所有简单路径。
- 规模友好：按主体名建桶（封存时用零密码学解析从 DER 抽取 Name 建索引），
  裁决时**惰性解析**证书——100k 张无关证书的图中裁决少量叶证书，
  不会反复全量解析 DER。
- 多路径唯一决胜：**证书数最少；并列取叶→根 DER SHA-256 指纹序列字典序最小**。
- 无有效路径时返回**覆盖所有可达候选分支**的拒绝证明：
  包含每张涉及证书的指纹、父子边，以及每条边/每条完整候选路径的
  **首个失败规则**（`SIGNATURE`/`VALIDITY`/`BASIC_CONSTRAINTS`/`KEY_USAGE`/
  `PATH_LEN`/`NAME_CONSTRAINTS`/`POLICY`/`EKU`/`REVOCATION`/`LOOP`/
  `NO_PATH_TO_ANCHOR` …），而不是只返回最后尝试的一条链。

---

## 6. 规范化与逐字节确定性

- 所有结果/证据包 JSON 使用项目内置的规范 JSON（RFC 8785 风格）：
  UTF-8、对象键按 UTF-16 码元排序、无空白、整数精确保留、无浮点。
- 证据集内容摘要、裁决请求摘要、`final_digest` 都基于规范 JSON 的 SHA-256。
- 相同证据、相同业务输入与配置，在不同 API 实例、不同上传顺序、
  进程重启后产生**逐字节一致**的结果与证据包摘要。
- 容错：持久化成功但响应丢失后，用相同 `client_request_id` 重试，
  返回首次持久化的原响应（字节一致）；相同标识不同内容 → `409`。

---

## 7. 证据包与离线复核

`GET .../packages/{adj_id}` 得到确定性 ZIP（成员固定顺序、时间戳固定为
1980-01-01），包含：

- `result.json`：完整裁决（规范 JSON）；
- `request.json`：规范化裁决输入；
- `manifest.json`：封存证据集内容摘要与 `content_digest`；
- `package-manifest.json`：每个成员的 SHA-256/长度清单；
- `der/certificates|crls|ocsps/<sha256>.der`：路径/拒绝证明/策略与撤销
  实际引用的全部原始 DER，以及该封存集的**全部** CRL/OCSP（≤2000）；
- 裁决中还含逐规则中间结论（rules）、逐层策略 trace、每个证书的撤销
  采用/排除记录、路径搜索边、所选路径或完整拒绝证明、`summary` 与
  `final_digest`。

离线复核（不访问服务、数据库或网络，仅读 ZIP）：

```bash
python -m verify path/to/<adjudication_id>.zip          # 人读
python -m verify path/to/<adjudication_id>.zip --json   # 机器读
```

复核器会：重新计算成员哈希与证据集内容摘要；用包内 DER **重建证书图并
重跑同一裁决核心**（真实签名、层级/名称/策略、双时态撤销、证据选择）；
把重算结果与 `result.json` **逐字节**比对；并核对 `final_digest`。
篡改任一输入 DER、规则结论或最终状态，都会改变哈希或重算结果，从而失败
——它不只比较服务预先写入的哈希。

---

## 8. 资源上限（单个封存集）

| 资源 | 上限 |
|------|------|
| 证书 | 100,000 |
| CRL + OCSP 证据 | 2,000 |
| 撤销条目合计（base/delta CRL 条目） | 1,000,000 |
| 单次上传批量条目 | 10,000 |
| 单个 DER/OCSP 对象 | 8 MiB |

超限时封存返回结构化 `409 CONFLICT`（带 limit/max/actual）。

---

## 9. 持久化与并发

- SQLite（WAL，`synchronous=FULL`，`busy_timeout=60s`）+ 内容寻址 blob 文件
  （临时文件 + `fsync` + 原子 rename）。
- 所有状态变更在 `BEGIN IMMEDIATE` 事务内完成；两个实例/两个线程同时封存
  只会得到同一份不可变清单。
- 幂等表以 `(scope, client_request_id)` 为主键，记录规范化摘要与响应；
  裁决另以规范化请求摘要内容寻址去重。

---

## 10. 目录结构

```
app/                 服务
  api.py             版本化 HTTP API（FastAPI）
  main.py            uvicorn 入口
  storage.py         SQLite + blob 持久化、幂等、封存
  certmodel.py       DER 证书解析、profile、真实签名/PSS 校验
  evidence.py        CRL/OCSP 解析与签名校验、certID
  der.py             最小 DER 读/写与 OID、policyMappings 解析
  graph.py           证书图（边/签名记忆化）
  pathfinder.py      整图路径构建、决胜、拒绝证明
  chain.py           pathLen/名称约束/EKU/RFC5280 策略树
  revocation.py      双时态撤销引擎、base/delta 合并、OCSP 授权
  adjudge.py        裁决编排与规范化（存储无关核心 run_core）
  loader.py          封存集惰性装载
  package.py         确定性证据包构建
  canonical.py       规范 JSON
  timeutil.py        时间解析/格式化
verify/              离线复核器（python -m verify）
acceptance/          一次性验收服务（compose 服务 verify）
tests/               单元/端到端/并发/性能测试与运行时 PKI 夹具工厂
Dockerfile, docker-compose.yml
```

## 11. 测试

```bash
pip install pytest && python -m pytest -q                     # 除性能外全部
python -m pytest tests/test_perf.py -q                        # 100k 证书/图环
```

测试在运行时用真实密码学生成全部证书/CRL/OCSP（RSA/EC/Ed25519），
业务逻辑中不包含任何夹具指纹，也没有任何固定响应或对在线 PKI 的依赖。
