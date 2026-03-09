# PQ-PAKE-TLS

本项目实现并评估基于 KEM 的 PQ-PAKE-TLS 协议，包含：

- 基础 KEM/PAKE 基准
- 协议分阶段性能评估
- 客户端/服务端独立程序
- 与传统 TLS1.3（ECDHE）对比实验

---

## 1. 环境要求

- Go: 1.24.x
- OS: Windows / Linux / macOS
- 依赖：
  - `github.com/cloudflare/circl`
  - `golang.org/x/crypto`

检查：

```powershell
go version
```

---

## 2. 项目结构

- `kemchcca/`：ML-KEM-768（OW-ChCCA 实例）
- `kempca/`：口令派生 Kyber768 PKE->KEM
- `pake/`：基础 PAKE 逻辑
- `tlspake/`：PQ-PAKE-TLS 核心实现（Init + Stage1~4）
- `cmd/bench/`：基础 PAKE 总体基准
- `cmd/protocolbench/`：分阶段协议基准（pqtls 版本）
- `cmd/pqtlsdemo/`：单次演示
- `cmd/tlspake-server/`：PQ-PAKE-TLS 服务端
- `cmd/tlspake-client/`：PQ-PAKE-TLS 客户端
- `cmd/tlspakebench/`：PQ-PAKE-TLS 基准（含完整性篡改检测）
- `cmd/tlscompare/`：PQ-PAKE-TLS 与传统 TLS1.3 对比
- `out/`：CSV/LaTeX 输出

---

## 3. 快速开始

```powershell
cd "C:\Users\34918\Golang_workplace\PQ-PAKE-TLS - 1"
```

### 3.1 基础 PAKE 基准

```powershell
go run ./cmd/bench -iters 1000 -pw "correct horse battery staple"
```

输出：

- `out/results.csv`
- `out/results.tex`
- `out/barplot.tex`

### 3.2 分阶段协议基准（pqtls）

```powershell
go run ./cmd/protocolbench -iters 2000 -pw "correct horse battery staple" -ctx "pqtls-transcript"
```

输出：

- `out/protocolbench.csv`

### 3.3 单次演示

```powershell
go run ./cmd/pqtlsdemo -pw "correct horse battery staple" -ctx "pqtls-transcript"
```

---

## 4. PQ-PAKE-TLS（当前主实现）

### 4.1 服务端 + 客户端手动运行

终端 A（服务端）：

```powershell
go run ./cmd/tlspake-server -addr 127.0.0.1:9443 -ctx "tls13-pq-pake"
```

终端 B（客户端，单次）：

```powershell
go run ./cmd/tlspake-client -addr 127.0.0.1:9443 -pw "correct horse battery staple" -n 1
```

完整性篡改测试（篡改 ClientFinished）：

```powershell
go run ./cmd/tlspake-client -addr 127.0.0.1:9443 -pw "correct horse battery staple" -n 1 -tamper_cf=true
```

### 4.2 一键基准（自动启动内置服务端）

```powershell
go run ./cmd/tlspakebench -iters 300 -integrity_trials 100
```

输出：

- `out/tlspakebench.csv`

CSV 关键字段：

- `client_init_us`, `client_stage1_us` ... `client_stage4_us`, `client_total_us`
- `server_init_us`, `server_stage1_us` ... `server_stage4_us`, `server_total_us`
- `registration_payload_bytes`, `online_payload_bytes`, `total_payload_bytes`
- `integrity_detection_rate_pct`

---

## 5. 与传统 TLS1.3 对比实验

```powershell
go run ./cmd/tlscompare -iters 300
```

输出：

- `out/tls_compare.csv`
- `out/tls_compare_barplot.tex`

说明：

- 基线：传统 TLS1.3（ECDHE）
- 本文方案：PQ-PAKE-TLS（Init + Stage1~4）
- 共享密钥生成对比口径：
  - 基线：TLS1.3 握手密钥协商阶段
  - 本文方案：`Stage1 + Stage2`

---

## 6. LaTeX 绘图

导言区：

```latex
\usepackage{pgfplots}
\pgfplotsset{compat=1.18}
```

插图：

```latex
\input{out/tls_compare_barplot.tex}
```

---

## 7. 常见问题

### Q1: 端口冲突（`Only one usage of each socket address...`）

- 关闭占用端口的旧进程
- 或使用自动端口：`-addr 127.0.0.1:0`

### Q2: CSV 文件被占用无法写入

- 关闭占用文件的软件（如 Excel/WPS）后重跑

### Q3: 客户端连接失败

- 确认服务端已启动
- 确认 `-addr` 一致

---

## 8. 推荐复现实验顺序

```powershell
go run ./cmd/bench -iters 1000 -pw "correct horse battery staple"
go run ./cmd/protocolbench -iters 2000 -pw "correct horse battery staple" -ctx "pqtls-transcript"
go run ./cmd/tlspakebench -iters 300 -integrity_trials 100
go run ./cmd/tlscompare -iters 300
```

完成后从 `out/` 目录读取 CSV 与 `.tex` 文件用于论文结果与绘图。
