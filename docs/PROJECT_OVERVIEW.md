# PQ-PAKE-TLS 项目简介

## 1. 项目目标

本项目实现并评估一个基于后量子 KEM 与口令认证机制的 `PQ-PAKE-TLS` 协议原型，并提供：

- 基础 KEM/PAKE 性能基准
- 协议分阶段性能分析
- 客户端/服务端运行程序
- 与传统 TLS1.3（ECDHE）的对比实验

当前主实验口径：

- `Init（注册阶段处理） + Stage1 + Stage2 + Stage3 + Stage4`
- 其中 Stage1~4 对应论文中的握手四阶段

---

## 2. 主要运行入口

- `go run ./cmd/bench`：基础 PAKE 基准
- `go run ./cmd/protocolbench`：`pqtls` 版本分阶段基准
- `go run ./cmd/pqtlsdemo`：`pqtls` 单次演示
- `go run ./cmd/tlspake-server`：PQ-PAKE-TLS 服务端
- `go run ./cmd/tlspake-client`：PQ-PAKE-TLS 客户端
- `go run ./cmd/tlspakebench`：PQ-PAKE-TLS 分阶段/通信/内存/完整性基准
- `go run ./cmd/tlscompare`：与传统 TLS1.3 对比

---

## 3. 核心模块说明

- `kemchcca/`：服务器侧 KEM（ML-KEM-768）封装
- `kempca/`：客户端侧口令派生 PKE->KEM 封装
- `pake/`：基础 PAKE 逻辑（非网络版）
- `pqtls/`：早期协议化实现（实验用）
- `tlspake/`：当前主协议实现（网络交互 + 分阶段计时）
- `sha3/`：本地 SHA3/SHAKE 实现
- `kyber/`：本地 Kyber 底层实现与代码生成模板

---

## 4. 每个 Go 文件的主要内容

### 4.1 命令行程序（`cmd/`）

- `cmd/bench/main.go`：基础 PAKE 总体基准，输出 `results.csv/.tex` 和柱状图 `barplot.tex`
- `cmd/protocolbench/main.go`：`pqtls` 协议分阶段、内存、通信统计
- `cmd/pqtlsdemo/main.go`：运行一次 `pqtls` 会话并输出主密钥与指标
- `cmd/tlspake-server/main.go`：启动 PQ-PAKE-TLS 服务端，打印每会话阶段指标
- `cmd/tlspake-client/main.go`：启动 PQ-PAKE-TLS 客户端，支持篡改 `ClientFinished`
- `cmd/tlspakebench/main.go`：批量运行 PQ-PAKE-TLS，输出阶段时延、通信、内存与完整性检测率
- `cmd/tlscompare/main.go`：并行评测传统 TLS1.3 与 PQ-PAKE-TLS，生成对比 CSV 和 LaTeX 图

### 4.2 协议与KEM封装

- `tlspake/session.go`：PQ-PAKE-TLS 主实现（消息帧、Init+Stage1~4、计时、统计、完整性验证）
- `pqtls/protocol.go`：早期协议化实现（保留用于实验对照）
- `pake/pq_pake.go`：基础 PAKE 逻辑实现（无网络层）
- `kemchcca/mlkem768_chcca.go`：ML-KEM-768 的 KeyGen/Encap/Decap 封装
- `kempca/pw_kyberpke_kem.go`：口令派生 Kyber PKE->KEM 封装（客户端侧）

### 4.3 SHA3 模块（`sha3/`）

- `sha3/doc.go`：包说明
- `sha3/hashes.go`：SHA3 哈希接口与构造函数
- `sha3/keccakf.go`：Keccak-f 置换核心
- `sha3/rc.go`：轮常量
- `sha3/sha3.go`：SHA3 主要实现
- `sha3/shake.go`：SHAKE XOF 实现
- `sha3/xor.go`：XOR 选择入口
- `sha3/xor_generic.go`：通用 XOR 实现
- `sha3/xor_unaligned.go`：未对齐优化 XOR 实现
- `sha3/sha3_test.go`：SHA3/SHAKE 功能与性能测试

### 4.4 Kyber 顶层与模板（`kyber/`）

- `kyber/kyber.go`：Kyber 包顶层接口
- `kyber/gen.go`：代码生成入口
- `kyber/templates/pkg.templ.go`：生成包模板
- `kyber/templates/params.templ.go`：参数模板

### 4.5 Kyber768 实现（`kyber/kyber768/`）

- `kyber/kyber768/params.go`：Kyber768 参数定义
- `kyber/kyber768/vec.go`：向量操作
- `kyber/kyber768/mat.go`：矩阵相关操作
- `kyber/kyber768/kyber.go`：Kyber768 方案接口
- `kyber/kyber768/cpapke.go`：CPA-PKE 核心实现
- `kyber/kyber768/cpapke_test.go`：CPA-PKE 测试

### 4.6 Kyber 公共组件（`kyber/common/`）

- `kyber/common/params.go`：公共参数
- `kyber/common/generic.go`：通用实现入口
- `kyber/common/field.go`：有限域运算
- `kyber/common/poly.go`：多项式运算
- `kyber/common/ntt.go`：NTT 变换
- `kyber/common/sample.go`：采样函数
- `kyber/common/amd64.go`：amd64 平台优化入口
- `kyber/common/arm64.go`：arm64 平台优化入口
- `kyber/common/stubs_amd64.go`：amd64 stub
- `kyber/common/field_test.go`：field 测试
- `kyber/common/poly_test.go`：poly 测试
- `kyber/common/ntt_test.go`：NTT 测试
- `kyber/common/sample_test.go`：采样测试
- `kyber/common/params/params.go`：公共参数子包
- `kyber/common/asm/src.go`：汇编代码生成辅助

---

## 5. 输出文件说明（`out/`）

- `results.csv/results.tex/barplot.tex`：基础 PAKE 基准输出
- `protocolbench.csv`：`pqtls` 分阶段基准
- `tlspakebench.csv`：PQ-PAKE-TLS 分阶段基准与完整性检测
- `tls_compare.csv`：TLS1.3 vs PQ-PAKE-TLS 对比数据
- `tls_compare_barplot.tex`：对比图 LaTeX 代码

---

## 6. 开发与维护建议

- 协议主逻辑优先查看：`tlspake/session.go`
- 论文数据主入口：`cmd/tlspakebench/main.go` 与 `cmd/tlscompare/main.go`
- 若修改消息流程，请同步更新：
  - `tlspake/session.go`
  - `cmd/tlspakebench/main.go`
  - `cmd/tlscompare/main.go`
  - `README.md` 与论文中的实验口径描述
