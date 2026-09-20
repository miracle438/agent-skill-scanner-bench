# agent-skill-scanner-bench

**Agent 技能扫描器对抗实测：28 个合成样本 × 7 个开源扫描器，三个没人给过的指标。**

对 7 个开源 Agent 技能（Claude Code Skills 等）扫描器做系统化对抗实测的数据集与样本工厂，度量：

| 指标 | 定义 | 本次结果 |
|---|---|---|
| 最小逃逸编辑距离 | 被捕获样本翻转为放行所需的最少字符编辑数 | HMA = **1**（`cur\l`）；Cisco = 20；NVIDIA 字符级未破；其余 4 家为 0 |
| 组合衰减率 | 1 − D(组合) / max(D(手法A), D(手法B)) | 平均 ≈ **0.25**，最高 0.50，且**非单调**（手法全叠反而更易被抓） |
| 运行时兜底率 | 静态放行样本被运行时防线拦截的比例 | 安装门实测 **0** |

其他一手发现：两家扫描器存在"检出引擎抓到 CRITICAL、最终裁决 SAFE"的层间脱节；某扫描器只扫 SKILL.md（File count: 1），对包内脚本结构性失明；社工话术对静态层零影响。

配套文章发布于奇安信攻防社区（链接待补）。

## 样本与扫描器

**28 道题**：11 个基线样本（X0 明文恶意基线 + S1-S7 单手法 + B1-B3 良性对照）、8 个逃逸变体（E1-E8）、9 个组合样本（C1-C8 + 全家桶 CFULL）。

单手法对齐腾讯朱雀 4 类绕过手法与 Adversa 攻击类：S1 同形字、S2 零宽字符、S3 编码变换、S4 输入截断利用、S5 文件类型盲区（.pyc/hook）、S6 源码与分发不一致、S7 社工话术。

被测扫描器：Cisco `skill-scanner`、NVIDIA `SkillSpector`、Mondoo `skillcheck`、`claude-skill-antivirus`、huifer `skill-security-scan`、`ai-skill-scanner`、`hackmyagent`（skillcop 因唯一引擎为本地 12B LLM、靶机内存不足，如实排除）。

## 免责声明 / 伦理边界

- 所有"恶意样本"均为**合成构造**：外联目标一律是 `127.0.0.1` 回环地址，"凭据"是标注 `SIMULATED` 的假数据，样本不具备真实攻击能力
- 未向任何技能市场、注册表、仓库提交过样本内容
- 本仓库仅供**防御研究**与扫描器厂商改进检测规则使用；请勿用于任何未授权测试
- 所有被测扫描器均以默认静态配置运行（LLM/联网增值层关闭），结论仅代表该口径

## 目录结构

```
├── factory/            # 样本工厂与矩阵 runner
│   ├── sample_factory.py   # 生成 11 个基线样本（X0/S1-S7/B1-B3）
│   ├── run_baseline.py     # 阶段一：基线矩阵（11 × 7）
│   ├── run_escape.py       # 阶段二：白盒逃逸变体 × 3 扫描器
│   └── run_combo.py        # 阶段三：组合矩阵（9 × 7）
├── samples/            # 11 个基线样本（每样本含 metadata.json 标注手法）
├── samples_combo/      # 9 个组合样本
├── escape/             # 8 个逃逸变体（E1-E8）
├── data/
│   ├── matrix.csv          # 阶段一基线矩阵（66 格）
│   ├── matrix_combo.csv    # 阶段三组合矩阵（54 格）
│   ├── escape.json         # 逃逸变体交叉结果 + 编辑距离
│   └── mondoo_status.csv   # Mondoo 哈希库查询结果（20/20 unknown）
└── README.md / LICENSE
```

## 复现

### 0. 环境

- Ubuntu 24.04 / Python 3.12
- Node ≥ 20.19（HMA 的依赖为纯 ESM，虽然它 engines 写的是 >=18）
- 7 个扫描器安装（均装在同一 BASE 目录下）：

| 扫描器 | 安装 |
|---|---|
| Cisco | `pip install cisco-ai-skill-scanner`（venv-cisco） |
| NVIDIA | `pip install ./scanners/SkillSpector`（venv-nvidia） |
| Mondoo | `npm install @mondoohq/skillcheck --prefix npm-global` |
| claude-av | 在其仓库内 `npm install` |
| huifer | `pip install -r scanners/skill-security-scan/requirements.txt`（venv-huifer） |
| ai-scan | `pip install -r scanners/ai-skill-scanner/requirements.txt`（venv-aiscan） |
| HMA | `npm install hackmyagent --ignore-scripts --prefix npm-hma`（见下方坑） |

### 已知环境坑（都是踩过的）

- HMA 的依赖 `onnxruntime-node` postinstall 会去微软 CDN 拉构建清单，国内网络收到 302 即抛错：`npm install --ignore-scripts` 可绕过，代价是 NanoMind 语义层不可用（静态引擎不受影响）
- HMA `engines` 标 `>=18.0.0`，实际依赖纯 ESM，Node 18 会 `ERR_REQUIRE_ESM`，用 Node 22
- GitHub 直连不稳定时，clone 走 `https://ghproxy.net/https://github.com/...` 前缀
- pip / npm 国内走清华源与 npmmirror

### 1-4. 跑通四阶段

```bash
# 1. 生成基线样本
python3 factory/sample_factory.py samples

# 2. 基线矩阵（需先按上表装好扫描器，目录结构见 factory 脚本头部 BASE 说明）
python3 factory/run_baseline.py .

# 3. 逃逸变体（需先跑 run_baseline 生成 X0，再由 run_escape 构造 E1-E8）
python3 factory/run_escape.py

# 4. 组合矩阵（脚本内含组合样本生成逻辑）
python3 factory/run_combo.py
```

## 数据

- `data/matrix.csv`：66 格基线矩阵，verdict 口径（用户最终看到的裁决，非引擎明细）
- `data/escape.json`：8 变体 × 3 扫描器交叉结果，含 Levenshtein 编辑距离与可执行性
- `data/matrix_combo.csv`：54 格组合矩阵
- `data/mondoo_status.csv`：Mondoo 哈希库查询，20 个样本全部 `unknown`

## 引用与致谢

- Adversa.AI — [A hole in every one: bypassing the open source AI skill scanners](https://adversa.ai/blog/agent-skill-scanners-bypass-eight-tested/)（2026-07-30）
- 腾讯朱雀实验室（联合港中深）— [SkillTrustBench：首个 Agent 技能安全评测基准](https://matrix.tencent.com/zh/2026/06/17/first-skill-trust-bench)（2026-06-17）
- Snyk — [ToxicSkills: malicious AI agent skills on ClawHub](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)（2026-02）
- 被测项目：[cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) · [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector) · [mondoohq/skillcheck](https://github.com/mondoohq/skillcheck) · [claude-world/claude-skill-antivirus](https://github.com/claude-world/claude-skill-antivirus) · [huifer/skill-security-scan](https://github.com/huifer/skill-security-scan) · [suchithnarayan/ai-skill-scanner](https://github.com/suchithnarayan/ai-skill-scanner) · [opena2a-org/hackmyagent](https://github.com/opena2a-org/hackmyagent)

## License

MIT
