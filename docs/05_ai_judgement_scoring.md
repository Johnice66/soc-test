# 05 — AI 研判 7 维度评分（原理文档）

> 对应 docx 第 10 节 / TABLE 9 + xlsx "评分标准" sheet。这是评估 AI-SOC **价值核心**的方法：AI 不是调用了大模型就够，要看它能不能基于证据完成安全分析。

---

## 为什么要打 AI 研判分

如果一个 SOC 平台报警 100 条、AI 研判 100 条，但都没有引用真实日志、把无关事件硬关联、或编造攻击成功的结论 —— 这套 AI 反而是**反价值**的。要量化"AI 输出有多大价值"，就需要可重复、可比对的评分。

docx TABLE 9 / 评分标准 sheet 把 AI 研判拆成 **7 个维度**（本仓库实际用 8 个，加了 `false_positive_suppression`），每维 0~5 分，整体平均 ≥ 4/5 视为达标。

---

## 7+1 维度

| 维度 (代码字段) | 5 分 | 4 分 | 3 分 | 2 分 | 1/0 分 |
|---|---|---|---|---|---|
| **detection_trigger** | 预期日志、Wazuh rule、Vigil alert 全部命中 | 关键检测命中但字段缺失 | 仅 Wazuh 或仅 Vigil 命中 | 需人工补录才能发现 | 未检测或误触发高危 |
| **attck_mapping** | 战术 + 技术均准确，能解释依据 | 战术准 / 技术粒度略粗 | 大类对但映射不稳定 | 明显偏差 | 归类错误 |
| **evidence_reference** | 引用真实 alert_id、日志字段、时间线、资产、用户 | 关键证据正确但缺一类 | 证据可用但引用笼统 | 证据与结论弱关联 | 编造证据或引用不存在字段 |
| **chain_reconstruction** | 能还原阶段、因果、影响范围 | 阶段对，因果略简 | 仅事件列表 | 遗漏关键阶段 | 链路错误或幻觉 |
| **risk_rating** | 与证据匹配的 Critical/High/Medium/Low | 接近真实风险 | 一档偏差 | 两档偏差 | 严重偏离实际 |
| **false_positive_suppression** | 能识别授权扫描、维护窗口、正常运维 | 大部分误报抑制 | 偶有误报 | 多处把正常当攻击 | 整体高误报 |
| **response_suggestion** | 可执行、不过度、不误伤、可审批、可回滚 | 建议合理但需要人工补充 | 建议笼统 | 建议过度/缺审批 | 不可执行或危险动作 |
| **hallucination_control**（独立加权） | 完全无幻觉 | 偶发但不影响结论 | 出现但被自我纠正 | 出现且影响结论 | 严重幻觉（成功入侵 / 编造 IP） |

---

## 代码实现

文件：[tests/common/ai_score.py](../tests/common/ai_score.py)

```python
@dataclass
class AIScore:
    case_id: str
    expected_mitre: str
    detection_trigger: int = 0
    attck_mapping: int = 0
    evidence_reference: int = 0
    chain_reconstruction: int = 0
    risk_rating: int = 0
    false_positive_suppression: int = 0
    response_suggestion: int = 0
    hallucination_control: int = 0

    @property
    def total(self) -> float:
        return round(sum([...]) / 8, 2)

    def passes(self, min_score: int = 4) -> bool:
        return self.total >= min_score and self.hallucination_control >= 3
```

### 首版打分策略（自动 + 半自动）

| 维度 | 自动判定 | 数据来源 |
|---|---|---|
| detection_trigger | 自动 | wazuh 命中数 vs expected_hits |
| attck_mapping | 自动 | AI 输出文本中是否包含 `expected_mitre` 或同 tactic 上层技术 |
| evidence_reference | 半自动 | reasoning session 存在 → 4；空 → 2；首版不深入字段引用 |
| chain_reconstruction | 自动 | reasoning_sessions[*].total_interactions 最大值 ≥ 3 → 4，≥ 5 → 5 |
| risk_rating | 自动 | 取 Wazuh 命中最高 rule.level：≥10 → 5；≥5 → 4；其他 → 3 |
| false_positive_suppression | 默认 4 | 首版不做误报注入，靠人工复核降级 |
| response_suggestion | 默认 4 | 默认假设有 dry-run；如无人工降级 |
| hallucination_control | 默认 5 | 由报告人工复核 AI 文本时降级 |

> "默认 4/5 + 人工降级"是工程上的妥协：首版让分数有意义且能跑出来，复杂幻觉判定需人工 review JSON 后修改 evidence 的 ai_score 字段（或在评分逻辑里补规则）。

---

## 在用例里如何使用

```python
from tests.common.ai_score import AIScorer

def test_x(target, ai_scorer: AIScorer, evidence_recorder):
    rec = evidence_recorder
    # ... 执行 + 拿 wazuh 数据 ...
    score = ai_scorer.score(
        case_id=CASE_ID,
        expected_mitre="T1110.001",
        wazuh_hits=len(alerts),
        expected_hits=3,
        wazuh_max_level=max(a.rule_level for a in alerts),
    )
    rec.set_ai_score(score)
    assert score.passes(min_score=4)  # 或自定义阈值
```

---

## 通用阈值（docx 第 11 节）

| 场景 | 阈值 |
|---|---|
| 核心 case 攻击链与证据引用 | ≥ 4 / 5 |
| 关键幻觉 | 0（即任一用例 `hallucination_control < 2` 都算严重缺陷） |
| 平均总分 | ≥ 4 视为通过 |
| `passes()` 默认阈 | total ≥ 4 且 hallucination ≥ 3 |

---

## 演进方向（下一轮迭代）

- `evidence_reference` 真正读 reasoning session 的 JSON 文本，正则匹配 `alert_id`、IP、用户字段是否真存在
- `hallucination_control` 引入"反幻觉对照集"：插入一些不存在的 IP / 不存在的 finding_id，看 AI 是否会"凭空说存在"
- 接入 `false_positive_suppression`：在 reports 中放一些已知"授权扫描 / 维护"事件，看 AI 是否把它们标记为正常
- 输出层：把 ai_score 输出到 Prometheus，长期跟踪每个 MITRE 战术的平均得分变化
