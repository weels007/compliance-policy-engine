<p align="center">
  <h1 align="center">⚡ CompliancePolicyEngine</h1>
  <p align="center">
    <strong>General-purpose Natural Language Compliance Evaluation on GenLayer</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Built%20on-GenLayer-6366f1?style=for-the-badge&logo=genlayer" alt="GenLayer">
    <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/tests-53%20passed-16a34a?style=for-the-badge" alt="Tests">
    <img src="https://img.shields.io/badge/E2E-verified-16a34a?style=for-the-badge" alt="E2E Verified">
  </p>
</p>

---

## 🎯 What is this?

**CompliancePolicyEngine** is an on-chain intelligent contract that evaluates **any content** against **natural language rules** — and stores the result **only after multi-validator consensus**.

You define rules like *"No profanity"*, *"Must cite sources"*, *"Under 500 words"* — and the contract fetches the content, runs it through an LLM judge, and produces **per-rule verdicts** (SATISFIED / VIOLATED / SKIPPED) with a scoring breakdown. **No single node decides alone** — validators independently re-run the entire pipeline and must agree on the result.

### 📌 Use Cases

| Use Case | How it works |
|----------|-------------|
| **Content Moderation** | Platform defines community rules → users submit content URLs → consensus verdict |
| **Regulatory Compliance** | CCPA, GDPR policy docs evaluated against legal criteria |
| **Brand Voice Enforcement** | Marketing content checked against brand guidelines |
| **Grant Eligibility** | Applications evaluated against funding criteria |
| **Technical Writing QA** | Documentation checked against style guides |
| **Cross-contract Primitive** | Any GenLayer contract can call `evaluate_content` as a sub-routine |

---

## 📜 Deployed Contract

<table>
<tr>
  <td><strong>Address</strong></td>
  <td><code>0xa77aDB26D2A77Ac59D2c258C30715e8A084f0E2C</code></td>
</tr>
<tr>
  <td><strong>Explorer</strong></td>
  <td>
    <a href="https://explorer-studio.genlayer.com/address/0xa77aDB26D2A77Ac59D2c258C30715e8A084f0E2C">
      🔗 explorer-studio.genlayer.com/address/0xa77aDB26...
    </a>
  </td>
</tr>
<tr>
  <td><strong>Network</strong></td>
  <td>GenLayer Studionet (gasless)</td>
</tr>
<tr>
  <td><strong>Deployer</strong></td>
  <td><code>0xD0B8fFA6ea2572D2a8F16512CAbB21eCFe6ea48b</code></td>
</tr>
<tr>
  <td><strong>Consensus</strong></td>
  <td>MAJORITY_AGREE (3/5 validators)</td>
</tr>
</table>

> ✅ **Fully verified on real chain**: All 14 methods tested end-to-end with real validator consensus, real LLM calls, and real web fetching.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Policy Owner                          │
│  create_policy() → define rules in natural language     │
│  update_rule()   → modify rules                         │
│  delete_policy() → remove policy + rules                │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│              CompliancePolicyEngine                      │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │   Policy    │───▶│ Policy Rules │───▶│ Evaluation │ │
│  │  (metadata) │    │ (per-rule)   │    │  (verdicts)│ │
│  └─────────────┘    └──────────────┘    └────────────┘ │
│                                                         │
│  evaluate_content(url) ──▶ Consensus Pipeline           │
│       │                    ┌───────────────┐            │
│       │                    │ 1. Fetch URL  │            │
│       │                    │ 2. LLM Judge  │            │
│       │                    │ 3. Score      │            │
│       │                    │ 4. Compare    │            │
│       │                    └───────┬───────┘            │
│       │                            │                     │
│       │                    ┌───────▼───────┐            │
│       │                    │   Equivalence  │            │
│       │                    │   Principle    │            │
│       │                    └───────┬───────┘            │
│       │                            │                     │
│       ▼                            ▼                     │
│  ┌──────────┐            ┌──────────────┐               │
│  │ Per-Rule │            │  Consensus   │               │
│  │ Verdicts │            │  Agreement   │               │
│  └──────────┘            └──────────────┘               │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  Anyone can read                         │
│  get_evaluation() → per-rule verdicts + reasoning       │
│  get_policy_summary() → aggregate pass rate             │
│  check_duplicate() → already evaluated?                 │
│  check_cooldown() → rate limit remaining                │
└─────────────────────────────────────────────────────────┘
```

---

## 🧠 Why This is NOT a "Thin LLM Wrapper"

Most AI contracts just ask an LLM *"decide X"* and store the answer. **This contract does not trust the LLM.** Here's what makes it different:

### 1. Per-Rule Verdicts, Not Just a Boolean

Each rule gets its own verdict with independent reasoning:

```json
{
  "verdicts": [
    {"rule_id": "No profanity", "status": "SATISFIED", "reasoning": "Clean content"},
    {"rule_id": "Must cite sources", "status": "VIOLATED", "reasoning": "No citations found"}
  ],
  "compliant": false,
  "pass_rate_pct": 50
}
```

### 2. Validators Must Agree on Structured Fields

The consensus settlement tuple is:

```python
(
    compliant: bool,
    rules_passed: int,
    rules_failed: int,
    total_rules: int,
    expected_rule_count: int,
    canonical_verdicts: tuple[(rule_id, status), ...]  # sorted by rule_id
)
```

Validators must agree on **exactly which rules passed/failed** — the canonical sorted (rule_id, status) mapping ensures both leader and validator produce the same deterministic ordering. If one says "Rule A: SATISFIED" and the other says "Rule A: VIOLATED", consensus fails.

### 3. Rule-Count Binding

Validators verify the LLM evaluated **ALL stored rules**. If a policy has 3 rules but the LLM only returned 2 verdicts, consensus fails. This prevents the LLM from silently skipping rules.

### 4. First-Class Rules as Storage Objects

Rules aren't a flat string — they're individual objects with title, description, and category:

```
PolicyRule(index=0, title="No profanity", description="...", category="language")
PolicyRule(index=1, title="Must cite sources", description="...", category="quality")
```

Other contracts and UIs can enumerate rules, track per-rule pass rates, and build dashboards.

---

## 🔒 Security

| Threat | Mitigation |
|--------|-----------|
| **Spam / Flooding** | 60s cooldown between evaluations per evaluator per policy |
| **Double Submit** | Same evaluator cannot re-evaluate the same URL against the same policy |
| **LLM Rule Skipping** | Settlement tuple includes `total_rules` + canonical (rule_id, status) mapping — validators verify all rules evaluated and agree on each rule's verdict |
| **Challenge Window** | 24h to challenge, after which evaluation is final |
| **Owner-Only Admin** | Only policy owner can update rules, toggle active, delete, or challenge |
| **Prompt Injection** | Content marked as untrusted data; LLM told to never follow instructions inside it |
| **Atomic Updates** | `update_rule` validates ALL inputs before applying ANY mutation |
| **Error Classification** | `[EXPECTED]`, `[EXTERNAL]`, `[TRANSIENT]`, `[LLM]` prefixes for validator consensus on failures |

---

## 📊 Methods (14 total)

### Write Methods (7)

| Method | Description |
|--------|-------------|
| `create_policy(id, title, desc, group, rule_titles[], rule_descs[], rule_cats[])` | Create a policy with individual rules |
| `update_rule(policy_id, index, title, desc, cat)` | Update a rule (owner only) |
| `set_policy_active(policy_id, active)` | Enable/disable a policy (owner only) |
| `delete_policy(policy_id)` | Delete policy + all rules (owner only) |
| `evaluate_content(policy_id, content_url)` | Evaluate content against policy (consensus) |
| `challenge_evaluation(eval_id, reason)` | Challenge an evaluation (24h window) |

### Read Methods (7)

| Method | Description |
|--------|-------------|
| `get_policy(policy_id)` | Full policy metadata |
| `get_rule(policy_id, index)` | Individual rule details |
| `get_policy_rules(policy_id)` | All rules for a policy |
| `get_evaluation(eval_id)` | Evaluation with per-rule verdicts |
| `get_policy_summary(policy_id)` | Aggregate stats (avg pass rate, challenge count) |
| `get_contract_stats()` | Contract-wide statistics |
| `check_duplicate(policy_id, url)` | Check if URL already evaluated |
| `check_cooldown(policy_id)` | Remaining cooldown seconds |

---

## 🧪 Testing

### Direct Mode (52 tests)

```bash
genvm-lint check contracts/compliance_policy_engine.py    # Lint: 3/3 checks
pytest tests/test_compliance_policy_engine.py -v -s       # Tests: 53/53 pass
```

### E2E on Studionet (real chain)

All methods verified end-to-end with real validator consensus:

| Method | Result |
|--------|--------|
| `create_policy` | ✅ MAJORITY_AGREE — 2 rules stored |
| `get_policy` / `get_rule` / `get_policy_rules` | ✅ Correct data returned |
| `update_rule` | ✅ Rule updated and verified |
| `set_policy_active` | ✅ Deactivate/reactivate works |
| `evaluate_content` | ✅ **Consensus call** — LLM evaluated, per-rule verdicts stored |
| `get_evaluation` | ✅ `compliant:true`, `rules_passed:2`, `pass_rate_pct:100` |
| `double submit` | ✅ REJECTED — `This URL has already been evaluated` |
| `check_duplicate` / `check_cooldown` | ✅ Correct detection |
| `challenge_evaluation` | ✅ `challenged:true`, reason stored, avg drops to 0 |
| `double challenge` | ✅ REJECTED — `Evaluation already challenged` |
| `delete_policy` | ✅ Policy deleted, returns empty |
| `get_contract_stats` | ✅ Aggregated stats correct |

---

## 📁 Project Structure

```
CompliancePolicyEngine/
├── contracts/
│   └── compliance_policy_engine.py    # The contract (single file)
├── tests/
│   ├── conftest.py                    # Windows workaround
│   └── test_compliance_policy_engine.py  # 53 direct-mode tests
├── scripts/
│   └── test-studionet-e2e.cjs        # E2E test on real chain
├── wallet/
│   └── cpe-deploy.json               # Deployer wallet backup
├── gltest.config.yaml                 # Test config
└── README.md                          # This document
```

---

## 🚀 Example Flow

```python
# 1. Create a policy with 2 rules
create_policy(
    "mod-01",
    "Community Standards",
    "Rules for community posts",
    "content_moderation",
    ["No profanity", "Must cite sources"],
    ["Content must not contain profane language",
     "Content must include at least one source citation"],
    ["language", "quality"]
)

# 2. Evaluate a blog post (consensus call — takes ~30-60s)
evaluate_content("mod-01", "https://example.com/my-blog-post")

# 3. Read per-rule verdicts
get_evaluation("mod-01:0xABC...:1")
# → compliant: false, rules_passed: 1, rules_failed: 1
# → verdicts: {0: SATISFIED, 1: VIOLATED}

# 4. Check aggregate stats
get_policy_summary("mod-01")
# → evaluation_count: 1, avg_pass_rate_pct: 50

# 5. Challenge if you disagree
challenge_evaluation("mod-01:0xABC...:1", "Content does cite sources in footnotes")
```

---

## 🔧 Extension Ideas

- **Programmatic Ground Truth** — AST sandbox for objective rules before LLM judgment
- **Evaluator Staking** — deposit tokens, slashed if evaluation diverges from median
- **Cross-contract Calls** — other GenLayer contracts consume verdicts as sub-routines
- **Policy Templates** — pre-built rule sets (CCPA, brand voice, technical writing)
- **Historical Analytics** — track per-rule pass rates over time

---

<p align="center">
  <sub>Built for the <a href="https://genlayer.com">GenLayer</a> Intelligent Contract track.</sub>
</p>
