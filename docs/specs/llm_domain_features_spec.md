# LLM ドメイン特徴量抽出仕様書

**作成日**: 2026-02-02
**更新日**: 2026-02-03
**バージョン**: 2.1
**ステータス**: 凍結（効果不十分により保留）

---

## 1. 概要

### 1.1 目的

Stage1 XGBoostモデルが検出できない「意味的特徴」をLLMで抽出し、フィッシング検出精度を向上させる。

### 1.2 背景

Stage1モデルの検出限界:
- 数値特徴量（ドメイン長、エントロピー、TLD等）のみで学習
- ブランド名の「意味」や「類似性」を理解できない
- 例: `amazones.xyz` (ML=0.01) はAmazon模倣だが、MLは検出失敗

### 1.3 期待効果

| 指標 | 現状 | 目標 |
|------|------|------|
| FN候補（ML < 0.10）のブランド検出率 | 0% | 30%以上 |
| FN救済（Stage2ルール追加時） | - | 500件以上 |

---

## 2. 抽出特徴量

### 2.1 Pydanticスキーマ

```python
class TypoAnalysis(BaseModel):
    """Typosquatting分析結果"""
    is_typosquatting: bool      # ブランド模倣か
    target_brand: Optional[str]  # 模倣対象ブランド
    similarity_score: float      # 類似度 (0-1)
    typo_type: Optional[str]     # タイポ種類

class LegitimacyAnalysis(BaseModel):
    """正当性分析結果"""
    legitimacy_score: float      # 正当性スコア (0-1)
    looks_legitimate: bool       # ビジネスドメインに見えるか
    red_flags: List[str]         # リスク要因リスト

class DGAAnalysis(BaseModel):
    """DGA分析結果"""
    is_likely_dga: bool          # 自動生成ドメインか
    dga_score: float             # DGAスコア (0-1)

class DomainFeatures(BaseModel):
    """統合特徴量"""
    domain: str
    typo_analysis: TypoAnalysis
    legitimacy_analysis: LegitimacyAnalysis
    dga_analysis: DGAAnalysis
    impersonation_target: Optional[str]  # 模倣対象サービス
    risk_score: float            # 総合リスクスコア (0-1)
```

### 2.2 特徴量詳細

| 特徴量 | 型 | 説明 | 用途 |
|--------|-----|------|------|
| `is_typosquatting` | bool | ブランド模倣か | Stage2ルール条件 |
| `target_brand` | str | 模倣対象ブランド名 | ログ・分析 |
| `similarity_score` | float | ブランド類似度 | 閾値判定 |
| `typo_type` | str | タイポ種類 | 分析 |
| `legitimacy_score` | float | 正当性スコア | Stage2ルール条件 |
| `red_flags` | List[str] | リスク要因 | ログ・分析 |
| `is_likely_dga` | bool | DGAか | 補助特徴量 |
| `dga_score` | float | DGAスコア | 補助特徴量 |
| `impersonation_target` | str | 模倣対象サービス | ログ・分析 |
| `risk_score` | float | 総合リスク | Stage2ルール条件 |

---

## 3. 実装

### 3.1 アーキテクチャ

LLMスクリーニングはStage3の並列インフラを共有し、安定性を確保。

```
┌─────────────────────────────────────────────────────────────┐
│                    LLM Screening Pipeline                    │
├─────────────────────────────────────────────────────────────┤
│  llm_screening.py (エントリポイント)                          │
│    │                                                         │
│    ├── FN候補抽出: Stage2結果からML < 0.10 & phishingを抽出   │
│    │                                                         │
│    └── ScreeningWorker                                       │
│          ├── CheckpointManager (Stage3共有)                  │
│          ├── ResultWriter (Stage3共有)                       │
│          └── with_structured_output (Pydanticスキーマ)       │
│                                                              │
│  出力: screening_results.csv, stage3_rescue_list.txt         │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 ファイル構成

```
scripts/
├── llm_screening.py                # LLMスクリーニングエントリポイント
├── llm_domain_features.py          # (旧) 単体特徴量抽出
└── parallel/
    ├── checkpoint.py               # CheckpointManager, ResultWriter (共有)
    ├── screening_worker.py         # ScreeningWorker (新規)
    └── screening_schema.py         # Pydanticスキーマ (新規)
```

### 3.3 クラス構成

| クラス | ファイル | 説明 |
|--------|---------|------|
| `ScreeningWorker` | screening_worker.py | LLMスクリーニングWorker |
| `DomainScreeningResult` | screening_schema.py | Structured Output用スキーマ |
| `TypoAnalysis` | screening_schema.py | Typosquatting分析結果 |
| `LegitimacyAnalysis` | screening_schema.py | 正当性分析結果 |
| `DGAAnalysis` | screening_schema.py | DGA分析結果 |
| `CheckpointManager` | checkpoint.py | チェックポイント管理 (Stage3共有) |
| `ResultWriter` | checkpoint.py | 結果書き込み (Stage3共有) |

### 3.4 使用方法

```bash
# 現在のRUN_IDを使用（artifacts/_current/run_id.txt）
python scripts/llm_screening.py

# オプション指定
python scripts/llm_screening.py --ml-threshold 0.10 --risk-threshold 0.70

# 再開
python scripts/llm_screening.py --resume

# ドライラン（データ確認のみ）
python scripts/llm_screening.py --dry-run
```

### 3.5 コマンドラインオプション

| オプション | デフォルト | 説明 |
|-----------|-----------|------|
| `--run-id` | (自動取得) | RUN_ID指定 |
| `--ml-threshold` | 0.10 | FN候補抽出のML閾値 |
| `--risk-threshold` | 0.70 | Stage3送信のリスク閾値 |
| `--typo-threshold` | 0.80 | ブランド類似度閾値 |
| `--resume` | False | チェックポイントから再開 |
| `--dry-run` | False | データ確認のみ |
| `--port` | 8000 | vLLMポート |
| `--model` | Qwen3-4B-Thinking | モデル名 |

### 3.6 日本語ブランド対応

ブランドキーワードは `phishing_agent/rules/data/brands.py` から取得:

```python
from phishing_agent.rules.data.brands import CRITICAL_BRAND_KEYWORDS

# 主要ブランド例
# - kuronekoyamato, yamato: ヤマト運輸
# - sagawa: 佐川急便
# - japanpost, yubin: 日本郵便
# - smbc: 三井住友銀行
# - rakuten: 楽天
# - mercari: メルカリ
# - amazon: Amazon
# - line: LINE
```

### 3.7 Stage3インフラ共有のメリット

| 観点 | メリット |
|-----|---------|
| **安定性** | Stage3で実績のあるCheckpointManager/ResultWriterを使用 |
| **再開機能** | チェックポイントから処理を再開可能 |
| **保守性** | インフラコードの重複を回避 |
| **一貫性** | 同じ出力フォーマットで後続処理が容易 |

---

## 4. 処理フロー

### 4.1 単一ドメイン処理

```
1. ドメイン入力
2. LLMプロンプト生成（日本語ブランドコンテキスト含む）
3. vLLM API呼び出し（max_tokens=1500）
4. 応答からJSON抽出（バランスドブレース法）
5. Pydanticバリデーション
6. DomainFeatures出力
```

### 4.2 バッチ処理

```
1. CSVからドメインリスト読み込み
2. 各ドメインに対して単一ドメイン処理
3. 結果を結合・フラット化
4. CSV出力
```

---

## 5. 並列処理計画

### 5.1 3GPU並列構成

| Port | GPU | 用途 |
|------|-----|------|
| 8000 | ローカル GPU 0 | vLLM #1 |
| 8001 | 外部サーバー RTX 3080 | vLLM #2 (常時起動) |
| 8002 | 192.168.100.70 RTX 4000 | vLLM #3 |

### 5.2 処理時間見積もり

| 対象 | 件数 | 1GPU | 3GPU |
|------|------|------|------|
| FN候補 | ~2,000 | ~1時間 | ~20分 |
| 全データ | ~127,000 | ~53時間 | ~18時間 |

---

## 6. Stage3救済フロー（採用案）

### 6.1 フロー概要

```
Stage1 (ML分類)
    │
    ├─→ ML >= 0.10: Stage2へ（通常フロー）
    │
    └─→ ML < 0.10 & phishing (FN候補)
          │
          └─→ LLMスクリーニング
                │
                ├─→ 高リスク (risk >= 0.70 OR typo >= 0.80)
                │     └─→ Stage3 Rescue List → Stage3送信
                │
                └─→ 低リスク
                      └─→ 見逃し許容（MLモデルの限界）
```

### 6.2 Stage3送信判定ロジック

```python
def _should_send_to_stage3(result: DomainScreeningResult) -> bool:
    """Stage3送信判定"""
    # 条件1: 高リスクスコア
    if result.risk_score >= 0.70:
        return True

    # 条件2: ブランド模倣（高類似度）
    if (result.typo_analysis.is_typosquatting and
        result.typo_analysis.similarity_score >= 0.80):
        return True

    return False
```

### 6.3 比較検討（却下案）

| オプション | 説明 | 採否 | 理由 |
|-----------|------|-----|------|
| A | Stage1再学習 | 却下 | 工数大、効果不確定 |
| B | Stage2ルール追加 | 却下 | LLM呼び出しが都度発生 |
| **C** | **LLMスクリーニング→Stage3救済** | **採用** | 事前処理で効率的 |

---

## 7. 評価計画

### 7.1 Phase 1: FN候補処理（推奨）

1. **対象抽出**: ML < 0.10 & label=phishing → ~2,000件
2. **LLM処理**: 3GPU並列で特徴量抽出
3. **分析**:
   - ブランド検出率
   - risk_score分布
   - 現行Stage2/3との比較

### 7.2 成功基準

| 指標 | 基準 |
|------|------|
| ブランド検出率 | >= 30% |
| risk_score >= 0.7 | >= 500件 |
| 処理エラー率 | < 5% |

---

## 8. リスクと対策

| リスク | 影響 | 対策 |
|--------|------|------|
| LLM応答のJSON解析失敗 | 特徴量欠損 | バランスドブレース法 + フォールバック |
| ブランド誤検出 | FP増加 | similarity_score閾値設定 |
| 処理時間超過 | 運用コスト | 並列処理、対象絞り込み |
| vLLM Thinkingモデル出力 | JSON抽出困難 | `</think>`タグ後の抽出 |

---

## 9. 関連ドキュメント

- 研究日誌: `docs/research/20260202.md`
- Stage1/Stage2特徴量仕様: `docs/specs/stage1_stage2_feature_spec.md`
- LangChain Structured Output: https://docs.langchain.com/oss/python/langchain/overview

---

## 10. 評価結果と結論（2026-02-03）

### 10.1 実行結果

| 項目 | 結果 |
|------|------|
| 処理件数 | 757件 |
| 成功 | 709件 (93.7%) |
| Stage3候補 | 77件 (10.2%) |

### 10.2 問題点

1. **ドメイン名のみの分析では効果が薄い**（10.2%しか抽出できず）
2. **FN候補の定義が誤っていた**（ML < 0.10 & y_true=1 は本番で使用不可）
3. **Stage2 FNの真の原因はCRL_DPゲート**（373件）

### 10.3 追加分析結果

証明書パターンを使った改善案も検証したが、phishingとbenignで特徴量がほぼ同じであり、区別困難と判明。

### 10.4 結論

**本アプローチは凍結**

- Stage2 FN 373件（0.6%）は許容する
- 改善には大きなコスト（Stage3 +43,973件処理）が必要
- 費用対効果が合わない

### 10.5 退避先

```
scripts/archived/llm_screening_v1/
├── llm_screening.py
├── screening_worker.py
└── screening_schema.py
```

---

## 変更履歴

| 日付 | バージョン | 変更内容 |
|------|-----------|----------|
| 2026-02-03 | 2.1 | 評価結果追加、ステータスを凍結に変更 |
| 2026-02-03 | 2.0 | Stage3インフラ共有方式に変更、Structured Output採用 |
| 2026-02-02 | 1.0 | 初版作成 |
