# アクセスパターン整理

## 概要

phishing_pipelineデータベースへのアクセスパターンを整理し、必要なクエリとインデックスを明確化する。

---

## 1. 特徴量抽出フェーズ

### 1.1 特徴量の書き込み

**タイミング**: パイプライン実行時（バッチ）

```sql
-- ML特徴量の挿入（UPSERT）
INSERT INTO ml_features (domain, domain_length, dot_count, ...)
VALUES ($1, $2, $3, ...)
ON CONFLICT (domain) DO UPDATE SET
    extracted_at = NOW(),
    domain_length = EXCLUDED.domain_length,
    ...;

-- 証明書情報の挿入（UPSERT）
INSERT INTO raw_cert_info (domain, issuer_org, cert_age_days, ...)
VALUES ($1, $2, $3, ...)
ON CONFLICT (domain) DO UPDATE SET
    extracted_at = NOW(),
    issuer_org = EXCLUDED.issuer_org,
    ...;
```

**頻度**: 新規ドメイン追加時のみ（既存ドメインは再利用）
**件数**: 初回〜10万件、追加時は数千件/回

### 1.2 特徴量の存在確認

```sql
-- 既に特徴量が抽出済みか確認
SELECT domain FROM ml_features WHERE domain = ANY($1);
```

**頻度**: 毎回のパイプライン実行時
**用途**: 再抽出をスキップするため

---

## 2. 実験実行フェーズ

### 2.1 実験の登録

```sql
-- 実験開始
INSERT INTO experiments (run_id, config, status)
VALUES ($1, $2, 'running')
RETURNING run_id;

-- 実験完了
UPDATE experiments
SET status = 'completed',
    completed_at = NOW(),
    total_samples = $2,
    stage1_auto_benign = $3,
    ...
WHERE run_id = $1;
```

**頻度**: 実験ごとに1回

### 2.2 Stage1結果の書き込み

```sql
-- バルクインサート
INSERT INTO stage1_results (run_id, domain, source, y_true, ml_probability, stage1_pred, stage1_decision, t_low, t_high)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8, $9),
    ($1, $10, $11, ...),
    ...;
```

**頻度**: 実験ごとに1回（バッチ）
**件数**: 〜13万件/実験

### 2.3 Stage2結果の書き込み

```sql
-- ハンドオフ候補の書き込み
INSERT INTO stage2_results (run_id, domain, ml_probability, is_candidate, is_selected, selection_method, lr_score, selection_rank)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8), ...;
```

**頻度**: 実験ごとに1回（バッチ）
**件数**: 〜2万件/実験（handoff候補数）

### 2.4 Stage3結果の書き込み

```sql
-- AI Agent結果の書き込み（1件ずつまたは小バッチ）
INSERT INTO stage3_results (
    run_id, domain, agent_pred, agent_confidence, agent_risk_level,
    agent_reasoning, detected_brands, risk_factors,
    policy_version, gate_fired, gate_decision, pre_gate_pred,
    processing_time_ms, tool_calls_count, error
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);
```

**頻度**: Stage3評価中に継続的に書き込み
**件数**: 〜3000件/実験（budget依存）

---

## 3. 分析フェーズ

### 3.1 エラーケース抽出

#### FN（見逃し）の抽出

```sql
-- FNケースの詳細取得
SELECT
    ur.domain, ur.source, ur.ml_probability,
    ur.stage1_decision, ur.agent_pred, ur.agent_confidence,
    mf.*,  -- 全42特徴量
    rc.*   -- 全証明書情報
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
JOIN raw_cert_info rc ON ur.domain = rc.domain
WHERE ur.run_id = $1
  AND ur.y_true = 1
  AND ur.final_pred = FALSE;
```

**頻度**: 分析時（インタラクティブ）
**件数**: 〜200件（結果セット）

#### FP（誤検出）の抽出

```sql
SELECT ...
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
JOIN raw_cert_info rc ON ur.domain = rc.domain
WHERE ur.run_id = $1
  AND ur.y_true = 0
  AND ur.final_pred = TRUE;
```

#### Extra TP（Stage3救済）の抽出

```sql
SELECT ...
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
WHERE ur.run_id = $1
  AND ur.y_true = 1
  AND ur.stage1_pred = 0
  AND ur.agent_pred = TRUE;
```

#### Extra FP（Stage3過検出）の抽出

```sql
SELECT ...
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
WHERE ur.run_id = $1
  AND ur.y_true = 0
  AND ur.stage1_pred = 0
  AND ur.agent_pred = TRUE;
```

### 3.2 集計・統計

#### TLDカテゴリ別集計

```sql
SELECT
    get_tld_category(domain) AS tld_category,
    COUNT(*) AS count,
    AVG(ml_probability) AS avg_ml_prob
FROM fn_cases
WHERE run_id = $1
GROUP BY tld_category;
```

#### CA別FN集計

```sql
SELECT
    rc.issuer_org,
    COUNT(*) AS fn_count,
    AVG(rc.validity_days) AS avg_validity
FROM unified_results ur
JOIN raw_cert_info rc ON ur.domain = rc.domain
WHERE ur.run_id = $1
  AND ur.y_true = 1 AND ur.final_pred = FALSE
GROUP BY rc.issuer_org
ORDER BY fn_count DESC
LIMIT 20;
```

#### Stage3ゲート発火統計

```sql
SELECT
    gate_decision,
    COUNT(*) AS count,
    AVG(agent_confidence) AS avg_confidence,
    SUM(CASE WHEN y_true = 1 THEN 1 ELSE 0 END) AS actual_phishing
FROM stage3_results s3
JOIN stage1_results s1 ON s3.run_id = s1.run_id AND s3.domain = s1.domain
WHERE s3.run_id = $1 AND s3.gate_fired = TRUE
GROUP BY gate_decision;
```

#### 評価指標計算

```sql
-- Confusion Matrix
SELECT
    SUM(CASE WHEN y_true = 1 AND final_pred = TRUE THEN 1 ELSE 0 END) AS tp,
    SUM(CASE WHEN y_true = 0 AND final_pred = TRUE THEN 1 ELSE 0 END) AS fp,
    SUM(CASE WHEN y_true = 1 AND final_pred = FALSE THEN 1 ELSE 0 END) AS fn,
    SUM(CASE WHEN y_true = 0 AND final_pred = FALSE THEN 1 ELSE 0 END) AS tn
FROM unified_results
WHERE run_id = $1;
```

### 3.3 実験比較

```sql
-- 複数実験のF1推移
SELECT
    run_id,
    created_at,
    final_precision,
    final_recall,
    final_f1,
    config->>'policy_version' AS policy_version
FROM experiments
WHERE status = 'completed'
ORDER BY created_at DESC
LIMIT 10;

-- 特定ドメインの実験間比較
SELECT
    e.run_id,
    e.created_at,
    s1.ml_probability,
    s1.stage1_decision,
    s3.agent_pred,
    s3.gate_fired,
    s3.gate_decision
FROM experiments e
JOIN stage1_results s1 ON e.run_id = s1.run_id
LEFT JOIN stage3_results s3 ON e.run_id = s3.run_id AND s1.domain = s3.domain
WHERE s1.domain = $1
ORDER BY e.created_at DESC;
```

---

## 4. 特徴量分析

### 4.1 特徴量分布比較（FN vs TP）

```sql
-- FNとTPの特徴量比較
WITH fn_stats AS (
    SELECT
        'FN' AS category,
        AVG(mf.domain_length) AS avg_domain_length,
        AVG(mf.entropy) AS avg_entropy,
        AVG(mf.cert_validity_days) AS avg_cert_validity,
        AVG(CASE WHEN mf.contains_brand = 1 THEN 1.0 ELSE 0.0 END) AS brand_ratio,
        AVG(CASE WHEN rc.is_free_ca THEN 1.0 ELSE 0.0 END) AS free_ca_ratio
    FROM unified_results ur
    JOIN ml_features mf ON ur.domain = mf.domain
    JOIN raw_cert_info rc ON ur.domain = rc.domain
    WHERE ur.run_id = $1 AND ur.y_true = 1 AND ur.final_pred = FALSE
),
tp_stats AS (
    SELECT
        'TP' AS category,
        AVG(mf.domain_length) AS avg_domain_length,
        AVG(mf.entropy) AS avg_entropy,
        AVG(mf.cert_validity_days) AS avg_cert_validity,
        AVG(CASE WHEN mf.contains_brand = 1 THEN 1.0 ELSE 0.0 END) AS brand_ratio,
        AVG(CASE WHEN rc.is_free_ca THEN 1.0 ELSE 0.0 END) AS free_ca_ratio
    FROM unified_results ur
    JOIN ml_features mf ON ur.domain = mf.domain
    JOIN raw_cert_info rc ON ur.domain = rc.domain
    WHERE ur.run_id = $1 AND ur.y_true = 1 AND ur.final_pred = TRUE
)
SELECT * FROM fn_stats
UNION ALL
SELECT * FROM tp_stats;
```

### 4.2 特徴量のヒストグラム用データ

```sql
-- ML確率の分布（ビン幅0.1）
SELECT
    FLOOR(ml_probability * 10) / 10 AS prob_bin,
    y_true,
    COUNT(*) AS count
FROM unified_results
WHERE run_id = $1
GROUP BY prob_bin, y_true
ORDER BY prob_bin, y_true;
```

---

## 5. アクセスパターンまとめ

| フェーズ | 操作 | 頻度 | 件数 | 要件 |
|----------|------|------|------|------|
| 特徴量抽出 | INSERT/UPSERT | バッチ | 〜10万 | スループット |
| 実験実行 | INSERT | バッチ | 〜13万 | スループット |
| Stage3実行 | INSERT | 逐次 | 〜3000 | 低レイテンシ |
| エラー分析 | SELECT+JOIN | インタラクティブ | 〜200 | 応答速度 |
| 集計 | SELECT+GROUP BY | インタラクティブ | 全件スキャン | 応答速度 |
| 実験比較 | SELECT | インタラクティブ | 少数 | 応答速度 |

---

## 6. 必要なインデックス（再確認）

### 既にスキーマで定義済み

```sql
-- experiments
CREATE INDEX idx_experiments_created_at ON experiments(created_at DESC);
CREATE INDEX idx_experiments_status ON experiments(status);

-- ml_features
CREATE INDEX idx_ml_features_contains_brand ON ml_features(contains_brand);
CREATE INDEX idx_ml_features_cert_is_lets_encrypt ON ml_features(cert_is_lets_encrypt);

-- raw_cert_info
CREATE INDEX idx_raw_cert_is_free_ca ON raw_cert_info(is_free_ca);
CREATE INDEX idx_raw_cert_issuer_org ON raw_cert_info(issuer_org);
CREATE INDEX idx_raw_cert_validity_days ON raw_cert_info(validity_days);

-- stage1_results
CREATE INDEX idx_stage1_run_id ON stage1_results(run_id);
CREATE INDEX idx_stage1_decision ON stage1_results(stage1_decision);
CREATE INDEX idx_stage1_y_true ON stage1_results(y_true);

-- stage2_results
CREATE INDEX idx_stage2_run_id ON stage2_results(run_id);
CREATE INDEX idx_stage2_is_selected ON stage2_results(is_selected);

-- stage3_results
CREATE INDEX idx_stage3_run_id ON stage3_results(run_id);
CREATE INDEX idx_stage3_agent_pred ON stage3_results(agent_pred);
CREATE INDEX idx_stage3_gate_fired ON stage3_results(gate_fired);
```

### 追加検討

```sql
-- 複合インデックス（エラー分析用）
CREATE INDEX idx_stage1_run_ytrue_pred ON stage1_results(run_id, y_true, stage1_pred);

-- unified_results ビューの高速化はマテリアライズドビューを検討
-- CREATE MATERIALIZED VIEW unified_results_mv AS SELECT ... ;
-- CREATE INDEX idx_urm_run_id ON unified_results_mv(run_id);
```

---

## 7. Python APIで必要なメソッド

```python
class PipelineDB:
    # 特徴量
    def upsert_ml_features(self, features_df: pd.DataFrame) -> int
    def upsert_raw_cert_info(self, cert_df: pd.DataFrame) -> int
    def get_existing_domains(self, domains: List[str]) -> Set[str]

    # 実験管理
    def create_experiment(self, run_id: str, config: dict) -> str
    def complete_experiment(self, run_id: str, metrics: dict) -> None

    # Stage結果
    def insert_stage1_results(self, run_id: str, results_df: pd.DataFrame) -> int
    def insert_stage2_results(self, run_id: str, results_df: pd.DataFrame) -> int
    def insert_stage3_result(self, run_id: str, result: dict) -> None

    # 分析
    def get_fn_cases(self, run_id: str) -> pd.DataFrame
    def get_fp_cases(self, run_id: str) -> pd.DataFrame
    def get_extra_tp_cases(self, run_id: str) -> pd.DataFrame
    def get_unified_results(self, run_id: str) -> pd.DataFrame
    def get_experiment_metrics(self, run_id: str) -> dict
    def compare_experiments(self, run_ids: List[str]) -> pd.DataFrame
```
