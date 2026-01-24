-- =============================================================================
-- Phishing Detection Pipeline - PostgreSQL Schema Definition
-- Version: 1.0
-- Created: 2026-01-20
-- Database: phishing_pipeline (新規作成、rapids_dataとは別)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. DATABASE CREATION
-- -----------------------------------------------------------------------------
-- 以下はpsqlで実行（postgresユーザーで）
-- CREATE DATABASE phishing_pipeline;
-- GRANT ALL PRIVILEGES ON DATABASE phishing_pipeline TO rapids;

-- 接続先: phishing_pipeline
-- \c phishing_pipeline

-- -----------------------------------------------------------------------------
-- 1. EXPERIMENTS TABLE - 実験管理
-- -----------------------------------------------------------------------------
CREATE TABLE experiments (
    run_id VARCHAR(32) PRIMARY KEY,           -- e.g., '2026-01-17_132657'
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- 実験設定
    config JSONB NOT NULL,                    -- 全設定をJSON形式で保存
    -- config例: {
    --   "t_low": 0.3,
    --   "t_high": 0.7,
    --   "stage2_method": "lr",
    --   "stage2_budget": 3000,
    --   "model_path": "models/xgb_model.pkl",
    --   "policy_version": "v1.6.3-fn-rescue"
    -- }

    -- 実験状態
    status VARCHAR(20) NOT NULL DEFAULT 'running',  -- running, completed, failed
    completed_at TIMESTAMP,

    -- サマリー統計
    total_samples INT,
    stage1_auto_benign INT,
    stage1_auto_phishing INT,
    stage2_handoff_count INT,
    stage3_evaluated_count INT,

    -- 評価指標（最終結果）
    final_precision FLOAT,
    final_recall FLOAT,
    final_f1 FLOAT,

    notes TEXT                                 -- 実験メモ
);

CREATE INDEX idx_experiments_created_at ON experiments(created_at DESC);
CREATE INDEX idx_experiments_status ON experiments(status);

-- -----------------------------------------------------------------------------
-- 2. ML_FEATURES TABLE - XGBoost特徴量 (42カラム)
-- -----------------------------------------------------------------------------
-- 注: 特徴量は実験横断で共有（同じドメインは同じ特徴量）
CREATE TABLE ml_features (
    domain VARCHAR(255) PRIMARY KEY,
    extracted_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- ドメイン特徴量 (15)
    domain_length INT NOT NULL,
    dot_count INT NOT NULL,
    hyphen_count INT NOT NULL,
    digit_count INT NOT NULL,
    digit_ratio FLOAT NOT NULL,
    tld_length INT NOT NULL,
    subdomain_count INT NOT NULL,
    longest_part_length INT NOT NULL,
    entropy FLOAT NOT NULL,
    vowel_ratio FLOAT NOT NULL,
    max_consonant_length INT NOT NULL,
    has_special_chars SMALLINT NOT NULL,       -- 0/1
    non_alphanumeric_count INT NOT NULL,
    contains_brand SMALLINT NOT NULL,          -- 0/1
    has_www SMALLINT NOT NULL,                 -- 0/1

    -- 証明書特徴量 - 基本 (5)
    cert_validity_days INT,
    cert_is_wildcard SMALLINT,                 -- 0/1
    cert_san_count INT,
    cert_issuer_length INT,
    cert_is_self_signed SMALLINT,              -- 0/1

    -- 証明書特徴量 - 拡張 (15)
    cert_cn_length INT,
    cert_subject_has_org SMALLINT,             -- 0/1
    cert_subject_org_length INT,
    cert_san_dns_count INT,
    cert_san_ip_count INT,
    cert_cn_matches_domain SMALLINT,           -- 0/1
    cert_san_matches_domain SMALLINT,          -- 0/1
    cert_san_matches_etld1 SMALLINT,           -- 0/1
    cert_has_ocsp SMALLINT,                    -- 0/1
    cert_has_crl_dp SMALLINT,                  -- 0/1
    cert_has_sct SMALLINT,                     -- 0/1
    cert_sig_algo_weak SMALLINT,               -- 0/1
    cert_pubkey_size INT,
    cert_key_type_code SMALLINT,               -- 0=unknown, 1=RSA, 2=EC, 3=DSA
    cert_is_lets_encrypt SMALLINT,             -- 0/1

    -- 証明書特徴量 - 追加 (6)
    cert_key_bits_normalized FLOAT,            -- 0-1 scale
    cert_issuer_country_code SMALLINT,         -- 0=unknown, 1=US, 2=other
    cert_serial_entropy FLOAT,
    cert_has_ext_key_usage SMALLINT,           -- 0/1
    cert_has_policies SMALLINT,                -- 0/1
    cert_issuer_type SMALLINT,                 -- 0=unknown, 1=LE, 2=Google, 3=Cloudflare, 4=Commercial

    -- 識別特徴量 (1)
    cert_is_le_r3 SMALLINT                     -- 0/1, Let's Encrypt R3/E1
);

-- 特徴量検索用インデックス
CREATE INDEX idx_ml_features_contains_brand ON ml_features(contains_brand);
CREATE INDEX idx_ml_features_cert_is_lets_encrypt ON ml_features(cert_is_lets_encrypt);

-- -----------------------------------------------------------------------------
-- 3. RAW_CERT_INFO TABLE - 人間可読な証明書情報 (11カラム)
-- -----------------------------------------------------------------------------
CREATE TABLE raw_cert_info (
    domain VARCHAR(255) PRIMARY KEY,
    extracted_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- cert_full_info_map の全項目
    issuer_org VARCHAR(255),                   -- 発行者組織名
    cert_age_days INT,                         -- 発行からの経過日数
    is_free_ca BOOLEAN NOT NULL DEFAULT FALSE, -- Let's Encrypt, ZeroSSL等
    san_count INT,                             -- SAN数
    is_wildcard BOOLEAN NOT NULL DEFAULT FALSE,
    is_self_signed BOOLEAN NOT NULL DEFAULT FALSE,
    has_organization BOOLEAN NOT NULL DEFAULT FALSE, -- Subject に組織名があるか
    not_before TIMESTAMP,                      -- 発行日
    not_after TIMESTAMP,                       -- 有効期限
    validity_days INT,                         -- 有効期間（日）
    has_certificate BOOLEAN NOT NULL DEFAULT FALSE,  -- 証明書取得成功フラグ

    -- 外部キー
    CONSTRAINT fk_raw_cert_domain FOREIGN KEY (domain) REFERENCES ml_features(domain)
);

CREATE INDEX idx_raw_cert_is_free_ca ON raw_cert_info(is_free_ca);
CREATE INDEX idx_raw_cert_issuer_org ON raw_cert_info(issuer_org);
CREATE INDEX idx_raw_cert_validity_days ON raw_cert_info(validity_days);

-- -----------------------------------------------------------------------------
-- 4. STAGE1_RESULTS TABLE - Stage1 XGBoost判定結果
-- -----------------------------------------------------------------------------
CREATE TABLE stage1_results (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(32) NOT NULL,
    domain VARCHAR(255) NOT NULL,

    -- 入力情報
    source VARCHAR(50) NOT NULL,               -- PhishTank, JPCERT, certificates, tranco
    y_true SMALLINT NOT NULL,                  -- 正解ラベル (0=benign, 1=phishing)

    -- Stage1出力
    ml_probability FLOAT NOT NULL,             -- XGBoost予測確率 [0.0-1.0]
    stage1_pred SMALLINT NOT NULL,             -- 閾値適用前の予測 (proba >= 0.5)
    stage1_decision VARCHAR(20) NOT NULL,      -- 'auto_benign', 'auto_phishing', 'handoff_to_agent'

    -- 閾値情報
    t_low FLOAT NOT NULL,                      -- 使用した下限閾値
    t_high FLOAT NOT NULL,                     -- 使用した上限閾値

    -- 外部キー
    CONSTRAINT fk_stage1_run FOREIGN KEY (run_id) REFERENCES experiments(run_id),
    CONSTRAINT fk_stage1_domain FOREIGN KEY (domain) REFERENCES ml_features(domain),
    CONSTRAINT uq_stage1_run_domain UNIQUE (run_id, domain)
);

CREATE INDEX idx_stage1_run_id ON stage1_results(run_id);
CREATE INDEX idx_stage1_decision ON stage1_results(stage1_decision);
CREATE INDEX idx_stage1_y_true ON stage1_results(y_true);

-- -----------------------------------------------------------------------------
-- 5. STAGE2_RESULTS TABLE - Stage2 ハンドオフ選択結果
-- -----------------------------------------------------------------------------
CREATE TABLE stage2_results (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(32) NOT NULL,
    domain VARCHAR(255) NOT NULL,

    -- Stage2入力（Stage1からの引き継ぎ）
    ml_probability FLOAT NOT NULL,

    -- Stage2出力
    is_candidate BOOLEAN NOT NULL DEFAULT TRUE, -- handoff候補か
    is_selected BOOLEAN NOT NULL,              -- 実際に選択されたか
    selection_method VARCHAR(20) NOT NULL,     -- 'lr', 'random', 'all'
    lr_score FLOAT,                            -- LRスコア（lr method使用時）
    selection_rank INT,                        -- 選択順位

    -- 外部キー
    CONSTRAINT fk_stage2_run FOREIGN KEY (run_id) REFERENCES experiments(run_id),
    CONSTRAINT fk_stage2_domain FOREIGN KEY (domain) REFERENCES ml_features(domain),
    CONSTRAINT uq_stage2_run_domain UNIQUE (run_id, domain)
);

CREATE INDEX idx_stage2_run_id ON stage2_results(run_id);
CREATE INDEX idx_stage2_is_selected ON stage2_results(is_selected);

-- -----------------------------------------------------------------------------
-- 6. STAGE3_RESULTS TABLE - Stage3 AI Agent判定結果
-- -----------------------------------------------------------------------------
CREATE TABLE stage3_results (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(32) NOT NULL,
    domain VARCHAR(255) NOT NULL,

    -- Agent出力
    agent_pred BOOLEAN NOT NULL,               -- AI判定結果 (True=phishing)
    agent_confidence FLOAT NOT NULL,           -- 確信度 [0.0-1.0]
    agent_risk_level VARCHAR(20) NOT NULL,     -- 'low', 'medium', 'medium-high', 'high', 'critical'
    agent_reasoning TEXT,                      -- 判定理由

    -- 検出情報
    detected_brands TEXT[],                    -- 検出されたブランド名リスト
    risk_factors TEXT[],                       -- リスク要因リスト

    -- Phase6ゲート情報
    policy_version VARCHAR(30),                -- e.g., 'v1.6.3-fn-rescue'
    gate_fired BOOLEAN NOT NULL DEFAULT FALSE, -- ゲートが発火したか
    gate_decision VARCHAR(30),                 -- 発火したゲート名
    pre_gate_pred BOOLEAN,                     -- ゲート適用前のLLM判定

    -- 処理情報
    processing_time_ms INT,                    -- 処理時間（ミリ秒）
    tool_calls_count INT,                      -- ツール呼び出し回数
    error TEXT,                                -- エラーメッセージ（失敗時）

    -- 外部キー
    CONSTRAINT fk_stage3_run FOREIGN KEY (run_id) REFERENCES experiments(run_id),
    CONSTRAINT fk_stage3_domain FOREIGN KEY (domain) REFERENCES ml_features(domain),
    CONSTRAINT uq_stage3_run_domain UNIQUE (run_id, domain)
);

CREATE INDEX idx_stage3_run_id ON stage3_results(run_id);
CREATE INDEX idx_stage3_agent_pred ON stage3_results(agent_pred);
CREATE INDEX idx_stage3_gate_fired ON stage3_results(gate_fired);

-- -----------------------------------------------------------------------------
-- 7. UNIFIED_RESULTS VIEW - 統合ビュー
-- -----------------------------------------------------------------------------
CREATE VIEW unified_results AS
SELECT
    -- 実験情報
    e.run_id,
    e.created_at AS experiment_created_at,
    e.config AS experiment_config,

    -- ドメイン基本情報
    s1.domain,
    s1.source,
    s1.y_true,

    -- ML特徴量（主要なもののみ）
    mf.domain_length,
    mf.entropy,
    mf.contains_brand,
    mf.cert_validity_days AS mf_cert_validity_days,
    mf.cert_is_lets_encrypt,
    mf.cert_san_count AS mf_cert_san_count,

    -- 証明書情報
    rc.issuer_org,
    rc.is_free_ca,
    rc.has_organization,
    rc.cert_age_days,
    rc.validity_days,

    -- Stage1結果
    s1.ml_probability,
    s1.stage1_pred,
    s1.stage1_decision,

    -- Stage2結果
    s2.is_candidate AS stage2_is_candidate,
    s2.is_selected AS stage2_is_selected,
    s2.lr_score AS stage2_lr_score,

    -- Stage3結果
    s3.agent_pred,
    s3.agent_confidence,
    s3.agent_risk_level,
    s3.gate_fired,
    s3.gate_decision,
    s3.detected_brands,
    s3.processing_time_ms,

    -- 最終判定
    CASE
        WHEN s1.stage1_decision = 'auto_phishing' THEN TRUE
        WHEN s1.stage1_decision = 'auto_benign' THEN FALSE
        WHEN s3.agent_pred IS NOT NULL THEN s3.agent_pred
        ELSE (s1.ml_probability >= 0.5)  -- fallback
    END AS final_pred,

    -- 評価カテゴリ
    CASE
        WHEN s1.stage1_decision IN ('auto_phishing', 'auto_benign') THEN 'stage1_auto'
        WHEN s2.is_selected = TRUE AND s3.agent_pred IS NOT NULL THEN 'stage3_evaluated'
        WHEN s2.is_candidate = TRUE THEN 'stage2_candidate'
        ELSE 'unknown'
    END AS eval_category

FROM stage1_results s1
JOIN experiments e ON s1.run_id = e.run_id
LEFT JOIN ml_features mf ON s1.domain = mf.domain
LEFT JOIN raw_cert_info rc ON s1.domain = rc.domain
LEFT JOIN stage2_results s2 ON s1.run_id = s2.run_id AND s1.domain = s2.domain
LEFT JOIN stage3_results s3 ON s1.run_id = s3.run_id AND s1.domain = s3.domain;

-- -----------------------------------------------------------------------------
-- 8. ANALYSIS VIEWS - 分析用ビュー
-- -----------------------------------------------------------------------------

-- FN分析用ビュー（Stage3でFalse Negativeになったケース）
CREATE VIEW fn_cases AS
SELECT
    ur.*,
    mf.*
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
WHERE ur.y_true = 1  -- 実際はphishing
  AND ur.final_pred = FALSE;  -- benignと判定

-- FP分析用ビュー（Stage3でFalse Positiveになったケース）
CREATE VIEW fp_cases AS
SELECT
    ur.*,
    mf.*
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
WHERE ur.y_true = 0  -- 実際はbenign
  AND ur.final_pred = TRUE;  -- phishingと判定

-- Extra TP分析用ビュー（Stage1はmiss、Stage3で救済したケース）
CREATE VIEW extra_tp_cases AS
SELECT
    ur.*,
    mf.*
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
WHERE ur.y_true = 1  -- 実際はphishing
  AND ur.stage1_pred = 0  -- Stage1は見逃し
  AND ur.agent_pred = TRUE;  -- Stage3で検出

-- Extra FP分析用ビュー（Stage1はOK、Stage3で過検出したケース）
CREATE VIEW extra_fp_cases AS
SELECT
    ur.*,
    mf.*
FROM unified_results ur
JOIN ml_features mf ON ur.domain = mf.domain
WHERE ur.y_true = 0  -- 実際はbenign
  AND ur.stage1_pred = 0  -- Stage1はbenign判定
  AND ur.agent_pred = TRUE;  -- Stage3でphishing判定

-- -----------------------------------------------------------------------------
-- 9. HELPER FUNCTIONS
-- -----------------------------------------------------------------------------

-- TLDカテゴリを返す関数
CREATE OR REPLACE FUNCTION get_tld_category(domain_name VARCHAR)
RETURNS VARCHAR AS $$
DECLARE
    tld VARCHAR;
    high_danger_tlds VARCHAR[] := ARRAY['xyz', 'top', 'icu', 'cn', 'buzz', 'cc', 'cyou',
                                         'cfd', 'sbs', 'lat', 'bond', 'rest', 'boats',
                                         'makeup', 'hair', 'autos', 'wiki', 'mom', 'gy'];
    medium_danger_tlds VARCHAR[] := ARRAY['online', 'site', 'club', 'shop', 'info', 'biz',
                                           'store', 'app', 'dev', 'io', 'me', 'work',
                                           'life', 'live', 'pro', 'tech', 'click',
                                           'link', 'fun', 'vip'];
BEGIN
    -- TLDを抽出
    tld := LOWER(SPLIT_PART(domain_name, '.', -1));

    IF tld = ANY(high_danger_tlds) THEN
        RETURN 'high_danger';
    ELSIF tld = ANY(medium_danger_tlds) THEN
        RETURN 'medium_danger';
    ELSE
        RETURN 'non_danger';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- -----------------------------------------------------------------------------
-- 10. SAMPLE QUERIES FOR ANALYSIS
-- -----------------------------------------------------------------------------

-- FN件数の集計（TLDカテゴリ別）
-- SELECT get_tld_category(domain) AS tld_category, COUNT(*)
-- FROM fn_cases
-- WHERE run_id = '2026-01-17_132657'
-- GROUP BY tld_category;

-- 実験比較（F1スコア推移）
-- SELECT run_id, final_f1, created_at
-- FROM experiments
-- ORDER BY created_at DESC;

-- Stage3ゲート発火統計
-- SELECT gate_decision, COUNT(*), AVG(agent_confidence)
-- FROM stage3_results
-- WHERE run_id = '2026-01-17_132657' AND gate_fired = TRUE
-- GROUP BY gate_decision;

-- CA別FN分析
-- SELECT rc.issuer_org, COUNT(*) AS fn_count
-- FROM fn_cases fn
-- JOIN raw_cert_info rc ON fn.domain = rc.domain
-- WHERE fn.run_id = '2026-01-17_132657'
-- GROUP BY rc.issuer_org
-- ORDER BY fn_count DESC;
