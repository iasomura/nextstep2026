# データI/O整合性分析

## 1. データフロー概要

```
02_main.py
    │
    ├── stage1_decisions_latest.csv ──────────► evaluate_e2e.py
    │                                           analyze_evaluation_results.py
    │
    ├── handoff_candidates_latest.csv/pkl ────► evaluate_e2e.py
    │
    └── cert_full_info_map.pkl ───────────────► phishing_agent/
                                                   ├── __init__.py
                                                   ├── precheck_module.py
                                                   ├── langgraph_module.py
                                                   └── tools/certificate_analysis.py
```

---

## 2. カラム/フィールド名の整合性

### 2.1 stage1_decisions_latest.csv

| カラム名 | 02_main.py (出力) | evaluate_e2e.py (入力) | 整合性 |
|----------|-------------------|------------------------|--------|
| domain | ✓ | ✓ | OK |
| source | ✓ | ✓ | OK |
| ml_probability | ✓ | ✓ (必須) | OK |
| stage1_decision | ✓ | ✓ | OK |
| y_true | ✓ | ✓ or label (必須) | OK |
| cert_validity_days | ✓ | - | OK |
| cert_san_count | ✓ | - | OK |

### 2.2 cert_full_info_map フィールド名の不整合

| 02_main.py 出力 | precheck_module 期待 | certificate_analysis 期待 | 状態 |
|-----------------|---------------------|--------------------------|------|
| `issuer_org` | `issuer` | `issuer` or `issuer_org` | **要アダプタ** |
| `validity_days` | `valid_days` | `valid_days` | **❌ 不整合** |
| `has_organization` | `has_org` or `has_organization` | `has_org` or `has_organization` | OK (両方チェック) |
| `san_count` | `san_count` | `san_count` | OK |
| `is_free_ca` | `is_free_ca` | `is_free_ca` | OK |
| `is_self_signed` | `is_self_signed` | `is_self_signed` | OK |
| `is_wildcard` | `is_wildcard` | `is_wildcard` | OK |
| `not_before` | - | `not_before` | OK |
| `not_after` | - | `not_after` | OK |
| `cert_age_days` | - | `cert_age_days` | OK |
| - | `has_crl_dp` | `has_crl_dp` | **❌ 欠落** |

### 2.3 発見された問題

1. **`validity_days` vs `valid_days`**:
   - 02_main.py は `validity_days` を出力
   - precheck_module.py は `valid_days` を期待
   - certificate_analysis.py には `_adapt_cert_meta()` があるが、この変換は含まれていない

2. **`has_crl_dp` の欠落**:
   - precheck_module.py は `has_crl_dp` をチェック
   - 02_main.py の cert_full_info_map には含まれていない
   - ML特徴量には `cert_has_crl_dp` が存在

---

## 3. 修正方針

### 方針A: 02_main.py 側で統一名を出力

cert_full_info_map に以下を追加/修正:

```python
info = {
    # 既存（名前変更）
    'valid_days': 0,        # validity_days → valid_days に変更

    # 新規追加
    'has_crl_dp': False,    # CRL Distribution Point

    # 追加フィールド（LLM用）- 既に追加済み
    'key_type': None,
    'key_size': None,
    ...
}
```

**メリット**: 消費側の修正不要
**デメリット**: 既存の `validity_days` を参照するコードがあれば壊れる

### 方針B: 消費側でアダプタを追加

precheck_module.py の `_extract_cert_info` を修正:

```python
def _extract_cert_info(meta: Dict[str, Any]) -> Dict[str, Any]:
    meta = meta or {}
    return {
        ...
        "valid_days": int(meta.get("valid_days") or meta.get("validity_days") or 0),
        "has_crl_dp": bool(meta.get("has_crl_dp") or meta.get("has_crl") or False),
        ...
    }
```

**メリット**: 後方互換性を維持
**デメリット**: 複数箇所に同様の修正が必要

### 方針C: 両方出力（推奨）

02_main.py で両方の名前で出力:

```python
info = {
    'validity_days': 0,     # 既存（維持）
    'valid_days': 0,        # 新規（エイリアス）
    'has_crl_dp': False,    # 新規追加
    ...
}
```

**メリット**: 後方互換性を維持しつつ、消費側の期待にも応える

---

## 4. CSV拡張時のプレフィックス規則

### 4.1 推奨規則

| プレフィックス | 内容 | 例 |
|----------------|------|-----|
| (なし) | 基本情報 | domain, source, y_true |
| `ml_` | ML特徴量 (数値) | ml_domain_length, ml_cert_validity_days |
| `cert_` | 証明書情報 (可読) | cert_issuer_org, cert_key_type |

### 4.2 ML特徴量とcert情報の重複

| ML特徴量 | cert情報 | 内容 |
|----------|----------|------|
| `ml_cert_validity_days` | `cert_validity_days` | 同じ値だが別カラム |
| `ml_cert_san_count` | `cert_san_count` | 同じ値だが別カラム |
| `ml_cert_is_lets_encrypt` | `cert_issuer_type` | 数値 vs 文字列 |

**対応**: 両方保持（ML用数値とLLM用可読形式は用途が異なる）

---

## 5. 修正対象ファイル一覧

| ファイル | 修正内容 | 優先度 |
|----------|----------|--------|
| `02_main.py` | cert_full_info_map に `valid_days`, `has_crl_dp` 追加 | 高 |
| `02_main.py` | df_stage1 拡張（ML特徴量 + 証明書情報） | 高 |
| `precheck_module.py` | `_extract_cert_info` に `validity_days` フォールバック追加 | 中 |
| `evaluate_e2e.py` | 動作確認 | 低 |

---

## 6. 互換性マトリクス

修正後に以下の組み合わせが動作することを確認:

| 02_main.py | phishing_agent | evaluate_e2e.py | 状態 |
|------------|----------------|-----------------|------|
| 旧 | 旧 | 旧 | ✓ 現状 |
| 新 | 旧 | 旧 | ✓ 互換 (方針C採用時) |
| 新 | 新 | 旧 | ✓ |
| 新 | 新 | 新 | ✓ 目標 |
