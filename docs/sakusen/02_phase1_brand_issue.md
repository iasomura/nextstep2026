# Brand特徴が機能しない問題の原因調査レポート

**調査日**: 2026-01-10
**RUN_ID**: 2026-01-10_105017
**問題**: brand_hit列が全てゼロ（54,672候補のうち、brand_hit > 0 が0件）

---

## 調査結果サマリー

### ✅ 正常に動作している部分

1. **設定読み込み**: `seg_include_brand: true` が正しく設定されている
2. **LLM接続**: LLM（localhost:8000, Qwen3-4B-Thinking）に正常接続
3. **Brand抽出**: 100件のbrandキーワードが正常に生成されている

### ❌ 問題がある部分

4. **Brand照合**: Stage2ゲート処理で、BRAND_KEYWORDSが使用されていない

---

## 詳細調査ログ

### 1. LLM設定の確認

**Cell 6出力**:
```
LLM base_url: http://localhost:8000/v1
LLM model   : JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8
```

**評価**: ✅ LLM接続成功

---

### 2. Brand抽出の確認

**Cell 16出力**:
```
🔌 データベースに接続中...
✅ データベース接続成功

📊 phishtank_entries からターゲットを取得...
  ✅ 119 件

📊 jpcert_phishing_urls から説明文を取得...
  ✅ 200 件
🔧 MAX_BRANDS (effective): 100
🔧 BATCH_SIZE (effective): 5
🚀 Batch mode enabled: 1 request ≈ up to 5 brands

Brand validation:  97%|███████| 115/119 [00:44<00:01, 2.58cand/s, batch=5, elapsed=44.6s, found=100, target=100]

⏱️  Done. processed=115/119, found=100/100, elapsed=44.6s

✅ 最終的なBRAND_KEYWORDS: 100件（batch=5, max=100）
📋 最初の20件: ['allegro', 'internalrevenueservice', 'facebook', 'microsoft',
                'att', 'adobe', 'optus', 'aeoncard', 'amazoncom', 'apple',
                'yahoo', 'docusign', 'britishtelecom', 'coinbase', 'netflix',
                'aol', 'steam', 'bankofamericacorporation', 'hsbcgroup', 'ebayinc']
```

**評価**: ✅ BRAND_KEYWORDS変数は正常に生成されている（100件）

---

### 3. Brand照合ロジックの確認

**Cell 38（Stage2ゲート処理）のコード**:

```python
# brand-lite (optional): if we can get a brand list, do a conservative substring match (len>=4 only)
brand_hit = np.zeros_like(is_dang, dtype=bool)
brand_list = []
if seg_include_brand:
    try:
        pk = handoff_dir / "04-3_llm_tools_setup_with_tools.pkl"  # ← ここが問題
        if pk.exists():
            obj = joblib.load(pk)
            brand_list = list(obj.get("brand_keywords") or [])
    except Exception:
        brand_list = []
if brand_list:
    brand_list = [b.strip().lower() for b in brand_list if isinstance(b, str) and len(b.strip()) >= 4]
    if brand_list:
        dom_low = np.array([str(d).lower() for d in dom_c], dtype=object)
        for b in brand_list:
            brand_hit |= np.char.find(dom_low.astype(str), b) >= 0
```

**問題点**:
- pklファイル `04-3_llm_tools_setup_with_tools.pkl` から読み込もうとしている
- しかし、このファイルは存在しない

**確認**:
```bash
$ ls artifacts/2026-01-10_105017/handoff/04-3_llm_tools_setup_with_tools.pkl
pkl file not found
```

**結果**: brand_listは空 → brand_hitは全てFalse → brand_hit列は全て0

**評価**: ❌ BRAND_KEYWORDS変数が生成されているのに、使用されていない

---

## 根本原因

### 設計の不整合

**Cell 16（Brand抽出）**:
```python
# Output : BRAND_KEYWORDS (list[str])  ← same I/O as original (no file writes)
```
→ BRAND_KEYWORDSは**メモリ上の変数**として存在、ファイルには保存されない

**Cell 38（Stage2ゲート）**:
```python
pk = handoff_dir / "04-3_llm_tools_setup_with_tools.pkl"
if pk.exists():
    obj = joblib.load(pk)
    brand_list = list(obj.get("brand_keywords") or [])
```
→ **pklファイルから**読み込もうとする

### なぜこの不整合が発生したか

推測：
1. 元の設計では、pklファイルにBRAND_KEYWORDSが保存されていた
2. Cell 16の改修で "no file writes" にした
3. Cell 38の読み込みロジックは更新されなかった

---

## 影響範囲

### 直接的な影響

- **Priority pool**: 1,470件（期待値より小さい）
  - Dangerous TLD + IDN のみ
  - Brand keyword マッチが追加されていない

- **PENDING Phish**: 2,140件（削減されていない）
  - Brand keyword で救えたはずのPhishが残留

### 定量的影響（推定）

仮に100件のbrand keywordで平均10%のドメインがマッチすると仮定：
- DEFER候補: 54,672件
- Brand match: 約5,400件（10%）
- Priority pool: 1,470 → 約6,870件（4.7倍）
- Stage3 handoff: 優先度の高いPhishが増える
- PENDING Phish: 2,140 → 減少が期待される

---

## 修正方法

### 推奨: 方法A（BRAND_KEYWORDS変数を直接使用）

**修正箇所**: Cell 38

**修正前**:
```python
brand_list = []
if seg_include_brand:
    try:
        pk = handoff_dir / "04-3_llm_tools_setup_with_tools.pkl"
        if pk.exists():
            obj = joblib.load(pk)
            brand_list = list(obj.get("brand_keywords") or [])
    except Exception:
        brand_list = []
```

**修正後**:
```python
brand_list = []
if seg_include_brand:
    # Try to use BRAND_KEYWORDS variable from Cell 16
    try:
        if 'BRAND_KEYWORDS' in globals() and isinstance(BRAND_KEYWORDS, list):
            brand_list = BRAND_KEYWORDS
        else:
            # Fallback: try to load from pkl file (legacy compatibility)
            pk = handoff_dir / "04-3_llm_tools_setup_with_tools.pkl"
            if pk.exists():
                obj = joblib.load(pk)
                brand_list = list(obj.get("brand_keywords") or [])
    except Exception:
        brand_list = []
```

**メリット**:
- シンプル（メモリ上の変数を直接使用）
- ファイルI/O不要
- 既存のBRAND_KEYWORDS生成ロジックをそのまま活用

**デメリット**:
- Cell 16実行後にCell 38を実行する必要がある（通常のnotebook実行フローでは問題なし）

---

### 代替案: 方法B（pklファイルに保存）

**修正箇所**: Cell 16の最後に追加

**追加コード**:
```python
# Save BRAND_KEYWORDS to pkl for Stage2 gate
import joblib
from pathlib import Path

handoff_dir = Path(base_dirs.get("handoff", "artifacts/{}/handoff".format(RUN_ID)))
handoff_dir.mkdir(parents=True, exist_ok=True)

brand_pkl = handoff_dir / "04-3_llm_tools_setup_with_tools.pkl"
joblib.dump({"brand_keywords": BRAND_KEYWORDS}, brand_pkl)
print(f"💾 Saved BRAND_KEYWORDS to {brand_pkl}")
```

**メリット**:
- Cell 38のロジック変更不要
- 既存の設計を尊重

**デメリット**:
- 不要なファイルI/O
- RUN_ID、handoff_dirの定義タイミングに依存

---

## 推奨アクション

### 即時対応（Phase 1.5）

**方法A（BRAND_KEYWORDS変数直接使用）を採用**

1. Cell 38の brand_list 読み込みロジックを修正
2. 02_main.ipynb を再実行
3. 結果確認:
   - brand_hit > 0 の件数
   - Priority pool サイズ
   - PENDING Phish 数

**期待効果**:
- Priority pool: 1,470 → 5,000-7,000 程度
- PENDING Phish: 2,140 → 1,500-2,000 程度（30%削減を期待）

---

### 検証項目

修正後の実行で確認すべき項目：

1. **Brand照合の動作確認**
   ```python
   df_gate = pd.read_csv('artifacts/<RUN_ID>/results/gate_trace_candidates__<RUN_ID>.csv')
   print(f"brand_hit > 0: {(df_gate['brand_hit'] > 0).sum()} / {len(df_gate)}")
   print(f"brand_hit率: {(df_gate['brand_hit'] > 0).sum() / len(df_gate) * 100:.2f}%")
   ```

2. **Priority pool サイズ**
   ```python
   with open('artifacts/<RUN_ID>/results/stage2_budget_eval.json') as f:
       data = json.load(f)
   print(f"Priority pool: {data['stage2_select']['priority_pool']}")
   ```

3. **PENDING Phish削減**
   ```python
   df_pending = pd.read_csv('artifacts/<RUN_ID>/results/stage2_pending_latest.csv')
   pending_phish = (df_pending['y_true'] == 1).sum()
   print(f"PENDING Phish: {pending_phish}")
   ```

---

## まとめ

### 原因

BRAND_KEYWORDSは正常に生成されているが、Stage2ゲート処理で使用されていない。

**設計不整合**:
- Cell 16: メモリ上の変数（no file writes）
- Cell 38: pklファイルから読み込み（ファイルが存在しない）

### 解決策

Cell 38を修正して、BRAND_KEYWORDS変数を直接使用する。

### 期待効果

- Priority poolの拡大（1,470 → 5,000-7,000）
- PENDING Phish数の削減（2,140 → 1,500-2,000、約30%削減）
- Brand keyword による優先度付けの実現

---

**次のステップ**: 修正コードの適用と再実行
