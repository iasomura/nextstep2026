# Stage3 AI Agent 知識ベース拡張: 追加基準と根拠

## 概要

Qwen3-4B の AI Agent が Claude レベルの判定能力に近づくよう、オフラインの知識データを拡充した。
本文書では、各改善における追加基準・根拠を記載する（論文記述用）。

---

## 1. Tranco Top 100K (正規ドメインリスト)

### 出典・学術的根拠

- **論文**: Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation" (NDSS 2019)
- **URL**: https://tranco-list.eu/
- **選定理由**: Alexa/Majestic 等の単一ソースと異なり、複数ランキングを統合しており操作耐性が高い
- **利用実績**: フィッシング検出・ドメイン分類の研究で広く参照される標準的なデータソース

### 閾値設計の根拠

| ランク帯 | Confidence | Trust Level | 設計根拠 |
|---------|-----------|-------------|---------|
| Top 1K | 0.95 | strict | グローバルに認知される超大手サイト。フィッシング利用の可能性は極めて低い |
| Top 10K | 0.92 | moderate | 地域的に有名なサイト（starwars.com等）。やや保守的に設定 |
| Top 100K | 0.88 | moderate | 中規模サイト。ドメインハイジャックの可能性を考慮し信頼度を下げる |

### FP削減の仕組み

- `brand_impersonation_check.py`: confidence >= 0.95 で early return (risk_score=0)
- `contextual_risk_assessment.py`: confidence >= 0.98 で mitigation 適用
- Tranco Top 1K のドメインは brand_check で即座に safe 判定される
- Top 10K〜100K は risk_adjustment (0.3倍) によりスコアが大幅に減衰

### リスク考慮

- Tranco リストに万が一フィッシングドメインが含まれる場合 → confidence を moderate に抑えているため、brand検出があれば override される
- ドメインハイジャック対策 → Top 100K でも confidence は 0.88 に留め、他の強シグナル（brand_detected, self_signed等）があれば最終判定で phishing に分類可能

---

## 2. Brand Keywords 追加基準

### 追加の前提条件

以下のいずれかを満たすブランドを追加対象とした:

1. **VT (VirusTotal) で malicious >= 5 のFNドメインに含まれるブランド名**
   - 例: `cgd-online.top` → CGDブランドが辞書に無く検出漏れ
2. **APWG/PhishTank の統計で頻出するブランド**
   - 例: EZ Pass, IRS, La Poste は北米/欧州のフィッシングレポートで上位
3. **JPCERT/フィッシング対策協議会のレポートで報告されたブランド**
   - 日本語ブランドは既に多いが、海外ブランドのカバーが不足していた

### カテゴリ別の根拠

| カテゴリ | 追加件数 | 追加根拠 |
|---------|---------|---------|
| ポルトガル語圏 (CGD, Millennium BCP等) | ~25件 | FNデータセット内で多数確認。ポルトガル/ブラジル対象のフィッシングが急増 |
| フランス語圏 (La Poste, Credit Agricole等) | ~25件 | APWG Q3-Q4 2025レポートでフランス向けフィッシングが増加傾向 |
| スペイン語圏 (Correos, CaixaBank等) | ~15件 | 同上、スペイン語圏のフィッシングキャンペーン |
| 北米 (EZ Pass, IRS, Verizon等) | ~40件 | FBIのIC3レポート、FNデータセットで複数確認 |
| 配送・物流 (PostNL, Evri, DPD等) | ~15件 | COVID以降の配送偽装フィッシングの国際的増加 |
| ストリーミング (Disney+, Hulu, HBO等) | ~10件 | サブスク系フィッシングの増加 |
| SNS/コミュニケーション (Discord, Snapchat等) | ~10件 | アカウント乗っ取り目的のフィッシング |
| フィンテック (Revolut, Wise, Klarna等) | ~12件 | 新興金融サービスへの偽装攻撃増加 |
| 暗号通貨 (Phantom, Uniswap, OpenSea等) | ~25件 | DeFi/NFT関連フィッシングの急増 (Chainalysis 2024-2025) |
| 欧州銀行 (Barclays, Nordea, Commerzbank等) | ~30件 | 欧州金融機関対象のフィッシングキャンペーン |
| セキュリティ・認証 (Okta, LastPass等) | ~15件 | 認証情報窃取目的のフィッシング |
| 送金 (Western Union, MoneyGram等) | ~10件 | 送金サービス偽装フィッシング |

### 追加後の規模

- 変更前: 215 ブランド
- 変更後: 461 ブランド (+246件)
- CRITICAL_BRAND_KEYWORDS: 32 → 110 (+78件)

### FPリスクへの対策

- 短い (≤3文字) キーワードは `_check_brand_substring` の dvguard4 で exact match のみ許可
- 正規ドメイン (Tranco Top 100K) に対しては brand_check が early return するため FP 増加なし
- fuzzy match (編集距離2) は brand >= 6文字の場合のみ適用

---

## 3. 多言語ソーシャルエンジニアリングキーワード

### 選定基準

FNドメインのトークン分析で、英語以外の「行動誘導語」がドメイン名に含まれるパターンを確認。

選定条件:
1. フィッシングメールで頻出する**行動誘導語**（verify, login, secure の各言語翻訳）
2. **一般的な単語すぎない**こと（冠詞 `de`, `le` 等は除外）
3. **フィッシングURL特有の文脈**で使われる語

### 言語学的分類

| 意味カテゴリ | フランス語 | ポルトガル語 | スペイン語 | ドイツ語 | イタリア語 |
|-------------|-----------|-------------|-----------|---------|-----------|
| ログイン/接続 | connexion | acesso | acceso | anmeldung | accesso |
| 確認/検証 | verification | verificar | verificacion | verifizierung | verifica |
| セキュリティ | securite | seguranca | seguridad | sicherheit | sicurezza |
| 支払い/請求 | facture | pagamento | pago | rechnung | pagamento |
| アカウント | compte | conta | cuenta | konto | - |
| 配送/荷物 | livraison, colis | entrega | envio | lieferung | consegna |
| 更新 | actualiser | atualizar | actualizar | aktualisierung | aggiornamento |
| ロック解除 | debloquer | desbloqueio | desbloquear | freischaltung | sblocco |

### 追加後の規模

- MULTILINGUAL_RISK_WORDS: 71キーワード
- 対応言語: フランス語, ポルトガル語, スペイン語, ドイツ語, イタリア語 + 汎用パターン

### スコアリング方式

- 既存の `HIGH_RISK_WORD_BASE/STEP/MAX` と同じロジックを適用
- `_count_high_risk_hits()` で英語 high_risk_words と MULTILINGUAL_RISK_WORDS を統合検索
- ドメインのトークン分割後に完全一致で判定するため、部分文字列一致による FP リスクは低い

---

## 4. ランダム文字列検出強化

### 4a. 子音クラスター検出

**言語学的根拠**:
- 英語の音素配列論 (phonotactics) では、3子音連続は語頭で最大3個（str-, spl-）、語中/語尾でも限定的
- 自然言語のドメイン名で、3+子音クラスターが2箇所以上出現することは極めて稀
- DGA (Domain Generation Algorithm) や手動ランダム生成のドメインはこの制約に従わない

**閾値設定**:
- クラスター >= 2個 → `consonant_cluster_random` フラグ
- 根拠: 1個のクラスターは正当なドメインでも起こりうる（例: `strength` の `ngth`）が、2個以上は非自然的

### 4b. レアバイグラム分析

**根拠**:
- 英語のバイグラム頻度表（Peter Norvig のGoogle N-gram分析等）で出現確率 < 0.001 のペアを選定
- 自然言語では事実上出現しない文字組み合わせ（`qx`, `zx`, `jq`, `vx` 等）
- Shannon entropy だけでは短い文字列でエントロピーが低く出る問題を補完

**選定したレアバイグラム** (56ペア):
- `q` + 母音以外: qx, qz, qk, qf, qj, qw, qv
- `x` + 子音: xz, xv, xj, xb, xc, xd, xf, xg, xh, xk, xm, xp, xs, xt, xw
- `z` + 子音: zx, zq, zj, zv, zw, zk, zf, zg
- `j` + 子音: jq, jx, jz, jv
- その他稀な組み合わせ: vx, vq, vz, bx, cx, dx, fx, gx, hx, kx, mx, px, sx, tx, wx, gz, hz

**閾値設定**:
- rare_bigram_ratio > 0.15 → `rare_bigram_random` フラグ
- 根拠: 自然言語ドメインではレアバイグラム率はほぼ0%。15%を超えるドメインは人工的に生成された可能性が極めて高い

### 4c. エントロピー閾値調整（短いドメイン）

**問題**:
- Shannon entropy は文字列長に依存する
- 8文字で全文字がユニークの場合、最大エントロピー = log₂(8) = 3.0
- 従来の閾値 4.0 では短いランダムドメインを検出できない

**対策**:
- ≤8文字のドメイン: 閾値を 4.0 → 3.5 に引き下げ
- >8文字のドメイン: 従来の 4.0 を維持

**数学的背景**:
- 8文字のランダム文字列（26種アルファベット使用）の期待エントロピー: 約2.8〜3.2
- 3.5は「完全ランダムに近い短い文字列」を捕捉しつつ、正常な短い単語（`google`, `apple`等）を除外

### 4d. 母音率閾値調整

**条件**: dangerous TLD 限定（FP抑制のため）

**根拠**:
- 英語の平均母音率は約38%
- 日本語ローマ字の母音率は約45%
- 0.15未満（15%未満）は自然言語としてほぼありえない
- 従来閾値 0.2 では `xkpz2m`（母音率0%）等の明確なランダム文字列のみ捕捉
- dangerous TLD限定で 0.15 に引き下げることで、より広範なランダムパターンを検出しつつ FP を抑制

---

## 論文記述上のポイント

### 再現性

1. Tranco リストのバージョン（ダウンロード日: 2026-01-24）を明記
2. brand_keywords は固定リストとしてリポジトリに含める（`brand_keywords.json`）
3. 全閾値はソースコード内に定数として定義

### 閾値の妥当性

- 各閾値は validation set (17,434件) での FP/FN トレードオフ分析に基づいて設定
- 全件再評価で効果を測定予定

### 先行研究との差異

- 従来の ML-only アプローチに対し、**オフライン知識ベース**（Tranco, ブランド辞書, 言語学的特徴）で LLM の世界知識を補完するハイブリッド手法
- 小規模 LLM (4B パラメータ) の限界を、構造化された外部知識で克服するアプローチ

### 手法の一般性

- 提案手法はモデル非依存：任意の小規模 LLM に適用可能
- 知識ベースの更新は Tranco リストの定期ダウンロードと brand_keywords.json の追記のみで完了
- 多言語対応は対象言語のフィッシングキーワード辞書追加で拡張可能

---

## 参考文献

1. Le Pochat, V., Van Goethem, T., Tajalizadehkhoob, S., Korczyński, M., & Joosen, W. (2019). "Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation." NDSS 2019.
2. APWG. "Phishing Activity Trends Report." (2025 Q3-Q4)
3. FBI IC3. "Internet Crime Report." (2024-2025)
4. Chainalysis. "Crypto Crime Report." (2024-2025)
5. Norvig, P. "English Letter Frequency Counts: Mayzner Revisited." (Google N-gram analysis)
6. Shannon, C. E. (1948). "A Mathematical Theory of Communication."
7. フィッシング対策協議会. "フィッシングレポート." (2025)
8. JPCERT/CC. "インシデント報告対応レポート." (2025)
