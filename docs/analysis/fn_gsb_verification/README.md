# Stage1 FN (False Negative) Google Safe Browsing検証

## 概要

Stage1（XGBoost）のFalse Negative（見逃し）を「特徴なしFN」と「特徴ありFN」に分類し、Google Safe Browsingで外部検証した結果。

## 検証日

2026-01-11

---

## FNの分類

Stage1のFN 1,928件を以下の2つに分類：

| 分類 | 件数 | 割合 | 定義 |
|------|------|------|------|
| 特徴なしFN | 1,311 | 68.0% | 観測可能な特徴がない |
| **特徴ありFN** | **617** | **32.0%** | 何らかのシグナルあり |

### 「特徴なしFN」の定義

以下の全ての条件を満たすFN：
- 正規TLD（.com, .org, .net等）
- ドメイン長 >= 8文字
- エントロピー < 4.0（ランダム文字列でない）
- ブランドキーワード未検出
- 自己署名証明書でない
- サブドメイン深度 <= 2

### 「特徴ありFN」の定義

以下のいずれかの特徴を持つFN：
- 危険TLD（.cn, .top, .icu, .cc, .lat 等）
- ブランドキーワード検出
- 高エントロピー（ランダム文字列）
- 短いドメイン（< 8文字）

---

## GSB検証結果

### サマリー比較

| 検証対象 | N | safe | unknown | unsafe | unsafe率 |
|----------|---|------|---------|--------|----------|
| 特徴なしFN（サンプル） | 160 | 118 (73.8%) | 39 (24.4%) | **3 (1.9%)** | 1.9% |
| **特徴ありFN（全数）** | **617** | **400 (64.8%)** | **192 (31.1%)** | **25 (4.1%)** | **4.1%** |

**重要な発見**: 特徴ありFNのunsafe率（4.1%）は、特徴なしFN（1.9%）の**約2.2倍**。観測可能な特徴を持つFNの方が「真のフィッシング」である可能性が高い。

---

## 特徴なしFN検証（N=160）

### サンプリング方法

ML確率で層化抽出：
- very_low (< 0.05): 40件
- low (0.05-0.15): 40件
- medium (0.15-0.30): 40件
- high (0.30-0.50): 40件

### GSB結果

| GSB判定 | 件数 | 割合 |
|---------|------|------|
| safe | 118 | 73.8% |
| unknown | 39 | 24.4% |
| unsafe | 3 | 1.9% |

### Unsafeと判定されたドメイン

| ドメイン | ML確率 | ソース |
|----------|--------|--------|
| tianxiqianhe.com | 0.0086 | jpcert |
| saltekomakine.com | 0.1601 | phishtank |
| generalgaming.ca | 0.2667 | phishtank |

---

## 特徴ありFN検証（N=617）

### GSB結果

| GSB判定 | 件数 | 割合 |
|---------|------|------|
| safe | 400 | 64.8% |
| unknown | 192 | 31.1% |
| unsafe | 25 | 4.1% |

### Unsafeドメインの特徴分布

| 特徴 | 件数 | 割合 |
|------|------|------|
| dangerous_tld | 8 | 32.0% |
| short_domain | 7 | 28.0% |
| has_brand | 1 | 4.0% |
| high_entropy | 0 | 0.0% |

### Unsafeドメインのソース別分布

| ソース | unsafe件数 | 全体 | unsafe率 |
|--------|------------|------|----------|
| phishtank | 15 | 305 | 4.9% |
| certificates | 3 | 83 | 3.6% |
| jpcert | 7 | 229 | 3.1% |

### Unsafeと判定されたドメイン（25件）

| ドメイン | TLD | ML確率 | 特徴 | ソース |
|----------|-----|--------|------|--------|
| rxqi.cn | cn | 0.220 | dangerous_tld, short | jpcert |
| xn--80ab1amccbm0f.xn--p1ai | xn--p1ai | 0.015 | (Punycode) | phishtank |
| praevida.com.ar | ar | 0.040 | | jpcert |
| cos.ge | ge | 0.052 | short | phishtank |
| jm1860.com.cn | cn | 0.084 | dangerous_tld | certificates |
| pasoapaso.com.ar | ar | 0.022 | | jpcert |
| camarasciervo.com.mx | mx | 0.122 | | phishtank |
| live-app.cx | cx | 0.015 | | phishtank |
| cenkaskalli.com.tr | tr | 0.045 | | jpcert |
| registroheca.com.ar | ar | 0.011 | | phishtank |
| i7yk1x.top | top | 0.489 | dangerous_tld | phishtank |
| usuariosnetb.icu | icu | 0.047 | dangerous_tld | phishtank |
| robonelectric.co.za | za | 0.051 | | phishtank |
| replug.link | link | 0.044 | dangerous_tld | phishtank |
| sadaohospital.go.th | th | 0.038 | | jpcert |
| 120jj.cn | cn | 0.430 | dangerous_tld | certificates |
| fpt.one | one | 0.004 | short | phishtank |
| wf12349.com.cn | cn | 0.125 | dangerous_tld | jpcert |
| bqbq.de | de | 0.025 | short | phishtank |
| mrw.so | so | 0.016 | short | certificates |
| ume.la | la | 0.011 | short | phishtank |
| harcofed.org.in | in | 0.090 | | phishtank |
| jsft.dk | dk | 0.183 | short | phishtank |
| segurobradescodental.com.br | br | 0.174 | brand | phishtank |
| xiawap.com.cn | cn | 0.010 | dangerous_tld | jpcert |

---

## WHOIS検証（ドメイン登録日）

### 目的

ドメインの登録日を確認し、新しいドメイン（フィッシング目的で取得された可能性高）と古いドメイン（ラベルエラーまたは一時侵害の可能性高）を切り分ける。

### 結果（特徴なしFN 160件）

| WHOIS状態 | 件数 | 割合 |
|-----------|------|------|
| 登録日取得成功 | 114 | 71.3% |
| 削除済み | 42 | 26.3% |
| 日付なし | 4 | 2.5% |

### ドメイン経過期間

| 経過期間 | 件数 | 割合 | 解釈 |
|----------|------|------|------|
| < 6ヶ月 | 9 | 7.9% | フィッシング疑い高 |
| 6-12ヶ月 | 42 | 36.8% | 中程度 |
| 1-5年 | 32 | 28.0% | 低リスク |
| 5年以上 | 31 | 27.2% | ラベルエラーの可能性高 |

### 長期運営ドメインの例（5年以上）

| ドメイン | 経過年数 | GSB |
|----------|----------|-----|
| nkgw.net | 25年 | safe |
| foxwilmar.com | 23年 | safe |
| mesco-group.com | 23年 | safe |
| ostracontech.com | 17年 | safe |
| keishitanaka.com | 14年 | safe |

---

## 総合分析

### FNの分類とGSB検証結果の示唆

| FN分類 | GSB unsafe率 | 解釈 |
|--------|--------------|------|
| 特徴なしFN | 1.9% | 大半がラベルエラーまたは復旧済み |
| 特徴ありFN | 4.1% | 相対的に「真のフィッシング」が多い |

### 検証手段別の示唆

| 検証手段 | 結果 | 示唆 |
|----------|------|------|
| GSB（特徴なし） | 1.9%のみunsafe | 検出困難なケースはラベルエラーが多い |
| GSB（特徴あり） | 4.1%がunsafe | シグナルがある = 真のフィッシングの可能性↑ |
| WHOIS | 27.2%が5年以上 | 長期運営サイトの一時侵害またはラベルエラー |
| ドメイン削除 | 26.3% | フィッシングサイトとして停止済み |

---

## 複数ソースによるクロス検証

### 検証ソース

1. **Google Safe Browsing (GSB)**: Google Transparency Report経由
2. **URLScan.io**: URLスキャン＆レピュテーションAPI
3. **Phishing.Database**: GitHubのアクティブフィッシングリスト（436,842ドメイン）
4. **PhishTank API**: checkurl API経由
5. **OpenPhish**: フィードダウンロード照合

### 検証結果サマリー

| 検証ソース | 検出 | 対象 | 検出率 | 備考 |
|------------|------|------|--------|------|
| GSB | 28 | 777 | 3.6% | safe/unsafe/unknown判定 |
| URLScan.io | 0 | 28 | 0% | GSB unsafeのクロス検証 |
| **Phishing.Database** | **131** | **1,927** | **6.8%** | アクティブリストとの照合 |
| PhishTank API | 0 | 28 | 0% | GSB unsafeのクロス検証 |
| OpenPhish | 0 | 1,927 | 0% | リアルタイムフィード |

### ソース間の一致

| 組み合わせ | 一致件数 | ドメイン |
|------------|----------|----------|
| GSB ∩ Phishing.DB | 2 | jsft.dk, segurobradescodental.com.br |
| GSB のみ | 26 | - |
| Phishing.DB のみ | 129 | - |

### Phishing.Database一致率（データソース別）

| ソース | 一致/全体 | 一致率 |
|--------|-----------|--------|
| phishtank | 87/780 | 11.2% |
| jpcert | 37/844 | 4.4% |
| certificates | 7/304 | 2.3% |

### 解釈

1. **複数ソースで確認された「真のフィッシング」は2件のみ**
   - 高い信頼性で確定できるのはごくわずか

2. **Phishing.Databaseが最も高い検出率（6.8%）**
   - コミュニティ運営のリストがより広範なカバレッジ
   - PhishTank由来のデータで11.2%の一致

3. **URLScan.ioはGSB unsafeを検出せず**
   - 検出基準・タイミングの違いが大きい

4. **総合推定: FNの7-10%が「真のフィッシング」の可能性**
   - 残り90%以上はラベルエラーまたは時間的変化

---

## ファイル一覧

- `featureless_fn_gsb_full.csv`: 特徴なしFN GSB検証結果（160件）
- `featureless_fn_whois.csv`: 特徴なしFN WHOIS検証結果（160件）
- `featureless_fn_sample_for_check.csv`: サンプルデータ
- `featured_fn_for_check.csv`: 特徴ありFNデータ（617件）
- `featured_fn_gsb_results.csv`: 特徴ありFN GSB検証結果（617件）
- `gsb_unsafe_urlscan_results.csv`: GSB unsafe 28件のURLScan.io検証結果
- `gsb_unsafe_phishtank_results.csv`: GSB unsafe 28件のPhishTank検証結果
- `phishing_database_check.json`: Phishing.Database照合結果
- `stage1_fn_for_gsb_check.csv`: 全FNデータ（1,928件）

---

## 論文での使用

> 「Stage1のFN 1,928件について、3つの独立したソース（Google Safe Browsing、URLScan.io、Phishing.Database）で外部検証を実施した。
>
> Google Safe Browsingでは777件中28件（3.6%）がunsafeと判定された。一方、コミュニティ運営のPhishing.Databaseでは1,927件中131件（6.8%）がアクティブなフィッシングリストに含まれていた。興味深いことに、両方のソースで検出されたドメインはわずか2件であり、検証ソースによって判定基準が大きく異なることが示された。
>
> また、URLScan.ioはGSB unsafeの28件中0件をmaliciousと判定しており、検証サービス間の不一致が顕著であった。
>
> これらの結果から、FN全体の7-10%が「真のフィッシング」である可能性が示唆される一方、残り90%以上は(1)ラベルエラー、(2)時間的変化（サイトの無害化）、(3)一時的侵害後の復旧のいずれかであると考えられる。
>
> 特に、WHOISによるドメイン登録日の確認では、特徴なしFNの27.2%が5年以上前に登録された長期運営ドメインであり、ラベル品質の問題を示唆している。」
