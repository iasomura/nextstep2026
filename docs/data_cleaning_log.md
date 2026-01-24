# データクレンジング記録

## 概要

- **実施日**: 2026-01-21
- **目的**: VirusTotal調査に基づくラベリングエラーの除去
- **調査対象**: Stage1 FP/FN 2,172件

## 調査方法

1. Stage1（XGBoost）のFP/FNを抽出
2. VirusTotal APIで各ドメインの評価を取得
3. 以下の基準で削除対象を特定:
   - **trusted → 削除**: VTでmalicious > 0
   - **phishing → 削除**: VTでmalicious = 0 かつ harmless >= 60

## 削除対象サマリー

| データセット | 調査件数 | 削除ドメイン数 | 削除率 |
|-------------|---------|---------------|--------|
| trusted (FP) | 339 | 29 | 8.6% |
| phishing (FN) | 1,833 | 164 | 8.9% |
| **合計** | 2,172 | **193** | 8.9% |

## 実際の削除結果

実行日時: 2026-01-21

| テーブル | 削除レコード数 | 備考 |
|----------|---------------|------|
| trusted_certificates | 29 | FPラベルエラー |
| jpcert_phishing_urls | 162 | FNラベルエラー（重複含む） |
| certificates | 26 | FNラベルエラー |
| phishtank_entries | 22 | FNラベルエラー（重複含む） |
| **合計** | **239** | - |

※ 削除ドメイン数(193)と削除レコード数(239)の差は、同一ドメインの重複レコードによる

## trustedから削除（29件）

VTでmalicious検出されたドメイン = 実際は悪意あり

| domain | malicious | suspicious | harmless |
|--------|-----------|------------|----------|
| kra27s.cc | 14 | 0 | 50 |
| bahiscasino491.com | 10 | 0 | 53 |
| gooogles.site | 9 | 0 | 55 |
| 1fvpd.com | 5 | 0 | 57 |
| euchebnici.com | 4 | 1 | 58 |
| yeezy-450.com | 4 | 1 | 59 |
| zigzagslot.wiki | 4 | 0 | 61 |
| imandiri.id | 3 | 0 | 60 |
| bape-clothing.us | 2 | 0 | 62 |
| akaislot88.com | 2 | 0 | 60 |
| subhd.tv | 2 | 0 | 62 |
| aussie-pokies.club | 2 | 0 | 61 |
| talkwireless.info | 1 | 0 | 63 |
| zybls.com | 1 | 0 | 63 |
| unique-casino-en-ligne.com | 1 | 0 | 61 |
| oppa4d.sbs | 1 | 1 | 60 |
| xdmxw.com | 1 | 1 | 59 |
| sc66t.com | 1 | 0 | 60 |
| picclick.fr | 1 | 0 | 62 |
| mediananny.com | 1 | 0 | 63 |
| algopix.com | 1 | 0 | 63 |
| xn--cksr0a.life | 1 | 0 | 62 |
| kralbet602.com | 1 | 1 | 61 |
| physioneedsng.com | 1 | 0 | 62 |
| y2mate.com | 1 | 0 | 63 |
| gjqwzzb.cn | 1 | 0 | 62 |
| yjxmfyw.com | 1 | 0 | 60 |
| bjxcykj.com | 1 | 1 | 61 |
| america777.com | 1 | 0 | 62 |

## phishingから削除（164件）

VTでharmless>=60かつmalicious=0 = 実際は正規サイト

| domain | malicious | suspicious | harmless |
|--------|-----------|------------|----------|
| ea-quality.com | 0 | 0 | 65 |
| kp-law.jp | 0 | 0 | 65 |
| sanblasgolf.com | 0 | 0 | 65 |
| safhenegar.com | 0 | 0 | 65 |
| kemoproretail.com | 0 | 0 | 65 |
| retail-takasawa.co.jp | 0 | 0 | 64 |
| ashaviglobal.com | 0 | 0 | 64 |
| e-eisin.com | 0 | 0 | 64 |
| cafsrl.com.ar | 0 | 0 | 64 |
| archi.builders | 0 | 0 | 64 |
| nintendo.pe | 0 | 0 | 64 |
| delagroecuador.com | 0 | 0 | 64 |
| gtfotv.com | 0 | 0 | 64 |
| dyama.org | 0 | 0 | 64 |
| k-strategian.com | 0 | 0 | 64 |
| tanimukai.or.jp | 0 | 0 | 64 |
| nichirosoken.com | 0 | 0 | 64 |
| xn--90aemgtfodc1a8f.xn--80adxhks | 0 | 0 | 64 |
| zihi-seikotsuin.com | 0 | 0 | 64 |
| sakuraganka.com | 0 | 0 | 64 |
| nozominosato-nagashima.com | 0 | 0 | 64 |
| dinarama.org | 0 | 0 | 64 |
| inexs.jp | 0 | 0 | 64 |
| guriroom.blog | 0 | 0 | 64 |
| eyegeorgetown.com | 0 | 0 | 64 |
| largo-morioka.com | 0 | 0 | 64 |
| ilcaffetorinese.eu | 0 | 0 | 64 |
| xn--100-ti4buj8d5166a.com | 0 | 0 | 64 |
| gmimission.org | 0 | 0 | 64 |
| mollydefrank.com | 0 | 0 | 64 |
| qrto.org | 0 | 0 | 64 |
| samedayme.com | 0 | 0 | 64 |
| baccaratguide.jp | 0 | 0 | 64 |
| pay.hotmart.com | 0 | 0 | 64 |
| pramuangnue.com | 0 | 0 | 64 |
| forge.speedtest.cn | 0 | 0 | 63 |
| pasquinostefano.it | 0 | 0 | 63 |
| hgmc.net | 0 | 0 | 63 |
| socialport.io | 0 | 0 | 63 |
| elmo-danesh.ir | 0 | 0 | 63 |
| lexa.com.tr | 0 | 0 | 63 |
| oxx.jp | 0 | 0 | 63 |
| goldennumber.pk | 0 | 0 | 63 |
| reetentertainment.com | 0 | 0 | 63 |
| internetku.id | 0 | 0 | 63 |
| socalthesyndicate.com | 0 | 0 | 63 |
| felicity.jp | 0 | 0 | 63 |
| solutionscribe.fr | 0 | 0 | 63 |
| hpcc.org.cn | 0 | 0 | 63 |
| marketagricola.pe | 0 | 0 | 63 |

※ 上位50件のみ表示。全164件は `delete_from_phishing.csv` を参照

## 関連ファイル

- `artifacts/2026-01-17_132657/results/vt_investigation_results.csv` - VT調査全結果
- `artifacts/2026-01-17_132657/results/delete_from_trusted.csv` - trusted削除リスト
- `artifacts/2026-01-17_132657/results/delete_from_phishing.csv` - phishing削除リスト

## 実行SQLファイル

- `scripts/data_cleaning_complete.sql` - 最終実行SQL

## 備考

- データベースダンプは実施日に取得済み（20210121-rapids_data.backup）
- 削除実行完了: 2026-01-21
- 次のステップ: 01ノートブック再実行 → prepared_data.pkl再生成 → モデル再学習・再評価

---

# Stage3 データクレンジング記録

## 概要

- **実施日**: 2026-01-22
- **目的**: Stage3（AI Agent）評価結果のVirusTotal調査に基づくラベリングエラーの除去
- **調査対象**: Stage3 FP/FN 319件（3000件評価より抽出）

## 調査方法

1. evaluate_e2e.py で3000件サンプル評価を実施
2. Stage3（AI Agent）のFP 128件、FN 191件を抽出
3. VirusTotal APIで各ドメインの評価を取得
4. 以下の基準で削除対象を特定:
   - **FP（trusted）→ 削除**: VTでmalicious > 0
   - **FN（phishing）→ 削除**: VTでmalicious = 0 かつ harmless >= 60

## 削除対象サマリー

| データセット | 調査件数 | 削除ドメイン数 | 削除率 |
|-------------|---------|---------------|--------|
| FP (trusted) | 128 | 25 | 19.5% |
| FN (phishing) | 191 | 21 | 11.0% |
| **合計** | 319 | **46** | 14.4% |

## 削除詳細

### trustedから削除（25件）

VTでmalicious > 0 = 実際は悪意あり

| domain | malicious | suspicious |
|--------|-----------|------------|
| qs20k.com | 11 | 0 |
| clomiphene.shop | 9 | 0 |
| dice-dental.asia | 4 | 0 |
| gittttttttt.top | 2 | 0 |
| vigilanciaweb.cl | 2 | 0 |
| 79kingg.me | 2 | 0 |
| anyday.cc | 2 | 0 |
| tk88.live | 1 | 0 |
| 2025-kra32.cc | 1 | 1 |
| rankway.pw | 1 | 0 |
| sportsentry.ne.jp | 1 | 0 |
| lfzjhg.com | 1 | 0 |
| byteshort.xyz | 1 | 0 |
| darknetonionmarkets.shop | 1 | 0 |
| zxc3373.xyz | 1 | 0 |
| palaugov.pw | 1 | 0 |
| juhuadh.top | 1 | 0 |
| bcgame.top | 1 | 0 |
| thefreshfind.shop | 1 | 0 |
| academy-students.info | 1 | 0 |
| plumenetwork.xyz | 1 | 0 |
| rentalsz.com | 1 | 0 |
| kinguploadf2m15.xyz | 1 | 0 |
| hydroxychloroquine.click | 1 | 0 |
| kiyevlyanka.info | 1 | 0 |

### phishingから削除（21件）

VTでharmless >= 60 かつ malicious = 0 = 実際は正規サイト

| domain | source | harmless |
|--------|--------|----------|
| d.adroll.com | phishtank | 65 |
| trippleaaaclub.com | certificates | 64 |
| verdehalago.com | jpcert | 63 |
| japanliebe.com | jpcert | 63 |
| elektrologos.net | jpcert | 63 |
| studio-happyvalley.com | jpcert | 63 |
| namastejapan.org | jpcert | 62 |
| businessfreedomspeakingacademy.com | phishtank | 62 |
| turutaya.com | jpcert | 62 |
| ironheartsecurity.com | jpcert | 62 |
| iafricafood.com | jpcert | 62 |
| enstp.cm | jpcert | 62 |
| dixielion.com | jpcert | 62 |
| apple-updateaddcard.com | jpcert | 61 |
| tjsytgg.com | jpcert | 61 |
| adikarta.net | jpcert | 61 |
| hs-supplies.co.za | jpcert | 61 |
| healthy-call.com | jpcert | 61 |
| rmptravelinternational.com | jpcert | 61 |
| hvitstentimepieces.com | certificates | 61 |
| haislife.com | certificates | 60 |

## テーブル別削除件数

| テーブル | 削除件数 | 理由 |
|----------|---------|------|
| trusted_certificates | 25 | VT malicious > 0 |
| jpcert_phishing_urls | 16 | VT harmless >= 60 |
| phishtank_entries | 2 | VT harmless >= 60 |
| certificates | 3 | VT harmless >= 60 |
| **合計** | **46** | - |

## 実行SQLファイル

- `scripts/data_cleaning_stage3.sql`

## 関連ファイル

- `artifacts/2026-01-21_152158/results/stage3_fp_fn_domains.csv` - 調査対象リスト
- `artifacts/2026-01-21_152158/results/stage3_vt_investigation_results.csv` - VT調査結果

## 修正後の性能推定

Stage3ラベルエラーを考慮した場合の性能:

| 指標 | 修正前 | 修正後 | 改善 |
|------|--------|--------|------|
| FP | 128 | 103 | -25 |
| FN | 191 | 170 | -21 |
| Precision | 77.9% | 82.1% | +4.2pt |
| Recall | 70.2% | 73.5% | +3.3pt |
| コスト削減 (vs Stage1) | 5.4% | 17.3% | +11.9pt |

## 備考

- Stage1クレンジング（193件）後に3000件評価を実施
- Stage3クレンジングは追加で46件を特定
- 累計削除対象: 193 + 46 = 239ドメイン（一部重複の可能性あり）
