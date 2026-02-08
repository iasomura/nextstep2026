# Mori参考論文 読み取りメモ（paper_outline更新用）

作成日: 2026-02-07

目的: `docs/paper/paper_outline.md` を更新する際に、`docs/paper/mori/` 配下の既存論文の**書き方（主張提示順・評価提示順・トレードオフの扱い）**を参照する。

このメモは「本文の主張」ではなく、**構成・論旨の見せ方**の参考情報として使う。

## 読み込んだ論文一覧（37本）

- atis2017_promotional_attacks.pdf (conferences, 2017, ATIS)
- esorics2018_fake_reviews.pdf (conferences, 2018, ESORICS)
- eurousec2019_password_language.pdf (conferences, 2019, EUROUSEC)
- imc2019_shamfinder.pdf (conferences, 2019, IMC)
- infocom2014_log_factorization.pdf (conferences, 2014, INFOCOM)
- ndss2020_melting_pot_origins.pdf (conferences, 2020, NDSS)
- ndss2023_browser_permissions.pdf (conferences, 2023, NDSS)
- pam2021_covid19_domains.pdf (conferences, 2021, PAM)
- pam2023_bimi.pdf (conferences, 2023, PAM)
- pets2022_exposure_notification.pdf (conferences, 2022, PETS)
- soups2015_text_inconsistencies.pdf (conferences, 2015, SOUPS)
- tma2015_sfmap.pdf (conferences, 2015, TMA)
- woot2015_routedetector.pdf (conferences, 2015, WOOT)
- woot2018_rf_retroreflector.pdf (conferences, 2018, WOOT)
- account_existence_privacy.pdf (journals)
- appraiser_android_clone.pdf (journals)
- auction_purchase_history_leak.pdf (journals)
- audio_hotspot_attack.pdf (journals)
- browser_permissions_inconsistency.pdf (journals)
- clap_android_pua_dns.pdf (journals)
- hardware_trojan_em_leakage.pdf (journals)
- human_mobility_sensors.pdf (journals)
- ip_spatial_malicious_websites.pdf (journals)
- malware_http_header.pdf (journals)
- malware_network_behavior.pdf (journals)
- malware_report_sandbox.pdf (journals)
- mobile_app_behavior_description.pdf (journals)
- mobile_app_vulnerabilities.pdf (journals)
- online_banking_fraud_detection.pdf (journals)
- password_linguistic_culture.pdf (journals)
- same_origin_policy_rehost.pdf (journals)
- security_qa_non_experts.pdf (journals)
- social_account_side_channel.pdf (journals)
- tls_cert_phishing_patterns.pdf (journals)
- vr_apps_privacy_security.pdf (journals)
- weak_crypto_android_apps.pdf (journals)
- web_tracking_detection.pdf (journals)

## 構成・論旨に関する観察（本論文に効く点）

1. **主結果（定量値）を早い段階で提示し、その後に設計・要因分析へ進む**構成が多い。
   - 例: IMC/PAM 系の測定論文では、Abstract/Introductionでデータ規模と主要観測を先に提示し、RQごとに分解して説明する。
2. **運用上の制約（計算コスト・検知コスト）やトレードオフは、主結果を示した後に「調整可能な設計パラメータ」として議論する**書き方が自然。
3. **制限・妥当性への脅威は、導入で強調し過ぎず、後半（Discussion/Threats）で整理する**のが一般的。
4. セキュリティ検知・観測の文脈では、**観測可能な前段シグナル（例: ドメイン文字列、TLS証明書、ログ）を活用する動機付け**を導入で簡潔に示し、適用範囲は後段で明確化する流れが多い。

## paper_outline.md への反映（今回の更新で行ったこと）

- **反映1: 主張の提示順を「全体性能（F1改善）→投入制御→グレーゾーン救済＋説明」に揃えた。**
  - 1.4（貢献）と 6章（まとめ）で、全体性能の改善を先頭に置き、その後に運用上の強み（call rate/auto-decision error）と、Agent/ルール統合の価値（difficult subsetでのRecall改善＋監査可能な根拠）を続けた。
- **反映2: Table 3 を「補助」ではなくヘッドライン結果として扱う書き方に変更した。**
  - RQ体系は維持しつつ、評価節では最初に全体性能（Table 3）を提示してから、RQ1（投入制御）へ入る流れを明文化した。
- **反映3: スコープ/一般化可能性の記述を、防御ではなく「移植性（モデル非依存性）」として前向きに表現した。**

## 直接関連が強い参考（テーマ接続の観点）

- `tls_cert_phishing_patterns.pdf`: HTTPS普及下でのフィッシングとTLS証明書の観測可能性（証明書フットプリント）を動機付けとして扱える。
- `pam2021_covid19_domains.pdf`: RQを明示して測定結果を積み上げる書き方の参考になる。
- `imc2019_shamfinder.pdf`: ドメイン文字列の視覚的悪用（homoglyph）を扱う検知・測定論文として、誤り分析や議論の組み立てが参考になる。
