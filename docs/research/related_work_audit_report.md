# 関連研究メモ 引用監査報告書

**監査日**: 2026-02-06
**監査対象**: `docs/research/related_work.md`（全14セクション、参考文献44件）
**監査方法**: 全44件のURLを実アクセスし、タイトル・著者・会場・年・数値を原文と照合

---

## A. エグゼクティブサマリ

**偽情報リスク: 中〜高**

- **文献44件中、存在確認OK: 42件、問題あり: 2件（R20 DOI誤り、R41 著者誤り）**
- **会場誤り: 1件（R30: NordSec → 正しくはSecureComm）**
- **数値の裏取り不能: 2件（R14 XGBoost 99.65%、R13 CNN-LSTM 93.26%）**
- **比較不能な性能比較を「公平な比較」と称している箇所あり（§11.2）**
- **「先行研究に見られない」「本研究が先駆的」等の強い新規性主張が根拠不足（§10.2, §13.7）**
- **出典不明の引用文が2箇所（§4.4, §5.3）**
- **査読なしプレプリントが査読論文と同列に扱われている箇所が複数**

**結論**: このまま論文に転載すると、誤引用（R20, R30, R41）と誇張（§11.2の比較、新規性主張）により査読で指摘される可能性が高い。Critical 5件、Major 12件の修正が必要。

---

## B. 監査表

### B-1. 文献の存在確認・書誌整合チェック

| Ref ID | 文献（メモ記載） | 存在確認 | 書誌一致 | 種別(査読区分) | 問題点 | 重大度 |
|--------|--------------|---------|---------|-------------|--------|--------|
| R01 | Evolution of Phishing Detection with AI | OK | タイトル不完全 | プレプリント(arXiv) | 副題欠落。査読なし | Minor |
| R02 | Two-Stage DL Framework for Phishing Email | OK | タイトル不完全 | 査読あり(MDPI) | 「Based on Persuasion Principles」欠落 | Minor |
| R03 | Dual-layer architecture for phishing and spam | OK | タイトル不完全 | 査読あり(Elsevier) | 「email detection」欠落 | Minor |
| R04 | PhishDebate | OK | 一致 | プレプリント(arXiv) | 数値4件全て照合OK。査読なし注意 | OK |
| R05 | MultiPhishGuard | OK | 一部不一致 | プレプリント(arXiv) | **「ACM CCS 2025投稿」が検証不能** | Major |
| R06 | Debate-Driven Multi-Agent LLMs | OK | 一致 | 査読あり(IEEE ISDFS) | OK | OK |
| R07 | Small Language Models for Phishing | OK | タイトル不完全 | プレプリント(arXiv) | 副題欠落。査読なし | Minor |
| R08 | Improving Phishing Email Detection of Small LLMs | OK | タイトル微修正要 | プレプリント(arXiv) | 正式名は「...Performance of Small Large Language Models」 | Minor |
| R09 | Benchmarking 21 Open-Source LLMs | OK | タイトル不正確 | 査読あり(MDPI) | 正式は「Phishing **Link**」「with Prompt Engineering」。F1=82.6%は**平均値**（最高91.24%） | Major |
| R10 | How Can We Effectively Use LLMs | OK | タイトル不完全 | プレプリント(arXiv) | 副題欠落 | Minor |
| R11 | Benchmarking LLMs for Zero-shot Phishing | OK | タイトル不正確 | ワークショップ(NeurIPS) | 正式は「Zero-shot **and Few-shot**」。スコープ変わる | Major |
| R12 | EXPLICATE | OK | 一致 | プレプリント(arXiv) | 数値3件照合OK。査読なし注意 | OK |
| R13 | IoT Phishing XAI | OK | 一致 | 査読あり(Springer) | CNN-LSTM 93.26%の裏取り不能 | Major |
| R14 | Explainable Phishing for Sustainable Cyber | OK | タイトル不完全 | 査読あり(Nature) | **XGBoost 99.65%の裏取り不能**（別ソースでは99.17%） | Major |
| R15 | ZdAD-UML | OK | 一致 | 査読あり(Elsevier) | F1 100%は**標準評価上の値**。未知データでは99.99% | Major |
| R16 | Automated AI-Driven Phishing Zero-Day | OK | 年不一致 | 査読あり(Springer) | **出版日は2026年1月**（会議は2025） | Major |
| R17 | X-Phishing-Writer | OK | 一致 | 査読あり(ACM TALLIP) | OK | OK |
| R18 | Multilingual Email Phishing OSINT | OK | 一致 | プレプリント(arXiv) | RF 97.37% 照合OK。査読なし | OK |
| R19 | KnowPhish | OK | 一致 | 査読あり(USENIX Sec) | 20,000ブランド照合OK | OK |
| R20 | PhishIntel | OK | **DOI誤り** | デモ(ACM WWW) | **提示DOIはKnowPhishのもの。正しいDOI: 10.1145/3701716.3715192** | **Critical** |
| R21 | PhishAgent | OK | URL未記載 | 査読あり(AAAI Oral) | Oral確認済。DOI: 10.1609/aaai.v39i27.35003 | Minor |
| R22 | Brand Domain ID Features | OK | 一致 | 査読あり(Springer ACNS WS) | 正式会場はACNS 2025 Workshop | Minor |
| R23 | Unmasking Phishers | OK | 一致 | 査読あり(Elsevier) | F1=0.77/0.89 照合OK | OK |
| R24 | ML models for phishing from TLS | OK | タイトル略称 | 査読あり(Springer) | 「ML」→正式は「Machine learning」 | Minor |
| R25 | An effective detection approach | OK | タイトル不完全 | 査読あり(Nature) | 「using URL and HTML features」欠落。F1=96.38%照合OK | Minor |
| R26 | Enhancing Phishing Detection XGBoost | OK | タイトル不完全 | **プレプリント(SSRN)** | **査読なし**。「Techniques」欠落。99.80%照合OK | Major |
| R27 | Phishing URL Detection XGBoost IJRASET | OK | 一致 | 査読あり(IJRASET) | 97.27% AUC=0.9957 照合OK | OK |
| R28 | Phicious (CT + Passive DNS) | OK | 一致 | 査読あり(RAID) | 「80+特徴量」は全文未確認 | Minor |
| R29 | Finding Phish in a Haystack | OK | タイトル不完全 | 査読あり(ARES) | 副題欠落 | Minor |
| R30 | Phish-Hook | OK | **会場誤り** | 査読あり | **NordSec 2019は誤り。正しくはSecureComm 2019** | **Critical** |
| R31 | Anomaly Detection in CT Logs | OK | 一致 | プレプリント(arXiv) | 査読なし（CEUR-WSにも掲載） | Minor |
| R32 | Graph-Based Phishing Certificate-DNS | OK | 一致 | **プレプリント(Preprints.org)** | **査読なし**。73%/+15.6pp照合OK | Major |
| R33 | Malicious X.509 Certificates ML | OK | 一致 | 査読あり(MDPI) | 95.9%/98.2%照合OK | OK |
| R34 | TLS Certificate Patterns (Sakurai) | OK | 一致 | 査読あり(IEEE+JCSM) | EuroSPW版のタイトルは別（「Discovering HTTPSified...」） | Minor |
| R35 | Malcertificate GCN | OK | タイトル不完全 | 査読あり(MDPI) | 「Research and Implementation of」欠落 | Minor |
| R36 | Brand Domain ID Features (§13) | OK | 一致 | 査読あり(Springer ACNS WS) | RF 99.7%/99.8%照合OK | OK |
| R37 | DomainDynamics | OK | 一致 | 査読あり(IEEE+Elsevier) | DR 82.58%/FPR 0.41%照合OK | OK |
| R38 | Certifiably Vulnerable | OK | 一致 | 査読あり(IEEE EuroS&P) | OK | OK |
| R39 | Uninvited Guests (CTPOT) | OK | 一致 | 査読あり(USENIX Sec) | NSA賞確認済（第11回、2023年ノミネート/2024年授与） | OK |
| R40 | CT Revisited | OK | 一致 | 査読あり(NDSS) | OK | OK |
| R41 | C-BERT | OK | **著者・タイトル誤り** | ワークショップ(AISec/CCS) | **著者「Arkhangorodsky et al.」は検証不能。正しくはShashwat, Hahn, Millar, Ou。タイトルにC-BERTは含まれない** | **Critical** |
| R42 | Enhanced Malicious Traffic TLS | OK | 一致 | 査読あり(Springer) | 94.85%照合OK | OK |
| R43 | Ensemble Learning TLS Phishing | OK | タイトル微修正要 | 査読あり(Springer) | 正式は「An ensemble learning approach for detecting...」 | Minor |
| R44 | Effectiveness of CT Check | OK | 会場不明確 | 査読あり(IEEE) | **正式会場はINDIACom 2023**（「IEEE 2023」は曖昧） | Minor |

### B-2. 主張検証サマリ

| 主張ID | 箇所 | 主張内容 | 検証結果 | 重大度 |
|--------|------|---------|---------|--------|
| C01 | §2.1 L65 | PhishDebate: Single→Multi で F1 74.69%→94.14% | OK（原論文Table I/II確認） | - |
| C02 | §3.2 L93 | Qwen-2.5-1.5B 精度 0.388→0.860 (122%向上) | OK（原論文確認。正式名は-Instruct付き） | Minor |
| C03 | §3.3 L101 | 21 LLMs Few-shot 平均F1=82.6% | **要修正**: 「平均」の明記なし。最高値91.24%を隠蔽 | Major |
| C04 | §4.1 L128 | EXPLICATE: 98.4% (accuracy, precision, recall, F1全て) | OK（原論文確認）。**全指標が同一値は異例→赤旗** | Minor |
| C05 | §4.4 L162 | 引用文 "Regulatory frameworks..." | **出典不明**。どの論文からの引用か記載なし | Major |
| C06 | §5.1 L172 | ZdAD-UML: RF-AE F1 100% | **要注釈**: 標準評価の値。未知データでは99.99%。フィッシング専用ではない | Major |
| C07 | §5.3 L194 | 引用文 "LLMs currently underperform..." | **出典不明**。どの論文からの引用か記載なし | Major |
| C08 | §6.3 L229-232 | クロスリンガル転移: Precision 66.7%→14.8% | **出典不明**。どの論文のどの実験の数値か記載なし | **Critical** |
| C09 | §10.2 L350 | 「この二重利用は先行研究に見られない」 | **未確認**。網羅的サーベイの根拠なし | Major |
| C10 | §10.3 L388 | 「フィッシングサイトが誕生する前に候補を強力に検知できる」 | **誇張**: 現システムはCT Log監視ではなく事後評価。先制検知は未実装 | **Critical** |
| C11 | §11.2 L405-416 | 「公平な比較」として本研究F1 98.60% vs PhishDebate 94.14% | **比較不能**: データセット・入力情報・クラス分布が全て異なる | Major |
| C12 | §13.7 L738 | 「フィッシング検出への適用は本研究が先駆的」 | **未確認**。網羅的調査の証拠なし | Major |

---

## C. Critical一覧（5件）

### C-1. R20 (PhishIntel): DOI誤り — 別の論文を指している

**箇所**: §7.2 (L280)、参考文献20
**問題**: 提示DOI `10.5555/3698900.3698945` はKnowPhish (USENIX Security 2024) のACM DL登録を指しており、PhishIntel (WWW 2025 Demo) ではない。
**正しいDOI**: `10.1145/3701716.3715192`
**リスク**: 論文に載せると**誤引用**。査読者が追跡した場合、別の論文に辿り着く。

### C-2. R30 (Phish-Hook): 会場名の誤り

**箇所**: §13.1.3 (L533-540)、参考文献30
**問題**: 「NordSec 2019」と記載されているが、実際は **SecureComm 2019** (15th EAI International Conference on Security and Privacy in Communication Networks)。Springer LNCS vol. 305。
**DOI**: `10.1007/978-3-030-37231-6_18` は確認済み（SecureCommの論文集）。
**リスク**: 会場名の誤りは研究不正を疑われる。

### C-3. R41 (C-BERT): 著者名の誤り

**箇所**: §13.4.1 (L661)、参考文献40
**問題**: 著者を「Arkhangorodsky et al. (Rapid7)」と記載しているが、原論文の著者は **Kumar Shashwat, Francis Hahn, Stuart Millar, Xinming Ou**。「Arkhangorodsky」という著者は確認できない。
**追加問題**: 論文タイトルに「C-BERT」は含まれない（C-BERTは手法名）。正式タイトルは "Using LLM Embeddings with Similarity Search for Botnet TLS Certificate Detection"。
**リスク**: 著者誤りは査読で致命的。

### C-4. C08: 出典不明の数値（クロスリンガル転移）

**箇所**: §6.3 (L229-232)
**問題**: 「Precision 66.7% → 14.8%」の数値が**どの論文のどの実験**から引用されたか記載がない。§6.1のX-Phishing-Writerか§6.2のMultilingualか、あるいは別の論文かが不明。
**リスク**: 出典不明の数値を論文に載せると捏造扱いの可能性。

### C-5. C10: 先制検知の誇張

**箇所**: §10.3 (L386-388)
**問題**: 「フィッシングサイトが誕生する前に候補を強力に検知できることを意味する」と記載しているが、現システムは**CT Logのリアルタイム監視システムではなく、収集済み証明書データの事後分類器**である。Phicious (R28) やDomainDynamics (R37) のようなCT Log監視パイプラインとは設計が異なる。
**リスク**: 実装されていない能力を主張すると査読で致命的な指摘を受ける。

---

## D. Major一覧（12件）

### D-1. R05: 「ACM CCS 2025投稿」が検証不能

**箇所**: §2.2 (L67)
**問題**: 「arXiv, May 2025 / ACM CCS 2025投稿」と記載されているが、論文本文にもメタデータにもCCS投稿の記述はない。
**対応**: 「arXiv, May 2025」のみに修正。投稿先が確認できない場合は記載しない。

### D-2. R09: F1=82.6%の文脈不足

**箇所**: §3.3 (L101)
**問題**: F1=82.6%は21モデルのFew-shot **平均値**であり、最高値は91.24% (Llama3.3_70b)。「平均」の明記なしでは最高性能と誤認される。
**対応**: 「Few-shot での平均 F1=82.6%（最高 91.24%）」に修正。

### D-3. R11: タイトルのスコープ変更

**箇所**: §3.5 (L111)
**問題**: 「Zero-shot」のみと記載しているが、正式タイトルは「Zero-shot **and Few-shot**」。論文のスコープを狭く誤認させる。
**対応**: 正式タイトルに修正。

### D-4. R14: XGBoost 99.65%の数値未確認

**箇所**: §4.3 (L148)
**問題**: 原論文のフルテキストにアクセスできず、99.65%を確認できない。別ソースでは99.17%との記載あり。
**対応**: フルテキストで確認するか、「[要確認]」を付記。

### D-5. R15: F1 100%の赤旗

**箇所**: §5.1 (L172)
**問題**: RF-AE F1 100%は標準評価上の値であり、未知データでは99.99%。また、**フィッシング検出ではなくネットワーク侵入検知**の論文。100%の報告自体が過学習の疑い。
**対応**: 「標準評価でF1 100%（未知データ99.99%）」と明記。フィッシング固有でないことを注記。

### D-6. R16: 出版年の不一致

**箇所**: §5.2 (L175-176)
**問題**: 「Springer, 2025」と記載しているが、出版日は**2026年1月2日**。会議はeHaCON 2025だが、論文集の出版は2026年。
**対応**: 「eHaCON 2025 (Springer, published 2026)」に修正。

### D-7. R26: SSRNは査読なし

**箇所**: §9.1 (L315-318)
**問題**: SSRN掲載論文だが、査読の有無が明記されていない（§9.1には「査読」表記なし）。SSRNはプレプリントサーバであり査読なし。99.80%の数値を査読済み論文と同列に扱うのは不適切。
**対応**: 「SSRN（査読なし）」と明記。

### D-8. R32: Preprints.orgは査読なし

**箇所**: §13.1.5 (L550-555)
**問題**: Preprints.org掲載論文。73%・+15.6ppの数値は確認済みだが、査読を経ていない。§13.7のまとめ（L737）で「先制検知が可能: 73%を検知可能」と査読済み研究の知見と同列に記載。
**対応**: 「プレプリント（査読なし）[要追加調査]」と明記。

### D-9. §4.4/§5.3: 出典不明の引用文

**箇所**: §4.4 (L162), §5.3 (L194)
**問題**:
- L162: "Regulatory frameworks require more and more AI-driven decisions..." — どの論文からの引用かが不明。
- L194: "LLMs currently underperform compared to ML and DL methods..." — 同上。
**対応**: 各引用に出典論文名と該当箇所を明記。確認できなければ削除。

### D-10. §11.2: 比較不能な性能比較

**箇所**: §11.2 (L405-416)
**問題**: 「システム全体での比較（公平な比較）」と題しているが、以下の点で公平ではない:
- **データセットが異なる**（本研究: 127,754件バランスデータ vs PhishDebate: 独自データセット）
- **入力情報が異なる**（証明書のみ vs URL+HTML+Content）
- **クラス分布が異なる**
- **タスク定義が異なる**（本研究はhandoffされたML困難ケースを含むシステム全体 vs PhishDebate単体）

§11.1で「直接比較は不適切」と注意書きがあるにもかかわらず、§11.2で「公平な比較」と銘打つのは矛盾。
**対応**: 「公平な比較」→「参考値としての比較（データセット・条件が異なる点に注意）」に修正。比較表に「データセット」「サンプル数」列を追加。

### D-11. §10.2 C09: 「先行研究に見られない」の根拠不足

**箇所**: §10.2 (L350)
**問題**: 「証明書の二重活用...この二重利用は先行研究に見られない」は、網羅的サーベイを行った証拠がない「初/唯一」型の主張。C-BERT (R41) はLLM埋め込みで証明書を解釈しており、完全に「見られない」とは言い切れない。
**対応**: 「我々の調査範囲では、証明書データをMLの数値特徴量とLLMのテキスト入力として二重に活用する手法は報告されていない [要追加調査]」

### D-12. §13.7 C12: 「本研究が先駆的」の根拠不足

**箇所**: §13.7 (L738)
**問題**: 「フィッシング検出への適用は本研究が先駆的」は、網羅的サーベイの証拠がない強い主張。
**対応**: 「我々の調査範囲では、LLMエージェントと証明書特徴を組み合わせたフィッシング検出の報告は見当たらなかった [要追加調査]」

---

## E. 修正文（安全な言い換え案）

### E-1. §2.2 L67（R05 MultiPhishGuard）
- **元文**: `arXiv, May 2025 / ACM CCS 2025投稿`
- **推奨文**: `arXiv, May 2025`

### E-2. §3.3 L101（R09 21 LLMs）
- **元文**: `Few-shot で平均 F1=82.6%、9B以上が最高性能`
- **推奨文**: `Few-shot で21モデル平均 F1=82.6%（最高 91.24%, Llama3.3-70B）。9B以上のモデルが上位を占める`

### E-3. §3.5 L111（R11）
- **元文**: `Benchmarking LLMs for Zero-shot Phishing URL Detection (NeurIPS 2025 Workshop)`
- **推奨文**: `Benchmarking Large Language Models for Zero-shot and Few-shot Phishing URL Detection (NeurIPS 2025 Workshop)`

### E-4. §4.3 L148（R14）
- **元文**: `XGBoostが99.65%の精度`
- **推奨文**: `XGBoostが高精度を達成 [要確認: 原論文では99.65%または99.17%の報告あり]`

### E-5. §5.1 L172（R15）
- **元文**: `Random Forest-AE で精度100%, F1 100%`
- **推奨文**: `Random Forest-AE で標準評価上F1 100%（未知データでは99.99%） [注: ネットワーク侵入検知であり、フィッシング固有ではない]`

### E-6. §6.3 L229-232（出典不明数値）
- **元文**: テーブル `英語（ソース） 66.7%` / `翻訳後（ターゲット） 14.8%`
- **推奨文**: `[出典要追記: この数値がどの論文のどの実験に基づくか明記すること]`

### E-7. §10.2 L350（新規性主張）
- **元文**: `この二重利用は先行研究に見られない。`
- **推奨文**: `我々の調査範囲では、同一の証明書データをML特徴量とLLMテキスト入力として二重に活用する手法は報告されていない。`

### E-8. §10.3 L386-388（先制検知の誇張）
- **元文**: `証明書からPhishingサイトが検知できるということは、フィッシングサイトが誕生する前に候補を強力に検知できることを意味する。`
- **推奨文**: `本研究で用いた証明書特徴はCT Logから取得可能であり、CT Log監視パイプラインと組み合わせることで、サイト稼働前の早期検知への応用が期待される。ただし、本研究の現時点での評価は収集済みデータに対する事後分類であり、リアルタイム早期検知の実証は今後の課題である。`

### E-9. §11.2 L405（比較の修正）
- **元文**: `### 11.2 システム全体での比較（公平な比較）`
- **推奨文**: `### 11.2 システム全体での性能比較（参考値）`（注記追加: 「各研究は異なるデータセット・入力情報・評価条件で評価されており、直接的な優劣比較は困難である。参考値として並記する。」）

### E-10. §11.2 L416
- **元文**: `**結果**: システム全体では**本研究がPhishDebateより+4.5pp優位**`
- **推奨文**: 削除、または「本研究のF1はPhishDebateの報告値より4.5pp高いが、データセット・入力条件が異なるため直接比較は困難である。」

### E-11. §13.1.3 L533-540（R30 会場修正）
- **元文**: `NordSec 2019, Springer LNCS`
- **推奨文**: `SecureComm 2019 (15th EAI International Conference on Security and Privacy in Communication Networks), Springer LNCS`

### E-12. §13.4.1 L661（R41 著者・タイトル修正）
- **元文**: `**著者**: Arkhangorodsky et al. (Rapid7)`
- **推奨文**: `**著者**: Kumar Shashwat, Francis Hahn, Stuart Millar, Xinming Ou`
- **元文（タイトル）**: `C-BERT: LLM Embeddings with Similarity Search for Botnet TLS Certificate Detection`
- **推奨文**: `Using LLM Embeddings with Similarity Search for Botnet TLS Certificate Detection (手法名: C-BERT)`

### E-13. §13.7 L738（新規性主張）
- **元文**: `C-BERT（ボットネット対象）のみが先行し、フィッシング検出への適用は本研究が先駆的`
- **推奨文**: `我々の調査範囲では、LLMエージェントを証明書ベースのフィッシング検出に適用した研究は確認されなかった。C-BERT [40] はLLM埋め込みを証明書分析に適用した先行事例だが、対象はボットネット検出である。`

---

## F. ToDo（差し戻し指示）

### 優先度1: Critical修正（論文提出前に必須）

| # | 対象 | 指示 |
|---|------|------|
| F-1 | R20 (PhishIntel) | 正しいDOI `10.1145/3701716.3715192` に差し替え。正式タイトル・著者をACM DLから取得して参考文献を修正 |
| F-2 | R30 (Phish-Hook) | 会場を「SecureComm 2019」に修正。§13.1.3と参考文献30の両方を更新 |
| F-3 | R41 (C-BERT) | (a) 著者を「Shashwat, K., Hahn, F., Millar, S., Ou, X.」に修正 (b) タイトルから「C-BERT:」を削除し正式タイトルに (c) §13.4.1と参考文献40の両方を更新 |
| F-4 | §6.3 (L229-232) | Precision 66.7%→14.8%の数値の出典を特定し明記。出典不明なら削除 |
| F-5 | §10.3 (L386-388) | 先制検知の記述をE-8の修正文に差し替え。現システムの能力と将来の応用可能性を明確に区別 |

### 優先度2: Major修正（査読前に修正推奨）

| # | 対象 | 指示 |
|---|------|------|
| F-6 | R05 (§2.2) | 「ACM CCS 2025投稿」を削除 |
| F-7 | R09 (§3.3) | F1=82.6%が「平均値」であることを明記。最高値91.24%も併記 |
| F-8 | R14 (§4.3) | XGBoost 99.65%をフルテキストで確認。確認できない場合は「[要確認]」付記 |
| F-9 | R15 (§5.1) | F1 100%に「標準評価上」と注記。フィッシング固有でないことを明記 |
| F-10 | §4.4/§5.3 | 引用文2箇所の出典論文名・セクションを特定して記載 |
| F-11 | §11.2 | 「公平な比較」→「参考値としての比較」に修正。比較条件の差異を注記 |
| F-12 | §10.2/§13.7 | 「先行研究に見られない」「先駆的」→「我々の調査範囲では」に弱化 |
| F-13 | R26/R32 | 「査読なし（SSRN/Preprints.org）」を明記。査読済み論文と同列に使用しない |

### 優先度3: Minor修正（体裁整備）

| # | 対象 | 指示 |
|---|------|------|
| F-14 | タイトル全般 | R01-R43のうちタイトル不完全な15件について、正式タイトルに修正 |
| F-15 | R11 (§3.5) | 「Zero-shot」→「Zero-shot and Few-shot」に修正 |
| F-16 | R16 (§5.2) | 出版年を「eHaCON 2025 proceedings (Springer, Jan 2026)」に修正 |
| F-17 | R21 (PhishAgent) | URLまたはDOI (`10.1609/aaai.v39i27.35003`) を追記 |
| F-18 | R34 (§13.2.3) | EuroSPW版の正式タイトル「Discovering HTTPSified Phishing Websites Using the TLS Certificates Footprints」を明記 |
| F-19 | R39 (§13.3.3) | NSA賞の年を「第11回（2023年ノミネート/2024年授与）」に正確化 |
| F-20 | R44 (§13.6.1) | 「IEEE 2023」→「INDIACom 2023 (IEEE)」に正確化 |

---

## 最終判定

**掲載可否: 条件付き可**

Critical 5件とMajor 12件を修正すれば、論文の関連研究セクションのベースとして使用可能。ただし、最終的な論文執筆時にはすべての数値を原論文のフルテキストで再確認すること。

**致命傷トップ5（修正しなければ論文事故）**:
1. R20 PhishIntel — DOIが別論文を指している
2. R30 Phish-Hook — 会場名が間違っている
3. R41 C-BERT — 著者名が間違っている
4. §6.3 — 出典不明の数値を記載
5. §10.3 — 未実装の能力を実現済みのように記述
