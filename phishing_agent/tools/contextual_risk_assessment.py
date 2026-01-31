# phishing_agent/tools/contextual_risk_assessment.py
from __future__ import annotations
# ---------------------------------------------------------------------
# Change history
# - 2026-01-02: Added score_components (score breakdown) for log export.
#              Refined ML paradox logic to avoid treating only {free_ca,no_org}
#              as an automatic strong paradox (FP reduction).
#              Expanded low-ML safety cap to p<0.2 with dangerous_tld guard.
# - 2026-01-02: Reworked multiple_risk_factors bonus to be category-based
#              (brand/cert/domain) instead of raw issue-count. This prevents
#              DV-like certificate signals (free_ca/no_org) alone from
#              artificially inflating the contextual score and causing FP.
# - 2026-01-12: Added low-signal phishing detection based on Handoff analysis.
#              Low-signal phishing has: low ML, short validity cert, low SAN count.
#              Added benign_indicators check to avoid FP on legitimate sites.
# - 2026-01-24: 多言語ソーシャルエンジニアリングキーワード追加 (MULTILINGUAL_RISK_WORDS)
#              フランス語/ポルトガル語/スペイン語/ドイツ語/イタリア語のフィッシング
#              頻出ワードを _count_high_risk_hits() で検出するよう拡張
# - 2026-01-25: 危険TLD組み合わせスコアリング追加 (DANGEROUS_TLDS_CTX)
#              FN分析より164件 (22.2%) が危険TLDで見逃し → 他シグナルとの
#              組み合わせ (ランダム/短ドメイン/ブランド検出) でリスク底上げ
# - 2026-01-25: FN分析に基づく追加改善 (4-3b3〜4-3b6)
#              - 4-3b3: critical_brand 最低スコア強制 (smbceco.net等)
#              - 4-3b4: 複数ブランド検出ボーナス (etherwallet.mobilelab.vn等)
#              - 4-3b5: ランダム+高ML相乗効果 (jcvuzh.com等)
#              - 4-3b6: サブドメイン+ブランド検出 (etherwallet.mobilelab.vn等)
#              - MULTILINGUAL_RISK_WORDS に英語アクション系追加 (update, renew等)
# - 2026-01-28: typical_phishing_cert_pattern 検出追加 (FN対策)
#              - free_ca + no_org + short_term (<=90日) → strong_evidence として扱う
#              - ブランド非依存でフィッシング検出を可能にする
# - 2026-01-29: typical_phishing_cert_pattern 検出無効化 (FP対策)
#              - Precision 39.4%で識別力不足 (FP 68件の原因)
#              - _strong_cert から削除済みだが、issues に含まれることで
#                LLM判定に影響していたため、完全に無効化
# - 2026-01-30: ml_paradox に dangerous TLD 条件を試行→ロールバック
#              - 試行: non-dangerous TLD では ml_paradox を発火させない
#              - 結果: 効果限定的（共通ドメインでFP -1件のみ）、F1改善なし
#              - 詳細: docs/analysis/02_improvement_analysis.md #14
# ---------------------------------------------------------------------
from typing import Any, Dict, List, Optional

from ..tools_module import safe_tool_wrapper, _ET, _tokenize_domain_labels

# Legitimate-domain helper (best effort).
# NOTE: known_domains passed from external data is sometimes a large "seen set".
# We must NOT treat it as a whitelist. Mitigation should apply only when the
# domain is strongly verified as legitimate (strict allowlist).
try:
    from .legitimate_domains import is_legitimate_domain  # type: ignore
except Exception:  # pragma: no cover
    is_legitimate_domain = None  # type: ignore


# ---------------------------------------------------------------------
# Thresholds & Weights (tuning-friendly configuration)
# ---------------------------------------------------------------------
# ML probability category boundaries
ML_VERY_LOW: float = 0.20
ML_LOW: float = 0.35       # up to 0.35 is treated as "low"
ML_MEDIUM: float = 0.50
ML_HIGH: float = 0.80

# ML Paradox detection thresholds
PARADOX_STRONG_MAX_ML: float = 0.20
PARADOX_WEAK_MAX_ML: float = 0.30
PARADOX_STRONG_MIN_SIGNALS: int = 2
PARADOX_WEAK_MIN_SIGNALS: int = 1
BASE_SCORE_STRONG_PARADOX: float = 0.80  # strong paradox → treat ML as 0.8
BASE_SCORE_WEAK_PARADOX: float = 0.60    # weak paradox → treat ML as 0.6

# Additional condition for strong paradox when signals are very dense
PARADOX_STRONG_ALT_MIN_SIGNALS: int = 3  # for p <= ML_LOW & many signals

# Core weights for ML & tool scores (ML + tools ≒ 0.80)
WEIGHT_ML: float = 0.45
WEIGHT_TOOLS: float = 0.35

# Bonus when multiple non-ML factors are present
# NOTE(2026-01-02): Reduced slightly and changed the trigger condition to
# category-based (see section 4-2). This reduces FP caused by over-counting
# weak/non-independent signals.
BONUS_MULTIPLE_FACTORS: float = 0.12

# High-risk words bonus
# 2026-01-26: FN分析に基づき強化 (livraison-monrelais.com等のフィッシングが検出されなかった)
# 複数のhigh_risk_wordsはフィッシングの強いシグナル
HIGH_RISK_WORD_BASE: float = 0.18  # 0.12 → 0.18
HIGH_RISK_WORD_STEP: float = 0.06  # 0.04 → 0.06
HIGH_RISK_WORD_MAX: float = 0.38   # 0.28 → 0.38

# Known domain mitigation (slightly weaker than old logic)
KNOWN_DOMAIN_MITIGATION_LOW: float = 0.08   # applied when score < 0.7
KNOWN_DOMAIN_MITIGATION_HIGH: float = 0.04  # applied when score >= 0.7
KNOWN_DOMAIN_MITIGATION_SWITCH: float = 0.70

# Consistency bonus when tools agree & issues are rich
CONSISTENCY_THRESHOLD_TOOL_RISK: float = 0.40
CONSISTENCY_THRESHOLD_ISSUES: int = 3
CONSISTENCY_BONUS: float = 0.10

# Risk signal helper thresholds
RISK_SIGNAL_MIN_TOOL_RISK: float = 0.30  # avg_tool_risk >= 0.3 → one signal

# Tags treated as strong non‑ML signals (certificate / domain / brand)
# NOTE(2026-01-02): free_ca/no_org は「弱い身元情報」(DV相当)であり、
#                   それ単体で Paradox(ML≪0だが非MLが強い) を強判定すると
#                   Let's Encrypt 等の一般サイトでFPが増えやすい。
#                   Paradox 用のシグナルには *より強い* タグのみを使う。
# NOTE(2026-01-14): dangerous_tld は FP の主要因であることが判明。
#                   STRONG_NON_ML_TAGS から除外し、より厳密なシグナルのみを使用。
#                   dangerous_tld は引き続き考慮されるが、単独では強シグナルとしない。
STRONG_NON_ML_TAGS: tuple = (
    "brand_detected",
    "self_signed",
    "idn_homograph",
    "very_high_entropy",
)

# 高危険TLD: フィッシングに特に多用され、正規利用が少ないTLD（llm_final_decision.py と同期）
HIGH_DANGER_TLDS_CTX = frozenset([
    'tk', 'ml', 'ga', 'cf', 'gq',  # 無料TLD（フィッシング頻出）
    'icu', 'cfd', 'sbs', 'rest', 'cyou',  # フィッシング特化
    'pw', 'buzz', 'lat',  # 高フィッシング率
])

# ---------------------------------------------------------------------------
# 危険TLD (2026-01-25追加)
# ---------------------------------------------------------------------------
# FN分析より、164件 (22.2%) が危険TLDに属するがAI Agentが見逃していた。
# HIGH_DANGER_TLDS_CTXより広範囲のTLDをカバーし、他シグナルとの組み合わせで
# リスクスコアを底上げする。
DANGEROUS_TLDS_CTX: frozenset = frozenset([
    # 超危険 (>50% フィッシング率) - HIGH_DANGER_TLDS_CTXと同じ
    "top", "xyz", "icu", "buzz", "cfd", "cyou", "rest", "sbs",
    "tk", "ml", "ga", "cf", "gq", "pw",
    # 高危険 (>20% フィッシング率)
    "cn", "cc", "asia", "vip", "shop", "club", "one", "click", "link",
    "online", "site", "website", "lat", "ws", "wang", "bar", "mw", "live",
    # 中危険 (フィッシング利用が増加傾向)
    "info", "biz", "mobi", "work", "email", "date", "party", "review",
    "stream", "download", "men", "win", "loan", "science", "kim",
])

# ただし free_ca/no_org 自体は risk 要因としては引き続き有効（スコア寄与は残す）。
WEAK_IDENTITY_TAGS: tuple = (
    "free_ca",
    "no_org",
)

# Multiple factors threshold
MULTIPLE_FACTORS_MIN_ISSUES: int = 2

# ---------------------------------------------------------------------------
# 多言語ソーシャルエンジニアリングキーワード (2026-01-24追加)
# ---------------------------------------------------------------------------
# FN分析で検出されたドメイン名に多い多言語キーワード。
# 英語の high_risk_words に加えて、フランス語/ポルトガル語/スペイン語/ドイツ語/
# イタリア語のフィッシング頻出ワードを検出する。
MULTILINGUAL_RISK_WORDS: frozenset = frozenset([
    # フランス語 (2026-01-26: FN分析に基づき拡充)
    "connexion", "verification", "confirmer", "actualiser", "securite",
    "authentification", "identifiant", "compte", "messagerie",
    "dossier", "livraison", "colis", "facture", "renouvellement",
    "debloquer", "reactiver", "espace",
    # 2026-01-26追加: フランス語 配送/税金/銀行詐欺で頻出
    "suivi", "remboursement", "virement", "paiement", "bancaire",
    "impots", "amende", "douane", "carte", "retrait", "depot",
    "chronopost", "laposte", "colissimo", "relais", "infos",
    # ポルトガル語
    "verificar", "confirmar", "atualizar", "seguranca", "autenticacao",
    "acesso", "conta", "pagamento", "fatura", "entrega",
    "desbloqueio", "atualizacao", "validacao",
    # スペイン語
    "verificacion", "confirmar", "actualizar", "seguridad", "autenticacion",
    "acceso", "cuenta", "pago", "factura", "envio",
    "desbloquear", "reactivar", "validacion",
    # ドイツ語
    "anmeldung", "bestatigung", "sicherheit", "konto", "passwort",
    "zugang", "lieferung", "rechnung", "aktualisierung",
    "freischaltung", "verifizierung",
    # イタリア語
    "accesso", "verifica", "sicurezza", "pagamento",
    "consegna", "fattura", "sblocco", "aggiornamento",
    # 一般的な多言語フィッシングパターン
    "webmail", "portail", "espace", "client", "membre",
    "usuario", "utilisateur", "utente", "benutzer",
    "recuperar", "recuperer", "ripristino",
    # 2026-01-25追加: 英語のアクション系フィッシングキーワード (FN分析: updateza.top等)
    "update", "renew", "suspend", "suspended",
    "expire", "expired", "expiring",
    "unlock", "reactivate", "restore",
    "verify", "validate", "confirm",
    "alert", "urgent", "warning", "notice",
    # 2026-01-26追加: サービス関連キーワード (FN分析: service偽装ドメイン)
    "service", "services", "support", "customer", "helpdesk",
    "technical", "billing", "invoice", "receipt", "refund",
    "activation", "registration", "subscription", "membership",
    "notification", "delivery", "shipping", "tracking", "parcel",
])


def _count_high_risk_hits(tokens: List[str], high_risk_words: Optional[List[str]]) -> int:
    """high_risk_words + MULTILINGUAL_RISK_WORDS に含まれるトークンがいくつあるか数えるヘルパー.

    変更履歴:
      - 2026-01-24: MULTILINGUAL_RISK_WORDS も検索対象に追加
      - 2026-01-25: 部分一致も検出するよう修正 (updateza → update)
                   ただし4文字未満のキーワードは除外（誤検知防止）
    """
    hr: set = set()
    if high_risk_words:
        hr = {w.strip().lower() for w in high_risk_words if w and str(w).strip()}
    # 多言語キーワードを常に含める
    hr.update(MULTILINGUAL_RISK_WORDS)
    if not hr:
        return 0

    hits = 0
    for t in tokens:
        # 完全一致
        if t in hr:
            hits += 1
            continue
        # 部分一致（4文字以上のキーワードのみ）
        for kw in hr:
            if len(kw) >= 4 and kw in t:
                hits += 1
                break  # 1トークンにつき1ヒットまで
    return hits


@safe_tool_wrapper("contextual_risk_assessment")
def contextual_risk_assessment(
    domain: str,
    ml_probability: float = 0.0,
    tool_results: Optional[Dict[str, Any]] = None,
    high_risk_words: Optional[List[str]] = None,
    known_domains: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    文脈的リスク評価ツール（Contextual Risk Assessment）

    - 第1層 ML（XGBoost）の確率と、brand/cert/domain の 3 つのツール結果を統合
    - 「ML パラドックス」（ML は非常に低いが非 ML シグナルが強いケース）を検出し、
      ML ベーススコアを 2 段階で底上げ（強/弱パラドックス）
    - known_domains（既知正規ドメイン）については、最終スコアから緩やかに減点
    """
    et = _ET(domain)
    p = float(ml_probability or 0.0)

    # ------------------------------------------------------------------
    # 0. ML カテゴリ判定（定数に基づく）
    # ------------------------------------------------------------------
    if p < ML_VERY_LOW:
        ml_category = "very_low"
    elif p < ML_LOW:
        ml_category = "low"
    elif p < ML_MEDIUM:
        ml_category = "medium"
    elif p < ML_HIGH:
        ml_category = "high"
    else:
        ml_category = "very_high"

    # ------------------------------------------------------------------
    # 1. ツール結果の集計（brand / cert / domain など）
    # ------------------------------------------------------------------
    results = tool_results or {}
    uniq_issues: List[str] = []
    s, c = 0.0, 0

    for res in results.values():
        if not isinstance(res, dict):
            continue

        # 対応形式:
        # - {"success": True, "data": {...}}
        # - {...} （data 本体のみ）
        data = res.get("data") if "data" in res else res
        if not isinstance(data, dict):
            continue

        # 明示的な失敗 or フォールバックはスコアから除外
        if res.get("success") is False or data.get("_fallback"):
            continue

        issues = data.get("detected_issues", []) or []
        uniq_issues.extend(issues)

        s += float(data.get("risk_score", 0.0) or 0.0)
        c += 1

    # ツールで検出された issue をユニーク化
    uniq_issues = list(dict.fromkeys(uniq_issues))
    issue_set = set(uniq_issues)
    avg_tool_risk: float = (s / c) if c else 0.0

    # --------------------------------------------------------------
    # 1b. Per-tool extraction (for category-based scoring/logging)
    # --------------------------------------------------------------
    def _extract_tool_data(name: str) -> Dict[str, Any]:
        """Return tool 'data' dict in a tolerant way.

        tool_results can be either:
          - {"success": True, "data": {...}}
          - {...} (data-only)
        """
        raw = results.get(name) or {}
        if not isinstance(raw, dict):
            return {}
        data = raw.get("data") if "data" in raw else raw
        if not isinstance(data, dict):
            return {}
        # explicit failure / fallback → ignore
        if raw.get("success") is False or data.get("_fallback"):
            return {}
        return data

    brand_data = _extract_tool_data("brand_impersonation_check")
    cert_data  = _extract_tool_data("certificate_analysis")
    dom_data   = _extract_tool_data("short_domain_analysis")

    brand_risk = float(brand_data.get("risk_score", 0.0) or 0.0)
    cert_risk  = float(cert_data.get("risk_score", 0.0) or 0.0)
    dom_risk   = float(dom_data.get("risk_score", 0.0) or 0.0)

    brand_issues = set(brand_data.get("detected_issues", []) or [])
    cert_issues  = set(cert_data.get("detected_issues", []) or [])
    dom_issues   = set(dom_data.get("detected_issues", []) or [])

    # ------------------------------------------------------------------
    # 2. 高リスク単語ヒット数 / 既知ドメイン判定
    # ------------------------------------------------------------------
    tokens = _tokenize_domain_labels(et)
    hr_hits = _count_high_risk_hits(tokens, high_risk_words)

    # "known_domains" is external-data dependent. In some runs it behaves like a
    # seen-set (contains almost everything), which would incorrectly apply
    # mitigation to phishing domains. We therefore separate:
    #   - is_known_seen : membership in the external dict
    #   - is_known_legit: *strict* legitimate allowlist check
    is_known_seen = False
    known_label: Any = None
    rd = getattr(et, "registered_domain", None)
    if isinstance(known_domains, dict) and rd in known_domains:
        is_known_seen = True
        known_label = known_domains.get(rd)

    is_known_legit = False
    legit_info: Optional[Dict[str, Any]] = None
    try:
        if callable(is_legitimate_domain) and rd:
            legit_info = is_legitimate_domain(str(rd))
            # strict allowlist only
            is_known_legit = bool(legit_info.get("is_legitimate")) and float(legit_info.get("confidence", 0.0) or 0.0) >= 0.98
    except Exception:
        is_known_legit = False

    issues: List[str] = []
    score: float = 0.0
    mitigation: float = 0.0
    consistency_boost: float = 0.0

    # ------------------------------------------------------------------
    # 3. ML パラドックス判定（定数化）
    #
    # risk_signal_count = 0〜3:
    #   1) avg_tool_risk >= RISK_SIGNAL_MIN_TOOL_RISK
    #   2) hr_hits > 0
    #   3) STRONG_NON_ML_TAGS のいずれかが含まれる
    #
    # 強パラドックス:
    #   (p <= PARADOX_STRONG_MAX_ML & signals >= PARADOX_STRONG_MIN_SIGNALS)
    #   or (p <= ML_LOW & signals >= PARADOX_STRONG_ALT_MIN_SIGNALS)
    #
    # 弱パラドックス:
    #   not strong & (p <= PARADOX_WEAK_MAX_ML & signals >= PARADOX_WEAK_MIN_SIGNALS)
    #
    # NOTE(2026-01-02): 以前は p<=PARADOX_STRONG_MAX_ML & {free_ca,no_org} で
    # 「常に強パラドックス」だったが、Let's Encrypt 等の一般サイトでも頻出なため
    # FP を誘発しやすい。現在は “追加の強シグナルがある場合のみ” strong に昇格。
    # ------------------------------------------------------------------
    risk_signal_count = 0
    if avg_tool_risk >= RISK_SIGNAL_MIN_TOOL_RISK:
        risk_signal_count += 1
    if hr_hits > 0:
        risk_signal_count += 1
    # NOTE: STRONG_NON_ML_TAGS には free_ca/no_org を含めない（FP低減）
    if any(tag in issue_set for tag in STRONG_NON_ML_TAGS):
        risk_signal_count += 1

    is_paradox_strong = False
    is_paradox_weak = False

    # 強パラドックス条件（2 パターン）
    # NOTE: 2026-01-30に dangerous TLD ガードを試行したが効果限定的のためロールバック
    if (
        (p <= PARADOX_STRONG_MAX_ML and risk_signal_count >= PARADOX_STRONG_MIN_SIGNALS)
        or (p <= ML_LOW and risk_signal_count >= PARADOX_STRONG_ALT_MIN_SIGNALS)
    ):
        is_paradox_strong = True

    # 弱パラドックス条件
    if (not is_paradox_strong) and (
        p <= PARADOX_WEAK_MAX_ML and risk_signal_count >= PARADOX_WEAK_MIN_SIGNALS
    ):
        is_paradox_weak = True

    # very low ML かつ free_ca + no_org:
    #   以前は「常に強パラドックス扱い」だったが、Let's Encrypt + No Org は
    #   *一般サイトでも頻出* のため FP を誘発しやすい。
    #   → 追加の強い非MLシグナルがある場合にのみ strong に昇格する。
    #
    # 変更履歴:
    #   - 2026-01-31: brand_detected, consonant_cluster_random を除外（FP削減）
    #     - brand_detected: Precision 18.2% (FP 130件 vs TP 29件)
    #     - consonant_cluster_random: Precision 10.5% (FP 17件 vs TP 2件)
    #     - 期待効果: FP -122件, F1 +1.31pp
    # 効果測定用: 除外されたシグナルのトラッキング
    _excluded_from_needs_extra = {"brand_detected", "consonant_cluster_random"}
    _paradox_excluded_signals: List[str] = []  # 除外により発火しなかったシグナル
    _paradox_would_have_triggered = False  # 除外がなければ発火していたか

    if p <= PARADOX_STRONG_MAX_ML and {"free_ca", "no_org"}.issubset(issue_set):
        _needs_extra = {
            "dangerous_tld",
            # "brand_detected",  # 2026-01-31除外: Precision 18.2%で低すぎる
            "random_pattern",
            "high_entropy",
            "short_random_combo",
            "random_with_high_tld_stat",
            "idn_homograph",
            # "consonant_cluster_random",  # 2026-01-31除外: Precision 10.5%で低すぎる
            "rare_bigram_random",
        }
        if issue_set & _needs_extra:
            is_paradox_strong = True
            is_paradox_weak = False
        else:
            # 除外シグナルがあれば記録（効果測定用）
            _hit_excluded = issue_set & _excluded_from_needs_extra
            if _hit_excluded:
                _paradox_excluded_signals = list(_hit_excluded)
                _paradox_would_have_triggered = True

    # ML 由来ベーススコアの決定
    if is_paradox_strong:
        issues.append("ml_paradox")
        base_from_ml = BASE_SCORE_STRONG_PARADOX
    elif is_paradox_weak:
        issues.append("ml_paradox_medium")
        base_from_ml = BASE_SCORE_WEAK_PARADOX
    else:
        base_from_ml = p

    # ------------------------------------------------------------------
    # 4. スコア計算（ML + ツール平均 + 各種ボーナス/減点）
    # ------------------------------------------------------------------
    # (ログ/チューニング向け) スコア内訳を残す
    score_components: Dict[str, Any] = {
        "ml_probability": p,
        "ml_category": ml_category,
        "base_from_ml": base_from_ml,
        "avg_tool_risk": avg_tool_risk,
        "weight_ml": WEIGHT_ML,
        "weight_tools": WEIGHT_TOOLS,
        "ml_contrib": round(base_from_ml * WEIGHT_ML, 4),
        "tools_contrib": round(avg_tool_risk * WEIGHT_TOOLS, 4),
        "bonus_multiple_factors": 0.0,
        "multi_factor_categories": [],
        "multi_factor_count": 0,
        "bonus_high_risk_words": 0.0,
        "dv_suspicious_combo": False,
        "known_domain_mitigation": 0.0,
        "consistency_boost": 0.0,
        "low_ml_safety_cap_applied": False,
        "low_ml_safety_cap_before": None,
        "low_ml_safety_cap_after": None,
        "final_score": None,
    }

    # 4-1. ML / ツールからの寄与
    score += base_from_ml * WEIGHT_ML
    score += avg_tool_risk * WEIGHT_TOOLS

    # 4-2. 複数要因ボーナス（カテゴリベース）
    # NOTE(2026-01-02):
    #   以前は「検出 issue 数」で判定していたため、free_ca/no_org/no_san/short_term などの
    #   “弱い/非独立” な証明書由来シグナルだけでボーナスが乗り、FP を誘発しやすかった。
    #   → brand/cert/domain の *複数カテゴリ* から意味のあるシグナルが出ている場合のみ bonus。
    _domain_strong = {
        "dangerous_tld",
        "idn_homograph",
        "random_pattern",
        "high_entropy",
        "very_high_entropy",
        "short_random_combo",
        "random_with_high_tld_stat",
        "very_short_dangerous_combo",
        "deep_chain_with_risky_tld",
        "consonant_cluster_random",   # 2026-01-24追加
        "rare_bigram_random",          # 2026-01-24追加
    }
    _cert_strong = {
        "self_signed",
        "dv_multi_risk_combo",
        # NOTE: dv_weak_identity/free_ca_no_org は benign でも多いため
        # multi-factor の「強い独立シグナル」としては扱わない。
    }

    brand_signal = ("brand_detected" in brand_issues) or (brand_risk >= 0.40)
    domain_signal = (dom_risk >= 0.40) or bool(dom_issues & _domain_strong)
    cert_signal = (cert_risk >= 0.65) or bool(cert_issues & _cert_strong)

    _cats: List[str] = []
    if brand_signal:
        _cats.append("brand")
    if domain_signal:
        _cats.append("domain")
    if cert_signal:
        _cats.append("cert")

    score_components["multi_factor_categories"] = _cats
    score_components["multi_factor_count"] = len(_cats)

    if len(_cats) >= 2:
        issues.append("multiple_risk_factors")
        score += BONUS_MULTIPLE_FACTORS
        score_components["bonus_multiple_factors"] = BONUS_MULTIPLE_FACTORS

    # 4-3. 高リスク単語ボーナス
    if hr_hits > 0:
        issues.append("high_risk_words")
        _hr_bonus = min(
            HIGH_RISK_WORD_MAX,
            HIGH_RISK_WORD_BASE + HIGH_RISK_WORD_STEP * (hr_hits - 1),
        )
        score += _hr_bonus
        score_components["bonus_high_risk_words"] = round(float(_hr_bonus), 4)

    # 4-3b. "DV weak identity" + suspicious domain combo boost
    # This targets the common FN pattern: brand absent, cert looks DV-ish (free_ca/no_org)
    # and the domain has strong structural signals (dangerous_tld / random / entropy).
    # NOTE(2026-01-14): dangerous_tld だけでスコア底上げするとFPが多発するため、
    #   - 高危険TLDの場合のみ 0.42 に底上げ
    #   - 中危険TLDの場合は 0.35 に底上げ（控えめ）
    #   - random_pattern/high_entropy 等は従来通り 0.42
    _tld_suffix_ctx = ""
    try:
        _tld_suffix_ctx = et.suffix.lower().strip(".") if hasattr(et, "suffix") else ""
    except Exception:
        pass

    # 変更履歴:
    #   - 2026-01-27: ML < 0.10 の場合はスキップ (FP削減)
    #     理由: ML < 0.10 は「非常にbenign」を意味し、DV cert + dangerous TLD
    #     だけでphishing判定するとFPが増加（分析: 61%のFPがこのルール起因）
    if (
        ("free_ca_no_org" in issue_set or ("free_ca" in issue_set and "no_org" in issue_set))
        and (
            "dangerous_tld" in issue_set
            or "random_pattern" in issue_set
            or "high_entropy" in issue_set
            or "short_random_combo" in issue_set
            or "random_with_high_tld_stat" in issue_set
        )
        and p >= 0.10  # 2026-01-27: ML < 0.10 の場合はスキップ
    ):
        issues.append("dv_suspicious_combo")
        # TLD危険度に応じてスコア底上げ幅を調整
        if "dangerous_tld" in issue_set and _tld_suffix_ctx not in HIGH_DANGER_TLDS_CTX:
            # 中危険TLDの場合は控えめに
            if (
                "random_pattern" not in issue_set
                and "high_entropy" not in issue_set
                and "short_random_combo" not in issue_set
                and "random_with_high_tld_stat" not in issue_set
            ):
                score = max(score, 0.35)  # 控えめな底上げ
                score_components["dv_suspicious_combo"] = "medium_tld"
            else:
                score = max(score, 0.42)
                score_components["dv_suspicious_combo"] = True
        else:
            score = max(score, 0.42)
            score_components["dv_suspicious_combo"] = True

    # 4-3b2. Dangerous TLD Combination Scoring (2026-01-25)
    # FN分析より、164件 (22.2%) が危険TLDに属するがAI Agentが見逃していた。
    # 危険TLD + 他のシグナル（ランダムパターン/短ドメイン/ブランド検出）の組み合わせで
    # リスクスコアを底上げする。
    #
    # ルール:
    #   危険TLD + random_pattern/high_entropy/consonant_cluster/rare_bigram → +0.20
    #   危険TLD + short/very_short → +0.15
    #   危険TLD + brand_detected → +0.25 (最も強い組み合わせ)
    #   複数組み合わせの場合は加算（上限0.50）
    dangerous_tld_combo_boost = 0.0
    dangerous_tld_combo_signals: List[str] = []

    # TLDが危険リスト（DANGEROUS_TLDS_CTX）に含まれるか確認
    is_dangerous_tld = _tld_suffix_ctx in DANGEROUS_TLDS_CTX

    if is_dangerous_tld:
        # 2026-01-26追加: 危険TLD + 低ML のベースブースト
        # 変更履歴:
        #   - 2026-01-26: FN分析より、危険TLDで他シグナルなしの見逃しが29件
        #   - 正規ドメインが .buzz, .icu, .top 等を使うことは稀
        #   - ML < 0.15 でも危険TLDならベースブーストを適用
        #   - 2026-01-27: ML < 0.10 の場合はスキップ (FP削減)
        #     理由: ML < 0.10 はMLが「明確にbenign」と判断しているため、
        #     危険TLDだけでブーストするとFPが増加する（分析: 35%のFP原因）
        if 0.10 <= p < 0.15:
            dangerous_tld_combo_boost += 0.12
            dangerous_tld_combo_signals.append("dangerous_tld_low_ml")

        # ランダムパターン検出との組み合わせ
        _random_signals = {
            "random_pattern", "high_entropy", "very_high_entropy",
            "consonant_cluster_random", "rare_bigram_random",
            "short_random_combo", "random_with_high_tld_stat",
        }
        if issue_set & _random_signals:
            dangerous_tld_combo_boost += 0.20
            dangerous_tld_combo_signals.append("dangerous_tld_random")

        # 短ドメインとの組み合わせ
        if "short" in issue_set or "very_short" in issue_set:
            dangerous_tld_combo_boost += 0.15
            dangerous_tld_combo_signals.append("dangerous_tld_short")

        # ブランド検出との組み合わせ（最も強いシグナル）
        if "brand_detected" in issue_set:
            dangerous_tld_combo_boost += 0.25
            dangerous_tld_combo_signals.append("dangerous_tld_brand")

        # 2026-01-25追加: high_risk_words との組み合わせ (updateza.top等)
        # ソーシャルエンジニアリングキーワード + 危険TLD は強い組み合わせ
        if hr_hits > 0:
            dangerous_tld_combo_boost += 0.28
            dangerous_tld_combo_signals.append("dangerous_tld_high_risk_words")

        # 2026-01-26追加: .cn TLD 強化 (FN分析: 50件の見逃し)
        # .cn は正規サイトも多いが、フィッシングも多用される
        # 追加シグナルがある場合のみ強化（FP防止）
        if _tld_suffix_ctx == "cn":
            _cn_additional_signals = 0
            if issue_set & _random_signals:
                _cn_additional_signals += 1
            if "short" in issue_set or "very_short" in issue_set:
                _cn_additional_signals += 1
            if hr_hits > 0:
                _cn_additional_signals += 1
            if "brand_detected" in issue_set:
                _cn_additional_signals += 2  # ブランド偽装は強いシグナル
            # 2つ以上のシグナルがある場合、追加ブースト
            if _cn_additional_signals >= 2:
                dangerous_tld_combo_boost += 0.15
                dangerous_tld_combo_signals.append("cn_tld_high_risk")

        # 上限0.50でクリップ
        dangerous_tld_combo_boost = min(dangerous_tld_combo_boost, 0.50)

        if dangerous_tld_combo_boost > 0:
            issues.append("dangerous_tld_combo")
            # 現在のスコアに加算（他のボーナスとは独立）
            score = max(score, score + dangerous_tld_combo_boost * 0.5)  # 半分を加算
            # または最低スコアを底上げ
            min_score_for_combo = 0.35 + dangerous_tld_combo_boost * 0.3
            score = max(score, min_score_for_combo)
            # 2026-01-25: high_risk_words + dangerous_tld は特に強い組み合わせ
            # (updateza.top等: ソーシャルエンジニアリング + 危険TLD)
            if "dangerous_tld_high_risk_words" in dangerous_tld_combo_signals:
                score = max(score, 0.50)
            score_components["dangerous_tld_combo"] = {
                "boost": round(dangerous_tld_combo_boost, 3),
                "signals": dangerous_tld_combo_signals,
                "tld": _tld_suffix_ctx,
            }

    # 4-3b3. Critical Brand Minimum Score Enforcement (2026-01-25)
    # FN分析より、brand_impersonation_check で has_critical_brand=True を返しても
    # contextual_risk_assessment の重み付けで希釈され、閾値0.5に届かないケースが多発。
    # (例: smbceco.net → smbc検出, risk=0.4 だが最終スコア0.34)
    # critical_brand が検出された場合、最終スコアを強制的に底上げする。
    brand_details_ctx = brand_data.get("details", {}) or {}
    has_critical_brand = brand_details_ctx.get("has_critical_brand", False)

    if has_critical_brand and "brand_detected" in issue_set:
        if is_dangerous_tld:
            # 危険TLD + critical_brand → 高リスク確定
            score = max(score, 0.55)
            if "critical_brand_dangerous_tld" not in issues:
                issues.append("critical_brand_dangerous_tld")
            score_components["critical_brand_enforcement"] = "dangerous_tld"
        else:
            # critical_brand のみ → 中〜高リスク
            score = max(score, 0.50)
            if "critical_brand_minimum" not in issues:
                issues.append("critical_brand_minimum")
            score_components["critical_brand_enforcement"] = "standard"

    # 4-3b4. Multiple Brand Keywords Boost (2026-01-25)
    # FN分析より、複数ブランドキーワードが検出されても単一ブランドと同じ扱いだった。
    # (例: etherwallet.mobilelab.vn → eth, ether, wallet の3つ検出だが low risk)
    # 複数ブランド検出時は追加ボーナスを付与する。
    detected_brands_list = brand_details_ctx.get("detected_brands", []) or []
    brand_count = len(detected_brands_list)

    if brand_count >= 2:
        multi_brand_boost = min(0.15, 0.05 * brand_count)
        score += multi_brand_boost
        if "multiple_brands_detected" not in issues:
            issues.append("multiple_brands_detected")
        score_components["multi_brand_boost"] = round(multi_brand_boost, 3)
        score_components["brand_count"] = brand_count

    # 4-3b5. Random Pattern + High ML Synergy (2026-01-25)
    # FN分析より、random_pattern検出 + 高ML (>0.5) でも最終スコアが低いケースがあった。
    # (例: jcvuzh.com → random_pattern, ML=0.57 だが最終スコア0.32)
    # MLが高い（モデルがphishingと疑っている）+ ランダムパターン → 相乗効果を付与。
    _random_indicators = {
        "random_pattern", "rare_bigram_random",
        "consonant_cluster_random", "high_entropy", "very_high_entropy"
    }

    if issue_set & _random_indicators and p > 0.50:
        # MLが0.5超 + ランダムパターン → 相乗効果
        # 2026-01-25: 閾値調整 (jcvuzh.com ML=0.57 が 0.5 を超えるよう)
        synergy_score = 0.46 + (p - 0.50) * 0.6  # ML=0.57 → 0.502, ML=0.7 → 0.58
        if score < synergy_score:
            score = synergy_score
            if "random_high_ml_synergy" not in issues:
                issues.append("random_high_ml_synergy")
            score_components["random_high_ml_synergy"] = {
                "ml_prob": round(p, 3),
                "synergy_score": round(synergy_score, 3),
            }

    # 4-3b6. Subdomain + Brand Keyword Detection (2026-01-25)
    # FN分析より、サブドメイン部分にブランドキーワードがあるケースが見逃されていた。
    # (例: etherwallet.mobilelab.vn → サブドメイン "etherwallet" に wallet, ether)
    # サブドメインラベルに CRITICAL_BRAND_KEYWORDS が含まれる場合、追加リスクを付与。
    try:
        domain_labels = domain.split('.') if domain else []
        # 最後の2ラベル (registered_domain) を除いたサブドメイン部分
        subdomain_labels = domain_labels[:-2] if len(domain_labels) > 2 else []

        # CRITICAL_BRAND_KEYWORDS を使用してサブドメインをチェック
        # (brand_impersonation_check からインポートが重いため、主要キーワードのみ)
        _critical_subdomain_keywords = {
            "wallet", "ether", "ethereum", "bitcoin", "crypto", "metamask",
            "binance", "coinbase", "ledger", "phantom", "solana",
            "paypal", "bank", "secure", "login", "account",
            "apple", "amazon", "google", "microsoft", "netflix",
        }

        subdomain_brand_found = False
        for label in subdomain_labels:
            label_lower = label.lower()
            for kw in _critical_subdomain_keywords:
                if kw in label_lower and len(kw) >= 4:  # 短すぎるキーワードは除外
                    subdomain_brand_found = True
                    break
            if subdomain_brand_found:
                break

        if subdomain_brand_found and not is_known_legit:
            # 2026-01-25: ブースト増加 + brand_detected との組み合わせボーナス
            subdomain_boost = 0.15
            # brand_detected も同時に検出されている場合、より強い組み合わせ
            if "brand_detected" in issue_set:
                subdomain_boost = 0.22
                # さらに、最低スコアを保証
                score = max(score, 0.48)
            score += subdomain_boost
            if "brand_in_subdomain" not in issues:
                issues.append("brand_in_subdomain")
            score_components["brand_in_subdomain"] = {
                "subdomain_labels": subdomain_labels,
                "boost": round(subdomain_boost, 3),
            }
    except Exception:
        pass  # サブドメイン解析エラーは無視

    # 4-3b7. Random Pattern Minimum Score (2026-01-25)
    # FN分析より、random_pattern/rare_bigram_random が検出されても、
    # 低ML + 非危険TLD の場合にスコアが低すぎるケースが判明。
    # (例: gzkuyc.com → random_pattern, rare_bigram_random だが最終スコア0.117)
    # ランダムパターン検出時は最低スコアを保証する。
    _random_pattern_indicators = {
        "random_pattern", "rare_bigram_random", "consonant_cluster_random",
        "digit_mixed_random"  # 2026-01-25追加
    }
    if issue_set & _random_pattern_indicators and not is_known_legit:
        # ランダムパターン検出 + 非正規ドメイン → 最低スコア保証
        # short ドメイン（6文字以下）の場合はより高いスコアを付与
        is_short = "short" in issue_set or dom_data.get("details", {}).get("domain_length", 99) <= 6
        # 2026-01-25: digit_mixed_random は数字が混在した明確なランダムなので高めに設定
        has_digit_mixed = "digit_mixed_random" in issue_set
        if is_short:
            # 短い + ランダム → より疑わしい
            random_min_score = 0.50
        elif has_digit_mixed:
            # 長め + 数字混在ランダム → 明確に怪しい
            random_min_score = 0.50
        else:
            # 長め + ランダム
            random_min_score = 0.45

        # 危険TLDの場合はさらにブースト
        if is_dangerous_tld:
            random_min_score = max(random_min_score, 0.55)

        if score < random_min_score:
            score = random_min_score
            if "random_pattern_minimum" not in issues:
                issues.append("random_pattern_minimum")
            score_components["random_pattern_minimum"] = {
                "min_score": round(random_min_score, 3),
                "is_short": is_short,
                "is_dangerous_tld": is_dangerous_tld,
            }

    # 4-3b7a. Random Pattern + CRL DP Benign Override
    # 変更履歴:
    #   - 2026-01-27: 追加 (FN対策)
    #   - 2026-01-27: 削除 (FP増加のため) - 26%のFPに寄与していた
    # 理由: random_pattern検出が正規略語/頭字語にも誤検出するため、
    #       CRL DP overrideは過度にFPを増加させる。
    # → 削除: random_crl_override ロジックを無効化

    # 4-3b8. Dangerous TLD + Suspicious Domain Pattern (2026-01-25)
    # FN分析より、危険TLD + ランダム的なドメイン名（ただしrandom_pattern未検出）
    # のケースが見逃されていた。
    # (例: uwuwhsghs.icu → vowel_ratio=0.22で random_pattern未検出だが明らかに怪しい)
    # 危険TLD + 子音クラスター1以上 + 低母音率 → リスク付与
    dom_details = dom_data.get("details", {}) or {}
    consonant_clusters = dom_details.get("consonant_clusters", 0)
    vowel_ratio = dom_details.get("vowel_ratio", 0.5)

    if is_dangerous_tld and not is_known_legit:
        # 危険TLD + やや低い母音率 (< 0.25) + 子音クラスター1以上
        if vowel_ratio < 0.25 and consonant_clusters >= 1:
            suspicious_tld_min = 0.50
            if score < suspicious_tld_min:
                score = suspicious_tld_min
                if "dangerous_tld_suspicious_pattern" not in issues:
                    issues.append("dangerous_tld_suspicious_pattern")
                score_components["dangerous_tld_suspicious_pattern"] = {
                    "vowel_ratio": round(vowel_ratio, 3),
                    "consonant_clusters": consonant_clusters,
                    "min_score": suspicious_tld_min,
                }

    # 4-3c. Low-Signal Phishing Detection (2026-01-12)
    # Handoff分析から判明した低シグナルフィッシングのパターンを検出
    # 特徴: 低ML(<0.30) + 短期証明書(≤90日) + 低SAN数(≤5) + benign_indicatorsなし
    #
    # FP防止: benign_indicators (CRL, OV/EV, wildcard, high_san) がある場合はスキップ
    # 変更履歴:
    #   - 2026-01-27: ML < 0.10 の場合はスキップ (FP削減)
    #     理由: ML < 0.10 は「非常にbenign寄り」を意味し、構造的シグナルのみで
    #     phishing判定するとFPが増加する。78%のFPがこのルールに起因していた。
    low_signal_phishing_detected = False
    low_signal_signals: List[str] = []
    cert_details = cert_data.get("details", {}) or {}
    cert_benign_indicators = set(cert_details.get("benign_indicators", []) or [])

    # benign_indicatorsがある場合は低シグナルフィッシング検出をスキップ
    # 2026-01-27: ML < 0.10 の場合もスキップ（MLの判断を尊重）
    if not cert_benign_indicators and 0.10 <= p < 0.30:
        # 短期証明書（90日以下）
        valid_days = cert_details.get("valid_days", 0) or 0
        if valid_days > 0 and valid_days <= 90:
            low_signal_signals.append("short_validity_cert")

        # 低SAN数（5以下）
        san_count = cert_details.get("san_count", 0) or 0
        if san_count > 0 and san_count <= 5:
            low_signal_signals.append("low_san_count")

        # free_ca/no_org の組み合わせ
        if "free_ca" in issue_set and "no_org" in issue_set:
            low_signal_signals.append("dv_cert")

        # ブランド偽装の兆候（brand_detected がなくても potential_brands がある場合）
        brand_details = brand_data.get("details", {}) or {}
        potential_brands = brand_details.get("detected_brands", []) or brand_details.get("potential_brands", []) or []
        if potential_brands:
            low_signal_signals.append("potential_brand_match")

        # 2つ以上のシグナルがあれば低シグナルフィッシングとして検出
        if len(low_signal_signals) >= 2:
            low_signal_phishing_detected = True
            issues.append("low_signal_phishing")
            # スコアを少し底上げ（強制的な反転はしない）
            score = max(score, 0.38 + 0.03 * len(low_signal_signals))
            score_components["low_signal_phishing"] = True
            score_components["low_signal_signals"] = low_signal_signals

    # 4-3c2. Typical Phishing Certificate Pattern Detection (2026-01-28)
    # ブランド非依存のフィッシング検出: 証明書パターンを strong_evidence として扱う
    # 背景: FNの33.5%がcert > 0.4だがbrand=0のためルールが発火しない
    # パターン: free_ca + no_org + short_term (<=90日) = 典型的なフィッシング証明書
    # この issue は llm_final_decision.py の _strong_cert に追加され、
    # R1-R4 などの既存ルールの strong_evidence 条件を満たす
    #
    # 2026-01-29: 無効化
    #   - Precision 39.4%で識別力不足（FP 68件の原因）
    #   - _strong_cert から削除済みだが、issues に含まれることで
    #     LLM判定に影響していた
    #   - 完全に無効化してFP削減を優先
    #
    # typical_phishing_cert = False
    # cert_valid_days = cert_details.get("valid_days", 0) or 0
    # is_free_ca = "free_ca" in issue_set
    # is_no_org = "no_org" in issue_set
    # is_short_term = cert_valid_days > 0 and cert_valid_days <= 90
    #
    # # benign_indicators (CRL, OV/EV) がある場合は除外
    # cert_benign = set(cert_details.get("benign_indicators", []) or [])
    # has_cert_benign = bool(cert_benign & {"has_crl_dp", "ov_ev_cert"})
    #
    # if is_free_ca and is_no_org and is_short_term and not has_cert_benign:
    #     typical_phishing_cert = True
    #     issues.append("typical_phishing_cert_pattern")
    #     score_components["typical_phishing_cert_pattern"] = True
    #     score_components["typical_phishing_cert_details"] = {
    #         "is_free_ca": is_free_ca,
    #         "is_no_org": is_no_org,
    #         "valid_days": cert_valid_days,
    #     }
    #     # スコアには直接影響させず、strong_evidence としてのみ機能
    #     # これにより既存ルール (R1-R4) がブランドなしでも発火可能になる

    # 4-3d. Old Certificate Phishing Detection (2026-01-17)
    # Handoff分析から判明した「古い証明書」パターンによるフィッシング検出
    # 特徴: FN平均449.8日 vs FP平均248.0日、効果量d=0.745***
    #       old_cert (>365日): FN 49.3% vs FP 3.4%
    #       very_old_cert (>730日): FN 26.9% vs FP 0.9%
    #
    # ルール（TLDリスクレベルに応じて閾値を調整）:
    #   危険TLD:
    #     - ml >= 0.20 AND cert_age > 365: 中MLかつ古い証明書 → フィッシング疑い
    #     - ml >= 0.10 AND cert_age > 730: 低MLでも非常に古い証明書 → フィッシング疑い
    #   非危険TLD（FP削減のため保守的）:
    #     - ml >= 0.25 AND cert_age > 400: より厳しい閾値
    #     - ml >= 0.15 AND cert_age > 730: 非常に古い場合のみ
    #
    # FP防止: benign_indicators (CRL, OV/EV) がある場合は完全スキップ
    old_cert_phishing_detected = False
    old_cert_signals: List[str] = []
    cert_age_days = cert_details.get("cert_age_days", 0) or 0

    # benign_indicatorsがある場合は old_cert 検出をスキップ
    has_strong_benign = bool(cert_benign_indicators & {"has_crl_dp", "ov_ev_cert"})

    # TLDが危険かどうかを判定（dom_issuesまたはissue_setから取得）
    is_tld_dangerous = "dangerous_tld" in issue_set or "dangerous_tld" in dom_issues

    if cert_age_days > 0 and not has_strong_benign:
        score_components["cert_age_days"] = cert_age_days
        score_components["is_old_cert"] = cert_age_days > 365
        score_components["is_very_old_cert"] = cert_age_days > 730

        # TLDリスクレベルに応じた閾値設定
        if is_tld_dangerous:
            # 危険TLD: 元の閾値を使用
            ml_threshold_old = 0.20
            age_threshold_old = 365
            ml_threshold_very_old = 0.10
        else:
            # 非危険TLD: 保守的な閾値（FP削減）
            ml_threshold_old = 0.25
            age_threshold_old = 400
            ml_threshold_very_old = 0.15

        if p >= 0.50:
            # 高ML（既存ルールで対応済みだが、old_cert信号も追加）
            if cert_age_days > 365:
                old_cert_signals.append("high_ml_old_cert")
        elif p >= ml_threshold_old and cert_age_days > age_threshold_old:
            # 中ML + 古い証明書
            old_cert_signals.append("medium_ml_old_cert")
            old_cert_phishing_detected = True
        elif p >= ml_threshold_very_old and cert_age_days > 730:
            # 低ML + 非常に古い証明書
            old_cert_signals.append("low_ml_very_old_cert")
            old_cert_phishing_detected = True

        if old_cert_phishing_detected or old_cert_signals:
            issues.append("old_cert_phishing")
            score_components["old_cert_phishing"] = True
            score_components["old_cert_signals"] = old_cert_signals
            score_components["old_cert_tld_dangerous"] = is_tld_dangerous

            # スコア底上げ（危険TLDの場合はより高く）
            if is_tld_dangerous:
                score = max(score, 0.55 + 0.03 * len(old_cert_signals))
            else:
                score = max(score, 0.50 + 0.02 * len(old_cert_signals))

    # 4-4. 既知ドメイン緩和（減点）
    # NOTE: apply mitigation ONLY for strict legitimate allowlist matches.
    if is_known_legit:
        mitigation = (
            KNOWN_DOMAIN_MITIGATION_LOW
            if score < KNOWN_DOMAIN_MITIGATION_SWITCH
            else KNOWN_DOMAIN_MITIGATION_HIGH
        )
        score = max(0.0, score - mitigation)
        issues.append("known_domain")
        score_components["known_domain_mitigation"] = round(float(mitigation), 4)

    # 4-4b. 信頼TLD緩和（2026-01-26追加）
    # 変更履歴:
    #   - 2026-01-26: FP分析より .org (32件, 10.5%) の誤検知が多いため緩和
    # .org, .edu, .gov 等の信頼TLDはリスクスコアを軽減
    _trusted_tld_mitigation = {
        "org": 0.08,   # .org: 正規団体の可能性が高い
        "edu": 0.12,   # .edu: 教育機関
        "gov": 0.15,   # .gov: 政府機関
        "mil": 0.15,   # .mil: 軍事機関
        "int": 0.10,   # .int: 国際機関
    }
    _tld_for_mitigation = _tld_suffix_ctx.lower()
    _trusted_mitigation_value = _trusted_tld_mitigation.get(_tld_for_mitigation, 0.0)

    # サブTLD（.gov.xx, .edu.xx）の場合も緩和
    if _trusted_mitigation_value == 0.0:
        if ".gov" in _tld_for_mitigation or _tld_for_mitigation.startswith("gov."):
            _trusted_mitigation_value = 0.12
        elif ".edu" in _tld_for_mitigation or _tld_for_mitigation.startswith("edu.") or _tld_for_mitigation.startswith("ac."):
            _trusted_mitigation_value = 0.10

    # ブランド検出がない場合のみ緩和を適用（ブランド偽装は除外）
    if _trusted_mitigation_value > 0 and "brand_detected" not in issue_set:
        score = max(0.0, score - _trusted_mitigation_value)
        issues.append("trusted_tld_mitigation")
        score_components["trusted_tld_mitigation"] = {
            "tld": _tld_for_mitigation,
            "mitigation": round(_trusted_mitigation_value, 3),
        }

    # 4-5. ツール整合性ボーナス
    if avg_tool_risk >= CONSISTENCY_THRESHOLD_TOOL_RISK and len(uniq_issues) >= CONSISTENCY_THRESHOLD_ISSUES:
        consistency_boost = CONSISTENCY_BONUS
        score = min(1.0, score + consistency_boost)
        issues.append("consistency")
        score_components["consistency_boost"] = round(float(consistency_boost), 4)

    # 4-6. 最終クリップ
    score = min(1.0, score)

    # ------------------------------------------------------------------
    # 5.x  低MLセーフティキャップ:
    #   - ML が極端に低い (p < 0.2)
    #   - brand ツールはほぼ無反応 (risk < 0.5)
    #   - high_risk_words のヒットもない
    #   - 強い証明書・ドメイン問題もない（no_cert / dangerous_tld / random_pattern だけ等）
    #   - 既知で「明確に怪しい」ドメインラベルでもない
    #   → contextual の score が 0.49 を超えないようにクリップする
    # ------------------------------------------------------------------
    try:
        tr = tool_results or {}

        # brand_risk（data ラッパ対応）
        b_raw = tr.get("brand_impersonation_check") or {}
        b_data = b_raw.get("data") if isinstance(b_raw, dict) and "data" in b_raw else b_raw
        brand_risk = float((b_data or {}).get("risk_score", 0.0) or 0.0)

        # cert / domain issues（data ラッパ対応）
        c_raw = tr.get("certificate_analysis") or {}
        c_data = c_raw.get("data") if isinstance(c_raw, dict) and "data" in c_raw else c_raw
        cert_issues = set(((c_data or {}).get("detected_issues", []) or []))

        d_raw = tr.get("short_domain_analysis") or {}
        d_data = d_raw.get("data") if isinstance(d_raw, dict) and "data" in d_raw else d_raw
        dom_issues = set(((d_data or {}).get("detected_issues", []) or []))

        # 「本当にヤバい」系フラグ（必要に応じて拡張）
        strong_cert_flags = {"mismatched_name", "expired", "revoked", "invalid_chain"}
        # 2026-01-25: random_pattern系を追加（FN削減）
        strong_dom_flags = {
            "idn_homograph", "very_short", "extreme_random_pattern",
            "random_pattern", "rare_bigram_random", "consonant_cluster_random",
            "digit_mixed_random"  # 2026-01-25追加
        }

        has_strong_cert = bool(cert_issues & strong_cert_flags)
        has_strong_dom = bool(dom_issues & strong_dom_flags)

        # known_domain ラベルから「明確に怪しい」ものだけ除外対象にする
        label_str: Optional[str] = None
        if isinstance(known_label, str):
            label_str = known_label
        is_known_suspicious = bool(is_known_seen and label_str in {"phishing", "phishing_like", "block"})

        if (
            p < 0.20
            and hr_hits == 0
            and brand_risk < 0.5
            and not has_strong_cert
            and not has_strong_dom
            and not is_known_suspicious
            and not has_critical_brand  # 2026-01-25: critical_brand検出時は cap 対象外
        ):
            # Guard: dangerous_tld は強シグナルのため cap 対象外
            if "dangerous_tld" not in dom_issues and score > 0.49:
                score_components["low_ml_safety_cap_applied"] = True
                score_components["low_ml_safety_cap_before"] = round(float(score), 4)
                score = 0.49
                score_components["low_ml_safety_cap_after"] = 0.49
                if "low_ml_safety_cap" not in issues:
                    issues.append("low_ml_safety_cap")
    except Exception:
        # ここで落ちても元のスコアをそのまま返す
        pass

    # ------------------------------------------------------------------
    # 5. Reasoning / details（既存キーは保持）
    # ------------------------------------------------------------------
    reasoning_bits: List[str] = [
        f"ML={p:.2f}({ml_category})",
        f"ツール平均={avg_tool_risk:.2f}",
    ]
    if hr_hits:
        reasoning_bits.append(f"高リスク語ヒット={hr_hits}")
    if is_known_seen and rd:
        reasoning_bits.append(f"既知(外部)={rd}({known_label})")
    if is_known_legit and rd:
        reasoning_bits.append("正規allowlist一致")
    if is_paradox_strong or is_paradox_weak:
        reasoning_bits.append("ML Paradox")
    if "multiple_risk_factors" in issues:
        reasoning_bits.append(f"要因数={len(uniq_issues)}")
    if "consistency" in issues:
        reasoning_bits.append("整合性")
    if "low_ml_safety_cap" in issues:
        reasoning_bits.append("低MLセーフティキャップ適用")
    if "low_signal_phishing" in issues:
        reasoning_bits.append(f"低シグナルフィッシング検出({','.join(low_signal_signals)})")
    if "old_cert_phishing" in issues:
        reasoning_bits.append(f"古い証明書フィッシング検出(cert_age={cert_age_days}日,{','.join(old_cert_signals)})")
    if "dangerous_tld_combo" in issues:
        reasoning_bits.append(f"危険TLD組み合わせ検出({','.join(dangerous_tld_combo_signals)})")

    # finalize score breakdown for logging
    try:
        score_components["final_score"] = round(float(score), 4)
    except Exception:
        score_components["final_score"] = None

    return {
        "tool_name": "contextual_risk_assessment",
        "detected_issues": issues,
        "risk_score": score,
        "details": {
            "ml_probability": p,
            "ml_category": ml_category,
            "total_issues_count": len(uniq_issues),
            # 既存コードとの互換用
            "combined_risk_score": round(avg_tool_risk, 2),
            "tool_average_risk": round(avg_tool_risk, 2),
            "is_ml_paradox": is_paradox_strong,  # 互換のため「強パラドックスのみ」True
            "all_detected_issues": uniq_issues,
            "high_risk_hits": hr_hits,
            "known_domain": {
                "is_known_seen": is_known_seen,
                "is_known_legit": is_known_legit,
                "label": known_label,
                "mitigation": mitigation,
                "legit_info": legit_info or {},
            },
            "consistency_boost": round(consistency_boost, 2),
            "score_components": score_components,
            # 追加の内部情報（将来のチューニング用）
            "paradox": {
                "risk_signal_count": risk_signal_count,
                "is_paradox_strong": is_paradox_strong,
                "is_paradox_weak": is_paradox_weak,
                # 効果測定用（2026-01-31追加）
                "excluded_signals": _paradox_excluded_signals,
                "would_have_triggered": _paradox_would_have_triggered,
            },
        },
        "reasoning": " / ".join(reasoning_bits),
    }
