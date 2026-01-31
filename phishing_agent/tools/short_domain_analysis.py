# phishing_agent/tools/short_domain_analysis.py
# 変更履歴:
#   - 2026-01-28: FP分析に基づくロールバック
#     - random_pattern（低母音比率）を無効化: Precision 39%、FP 55件の主犯
#     - digit_mixed_random を削除: Precision 45%、効果薄い
#     - no_vowel_dangerous_tld を削除: Precision 43%、効果薄い
#     - 維持: consonant_cluster_random (68%), rare_bigram_random (54%), dangerous_tld (75%)
#   - 2026-01-27: ccTLD解釈機能追加（FP削減）
#     - ccTLDでは短いドメインが一般的という情報をLLMに提供
#   - 2026-01-24: ランダム文字列検出強化
#     - 子音クラスター検出 (_count_consonant_clusters)
#     - レアバイグラム分析 (_rare_bigram_ratio)
#     - 短いドメイン (≤8文字) でのエントロピー閾値引き下げ (4.0→3.5)
#     - dangerous TLD限定でのvowel_ratio閾値引き下げ (0.2→0.15)
from __future__ import annotations
from typing import Any, Dict, List, Optional
import math

from ..tools_module import safe_tool_wrapper, _ET, _CT, _tld_stat_weight
from .legitimate_domains import is_legitimate_domain  # 追加 :contentReference[oaicite:1]{index=1}


def _calculate_entropy(text: str) -> float:
    """文字列のエントロピーを計算（Notebook版ロジックを移植）"""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log(p, 2) for p in prob if p > 0)


# ---------------------------------------------------------------------------
# ランダム文字列検出強化 (2026-01-24追加)
# ---------------------------------------------------------------------------

# 英語で極めて稀なバイグラム (出現確率 < 0.001)
RARE_BIGRAMS: frozenset = frozenset([
    "qx", "qz", "zx", "xz", "jq", "qj", "vx", "xv",
    "zq", "qk", "kq", "fq", "qf", "jx", "xj", "vq",
    "wq", "qw", "zj", "jz", "xq", "qv", "bx", "xb",
    "cx", "xc", "dx", "xd", "fx", "xf", "gx", "xg",
    "hx", "xh", "jv", "vj", "kx", "xk", "mx", "xm",
    "px", "xp", "sx", "xs", "tx", "xt", "wx", "xw",
    "zv", "vz", "zw", "wz", "zk", "kz", "zf", "fz",
    "zg", "gz", "zh", "hz",
])

_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")

# ---------------------------------------------------------------------------
# ccTLD (Country Code TLD) 解釈機能 (2026-01-27追加)
# FP分析より、ccTLDでの短いドメイン（cndp.fr, rvp.cz等）が誤検知されていた
# ccTLDでは政府機関・企業の略称として短いドメインが一般的
# ---------------------------------------------------------------------------

# 主要なccTLDと国名のマッピング
CCTLD_COUNTRIES: Dict[str, str] = {
    # ヨーロッパ
    "fr": "France", "de": "Germany", "uk": "United Kingdom", "it": "Italy",
    "es": "Spain", "nl": "Netherlands", "be": "Belgium", "at": "Austria",
    "ch": "Switzerland", "pl": "Poland", "cz": "Czech Republic", "se": "Sweden",
    "no": "Norway", "dk": "Denmark", "fi": "Finland", "pt": "Portugal",
    "gr": "Greece", "ie": "Ireland", "hu": "Hungary", "ro": "Romania",
    "ua": "Ukraine", "sk": "Slovakia", "hr": "Croatia", "si": "Slovenia",
    "bg": "Bulgaria", "lt": "Lithuania", "lv": "Latvia", "ee": "Estonia",
    # アジア太平洋
    "jp": "Japan", "kr": "South Korea", "au": "Australia", "nz": "New Zealand",
    "in": "India", "sg": "Singapore", "hk": "Hong Kong", "tw": "Taiwan",
    "th": "Thailand", "my": "Malaysia", "id": "Indonesia", "ph": "Philippines",
    "vn": "Vietnam",
    # 南北アメリカ
    "ca": "Canada", "mx": "Mexico", "br": "Brazil", "ar": "Argentina",
    "cl": "Chile", "co": "Colombia", "pe": "Peru",
    # 中東・アフリカ
    "il": "Israel", "ae": "UAE", "za": "South Africa", "eg": "Egypt",
    "tr": "Turkey",
    # ロシア・CIS
    "ru": "Russia", "by": "Belarus", "kz": "Kazakhstan",
}

# 危険とみなすccTLD（フィッシング率が高い）
DANGEROUS_CCTLDS: frozenset = frozenset([
    "cn",  # 中国 - フィッシング率86.9%
    "cc",  # ココス諸島 - 実質的にgTLD的使用
    "tk", "ml", "ga", "cf", "gq",  # Freenom無料TLD
    "pw",  # パラオ - 悪用多い
])


def _interpret_cctld(tld: str, domain_length: int) -> Dict[str, Any]:
    """
    ccTLD（国別コードTLD）の解釈を生成（LLM判断材料用）

    研究知見:
    - ccTLDでは政府機関・企業の略称として短いドメインが一般的
    - 例: cndp.fr (フランス国立教育資料センター), rvp.cz (チェコ教育ポータル)
    - ただし、cn, cc等の危険ccTLDは例外
    """
    interpretation = {
        "is_cctld": False,
        "country": None,
        "is_dangerous_cctld": False,
        "short_domain_common": False,
        "explanation": "",
    }

    tld_lower = tld.lower().lstrip(".")

    # 2文字TLDかどうか確認
    if len(tld_lower) != 2:
        interpretation["explanation"] = "Not a country-code TLD (length != 2)"
        return interpretation

    # 危険ccTLDかどうか
    if tld_lower in DANGEROUS_CCTLDS:
        interpretation["is_cctld"] = True
        interpretation["is_dangerous_cctld"] = True
        interpretation["country"] = CCTLD_COUNTRIES.get(tld_lower, "Unknown")
        interpretation["explanation"] = (
            f".{tld_lower} is a high-risk country-code TLD. "
            "Short domains on this TLD should still be treated with caution."
        )
        return interpretation

    # 通常のccTLD
    if tld_lower in CCTLD_COUNTRIES:
        country = CCTLD_COUNTRIES[tld_lower]
        interpretation["is_cctld"] = True
        interpretation["country"] = country

        # 短いドメイン（6文字以下）は一般的
        if domain_length <= 6:
            interpretation["short_domain_common"] = True
            interpretation["explanation"] = (
                f".{tld_lower} is the country-code TLD for {country}. "
                f"Short domains ({domain_length} chars) are common on ccTLDs "
                "for government agencies, corporations, and established organizations. "
                "This reduces the suspicion of random_pattern detection."
            )
        else:
            interpretation["explanation"] = (
                f".{tld_lower} is the country-code TLD for {country}."
            )
        return interpretation

    # 2文字だがリストにない（新しいccTLD等）
    interpretation["explanation"] = (
        f".{tld_lower} appears to be a country-code TLD (2 characters) "
        "but is not in the known list."
    )
    return interpretation


def _count_consonant_clusters(text: str) -> int:
    """3文字以上の連続子音クラスターの数をカウント."""
    cluster_count = 0
    current_run = 0
    for ch in text.lower():
        if ch in _CONSONANTS:
            current_run += 1
        else:
            if current_run >= 3:
                cluster_count += 1
            current_run = 0
    if current_run >= 3:
        cluster_count += 1
    return cluster_count


def _rare_bigram_ratio(text: str) -> float:
    """テキスト中のレアバイグラムの出現率を計算."""
    if len(text) < 4:
        return 0.0
    text_lower = text.lower()
    # アルファベットのみ抽出
    alpha_only = "".join(ch for ch in text_lower if ch.isalpha())
    if len(alpha_only) < 4:
        return 0.0
    bigrams = [alpha_only[i:i+2] for i in range(len(alpha_only) - 1)]
    if not bigrams:
        return 0.0
    rare_count = sum(1 for bg in bigrams if bg in RARE_BIGRAMS)
    return rare_count / len(bigrams)


@safe_tool_wrapper("short_domain_analysis")
def short_domain_analysis(
    domain: str,
    dangerous_tlds: Optional[List[str]] = None,
    legitimate_tlds: Optional[List[str]] = None,
    neutral_tlds: Optional[List[str]] = None,
    phishing_tld_stats: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    短いドメインと構造分析
    - Phase3 既存ロジック + エントロピー検知 + ホワイトリスト + 構造情報 + コンボ強化
    """
    et = _ET(domain)
    base = getattr(et, "domain", "") or ""
    suffix = getattr(et, "suffix", "") or ""
    # tldextract がある環境では amazon.co.jp → registered_domain='amazon.co.jp'
    registered = getattr(et, "registered_domain", "") or ""

    n = len(base)

    # --- ラベル数・サブドメイン数（構造情報） ---
    host = (domain or "").split("://")[-1].split("/")[0].strip(".")
    labels = [p for p in host.split(".") if p]
    label_count = len(labels)
    # eTLD+1 を除いた「サブドメインラベル数」
    subdomain_label_count = max(0, label_count - 2)

    issues: List[str] = []
    score = 0.0

    # 2026-01-26追加: 信頼TLDの判定（短ドメインペナルティ緩和用）
    # 変更履歴:
    #   - 2026-01-26: FP分析より .org 等の誤検知が多いため、ペナルティを緩和
    _trusted_tlds = {"org", "edu", "gov", "mil", "int", "ac.jp", "go.jp", "co.jp", "ne.jp"}
    _is_trusted_tld = suffix.lower() in _trusted_tlds or any(
        suffix.lower().endswith(f".{t}") for t in ["gov", "edu", "mil", "ac", "go"]
    )

    # 1. 長さチェック（元ロジック踏襲＋short をやや弱め）
    # 2026-01-26: 信頼TLDの場合はペナルティをさらに緩和
    if n <= 3:
        cat = "very_short"
        issues.append("very_short")
        if _is_trusted_tld:
            score += 0.10  # 信頼TLD: 0.30 → 0.10
        else:
            score += 0.30
    elif n <= 6:
        cat = "short"
        issues.append("short")
        if _is_trusted_tld:
            score += 0.03  # 信頼TLD: 0.10 → 0.03
        else:
            score += 0.10  # 0.15 → 0.10 に調整
    elif n <= 10:
        cat = "normal"
    else:
        cat = "long"

    # 2. TLDチェック（デフォルト付き）
    # Always-dangerous TLDs (merge with external list to ensure coverage)
    _always_dangerous = [
        "info","top","xyz","buzz","click","win","loan","date","party","review","science",
        "stream","kim","men","gq","cf","ml","ga","tk","icu","download",
        # Additional high-risk TLDs often used in phishing
        "cc","lat","online","shop","cn","ws","pw","cfd","cyou","wang","bar","mw","live",
    ]
    danger_def = list(set((dangerous_tlds or []) + _always_dangerous))
    legit_def = list(legitimate_tlds or ["com","org","net","co.jp","jp","edu","gov","ac.jp","ne.jp"])
    neutral_def = list(neutral_tlds or ["io","co","me","ai"])

    tld_category = _CT(suffix, danger_def, legit_def, neutral_def)
    if tld_category == "dangerous":
        issues.append("dangerous_tld")
        score += 0.25

    # 3. エントロピー計算 + ランダムっぽさ判定
    # 2026-01-24: 短いドメイン (≤8文字) ではエントロピー閾値を引き下げ (4.0→3.5)
    entropy = _calculate_entropy(base)
    entropy_threshold = 3.5 if n <= 8 else 4.0
    is_high_entropy = entropy > entropy_threshold
    is_very_high_entropy = entropy >= 4.5  # 任意の強めフラグ

    vowel_ratio = (sum(1 for c in base.lower() if c in "aeiou") / len(base)) if base else 0.0
    digit_ratio = (sum(1 for c in base if c.isdigit()) / len(base)) if base else 0.0
    # 2026-01-28: random_pattern (低母音比率) を無効化
    # 理由: Precision 39%、FP 55件（主犯）。略語（frmtr, fncdg等）を誤検出
    # 旧コード: vowel_threshold = 0.15 if tld_category == "dangerous" else 0.2
    #          is_random = (vowel_ratio < vowel_threshold and digit_ratio < 0.5)
    vowel_threshold = 0.2  # 参照用に残す
    is_random = False  # 無効化

    # 2026-01-24: 子音クラスター検出
    # 2026-01-27: 長いドメイン（15文字以上）では無効化（FP削減）
    #   - directsellingnews.com (18文字) のような長い英単語組み合わせで
    #     偶発的に子音クラスター ("llings", "ctsell") が発生するため
    consonant_clusters = _count_consonant_clusters(base)
    is_consonant_cluster_random = consonant_clusters >= 2 and n < 15

    # 2026-01-24: レアバイグラム検出
    rare_bigram_r = _rare_bigram_ratio(base)
    is_rare_bigram_random = rare_bigram_r > 0.15

    if is_high_entropy:
        issues.append("high_entropy")
        score += 0.20
        if is_very_high_entropy:
            issues.append("very_high_entropy")
            score += 0.05
    elif is_random:
        issues.append("random_pattern")
        score += 0.20

    # 子音クラスター検出 (high_entropy/random_pattern と独立して加点)
    if is_consonant_cluster_random:
        issues.append("consonant_cluster_random")
        if "high_entropy" not in issues and "random_pattern" not in issues:
            score += 0.20  # 他のランダム検出がない場合のみフル加点
        else:
            score += 0.05  # 既にランダム検出されている場合は追加ボーナス

    # レアバイグラム検出
    if is_rare_bigram_random:
        issues.append("rare_bigram_random")
        if "high_entropy" not in issues and "random_pattern" not in issues and "consonant_cluster_random" not in issues:
            score += 0.20  # 他のランダム検出がない場合のみフル加点
        else:
            score += 0.05  # 既にランダム検出されている場合は追加ボーナス

    # 2026-01-28: digit_mixed_random を無効化
    # 理由: Precision 45%、効果薄い
    # 旧コード:
    # is_digit_mixed_random = (
    #     digit_ratio > 0 and digit_ratio < 0.3 and vowel_ratio <= 0.25
    #     and consonant_clusters >= 1 and len(base) >= 8
    #     and not is_random and not is_rare_bigram_random
    # )
    is_digit_mixed_random = False  # 無効化

    # 2026-01-28: no_vowel_dangerous_tld を無効化
    # 理由: Precision 43%、効果薄い
    # 旧コード:
    # is_no_vowel_suspicious = (
    #     vowel_ratio == 0 and len(base) >= 3 and len(base) <= 8
    #     and tld_category == "dangerous" and not is_high_entropy and not is_random
    # )
    is_no_vowel_suspicious = False  # 無効化

    # 2026-01-26: 連続文字パターン検出（機械生成ドメイン）
    # "aaabbcc.com", "112233.com" のようなパターンを検出
    def _has_repeating_pattern(s: str) -> bool:
        if len(s) < 4:
            return False
        # 3文字以上の同じ文字の連続
        for i in range(len(s) - 2):
            if s[i] == s[i+1] == s[i+2]:
                return True
        # 連続する数字/文字のシーケンス (abc, 123)
        seq_count = 0
        for i in range(len(s) - 1):
            if ord(s[i+1]) - ord(s[i]) == 1:
                seq_count += 1
            else:
                seq_count = 0
            if seq_count >= 3:  # 4文字以上の連続シーケンス
                return True
        return False

    is_repeating_pattern = _has_repeating_pattern(base.lower())
    if is_repeating_pattern and tld_category == "dangerous":
        issues.append("repeating_pattern_dangerous_tld")
        score += 0.15

    # 4. TLD統計ウェイト（既存ロジック）
    stat_weight = _tld_stat_weight(suffix, phishing_tld_stats)
    score += stat_weight

    # 5. サブドメインの深さによる軽い加点
    #    subdomain_label_count >= 2 程度から「深め」とみなす（最大 +0.15）
    if subdomain_label_count >= 2:
        issues.append("deep_subdomain_chain")
        score += 0.10
        if (tld_category == "dangerous") or (stat_weight >= 0.20):
            issues.append("deep_chain_with_risky_tld")
            score += 0.05

    # ------------------------------------------------------
    # 6. コンビネーションルールでスコアの「下限」を底上げ
    # ------------------------------------------------------
    combo_flags: List[str] = []

    # 6-1. very_short + dangerous_tld
    if ("very_short" in issues) and ("dangerous_tld" in issues):
        score = max(score, 0.60)
        if "very_short_dangerous_combo" not in issues:
            issues.append("very_short_dangerous_combo")
        combo_flags.append("very_short_dangerous_combo")

    # 2026-01-28: ランダム検出フラグのヘルパー（ロールバック後）
    # random_pattern と digit_mixed_random は無効化済み
    _any_random = (
        "high_entropy" in issues
        or "consonant_cluster_random" in issues
        or "rare_bigram_random" in issues
    )

    # 6-2. short + (any random flag) + TLD が dangerous / neutral
    if (
        "short" in issues
        and _any_random
        and (tld_category in ("dangerous", "neutral"))
    ):
        score = max(score, 0.50)
        if "short_random_combo" not in issues:
            issues.append("short_random_combo")
        combo_flags.append("short_random_combo")

    # 6-3. (any random flag) + 高い TLD 統計
    if _any_random and (stat_weight >= 0.20):
        score = max(score, 0.55)
        if "random_with_high_tld_stat" not in issues:
            issues.append("random_with_high_tld_stat")
        combo_flags.append("random_with_high_tld_stat")

    # ------------------------------------------------------
    # 7. 正規ドメインホワイトリストによるリスク軽減（最後に適用）
    # ------------------------------------------------------
    legit_result: Dict[str, Any] = {
        "is_legitimate": False,
        "brand": None,
        "confidence": 0.0,
        "reason": "not_in_whitelist",
    }
    try:
        legit: Optional[Dict[str, Any]] = None
        # まず registered_domain を優先（tldextract がある環境を想定）:contentReference[oaicite:2]{index=2}
        if registered:
            legit = is_legitimate_domain(registered)
        # fall back: tldextract が無く registered_domain がうまく取れていない場合は host 全体でチェック
        if not legit or not isinstance(legit, dict) or not legit.get("is_legitimate"):
            if host:
                legit = is_legitimate_domain(host)
        if isinstance(legit, dict):
            legit_result.update(
                {
                    "is_legitimate": bool(legit.get("is_legitimate")),
                    "brand": legit.get("brand"),
                    "confidence": float(legit.get("confidence") or 0.0),
                    "reason": str(legit.get("reason") or ""),
                }
            )
    except Exception as e:
        legit_result["reason"] = f"legitimate_check_error:{e}"

    is_legit = bool(legit_result["is_legitimate"])
    legit_conf = float(legit_result.get("confidence") or 0.0)

    if is_legit:
        if legit_conf >= 0.95:
            # ほぼ確実な正規ドメイン → スコアを極小にクリップ
            score = min(score, 0.05)
            if "known_legitimate_domain" not in issues:
                issues.append("known_legitimate_domain")
        elif legit_conf >= 0.90:
            # 高めの信頼度 → 70% 減衰
            score *= 0.3
            if "likely_legitimate_domain" not in issues:
                issues.append("likely_legitimate_domain")

    # ------------------------------------------------------
    # 8. flags と details の組み立て
    # ------------------------------------------------------
    length_flags: List[str] = []
    if "very_short" in issues:
        length_flags.append("very_short")
    if "short" in issues:
        length_flags.append("short")

    entropy_flags: List[str] = []
    if "high_entropy" in issues:
        entropy_flags.append("high_entropy")
    if "very_high_entropy" in issues:
        entropy_flags.append("very_high_entropy")

    # 旧来フィールドはそのまま維持
    tld_stat_val = phishing_tld_stats.get(suffix, 0) if isinstance(phishing_tld_stats, dict) else 0

    # 最後にクリップ
    score = max(0.0, min(1.0, float(score)))

    # ccTLD解釈を生成（2026-01-27追加）
    cctld_interpretation = _interpret_cctld(suffix, n)

    details: Dict[str, Any] = {
        "domain_length": n,
        "domain_length_category": cat,
        "base_domain": base,
        "tld": suffix,
        "tld_category": tld_category,
        "entropy": round(entropy, 2),
        "entropy_threshold": entropy_threshold,
        "is_random_pattern": is_random,
        "vowel_ratio": round(vowel_ratio, 2),
        "vowel_threshold": vowel_threshold,
        "digit_ratio": round(digit_ratio, 2),
        "consonant_clusters": consonant_clusters,
        "rare_bigram_ratio": round(rare_bigram_r, 3),
        "tld_stat": tld_stat_val,
        "tld_stat_weight": round(stat_weight, 3),
        # 追加構造情報
        "label_count": label_count,
        "subdomain_label_count": subdomain_label_count,
        # 追加フラグ
        "length_flags": length_flags,
        "entropy_flags": entropy_flags,
        "combo_flags": combo_flags,
        # 正規ドメイン判定結果
        "legitimate_check": legit_result,
        # ccTLD解釈（2026-01-27追加）
        "cctld_interpretation": cctld_interpretation,
    }

    # ------------------------------------------------------
    # 9. reasoning（どの要因が効いたかをわかりやすく列挙）
    # ------------------------------------------------------
    reasons: List[str] = []

    if "very_short" in issues:
        reasons.append(f"非常に短い({n}文字)")
    elif "short" in issues:
        reasons.append(f"短い({n}文字)")

    if tld_category == "dangerous":
        reasons.append(f"危険TLD({suffix})")
    elif tld_category == "neutral":
        reasons.append(f"中立TLD({suffix})")

    if "high_entropy" in issues:
        reasons.append(f"高エントロピー({entropy:.2f}, 閾値={entropy_threshold})")
        if "very_high_entropy" in issues:
            reasons.append("非常に高いエントロピー")
    elif "random_pattern" in issues:
        reasons.append(f"ランダム指標(母音率={vowel_ratio:.2f}<{vowel_threshold})")

    if "consonant_cluster_random" in issues:
        reasons.append(f"子音クラスター検出({consonant_clusters}個)")
    if "rare_bigram_random" in issues:
        reasons.append(f"レアバイグラム検出(比率={rare_bigram_r:.3f})")

    if "deep_subdomain_chain" in issues:
        reasons.append(f"深いサブドメインチェーン(ラベル数={label_count})")
    if "deep_chain_with_risky_tld" in issues:
        reasons.append("深いサブドメイン + 危険/高リスクTLD")

    if stat_weight > 0:
        reasons.append(f"TLD統計ウェイト(+{stat_weight:.2f})")

    # コンビネーション要因
    if "very_short_dangerous_combo" in issues:
        reasons.append("very_short + dangerous_tld コンボ")
    if "short_random_combo" in issues:
        reasons.append("short + (high_entropy/random_pattern) コンボ")
    if "random_with_high_tld_stat" in issues:
        reasons.append("random/high_entropy + 高TLD統計 コンボ")

    # 正規ドメイン軽減
    if is_legit:
        b = legit_result.get("brand")
        reasons.append(
            f"正規ドメインホワイトリスト一致({b}, conf={legit_conf:.2f}) によりリスク軽減"
        )

    if not reasons:
        reasons.append("短いドメインの顕著な問題なし")

    # ccTLD解釈をreasoningに追加（2026-01-27）
    # 短いドメイン + 非危険ccTLD の場合、LLMに文脈情報を提供
    cctld_reasoning = ""
    if cctld_interpretation.get("is_cctld") and not cctld_interpretation.get("is_dangerous_cctld"):
        if cctld_interpretation.get("short_domain_common"):
            country = cctld_interpretation.get("country", "Unknown")
            cctld_reasoning = (
                f" || [CCTLD CONTEXT] .{suffix} is the country-code TLD for {country}. "
                f"Short domains ({n} chars) are common on ccTLDs for government/corporate abbreviations. "
                "This context should reduce suspicion of random_pattern detection."
            )

    return {
        "tool_name": "short_domain_analysis",
        "detected_issues": issues,
        "risk_score": score,
        "details": details,
        "reasoning": " / ".join(reasons) + cctld_reasoning,
    }


if __name__ == "__main__":
    # 簡易自己テスト（スタンドアロン実行用）
    from pprint import pprint

    test_domains = [
        "ab.tk",                    # 非常に短い + 危険TLD
        "xj3p9.top",                # 短い + ランダム + 危険TLD
        "rakuten.co.jp",            # 正規ドメイン（ホワイトリスト）
        "login.secure.example.info" # 深いサブドメイン + 危険TLD
    ]

    phishing_tld_stats = {
        "tk": 0.9,
        "top": 0.8,
        "info": 0.5,
        "co.jp": 0.1,
        "jp": 0.1,
    }

    for d in test_domains:
        print("=" * 60)
        print(f"Domain: {d}")
        # safe_tool_wrapper により {"success": True, "data": {...}} 形式になる想定
        result = short_domain_analysis(
            domain=d,
            dangerous_tlds=["info", "top", "xyz", "buzz", "tk"],
            legitimate_tlds=["com", "org", "net", "co.jp", "jp"],
            neutral_tlds=["io", "ai", "co"],
            phishing_tld_stats=phishing_tld_stats,
        )
        pprint(result)
