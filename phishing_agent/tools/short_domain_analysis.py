# phishing_agent/tools/short_domain_analysis.py
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

    # 1. 長さチェック（元ロジック踏襲＋short をやや弱め）
    if n <= 3:
        cat = "very_short"
        issues.append("very_short")
        score += 0.30
    elif n <= 6:
        cat = "short"
        issues.append("short")
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
    entropy = _calculate_entropy(base)
    is_high_entropy = entropy > 4.0
    is_very_high_entropy = entropy >= 4.5  # 任意の強めフラグ

    vowel_ratio = (sum(1 for c in base.lower() if c in "aeiou") / len(base)) if base else 0.0
    digit_ratio = (sum(1 for c in base if c.isdigit()) / len(base)) if base else 0.0
    is_random = (vowel_ratio < 0.2 and digit_ratio < 0.5)

    if is_high_entropy:
        issues.append("high_entropy")
        score += 0.20
        if is_very_high_entropy:
            issues.append("very_high_entropy")
            score += 0.05
    elif is_random:
        issues.append("random_pattern")
        score += 0.20

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

    # 6-2. short + (high_entropy or random_pattern) + TLD が dangerous / neutral
    if (
        "short" in issues
        and (("high_entropy" in issues) or ("random_pattern" in issues))
        and (tld_category in ("dangerous", "neutral"))
    ):
        score = max(score, 0.50)
        if "short_random_combo" not in issues:
            issues.append("short_random_combo")
        combo_flags.append("short_random_combo")

    # 6-3. (high_entropy or random_pattern) + 高い TLD 統計
    if (("high_entropy" in issues) or ("random_pattern" in issues)) and (stat_weight >= 0.20):
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

    details: Dict[str, Any] = {
        "domain_length": n,
        "domain_length_category": cat,
        "base_domain": base,
        "tld": suffix,
        "tld_category": tld_category,
        "entropy": round(entropy, 2),
        "is_random_pattern": is_random,
        "vowel_ratio": round(vowel_ratio, 2),
        "digit_ratio": round(digit_ratio, 2),
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
        reasons.append(f"高エントロピー({entropy:.2f})")
        if "very_high_entropy" in issues:
            reasons.append("非常に高いエントロピー")
    elif "random_pattern" in issues:
        reasons.append("ランダム指標(母音/数字)")

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

    return {
        "tool_name": "short_domain_analysis",
        "detected_issues": issues,
        "risk_score": score,
        "details": details,
        "reasoning": " / ".join(reasons),
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
