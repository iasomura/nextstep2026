# -*- coding: utf-8 -*-
"""phishing_agent.stage2_decider_v2

Stage2 v2b: Stage1 DEFER集合に対する第2意思決定器（p2=phish確率）を提供します。
- Stage1のAUTO領域は変更しない（Stage2はStage1=DEFERにのみ適用）
- Stage2は p2 を出力し、phi_low/phi_high の2閾値で
    AUTO_BENIGN_2 / AUTO_PHISH_2 / DEFER2 を返す
- DEFER2 は agent もしくは human に送る（DEFER2をbenign扱いしない）

CHANGELOG
- 2026-01-07: 初版。TaskB設計（Stage2を第2意思決定器へ）に対応。
  既存の err_pred (lr_defer_model) とは別系統として実装し、互換性のため既存列は維持しつつ
  p2 と stage2_decision などの列を追加する前提。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import numpy as np

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None  # type: ignore

from scipy.stats import norm


def _logit(p: np.ndarray, eps: float = 1e-9) -> np.ndarray:
    p = np.clip(p, eps, 1.0 - eps)
    return np.log(p / (1.0 - p))


def wilson_upper(k: int, n: int, alpha_one_sided: float = 0.05) -> float:
    """One-sided (upper) Wilson bound for binomial proportion.

    k: #errors
    n: sample size
    returns: upper confidence bound for error rate
    """
    if n <= 0:
        return 1.0
    z = float(norm.ppf(1.0 - alpha_one_sided))
    phat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (phat + z2 / (2.0 * n)) / denom
    half = (z * np.sqrt((phat * (1.0 - phat) / n) + (z2 / (4.0 * n * n)))) / denom
    return float(min(1.0, center + half))


@dataclass
class Stage2Thresholds:
    phi_low: float
    phi_high: float
    alpha_one_sided: float = 0.05
    min_auto_samples_benign: int = 200
    min_auto_samples_phish_priority: int = 50
    risk_max_auto_benign_2: float = 0.005
    risk_max_auto_phish_2_priority: float = 0.1
    auto_benign_condition: str = "stage1_pred==0 AND p2<=phi_low"
    auto_phish_condition: str = "priority_segment AND p2>=phi_high"

    val_meta: Optional[Dict[str, Any]] = None


def build_stage2_features(X_scaled: np.ndarray, p1: np.ndarray) -> np.ndarray:
    """Stage2の特徴量: [X_scaled, p1, logit(p1)]"""
    return np.hstack([X_scaled, p1.reshape(-1, 1), _logit(p1).reshape(-1, 1)])


def train_stage2_xgb(
    X2_train: np.ndarray,
    y_train: np.ndarray,
    *,
    random_state: int = 42,
    n_estimators: int = 600,
    max_depth: int = 4,
    learning_rate: float = 0.05,
    subsample: float = 0.8,
    colsample_bytree: float = 0.8,
    reg_lambda: float = 1.0,
    n_jobs: int = 4,
):
    """Train Stage2 phish probability model (XGBClassifier)."""
    if XGBClassifier is None:
        raise RuntimeError("xgboost is not available in this environment")

    n_pos = int(np.sum(y_train == 1))
    n_neg = int(np.sum(y_train == 0))
    scale_pos_weight = (n_neg / max(1, n_pos)) if n_pos > 0 else 1.0

    model = XGBClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        subsample=subsample,
        colsample_bytree=colsample_bytree,
        reg_lambda=reg_lambda,
        objective="binary:logistic",
        eval_metric="logloss",
        n_jobs=n_jobs,
        random_state=random_state,
        scale_pos_weight=scale_pos_weight,
    )
    model.fit(X2_train, y_train)
    return model


def _select_phi_low(
    p2_val: np.ndarray,
    y_val: np.ndarray,
    *,
    risk_max: float,
    min_n: int,
    alpha_one_sided: float,
) -> Tuple[float, Dict[str, Any]]:
    order = np.argsort(p2_val)
    p_sorted = p2_val[order]
    y_sorted = y_val[order]
    cum_phish = np.cumsum(y_sorted == 1)
    n = np.arange(1, len(p_sorted) + 1)

    best_i: Optional[int] = None
    for i in range(len(p_sorted)):
        if n[i] < min_n:
            continue
        k = int(cum_phish[i])
        ub = wilson_upper(k, int(n[i]), alpha_one_sided=alpha_one_sided)
        if ub <= risk_max:
            best_i = i
    if best_i is None:
        raise RuntimeError("No feasible phi_low under the given constraints")

    i = best_i
    return float(p_sorted[i]), {
        "n": int(n[i]),
        "k_phish_in_auto_benign_2": int(cum_phish[i]),
        "phish_rate_point": float(cum_phish[i] / n[i]),
        "phish_rate_wilson_upper": float(wilson_upper(int(cum_phish[i]), int(n[i]), alpha_one_sided=alpha_one_sided)),
    }


def _select_phi_high_on_priority(
    p2_val: np.ndarray,
    y_val: np.ndarray,
    priority_mask: np.ndarray,
    *,
    risk_max: float,
    min_n: int,
    alpha_one_sided: float,
) -> Tuple[float, Dict[str, Any]]:
    p2 = p2_val[priority_mask]
    y = y_val[priority_mask]
    if len(p2) == 0:
        raise RuntimeError("priority_mask produced empty validation set")

    order = np.argsort(-p2)
    p_desc = p2[order]
    y_desc = y[order]
    cum_benign = np.cumsum(y_desc == 0)
    n = np.arange(1, len(p_desc) + 1)

    best_i: Optional[int] = None
    for i in range(len(p_desc)):
        if n[i] < min_n:
            continue
        k = int(cum_benign[i])
        ub = wilson_upper(k, int(n[i]), alpha_one_sided=alpha_one_sided)
        if ub <= risk_max:
            best_i = i
    if best_i is None:
        raise RuntimeError("No feasible phi_high under the given constraints")

    i = best_i
    return float(p_desc[i]), {
        "n": int(n[i]),
        "k_benign_in_auto_phish_2": int(cum_benign[i]),
        "benign_rate_point": float(cum_benign[i] / n[i]),
        "benign_rate_wilson_upper": float(wilson_upper(int(cum_benign[i]), int(n[i]), alpha_one_sided=alpha_one_sided)),
    }


def choose_thresholds(
    p2_val: np.ndarray,
    y_val: np.ndarray,
    priority_mask: np.ndarray,
    *,
    alpha_one_sided: float = 0.05,
    min_auto_samples_benign: int = 200,
    min_auto_samples_phish_priority: int = 50,
    risk_max_auto_benign_2: float = 0.005,
    risk_max_auto_phish_2_priority: float = 0.1,
) -> Stage2Thresholds:
    """Choose phi_low/phi_high on validation set with Wilson safety constraints."""
    phi_low, meta_low = _select_phi_low(
        p2_val,
        y_val,
        risk_max=risk_max_auto_benign_2,
        min_n=min_auto_samples_benign,
        alpha_one_sided=alpha_one_sided,
    )
    phi_high, meta_high = _select_phi_high_on_priority(
        p2_val,
        y_val,
        priority_mask,
        risk_max=risk_max_auto_phish_2_priority,
        min_n=min_auto_samples_phish_priority,
        alpha_one_sided=alpha_one_sided,
    )

    th = Stage2Thresholds(
        phi_low=phi_low,
        phi_high=phi_high,
        alpha_one_sided=alpha_one_sided,
        min_auto_samples_benign=min_auto_samples_benign,
        min_auto_samples_phish_priority=min_auto_samples_phish_priority,
        risk_max_auto_benign_2=risk_max_auto_benign_2,
        risk_max_auto_phish_2_priority=risk_max_auto_phish_2_priority,
    )
    th.val_meta = {"phi_low_meta": meta_low, "phi_high_meta_priority": meta_high}
    return th


def apply_stage2(
    p2: np.ndarray,
    stage1_pred: np.ndarray,
    priority_mask: np.ndarray,
    thresholds: Stage2Thresholds,
) -> np.ndarray:
    """Return stage2 decision for Stage1 DEFER samples."""
    out = np.full(len(p2), "DEFER2", dtype=object)
    out[(stage1_pred == 0) & (p2 <= thresholds.phi_low)] = "AUTO_BENIGN_2"
    out[(priority_mask) & (p2 >= thresholds.phi_high)] = "AUTO_PHISH_2"
    return out
