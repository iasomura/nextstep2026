"""
Configuration management for 02 Stage1/Stage2 system.

This module provides type-safe configuration loading from YAML files
using dataclasses.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
import yaml


@dataclass
class ExperimentConfig:
    """Experiment and visualization settings."""
    viz_max_k: int = 40000
    viz_k_step: int = 500
    viz_fn_cost: float = 3.0
    eval_imbalance: bool = False
    eval_pos_rate: float = 0.001
    eval_min_pos: int = 200
    eval_seed: int = 42


@dataclass
class XGBoostConfig:
    """Stage1 XGBoost hyperparameters."""
    n_estimators: int = 300
    max_depth: int = 8
    learning_rate: float = 0.1
    objective: str = "binary:logistic"
    eval_metric: str = "logloss"
    subsample: float = 0.8
    colsample_bytree: float = 0.8
    random_state: int = 42
    verbosity: int = 1
    early_stopping_rounds: int = 20
    val_size: float = 0.10


@dataclass
class Route1Config:
    """Route1 automatic threshold selection settings."""
    t_mode: str = "auto_from_val"
    risk_max_auto_benign: float = 0.001
    risk_max_auto_phish: float = 0.0002
    min_auto_samples: int = 200
    risk_use_upper: bool = True
    risk_alpha: float = 0.05


@dataclass
class Stage2Config:
    """Stage2 gate settings (segment_priority mode)."""
    select_mode: str = "segment_priority"
    max_budget: int = 5000

    # Thresholds
    tau: float = 0.40
    override_tau: float = 0.60
    phi_phish: float = 0.99
    phi_benign: float = 0.01

    # Segment gate settings
    seg_only_benign: bool = False
    seg_optional: bool = True
    seg_include_idn: bool = True
    seg_include_brand: bool = True
    seg_min_p1: float = 0.00
    seg_tau_priority: Optional[float] = None
    seg_tau_optional: Optional[float] = None

    # Other settings
    oof_folds: int = 5
    cert_extra: bool = True


@dataclass
class BrandConfig:
    """Brand keyword extraction and filtering settings."""
    min_count: int = 2
    max_brands: int = 100
    dynamic: bool = True

    # Phase 2: Advanced filtering options
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    blacklist: Optional[List[str]] = None
    manual_additions: Optional[List[str]] = None
    phish_rate_threshold: Optional[float] = None

    # Validation settings
    validate_with_data: bool = False
    validation_report: bool = False


@dataclass
class IOConfig:
    """Input/Output path settings."""
    run_id_env: str = "RUN_ID"
    artifacts_base: str = "artifacts"


@dataclass
class Config:
    """
    Complete configuration for 02 Stage1/Stage2 system.

    Example:
        >>> cfg = Config.from_yaml("02_stage1_stage2/configs/default.yaml")
        >>> print(cfg.stage2.max_budget)
        5000
    """
    experiment: ExperimentConfig
    xgboost: XGBoostConfig
    route1: Route1Config
    stage2: Stage2Config
    brand_keywords: BrandConfig
    io: IOConfig

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "Config":
        """
        Load configuration from YAML file.

        Args:
            yaml_path: Path to YAML configuration file

        Returns:
            Config object with all settings

        Example:
            >>> cfg = Config.from_yaml("02_stage1_stage2/configs/default.yaml")
        """
        yaml_path = Path(yaml_path)
        if not yaml_path.exists():
            raise FileNotFoundError(f"Config file not found: {yaml_path}")

        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)

        return cls(
            experiment=ExperimentConfig(**data.get('experiment', {})),
            xgboost=XGBoostConfig(**data.get('xgboost', {})),
            route1=Route1Config(**data.get('route1', {})),
            stage2=Stage2Config(**data.get('stage2', {})),
            brand_keywords=BrandConfig(**data.get('brand_keywords', {})),
            io=IOConfig(**data.get('io', {}))
        )

    def to_env_vars(self) -> Dict[str, str]:
        """
        Convert config to environment variables for backward compatibility.

        Returns:
            Dictionary of environment variable names and values
        """
        env_vars = {}

        # Route1 settings
        env_vars['XGB_T_MODE'] = self.route1.t_mode
        env_vars['XGB_RISK_MAX_AUTO_BENIGN'] = str(self.route1.risk_max_auto_benign)
        env_vars['XGB_RISK_MAX_AUTO_PHISH'] = str(self.route1.risk_max_auto_phish)
        env_vars['XGB_MIN_AUTO_SAMPLES'] = str(self.route1.min_auto_samples)
        env_vars['XGB_RISK_USE_UPPER'] = '1' if self.route1.risk_use_upper else '0'
        env_vars['XGB_RISK_ALPHA'] = str(self.route1.risk_alpha)

        # XGBoost settings
        env_vars['XGB_VAL_SIZE'] = str(self.xgboost.val_size)

        # Stage2 settings
        env_vars['STAGE2_SELECT_MODE'] = self.stage2.select_mode
        env_vars['STAGE2_SEG_ONLY_BENIGN'] = '1' if self.stage2.seg_only_benign else '0'
        env_vars['STAGE2_SEG_OPTIONAL'] = '1' if self.stage2.seg_optional else '0'
        env_vars['STAGE2_SEG_MIN_P1'] = str(self.stage2.seg_min_p1)
        env_vars['STAGE2_TAU'] = str(self.stage2.tau)
        env_vars['STAGE2_MAX_BUDGET'] = str(self.stage2.max_budget)
        env_vars['STAGE2_SEG_INCLUDE_IDN'] = '1' if self.stage2.seg_include_idn else '0'
        env_vars['STAGE2_SEG_INCLUDE_BRAND'] = '1' if self.stage2.seg_include_brand else '0'

        # Experiment settings
        env_vars['VIZ_MAX_K'] = str(self.experiment.viz_max_k)
        env_vars['VIZ_K_STEP'] = str(self.experiment.viz_k_step)
        env_vars['VIZ_FN_COST'] = str(self.experiment.viz_fn_cost)
        env_vars['EVAL_IMBALANCE'] = '1' if self.experiment.eval_imbalance else '0'
        env_vars['EVAL_POS_RATE'] = str(self.experiment.eval_pos_rate)
        env_vars['EVAL_MIN_POS'] = str(self.experiment.eval_min_pos)
        env_vars['EVAL_SEED'] = str(self.experiment.eval_seed)

        return env_vars

    def apply_env_vars(self) -> None:
        """Apply configuration to environment variables."""
        import os
        for key, value in self.to_env_vars().items():
            os.environ[key] = value

    def print_summary(self) -> None:
        """Print configuration summary."""
        print("📋 Configuration Summary:")
        print(f"   Brand feature: {'enabled' if self.stage2.seg_include_brand else 'disabled'}")
        print(f"   Stage2 budget: {self.stage2.max_budget:,}")
        print(f"   Route1 mode: {self.route1.t_mode}")
        print(f"   XGBoost estimators: {self.xgboost.n_estimators}")
        print(f"   Max brands: {self.brand_keywords.max_brands}")


def load_config(yaml_path: str = "02_stage1_stage2/configs/default.yaml") -> Config:
    """
    Convenience function to load configuration.

    Args:
        yaml_path: Path to YAML configuration file

    Returns:
        Config object

    Example:
        >>> from src.config import load_config
        >>> cfg = load_config()
        >>> print(cfg.stage2.max_budget)
        5000
    """
    return Config.from_yaml(yaml_path)
