# Phase 2 Planning: Python Modularization

**Date**: 2026-01-10
**Scope**: Python module extraction and config-driven redesign
**Baseline**: Phase 1.5 (brand feature working, PENDING output added)

---

## Executive Summary

Phase 2 transforms the 02_main.ipynb notebook into a **modular Python codebase** with:

1. **Config-driven design**: All settings externalized to YAML
2. **Reusable modules**: Features, training, gate logic separated
3. **Experimentation framework**: Systematic A/B testing capability
4. **Budget optimization**: Automated experiments for optimal Stage3 budget

**Expected Benefits**:
- Faster iteration (change config, not code)
- Reproducible experiments (version-controlled YAML)
- Systematic optimization (automated A/B testing)
- Cleaner codebase (separation of concerns)

---

## 1. Module Structure

### 1.1 Directory Layout

```
02_stage1_stage2/
├── configs/
│   ├── default.yaml              # Current baseline config
│   ├── experiments/
│   │   ├── budget_5k.yaml        # Budget experiment configs
│   │   ├── budget_10k.yaml
│   │   ├── budget_15k.yaml
│   │   └── budget_20k.yaml
│   └── brand_filtering/
│       ├── baseline.yaml         # No filtering (current)
│       ├── conservative.yaml     # Minimal blacklist (visa only)
│       └── aggressive.yaml       # Phase 1.6 style (for reference)
├── src/
│   ├── __init__.py
│   ├── config.py                 # Config loading and validation
│   ├── features.py               # Feature engineering
│   ├── brand_extraction.py       # LLM-based brand keyword extraction
│   ├── train_xgb.py              # Stage1 XGBoost training
│   ├── stage2_gate.py            # Stage2 LR gate logic
│   ├── route1.py                 # Threshold selection (Wilson score)
│   ├── segment_priority.py       # Priority pool construction
│   └── utils.py                  # Common utilities
├── scripts/
│   ├── run_experiment.py         # Single experiment runner
│   ├── run_budget_sweep.py       # Budget optimization experiments
│   └── compare_results.py        # Result comparison tool
├── notebooks/
│   └── 02_main_legacy.ipynb      # Backup of original notebook
└── README.md
```

### 1.2 Root Level

```
nextstep/
├── 02_main.py                    # New: Python script version (calls modules)
├── 02_main.ipynb                 # Keep for interactive exploration
├── 02_stage1_stage2/             # Module directory
└── artifacts/<RUN_ID>/           # Results (unchanged)
```

---

## 2. Module Specifications

### 2.1 config.py

**Purpose**: Load and validate YAML configuration

**Interface**:
```python
from dataclasses import dataclass
from typing import Optional, List
import yaml

@dataclass
class ExperimentConfig:
    viz_max_k: int
    viz_k_step: int
    viz_fn_cost: float
    eval_imbalance: bool
    eval_pos_rate: float
    eval_min_pos: int
    eval_seed: int

@dataclass
class XGBoostConfig:
    n_estimators: int
    max_depth: int
    learning_rate: float
    objective: str
    eval_metric: str
    subsample: float
    colsample_bytree: float
    random_state: int
    verbosity: int
    early_stopping_rounds: int
    val_size: float

@dataclass
class Route1Config:
    t_mode: str
    risk_max_auto_benign: float
    risk_max_auto_phish: float
    min_auto_samples: int
    risk_use_upper: bool
    risk_alpha: float

@dataclass
class Stage2Config:
    select_mode: str
    max_budget: int
    tau: float
    override_tau: float
    phi_phish: float
    phi_benign: float
    seg_only_benign: bool
    seg_optional: bool
    seg_include_idn: bool
    seg_include_brand: bool
    seg_min_p1: float
    seg_tau_priority: Optional[float]
    seg_tau_optional: Optional[float]
    oof_folds: int
    cert_extra: bool

@dataclass
class BrandConfig:
    min_count: int
    max_brands: int
    dynamic: bool
    # Phase 2 additions:
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    blacklist: Optional[List[str]] = None
    manual_additions: Optional[List[str]] = None
    phish_rate_threshold: Optional[float] = None

@dataclass
class IOConfig:
    run_id_env: str
    artifacts_base: str

@dataclass
class Config:
    experiment: ExperimentConfig
    xgboost: XGBoostConfig
    route1: Route1Config
    stage2: Stage2Config
    brand_keywords: BrandConfig
    io: IOConfig

def load_config(yaml_path: str) -> Config:
    """Load and validate config from YAML file"""
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    return Config(
        experiment=ExperimentConfig(**data['experiment']),
        xgboost=XGBoostConfig(**data['xgboost']),
        route1=Route1Config(**data['route1']),
        stage2=Stage2Config(**data['stage2']),
        brand_keywords=BrandConfig(**data['brand_keywords']),
        io=IOConfig(**data['io'])
    )
```

---

### 2.2 brand_extraction.py

**Purpose**: Extract brand keywords from phishing targets via LLM

**Interface**:
```python
from typing import List, Dict, Optional
import pandas as pd

class BrandExtractor:
    def __init__(self, config: BrandConfig):
        self.config = config
        self.batch_size = 5  # For LLM API rate limiting

    def extract_from_database(self, db_path: str) -> List[str]:
        """Extract brand keywords from phishtank_entries and jpcert tables"""
        # Implementation from Cell 16
        pass

    def filter_keywords(self, keywords: List[str]) -> List[str]:
        """Apply filtering based on config"""
        filtered = keywords

        # Length filter
        if self.config.min_length is not None:
            filtered = [k for k in filtered if len(k) >= self.config.min_length]
        if self.config.max_length is not None:
            filtered = [k for k in filtered if len(k) <= self.config.max_length]

        # Blacklist filter
        if self.config.blacklist:
            filtered = [k for k in filtered if k not in self.config.blacklist]

        # Manual additions
        if self.config.manual_additions:
            for kw in self.config.manual_additions:
                if kw not in filtered:
                    filtered.append(kw)

        return filtered

    def validate_with_data(
        self,
        keywords: List[str],
        df_candidates: pd.DataFrame
    ) -> Dict[str, dict]:
        """
        Validate keywords against actual candidate data.
        Returns performance statistics for each keyword.
        """
        stats = {}
        dom_low = df_candidates['domain'].str.lower()

        for kw in keywords:
            mask = dom_low.str.contains(kw, regex=False)
            matched = df_candidates[mask]

            if len(matched) > 0:
                n_phish = (matched['y_true'] == 1).sum()
                phish_rate = n_phish / len(matched)

                stats[kw] = {
                    'matches': len(matched),
                    'phish_count': int(n_phish),
                    'phish_rate': float(phish_rate),
                    'keep': (
                        self.config.phish_rate_threshold is None or
                        phish_rate >= self.config.phish_rate_threshold
                    )
                }

        return stats
```

---

### 2.3 features.py

**Purpose**: Feature engineering for Stage1 XGBoost

**Interface**:
```python
import pandas as pd
import numpy as np
from typing import List

class FeatureEngineer:
    def __init__(self, brand_keywords: List[str], cert_extra: bool = True):
        self.brand_keywords = brand_keywords
        self.cert_extra = cert_extra

    def add_brand_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add contains_brand feature"""
        dom_low = df['domain'].str.lower().astype(str)
        brand_hit = np.zeros(len(df), dtype=bool)

        for b in self.brand_keywords:
            brand_hit |= np.char.find(dom_low.values, b) >= 0

        df['contains_brand'] = brand_hit.astype(int)
        return df

    def add_idn_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add IDN (xn--) features"""
        df['is_idn'] = df['domain'].str.contains('xn--', regex=False).astype(int)
        return df

    def add_tld_features(self, df: pd.DataFrame, dangerous_tlds: List[str]) -> pd.DataFrame:
        """Add TLD-based features"""
        tld_lower = df['tld'].str.lower()
        df['is_dangerous_tld'] = tld_lower.isin(dangerous_tlds).astype(int)
        return df

    def build_features(
        self,
        df: pd.DataFrame,
        dangerous_tlds: List[str]
    ) -> pd.DataFrame:
        """Build all features for Stage1 training"""
        df = self.add_brand_features(df)
        df = self.add_idn_features(df)
        df = self.add_tld_features(df, dangerous_tlds)

        # Additional features from original notebook
        # (entropy, length, digit ratio, etc.)

        return df
```

---

### 2.4 train_xgb.py

**Purpose**: Train Stage1 XGBoost classifier

**Interface**:
```python
import xgboost as xgb
from sklearn.model_selection import train_test_split
from typing import Tuple
import pandas as pd

class Stage1Trainer:
    def __init__(self, config: XGBoostConfig):
        self.config = config
        self.model = None

    def train(
        self,
        df_train: pd.DataFrame,
        feature_cols: List[str],
        gpu_available: bool = False
    ) -> Tuple[xgb.Booster, dict]:
        """
        Train XGBoost model with early stopping.
        Returns (model, metrics_dict)
        """
        X = df_train[feature_cols]
        y = df_train['y_true']

        # Train/val split
        X_tr, X_val, y_tr, y_val = train_test_split(
            X, y,
            test_size=self.config.val_size,
            random_state=self.config.random_state,
            stratify=y
        )

        # XGBoost parameters
        params = {
            'max_depth': self.config.max_depth,
            'learning_rate': self.config.learning_rate,
            'objective': self.config.objective,
            'eval_metric': self.config.eval_metric,
            'subsample': self.config.subsample,
            'colsample_bytree': self.config.colsample_bytree,
            'random_state': self.config.random_state,
            'verbosity': self.config.verbosity,
            'tree_method': 'gpu_hist' if gpu_available else 'hist',
            'device': 'cuda' if gpu_available else 'cpu'
        }

        dtrain = xgb.DMatrix(X_tr, label=y_tr)
        dval = xgb.DMatrix(X_val, label=y_val)

        evals = [(dtrain, 'train'), (dval, 'val')]

        self.model = xgb.train(
            params,
            dtrain,
            num_boost_round=self.config.n_estimators,
            evals=evals,
            early_stopping_rounds=self.config.early_stopping_rounds,
            verbose_eval=10
        )

        # Compute metrics
        metrics = {
            'best_iteration': self.model.best_iteration,
            'best_score': self.model.best_score,
            'train_logloss': self.model.eval(dtrain),
            'val_logloss': self.model.eval(dval)
        }

        return self.model, metrics

    def predict_proba(self, df: pd.DataFrame, feature_cols: List[str]) -> np.ndarray:
        """Predict probabilities for Stage1"""
        X = df[feature_cols]
        dtest = xgb.DMatrix(X)
        return self.model.predict(dtest)
```

---

### 2.5 route1.py

**Purpose**: Automatic threshold selection via Wilson score

**Interface**:
```python
import numpy as np
from scipy import stats
from typing import Tuple

class Route1ThresholdSelector:
    def __init__(self, config: Route1Config):
        self.config = config

    def wilson_upper_bound(
        self,
        n_total: int,
        n_error: int,
        alpha: float = 0.05
    ) -> float:
        """Wilson score one-sided upper confidence bound"""
        if n_total == 0:
            return 1.0

        p = n_error / n_total
        z = stats.norm.ppf(1 - alpha)

        denominator = 1 + z**2 / n_total
        center = (p + z**2 / (2 * n_total)) / denominator
        margin = (z / denominator) * np.sqrt(p * (1 - p) / n_total + z**2 / (4 * n_total**2))

        return center + margin

    def select_thresholds(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray
    ) -> Tuple[float, float, dict]:
        """
        Select t_low and t_high based on Wilson score risk bounds.
        Returns (t_low, t_high, stats_dict)
        """
        # Implementation from original notebook Cell (Route1 logic)
        # ...

        return t_low, t_high, stats
```

---

### 2.6 stage2_gate.py

**Purpose**: Stage2 Logistic Regression gate with segment_priority selection

**Interface**:
```python
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from typing import List, Tuple

class Stage2Gate:
    def __init__(self, config: Stage2Config, brand_keywords: List[str]):
        self.config = config
        self.brand_keywords = brand_keywords
        self.model = None

    def train_oof(
        self,
        df_defer: pd.DataFrame,
        feature_cols: List[str]
    ) -> Tuple[LogisticRegression, np.ndarray]:
        """
        Train Stage2 LR with out-of-fold predictions.
        Returns (model, oof_proba)
        """
        # Implementation from original notebook
        # K-fold OOF training logic
        pass

    def select_segment_priority(
        self,
        df_defer: pd.DataFrame,
        p2: np.ndarray,
        dangerous_tlds: List[str]
    ) -> pd.DataFrame:
        """
        Select candidates using segment_priority mode.
        Returns df_defer with 'stage2_decision' column.
        """
        # Priority pool construction
        priority_mask = self._build_priority_pool(df_defer, dangerous_tlds)

        # Optional pool construction
        optional_mask = self._build_optional_pool(df_defer, dangerous_tlds)

        # Select from priority pool
        selected_priority = self._select_from_pool(
            df_defer[priority_mask],
            p2[priority_mask],
            tau=self.config.seg_tau_priority or self.config.tau,
            budget_remaining=self.config.max_budget
        )

        # Select from optional pool
        budget_remaining = self.config.max_budget - len(selected_priority)
        selected_optional = self._select_from_pool(
            df_defer[optional_mask],
            p2[optional_mask],
            tau=self.config.seg_tau_optional or self.config.tau,
            budget_remaining=budget_remaining
        )

        # Mark decisions
        df_defer['stage2_decision'] = 'drop_to_auto'  # PENDING
        df_defer.loc[selected_priority.index, 'stage2_decision'] = 'handoff'
        df_defer.loc[selected_optional.index, 'stage2_decision'] = 'handoff'

        return df_defer

    def _build_priority_pool(
        self,
        df: pd.DataFrame,
        dangerous_tlds: List[str]
    ) -> np.ndarray:
        """Build priority pool mask"""
        mask = np.zeros(len(df), dtype=bool)

        # Dangerous TLDs
        tld_low = df['tld'].str.lower()
        mask |= tld_low.isin(dangerous_tlds).values

        # IDN
        if self.config.seg_include_idn:
            mask |= df['domain'].str.contains('xn--', regex=False).values

        # Brand
        if self.config.seg_include_brand:
            dom_low = df['domain'].str.lower().astype(str)
            brand_mask = np.zeros(len(df), dtype=bool)
            for b in self.brand_keywords:
                brand_mask |= np.char.find(dom_low.values, b) >= 0
            mask |= brand_mask

        return mask

    def _build_optional_pool(
        self,
        df: pd.DataFrame,
        dangerous_tlds: List[str]
    ) -> np.ndarray:
        """Build optional pool mask (unknown TLD candidates)"""
        if not self.config.seg_optional:
            return np.zeros(len(df), dtype=bool)

        # Unknown TLD = not dangerous, not legitimate
        # (Implementation from original notebook)
        pass

    def _select_from_pool(
        self,
        df_pool: pd.DataFrame,
        p2_pool: np.ndarray,
        tau: float,
        budget_remaining: int
    ) -> pd.DataFrame:
        """Select candidates from pool based on tau threshold"""
        # Gray zone: tau < p2 < 1-tau
        gray_mask = (p2_pool > tau) & (p2_pool < 1 - tau)

        # Override rescue: confident mistakes
        override_mask = (
            ((p2_pool >= self.config.phi_phish) & (df_pool['y_true'] == 0)) |
            ((p2_pool <= self.config.phi_benign) & (df_pool['y_true'] == 1))
        )

        selected_mask = gray_mask | override_mask
        selected = df_pool[selected_mask]

        # Apply budget cap
        if len(selected) > budget_remaining:
            # Sort by distance from 0.5 (most uncertain first)
            distance = np.abs(p2_pool[selected_mask] - 0.5)
            sorted_idx = np.argsort(distance)
            selected = selected.iloc[sorted_idx[:budget_remaining]]

        return selected
```

---

### 2.7 segment_priority.py

**Purpose**: Standalone priority pool construction logic

**Interface**:
```python
import pandas as pd
import numpy as np
from typing import List, Dict

class PriorityPoolBuilder:
    def __init__(
        self,
        dangerous_tlds: List[str],
        brand_keywords: List[str],
        include_idn: bool = True,
        include_brand: bool = True
    ):
        self.dangerous_tlds = dangerous_tlds
        self.brand_keywords = brand_keywords
        self.include_idn = include_idn
        self.include_brand = include_brand

    def build_pool(self, df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """
        Build priority pool with component breakdown.
        Returns dict with masks for each component.
        """
        result = {}

        # Dangerous TLDs
        tld_low = df['tld'].str.lower()
        result['dangerous_tld'] = tld_low.isin(self.dangerous_tlds).values

        # IDN
        if self.include_idn:
            result['idn'] = df['domain'].str.contains('xn--', regex=False).values
        else:
            result['idn'] = np.zeros(len(df), dtype=bool)

        # Brand
        if self.include_brand:
            dom_low = df['domain'].str.lower().astype(str)
            brand_mask = np.zeros(len(df), dtype=bool)
            for b in self.brand_keywords:
                brand_mask |= np.char.find(dom_low.values, b) >= 0
            result['brand'] = brand_mask
        else:
            result['brand'] = np.zeros(len(df), dtype=bool)

        # Combined priority pool
        result['priority_pool'] = (
            result['dangerous_tld'] |
            result['idn'] |
            result['brand']
        )

        return result
```

---

## 3. Configuration Schema Updates

### 3.1 Enhanced brand_keywords Section

```yaml
brand_keywords:
  # Basic settings (Phase 1.5)
  min_count: 2
  max_brands: 100
  dynamic: true

  # Phase 2: Advanced filtering
  min_length: 4              # null = no filter
  max_length: 12             # null = no filter

  # Phase 2: Data-driven blacklist
  blacklist: null            # List of keywords to exclude, or null
  # Example: ['visa', 'india']

  # Phase 2: Manual additions
  manual_additions: null     # List of keywords to add, or null
  # Example: ['paypal', 'ebay', 'whatsapp']

  # Phase 2: Statistical filtering
  phish_rate_threshold: null # Minimum phish rate to keep keyword (0.0-1.0), or null
  # Example: 0.10 means only keep keywords with ≥10% phish rate

  # Phase 2: Validation settings
  validate_with_data: true   # Validate keywords against training data
  validation_report: true    # Generate keyword performance report
```

### 3.2 Experiment Config Template

**File**: `02_stage1_stage2/configs/experiments/budget_10k.yaml`

```yaml
# Experiment: Budget 10k (2x baseline)
# Baseline: default.yaml (budget 5k)
# Hypothesis: Doubling budget will reduce PENDING Phish by 30-40%

experiment:
  name: "budget_10k"
  description: "Stage3 budget increased to 10,000"
  baseline_config: "default.yaml"

  # Override Stage2 max_budget
  stage2:
    max_budget: 10000

# All other settings inherit from default.yaml
```

---

## 4. Experimentation Framework

### 4.1 Single Experiment Runner

**File**: `02_stage1_stage2/scripts/run_experiment.py`

```python
#!/usr/bin/env python3
"""
Run a single experiment with specified config.

Usage:
    python run_experiment.py --config configs/experiments/budget_10k.yaml
"""

import argparse
from pathlib import Path
from datetime import datetime
import json

from src.config import load_config
from src.brand_extraction import BrandExtractor
from src.features import FeatureEngineer
from src.train_xgb import Stage1Trainer
from src.route1 import Route1ThresholdSelector
from src.stage2_gate import Stage2Gate

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, help='Path to config YAML')
    parser.add_argument('--run-id', help='Custom RUN_ID (default: timestamp)')
    args = parser.parse_args()

    # Load config
    cfg = load_config(args.config)

    # Generate RUN_ID
    run_id = args.run_id or datetime.now().strftime('%Y-%m-%d_%H%M%S')

    # Setup artifacts directory
    artifacts_dir = Path(cfg.io.artifacts_base) / run_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Extract brand keywords
    print("🔌 Extracting brand keywords...")
    extractor = BrandExtractor(cfg.brand_keywords)
    brand_keywords = extractor.extract_from_database('data/phishing_db.sqlite')

    # Feature engineering
    print("🔧 Building features...")
    engineer = FeatureEngineer(brand_keywords, cert_extra=cfg.stage2.cert_extra)
    # ... load data, build features

    # Stage1 training
    print("🚀 Training Stage1 XGBoost...")
    trainer = Stage1Trainer(cfg.xgboost)
    model, metrics = trainer.train(df_train, feature_cols)

    # Route1 threshold selection
    print("📊 Selecting thresholds (Route1)...")
    route1 = Route1ThresholdSelector(cfg.route1)
    t_low, t_high, route1_stats = route1.select_thresholds(y_val, y_proba_val)

    # Stage2 gate
    print("🚪 Stage2 gate selection...")
    gate = Stage2Gate(cfg.stage2, brand_keywords)
    df_defer = gate.select_segment_priority(df_defer, p2, dangerous_tlds)

    # Save results
    print("💾 Saving results...")
    # ... save outputs to artifacts_dir

    # Compute final metrics
    pending_phish = (df_defer[df_defer['stage2_decision'] == 'drop_to_auto']['y_true'] == 1).sum()

    results = {
        'run_id': run_id,
        'config': args.config,
        'metrics': {
            'pending_phish': int(pending_phish),
            'priority_pool': int(gate.priority_pool_size),
            'brand_matches': int(gate.brand_match_count),
            # ... other metrics
        }
    }

    with open(artifacts_dir / 'experiment_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"✅ Experiment complete: {run_id}")
    print(f"   PENDING Phish: {pending_phish:,}")

if __name__ == '__main__':
    main()
```

---

### 4.2 Budget Sweep Runner

**File**: `02_stage1_stage2/scripts/run_budget_sweep.py`

```python
#!/usr/bin/env python3
"""
Run budget optimization experiments (5k, 10k, 15k, 20k).

Usage:
    python run_budget_sweep.py
"""

from pathlib import Path
import subprocess
import json
import pandas as pd

BUDGETS = [5000, 10000, 15000, 20000]

def main():
    results = []

    for budget in BUDGETS:
        print(f"\n{'='*60}")
        print(f"Running experiment: budget={budget:,}")
        print(f"{'='*60}\n")

        config_path = f"02_stage1_stage2/configs/experiments/budget_{budget//1000}k.yaml"

        # Run experiment
        result = subprocess.run(
            ['python', '02_stage1_stage2/scripts/run_experiment.py', '--config', config_path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"❌ Experiment failed: {result.stderr}")
            continue

        # Parse results
        run_id = result.stdout.split('RUN_ID:')[1].split()[0]
        results_path = Path('artifacts') / run_id / 'experiment_results.json'

        with open(results_path) as f:
            data = json.load(f)

        results.append({
            'budget': budget,
            'run_id': run_id,
            **data['metrics']
        })

    # Generate comparison report
    df_results = pd.DataFrame(results)
    df_results.to_csv('artifacts/budget_sweep_results.csv', index=False)

    print("\n" + "="*60)
    print("Budget Sweep Results")
    print("="*60)
    print(df_results[['budget', 'pending_phish', 'priority_pool']].to_string(index=False))

    # Analysis
    baseline_pending = df_results[df_results['budget'] == 5000]['pending_phish'].iloc[0]

    print("\n📊 Analysis:")
    for _, row in df_results.iterrows():
        reduction = (baseline_pending - row['pending_phish']) / baseline_pending * 100
        print(f"  Budget {row['budget']:,}: PENDING Phish {row['pending_phish']:,} ({reduction:+.1f}%)")

if __name__ == '__main__':
    main()
```

---

### 4.3 Result Comparison Tool

**File**: `02_stage1_stage2/scripts/compare_results.py`

```python
#!/usr/bin/env python3
"""
Compare results between two experiments.

Usage:
    python compare_results.py RUN_ID_1 RUN_ID_2
"""

import argparse
from pathlib import Path
import json
import pandas as pd

def load_results(run_id: str) -> dict:
    """Load experiment results"""
    results_path = Path('artifacts') / run_id / 'experiment_results.json'
    with open(results_path) as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('baseline_run_id', help='Baseline RUN_ID')
    parser.add_argument('experiment_run_id', help='Experiment RUN_ID')
    args = parser.parse_args()

    # Load results
    baseline = load_results(args.baseline_run_id)
    experiment = load_results(args.experiment_run_id)

    # Compare metrics
    print("="*60)
    print(f"Comparison: {args.baseline_run_id} vs {args.experiment_run_id}")
    print("="*60)

    metrics = [
        'pending_phish',
        'priority_pool',
        'brand_matches',
        'auto_error_rate'
    ]

    comparison = []
    for metric in metrics:
        base_val = baseline['metrics'].get(metric, 0)
        exp_val = experiment['metrics'].get(metric, 0)

        if base_val > 0:
            change_pct = (exp_val - base_val) / base_val * 100
        else:
            change_pct = 0

        comparison.append({
            'Metric': metric,
            'Baseline': base_val,
            'Experiment': exp_val,
            'Change': exp_val - base_val,
            'Change %': f"{change_pct:+.1f}%"
        })

    df_comparison = pd.DataFrame(comparison)
    print(df_comparison.to_string(index=False))

if __name__ == '__main__':
    main()
```

---

## 5. Migration Strategy

### 5.1 Phase 2.0: Module Extraction

**Goal**: Extract core logic into Python modules WITHOUT changing behavior

**Tasks**:
1. Create `02_stage1_stage2/src/` directory structure
2. Extract Cell 16 → `brand_extraction.py`
3. Extract Cell 19 → `features.py`
4. Extract Cell 20-25 → `train_xgb.py`
5. Extract Cell 26-30 → `route1.py`
6. Extract Cell 31-42 → `stage2_gate.py`
7. Create `config.py` with dataclass schema

**Validation**: Run 02_main.py and verify identical results to 02_main.ipynb

---

### 5.2 Phase 2.1: Config-Driven Design

**Goal**: Move all hardcoded values to YAML config

**Tasks**:
1. Extend `default.yaml` with brand_keywords filtering options
2. Update modules to read from Config objects
3. Create experiment configs (budget_5k.yaml, budget_10k.yaml, etc.)

**Validation**: Run multiple configs, verify config changes are reflected in results

---

### 5.3 Phase 2.2: Experimentation Framework

**Goal**: Enable automated A/B testing

**Tasks**:
1. Create `run_experiment.py` script
2. Create `run_budget_sweep.py` script
3. Create `compare_results.py` tool
4. Document experimentation workflow in README.md

**Validation**: Run budget sweep (5k/10k/15k/20k), generate comparison report

---

### 5.4 Phase 2.3: Brand Keyword Improvements

**Goal**: Implement smarter brand keyword filtering

**Tasks**:
1. Add `phish_rate_threshold` to BrandConfig
2. Implement data-driven validation in `brand_extraction.py`
3. Create conservative/aggressive filtering configs
4. Run A/B test: baseline vs conservative vs aggressive

**Validation**: Compare PENDING Phish reduction across configs

---

## 6. Expected Outcomes

### 6.1 Quantitative Goals

| Metric | Phase 1.5 Baseline | Phase 2 Target | Improvement |
|--------|-------------------|----------------|-------------|
| PENDING Phish | 2,119 | 1,500-1,700 | -20-30% |
| Priority pool | 1,657 | 2,000-2,500 | +20-50% |
| Brand matches | 198 (0.36%) | 500-800 (0.9-1.5%) | +150-300% |
| Config change time | N/A (code edit) | <1 min (YAML edit) | 10x faster |
| Experiment runtime | N/A (manual) | 15-20 min (automated) | Reproducible |

---

### 6.2 Qualitative Benefits

1. **Faster Iteration**:
   - Change config, not code
   - No need to edit notebook cells
   - Version control for experiments (git diff on YAML)

2. **Systematic Optimization**:
   - Automated A/B testing
   - Consistent comparison methodology
   - Reproducible results

3. **Cleaner Codebase**:
   - Separation of concerns (features, training, gate)
   - Testable modules
   - Easier to onboard new contributors

4. **Data-Driven Decisions**:
   - Brand keyword validation against real data
   - Statistical thresholds for filtering
   - No more "small sample" mistakes (Phase 1.6 lesson)

---

## 7. Risk Mitigation

### 7.1 Regression Testing

**Strategy**: Keep 02_main.ipynb as reference implementation

**Process**:
1. Run 02_main.ipynb → save results as baseline
2. Run 02_main.py (module version) → save results
3. Compare outputs (CSV files, metrics)
4. Verify identical results before proceeding

---

### 7.2 Incremental Migration

**Strategy**: Migrate one module at a time

**Process**:
1. Extract module (e.g., brand_extraction.py)
2. Test module in isolation
3. Integrate into 02_main.py
4. Run regression test
5. Repeat for next module

---

### 7.3 Fallback Plan

**If module version has issues**:
- Keep 02_main.ipynb as working baseline
- Fix module issues incrementally
- Do NOT abandon Phase 1.5 functional state

---

## 8. Success Criteria

### 8.1 Phase 2.0 (Module Extraction)

✅ Criteria:
- [ ] All 7 modules created with documented interfaces
- [ ] 02_main.py produces identical results to 02_main.ipynb
- [ ] Module tests pass (unit tests for each module)
- [ ] Code review complete

---

### 8.2 Phase 2.1 (Config-Driven)

✅ Criteria:
- [ ] Config schema documented in README
- [ ] Multiple experiment configs created (budget sweep)
- [ ] Config changes reflected in results
- [ ] YAML validation working

---

### 8.3 Phase 2.2 (Experimentation)

✅ Criteria:
- [ ] Budget sweep runs automatically (5k/10k/15k/20k)
- [ ] Comparison report generated
- [ ] Results reproducible (same config → same results)
- [ ] Runtime < 20 min per experiment

---

### 8.4 Phase 2.3 (Brand Improvements)

✅ Criteria:
- [ ] Data-driven filtering reduces false positives by 50%
- [ ] Brand matches increase by 150-300%
- [ ] PENDING Phish reduced by 20-30%
- [ ] No regression in auto_error_rate

---

## 9. Timeline Estimate

| Phase | Tasks | Estimated Effort | Dependencies |
|-------|-------|-----------------|--------------|
| 2.0: Module Extraction | 7 modules | 2-3 days | Phase 1.5 complete |
| 2.1: Config-Driven | Config schema, YAML | 1 day | Phase 2.0 |
| 2.2: Experimentation | Scripts, automation | 1 day | Phase 2.1 |
| 2.3: Brand Improvements | Smart filtering | 1-2 days | Phase 2.2 |
| **Total** | | **5-7 days** | |

**Note**: Timeline assumes no major blockers. Budget 20% buffer for debugging.

---

## 10. Next Immediate Steps

### Step 1: Create Module Structure

```bash
mkdir -p 02_stage1_stage2/src
mkdir -p 02_stage1_stage2/scripts
mkdir -p 02_stage1_stage2/notebooks
mkdir -p 02_stage1_stage2/configs/experiments
mkdir -p 02_stage1_stage2/configs/brand_filtering

touch 02_stage1_stage2/src/__init__.py
touch 02_stage1_stage2/src/config.py
touch 02_stage1_stage2/src/brand_extraction.py
touch 02_stage1_stage2/src/features.py
touch 02_stage1_stage2/src/train_xgb.py
touch 02_stage1_stage2/src/route1.py
touch 02_stage1_stage2/src/stage2_gate.py
touch 02_stage1_stage2/src/segment_priority.py
touch 02_stage1_stage2/src/utils.py
```

---

### Step 2: Backup Current Notebook

```bash
cp 02_main.ipynb 02_stage1_stage2/notebooks/02_main_legacy.ipynb
```

---

### Step 3: Start with config.py

Extract config loading logic from Cell 0 into `src/config.py` with dataclass schema.

---

### Step 4: Extract brand_extraction.py

Extract Cell 16 logic into `BrandExtractor` class with:
- `extract_from_database()` method
- `filter_keywords()` method
- `validate_with_data()` method

---

### Step 5: Create Minimal 02_main.py

Create working Python script that calls modules:

```python
#!/usr/bin/env python3
from pathlib import Path
from src.config import load_config
from src.brand_extraction import BrandExtractor

cfg = load_config('02_stage1_stage2/configs/default.yaml')

extractor = BrandExtractor(cfg.brand_keywords)
brand_keywords = extractor.extract_from_database('data/phishing_db.sqlite')

print(f"Extracted {len(brand_keywords)} brand keywords")
```

Run and verify output matches Cell 16.

---

## 11. Documentation Requirements

### 11.1 README Updates

**File**: `02_stage1_stage2/README.md`

Sections:
1. Overview (3-stage system architecture)
2. Module Structure (what each module does)
3. Configuration Schema (YAML documentation)
4. Running Experiments (how to use scripts)
5. Development Guide (how to add features)

---

### 11.2 Code Documentation

**Requirements**:
- Every module: docstring explaining purpose
- Every class: docstring with usage example
- Every method: docstring with parameters, returns, example

**Example**:
```python
class BrandExtractor:
    """
    Extract brand keywords from phishing target databases using LLM.

    This class handles the full pipeline:
    1. Query phishtank_entries and jpcert_phishing_urls tables
    2. Send targets to LLM for brand extraction
    3. Filter keywords based on config (length, blacklist, manual additions)
    4. Validate keywords against actual candidate data

    Example:
        >>> cfg = BrandConfig(min_count=2, max_brands=100, dynamic=True)
        >>> extractor = BrandExtractor(cfg)
        >>> keywords = extractor.extract_from_database('data/phishing_db.sqlite')
        >>> print(len(keywords))
        100
    """
```

---

## 12. Summary

Phase 2 transforms the 02 system from **notebook-based prototyping** to **production-ready modular codebase** with:

1. **7 Python modules** with clear responsibilities
2. **Config-driven design** for rapid experimentation
3. **Automated experimentation framework** for systematic optimization
4. **Data-driven brand keyword filtering** to avoid Phase 1.6 mistakes

**Key Success Metrics**:
- PENDING Phish: 2,119 → 1,500-1,700 (-20-30%)
- Brand matches: 198 → 500-800 (+150-300%)
- Experiment iteration time: Manual → <20 min automated

**Phase 2 sets the foundation for**:
- Phase 3: Advanced features (typo-tolerant matching, dynamic brand updates)
- Phase 4: Production deployment (API, monitoring, scaling)
- Phase 5: Research (Stage1 feature optimization, multi-model ensemble)

---

**Planning Document Date**: 2026-01-10
**Status**: Ready to begin Phase 2.0 (Module Extraction)
**Next Action**: Create module directory structure and start with config.py

