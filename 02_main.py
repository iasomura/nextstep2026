#!/usr/bin/env python3
"""
02 Stage1/Stage2 Main Script - Full Pipeline (Phase 2.1)

This script provides a complete end-to-end pipeline for phishing detection.

Usage:
    # Predict on new domains from CSV
    python 02_main.py --predict --input domains.csv --output results.csv

    # Evaluate on test data
    python 02_main.py --eval --run-id 2026-01-10_140940

    # Interactive mode (single domain)
    python 02_main.py --interactive
"""

import sys
from pathlib import Path
import argparse
import json

# Add 02_stage1_stage2 to Python path
sys.path.insert(0, str(Path(__file__).parent / "02_stage1_stage2"))

from src.config import load_config
from src.features import FeatureEngineer
from src.train_xgb import Stage1Trainer
from src.route1 import Route1ThresholdSelector
from src.stage2_gate import Stage2Gate
import pandas as pd
import numpy as np


def get_latest_run_id():
    """Get the most recent RUN_ID from artifacts directory."""
    artifacts_dir = Path("artifacts")
    if not artifacts_dir.exists():
        return None

    runs = [d.name for d in artifacts_dir.iterdir()
            if d.is_dir() and d.name != '_current' and not d.name.startswith('.')]

    if not runs:
        return None

    return sorted(runs)[-1]


def load_artifacts(run_id):
    """
    Load required artifacts for prediction.

    Returns:
        dict with brand_keywords, model, feature_order, thresholds
    """
    artifacts_dir = Path("artifacts") / run_id

    if not artifacts_dir.exists():
        raise FileNotFoundError(f"Artifacts directory not found: {artifacts_dir}")

    print(f"\n📦 Loading artifacts from: {run_id}")

    # Load brand keywords
    brand_keywords_path = artifacts_dir / "models" / "brand_keywords.json"
    with open(brand_keywords_path) as f:
        brand_keywords = json.load(f)
    print(f"   ✅ Brand keywords: {len(brand_keywords)} keywords")

    # Load feature order
    feature_order_path = artifacts_dir / "models" / "feature_order.json"
    with open(feature_order_path) as f:
        feature_order = json.load(f)
    print(f"   ✅ Feature order: {len(feature_order)} features")

    # Load model path
    model_path = artifacts_dir / "models" / "xgboost_model_baseline.pkl"
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    print(f"   ✅ Model: {model_path.name}")

    # Load thresholds
    thresholds_path = artifacts_dir / "results" / "route1_thresholds.json"
    thresholds = None
    if thresholds_path.exists():
        with open(thresholds_path) as f:
            thresholds = json.load(f)
        print(f"   ✅ Thresholds: t_low={thresholds['t_low']:.6f}, t_high={thresholds['t_high']:.6f}")
    else:
        print(f"   ⚠️  No thresholds file found (will use default)")

    return {
        'brand_keywords': brand_keywords,
        'model_path': model_path,
        'feature_order': feature_order,
        'thresholds': thresholds,
        'artifacts_dir': artifacts_dir
    }


def run_predict(args, cfg):
    """
    Prediction mode: predict on new domains from CSV or command line.

    Args:
        args: Command line arguments
        cfg: Configuration object

    Returns:
        Exit code (0 for success)
    """
    print("\n" + "="*80)
    print("🔮 Prediction Mode")
    print("="*80)

    # Determine RUN_ID
    run_id = args.run_id or get_latest_run_id()
    if not run_id:
        print("❌ Error: No RUN_ID specified and no artifacts found.")
        print("   Use --run-id to specify, or run 01_data_preparation.py first.")
        return 1

    # Load artifacts
    try:
        artifacts = load_artifacts(run_id)
    except Exception as e:
        print(f"❌ Error loading artifacts: {e}")
        return 1

    # Load input data
    if args.input:
        # From CSV file
        print(f"\n📂 Loading input data from: {args.input}")
        df_input = pd.read_csv(args.input)

        if 'domain' not in df_input.columns:
            print("❌ Error: Input CSV must have a 'domain' column")
            return 1

        domains = df_input['domain'].tolist()
        print(f"   ✅ Loaded {len(domains):,} domains")
    else:
        print("❌ Error: --input is required for predict mode")
        return 1

    # Initialize components
    print("\n🔧 Initializing components...")
    engineer = FeatureEngineer(artifacts['brand_keywords'])
    trainer = Stage1Trainer(cfg.xgboost)
    trainer.load_model(artifacts['model_path'])

    selector = Route1ThresholdSelector(cfg.route1)
    if artifacts['thresholds']:
        selector.t_low = artifacts['thresholds']['t_low']
        selector.t_high = artifacts['thresholds']['t_high']
        selector.selection_meta = artifacts['thresholds']
    else:
        # Use default thresholds
        selector.t_low = 0.2
        selector.t_high = 0.8
        selector.selection_meta = {'t_low': 0.2, 't_high': 0.8, 'mode': 'default'}

    gate = Stage2Gate(cfg.stage2, artifacts['brand_keywords'])
    print("   ✅ Components initialized")

    # Extract features
    print(f"\n🧬 Extracting features from {len(domains):,} domains...")
    features_list = []
    for i, domain in enumerate(domains):
        if (i + 1) % 1000 == 0:
            print(f"   Progress: {i+1:,}/{len(domains):,}")
        features = engineer.extract_features(domain, cert_data=None)
        features_list.append(features)

    df_features = pd.DataFrame(features_list, columns=engineer.get_feature_names())

    # Merge with original data
    for col in df_input.columns:
        if col not in df_features.columns:
            df_features[col] = df_input[col].values

    print(f"   ✅ Features extracted: {len(df_features):,} samples")

    # Stage1 prediction
    print("\n🤖 Running Stage1 prediction...")
    predictions = trainer.predict_proba(df_features, artifacts['feature_order'])
    df_features['stage1_score'] = predictions
    print(f"   ✅ Predictions: min={predictions.min():.4f}, max={predictions.max():.4f}, mean={predictions.mean():.4f}")

    # Route1 classification
    print("\n🚦 Applying Route1 thresholds...")
    decisions = selector.apply_thresholds(predictions)
    decision_map = {0: 'AUTO_BENIGN', 1: 'DEFER', 2: 'AUTO_PHISH'}
    df_features['route1_decision'] = [decision_map[d] for d in decisions]

    n_benign = (decisions == 0).sum()
    n_defer = (decisions == 1).sum()
    n_phish = (decisions == 2).sum()

    print(f"   ✅ Classification complete:")
    print(f"      AUTO_BENIGN: {n_benign:,} ({100*n_benign/len(decisions):.1f}%)")
    print(f"      DEFER:       {n_defer:,} ({100*n_defer/len(decisions):.1f}%)")
    print(f"      AUTO_PHISH:  {n_phish:,} ({100*n_phish/len(decisions):.1f}%)")

    # Stage2 gate (if enabled and DEFER candidates exist)
    if not args.skip_stage2 and n_defer > 0:
        print(f"\n🚪 Applying Stage2 gate to {n_defer:,} DEFER candidates...")

        df_defer = df_features[decisions == 1].copy()
        p_defer = predictions[decisions == 1]

        # Apply custom budget if specified
        if args.stage2_budget:
            from dataclasses import replace
            custom_config = replace(cfg.stage2, max_budget=args.stage2_budget)
            gate = Stage2Gate(custom_config, artifacts['brand_keywords'])

        df_defer = gate.select_segment_priority(df_defer, p_defer)

        # Merge results
        df_features.loc[df_defer.index, 'stage2_decision'] = df_defer['stage2_decision']

        n_handoff = (df_defer['stage2_decision'] == 'handoff').sum()
        n_pending = (df_defer['stage2_decision'] == 'drop_to_auto').sum()

        print(f"   ✅ Stage2 selection:")
        print(f"      Handoff (Stage3): {n_handoff:,} ({100*n_handoff/n_defer:.1f}% of DEFER)")
        print(f"      PENDING:          {n_pending:,} ({100*n_pending/n_defer:.1f}% of DEFER)")
    else:
        if args.skip_stage2:
            print("\n⏭️  Stage2 skipped (--skip-stage2)")
        else:
            print("\n⏭️  Stage2 skipped (no DEFER candidates)")
        df_features['stage2_decision'] = None

    # Create final decision
    df_features['final_decision'] = df_features['route1_decision'].copy()
    handoff_mask = df_features['stage2_decision'] == 'handoff'
    df_features.loc[handoff_mask, 'final_decision'] = 'HANDOFF_TO_STAGE3'

    # Save results
    output_path = args.output or f"results/predictions_{run_id}.csv"
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df_features.to_csv(output_path, index=False)
    print(f"\n💾 Results saved: {output_path}")

    # Save statistics
    stats = {
        'run_id': run_id,
        'total_domains': len(df_features),
        'auto_benign': int(n_benign),
        'auto_phish': int(n_phish),
        'defer': int(n_defer),
        'handoff_to_stage3': int((df_features['stage2_decision'] == 'handoff').sum()) if not args.skip_stage2 else 0,
        'pending': int((df_features['stage2_decision'] == 'drop_to_auto').sum()) if not args.skip_stage2 else 0,
    }

    stats_path = output_path.parent / f"stats_{run_id}.json"
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"   ✅ Statistics saved: {stats_path}")

    # Summary
    print("\n" + "="*80)
    print("✅ Prediction Complete!")
    print("="*80)
    print(f"\nResults summary:")
    print(f"  Total domains:     {len(df_features):,}")
    print(f"  AUTO_BENIGN:       {n_benign:,}")
    print(f"  AUTO_PHISH:        {n_phish:,}")
    print(f"  DEFER → Handoff:   {stats['handoff_to_stage3']:,}")
    print(f"  DEFER → PENDING:   {stats['pending']:,}")
    print(f"\n📄 Output: {output_path}")
    print("="*80)

    return 0


def run_eval(args, cfg):
    """
    Evaluation mode: evaluate model on test data.
    """
    print("\n" + "="*80)
    print("📊 Evaluation Mode")
    print("="*80)

    print("\n⚠️  Evaluation mode not yet implemented in Phase 2.1")
    print("   Use test_integration.py for testing with real data")

    return 0


def run_interactive(args, cfg):
    """
    Interactive mode: predict single domains interactively.
    """
    print("\n" + "="*80)
    print("💬 Interactive Mode")
    print("="*80)

    # Determine RUN_ID
    run_id = args.run_id or get_latest_run_id()
    if not run_id:
        print("❌ Error: No RUN_ID specified and no artifacts found.")
        return 1

    # Load artifacts
    try:
        artifacts = load_artifacts(run_id)
    except Exception as e:
        print(f"❌ Error loading artifacts: {e}")
        return 1

    # Initialize components
    print("\n🔧 Initializing components...")
    engineer = FeatureEngineer(artifacts['brand_keywords'])
    trainer = Stage1Trainer(cfg.xgboost)
    trainer.load_model(artifacts['model_path'])

    selector = Route1ThresholdSelector(cfg.route1)
    if artifacts['thresholds']:
        selector.t_low = artifacts['thresholds']['t_low']
        selector.t_high = artifacts['thresholds']['t_high']
    else:
        selector.t_low = 0.2
        selector.t_high = 0.8

    print("   ✅ Ready!")

    print("\n" + "="*80)
    print("Enter domains to classify (or 'quit' to exit)")
    print("="*80)

    while True:
        try:
            domain = input("\nDomain: ").strip()
            if not domain or domain.lower() in ['quit', 'exit', 'q']:
                break

            # Extract features
            features = engineer.extract_features(domain, None)
            df = pd.DataFrame([features], columns=engineer.get_feature_names())

            # Predict
            prediction = trainer.predict_proba(df, artifacts['feature_order'])[0]
            decision = selector.apply_thresholds(np.array([prediction]))[0]

            decision_map = {0: '🟢 AUTO_BENIGN', 1: '🟡 DEFER', 2: '🔴 AUTO_PHISH'}

            print(f"\n   Result: {decision_map[decision]}")
            print(f"   Score:  {prediction:.4f}")
            print(f"   Thresholds: t_low={selector.t_low:.4f}, t_high={selector.t_high:.4f}")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"   ❌ Error: {e}")

    print("\n" + "="*80)
    print("Goodbye!")
    print("="*80)

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="02 Stage1/Stage2 Phishing Detection System (Phase 2.1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Predict on CSV file
  python 02_main.py --predict --input domains.csv --output results.csv

  # Interactive mode
  python 02_main.py --interactive

  # Use specific RUN_ID
  python 02_main.py --predict --input domains.csv --run-id 2026-01-10_140940

  # Skip Stage2
  python 02_main.py --predict --input domains.csv --skip-stage2
        """
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('--predict', action='store_true',
                           help='Predict on new domains from CSV')
    mode_group.add_argument('--eval', action='store_true',
                           help='Evaluate on test data (not implemented yet)')
    mode_group.add_argument('--interactive', action='store_true',
                           help='Interactive mode for single domains')

    # Common options
    parser.add_argument('--config', type=str,
                       default='02_stage1_stage2/configs/default.yaml',
                       help='Path to configuration file')
    parser.add_argument('--run-id', type=str,
                       help='RUN_ID to use for artifacts (default: latest)')

    # Predict mode options
    parser.add_argument('--input', type=str,
                       help='Input CSV file with "domain" column')
    parser.add_argument('--output', type=str,
                       help='Output CSV file for results')
    parser.add_argument('--skip-stage2', action='store_true',
                       help='Skip Stage2 gate')
    parser.add_argument('--stage2-budget', type=int,
                       help='Override Stage2 budget')

    args = parser.parse_args()

    # Load configuration
    try:
        cfg = load_config(args.config)
        print(f"✅ Configuration loaded: {args.config}")
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        return 1

    # Execute mode
    if args.predict:
        return run_predict(args, cfg)
    elif args.eval:
        return run_eval(args, cfg)
    elif args.interactive:
        return run_interactive(args, cfg)

    return 0


if __name__ == '__main__':
    sys.exit(main())
