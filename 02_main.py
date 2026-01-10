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


def run_train(args, cfg):
    """
    Training mode: Full notebook workflow (train + evaluate).

    This replicates the original Notebook workflow:
    1. Load train_data.pkl and test_data.pkl
    2. Train XGBoost model
    3. Select Route1 thresholds
    4. Evaluate Stage2 gate
    5. Save all results to artifacts
    """
    print("\n" + "="*80)
    print("🎓 Training Mode (Notebook Workflow)")
    print("="*80)

    # Determine RUN_ID
    run_id = args.run_id or get_latest_run_id()
    if not run_id:
        print("❌ Error: No RUN_ID specified.")
        print("   This mode requires existing artifacts from 01_data_preparation.py")
        print("   Use --run-id to specify the RUN_ID")
        return 1

    artifacts_dir = Path("artifacts") / run_id
    processed_dir = artifacts_dir / "processed"

    # Check for required pkl files
    train_pkl = processed_dir / "train_data.pkl"
    test_pkl = processed_dir / "test_data.pkl"

    if not train_pkl.exists() or not test_pkl.exists():
        print(f"❌ Error: Required pkl files not found")
        print(f"   Train: {train_pkl} {'✅' if train_pkl.exists() else '❌'}")
        print(f"   Test:  {test_pkl} {'✅' if test_pkl.exists() else '❌'}")
        print(f"\n   Please run 01_data_preparation.py first to generate pkl files.")
        return 1

    print(f"\n📁 Using RUN_ID: {run_id}")
    print(f"   Artifacts: {artifacts_dir}")

    # Load data
    print("\n📂 Loading training data...")
    import joblib
    train_data = joblib.load(train_pkl)
    test_data = joblib.load(test_pkl)

    X_train = train_data['X']
    y_train = train_data['y']
    X_test = test_data['X']
    y_test = test_data['y']
    feature_names = train_data.get('feature_names', [])

    print(f"   ✅ Train: {X_train.shape[0]:,} samples, {X_train.shape[1]} features")
    print(f"   ✅ Test:  {X_test.shape[0]:,} samples, {X_test.shape[1]} features")

    # Create DataFrames
    df_train = pd.DataFrame(X_train, columns=feature_names)
    df_train['y_true'] = y_train

    df_test = pd.DataFrame(X_test, columns=feature_names)
    df_test['y_true'] = y_test

    # Add domains if available
    if 'domains' in train_data:
        df_train['domain'] = train_data['domains']
    if 'domains' in test_data:
        df_test['domain'] = test_data['domains']

    # Train XGBoost
    print("\n🤖 Training XGBoost model...")
    from sklearn.model_selection import train_test_split

    # Split train into train/val
    df_train_split, df_val = train_test_split(
        df_train,
        test_size=cfg.xgboost.val_size,
        random_state=cfg.xgboost.random_state,
        stratify=df_train['y_true']
    )

    print(f"   Train split: {len(df_train_split):,}")
    print(f"   Val split:   {len(df_val):,}")

    trainer = Stage1Trainer(cfg.xgboost)
    model, metrics = trainer.train(df_train_split, feature_names)

    print(f"\n   ✅ Training complete:")
    print(f"      Best iteration: {metrics['best_iteration']}")
    print(f"      Best score: {metrics['best_score']:.4f}")

    # Save model
    models_dir = artifacts_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    model_path = models_dir / "xgboost_model_baseline.pkl"
    trainer.save_model(model_path)

    # Save feature order
    import json
    feature_order_path = models_dir / "feature_order.json"
    with open(feature_order_path, 'w') as f:
        json.dump(feature_names, f)
    print(f"   ✅ Model saved: {model_path.name}")
    print(f"   ✅ Features saved: {feature_order_path.name}")

    # Predict on validation set
    print("\n🔮 Predicting on validation set...")
    p_val = trainer.predict_proba(df_val, feature_names)
    y_val = df_val['y_true'].values

    print(f"   ✅ Predictions: {len(p_val):,} samples")
    print(f"      Min: {p_val.min():.4f}, Max: {p_val.max():.4f}, Mean: {p_val.mean():.4f}")

    # Select Route1 thresholds
    print("\n🚦 Selecting Route1 thresholds...")
    selector = Route1ThresholdSelector(cfg.route1)
    t_low, t_high, meta = selector.select_thresholds(y_val, p_val)

    print(f"   ✅ Thresholds selected:")
    print(f"      t_low:  {t_low:.6f}")
    print(f"      t_high: {t_high:.6f}")

    # Save thresholds
    results_dir = artifacts_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    thresholds_path = results_dir / "route1_thresholds.json"
    with open(thresholds_path, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"   ✅ Thresholds saved: {thresholds_path.name}")

    # Evaluate on test set
    print("\n📊 Evaluating on test set...")
    p_test = trainer.predict_proba(df_test, feature_names)
    decisions = selector.apply_thresholds(p_test)

    n_benign = (decisions == 0).sum()
    n_defer = (decisions == 1).sum()
    n_phish = (decisions == 2).sum()

    print(f"   ✅ Test set classification:")
    print(f"      AUTO_BENIGN: {n_benign:,} ({100*n_benign/len(decisions):.1f}%)")
    print(f"      DEFER:       {n_defer:,} ({100*n_defer/len(decisions):.1f}%)")
    print(f"      AUTO_PHISH:  {n_phish:,} ({100*n_phish/len(decisions):.1f}%)")

    # Stage2 evaluation (if DEFER candidates exist)
    if n_defer > 0:
        print(f"\n🚪 Evaluating Stage2 gate...")

        # Load brand keywords
        brand_keywords_path = models_dir / "brand_keywords.json"
        if brand_keywords_path.exists():
            with open(brand_keywords_path) as f:
                brand_keywords = json.load(f)
        else:
            print(f"   ⚠️  No brand keywords found, using empty list")
            brand_keywords = []

        df_defer = df_test[decisions == 1].copy()
        p_defer = p_test[decisions == 1]

        gate = Stage2Gate(cfg.stage2, brand_keywords)
        df_defer = gate.select_segment_priority(df_defer, p_defer)

        n_handoff = (df_defer['stage2_decision'] == 'handoff').sum()
        n_pending = (df_defer['stage2_decision'] == 'drop_to_auto').sum()

        # Save Stage2 results
        stage2_stats = {
            'N_stage1_handoff_region': int(n_defer),
            'N_stage2_handoff': int(n_handoff),
            'stage2_select': {
                'mode': 'segment_priority',
                'max_budget': cfg.stage2.max_budget,
                'priority_pool': int((df_defer.get('stage2_priority', pd.Series([False]*len(df_defer)))).sum()),
                'selected_final': int(n_handoff)
            }
        }

        stage2_path = results_dir / "stage2_budget_eval.json"
        with open(stage2_path, 'w') as f:
            json.dump(stage2_stats, f, indent=2)
        print(f"   ✅ Stage2 stats saved: {stage2_path.name}")

    # Calculate metrics
    from sklearn.metrics import roc_auc_score, classification_report

    auc = roc_auc_score(df_test['y_true'], p_test)

    print(f"\n📈 Performance Metrics:")
    print(f"   AUC: {auc:.4f}")

    # Auto-classified samples
    auto_mask = decisions != 1
    if auto_mask.sum() > 0:
        y_pred_auto = (decisions[auto_mask] == 2).astype(int)
        y_true_auto = df_test.loc[auto_mask, 'y_true'].values

        print(f"\n   Auto-classification metrics:")
        print(classification_report(y_true_auto, y_pred_auto,
                                   target_names=['Benign', 'Phish'],
                                   digits=4))

    # Summary
    print("\n" + "="*80)
    print("✅ Training Complete!")
    print("="*80)
    print(f"\n📁 Results saved to: {artifacts_dir}")
    print(f"\nGenerated files:")
    print(f"  - {model_path.relative_to(Path.cwd())}")
    print(f"  - {feature_order_path.relative_to(Path.cwd())}")
    print(f"  - {thresholds_path.relative_to(Path.cwd())}")
    if n_defer > 0:
        print(f"  - {stage2_path.relative_to(Path.cwd())}")
    print("\n" + "="*80)

    return 0


def run_eval(args, cfg):
    """
    Evaluation mode: evaluate existing model on test data.
    """
    print("\n" + "="*80)
    print("📊 Evaluation Mode")
    print("="*80)

    print("\n⚠️  Use --train mode for full Notebook workflow")
    print("   Use --predict mode for new domain predictions")

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
  # Train from pkl data (Notebook workflow)
  python 02_main.py --train --run-id 2026-01-10_140940

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
    mode_group.add_argument('--train', action='store_true',
                           help='Train model from pkl data (Notebook workflow)')
    mode_group.add_argument('--predict', action='store_true',
                           help='Predict on new domains from CSV')
    mode_group.add_argument('--eval', action='store_true',
                           help='Evaluate on test data (use --train instead)')
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
    if args.train:
        return run_train(args, cfg)
    elif args.predict:
        return run_predict(args, cfg)
    elif args.eval:
        return run_eval(args, cfg)
    elif args.interactive:
        return run_interactive(args, cfg)

    return 0


if __name__ == '__main__':
    sys.exit(main())
