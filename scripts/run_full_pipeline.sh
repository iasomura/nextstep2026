#!/bin/bash
# =============================================================================
# Full Pipeline Execution Script
# =============================================================================
#
# フィッシング検知システム全体パイプライン実行スクリプト
#
# 実行順序:
#   1. 01_data_preparation.ipynb  - データ準備・前処理 (~4分)
#   2. 02_main.py                 - Stage1 XGBoost + Stage2 LR + Gate (~3分)
#   3. 03_part1.ipynb             - AI Agent設定確認
#   4. 03_part2.ipynb             - AI Agentサンプル検証
#   5. 03_part3.ipynb             - Config API確認
#   6. 04-1.ipynb                 - 統計分析準備
#   7. 04-2.ipynb                 - 統計分析
#   8. 04-3.ipynb                 - LLMツール設定
#   9. evaluate_e2e.py            - AI Agent全件実行 (~39時間)
#
# 使用方法:
#   ./scripts/run_full_pipeline.sh           # 全体実行
#   ./scripts/run_full_pipeline.sh --no-e2e  # evaluate_e2e.py以外を実行
#
# 作成日: 2026-01-13
# =============================================================================

set -e  # エラー時に停止

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# 引数処理
RUN_E2E=true
if [[ "$1" == "--no-e2e" ]]; then
    RUN_E2E=false
    echo "Note: evaluate_e2e.py will be skipped"
fi

# =============================================================================
# 0. 準備
# =============================================================================
echo "============================================================"
echo "Full Pipeline Execution"
echo "============================================================"
echo ""

# artifacts クリア確認
if [ -d "artifacts" ] && [ "$(ls -A artifacts 2>/dev/null)" ]; then
    read -p "artifacts/ フォルダをクリアしますか? (y/N): " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        rm -rf artifacts/*
        echo "artifacts/ cleared"
    fi
fi

# RUN_ID 作成
NEW_RUN_ID=$(date +%Y-%m-%d_%H%M%S)
mkdir -p "artifacts/$NEW_RUN_ID" "artifacts/_current"
echo "$NEW_RUN_ID" > "artifacts/_current/run_id.txt"
echo "RUN_ID: $NEW_RUN_ID"
echo ""

# =============================================================================
# 1. データ準備
# =============================================================================
echo "[1/9] Running 01_data_preparation.ipynb..."
papermill \
    01_data_preparation_fixed_patched_nocert_full_artifacts_unified.ipynb \
    artifacts/01_output.ipynb \
    2>&1 | tail -5
echo "Done."
echo ""

# =============================================================================
# 2. Stage1/Stage2 パイプライン
# =============================================================================
echo "[2/9] Running 02_main.py..."
python 02_main.py --run
echo ""

# feature_order.json 作成（03ノートブック用）
python3 << 'EOF'
import joblib
import json
from pathlib import Path
run_id = Path("artifacts/_current/run_id.txt").read_text().strip()
train_data = joblib.load(f"artifacts/{run_id}/processed/train_data.pkl")
features = train_data['feature_names']
with open(f"artifacts/{run_id}/models/feature_order.json", 'w') as f:
    json.dump(features, f, indent=2)
print(f"Created feature_order.json ({len(features)} features)")
EOF
echo ""

# =============================================================================
# 3-5. AI Agent Analysis (03 notebooks)
# =============================================================================
echo "[3/9] Running 03_ai_agent_analysis_part1.ipynb..."
papermill \
    03_ai_agent_analysis_part1.ipynb \
    artifacts/03_part1_output.ipynb \
    2>&1 | tail -3
echo "Done."

echo "[4/9] Running 03_ai_agent_analysis_part2.ipynb..."
papermill \
    03_ai_agent_analysis_part2_full_HardFail_patched.ipynb \
    artifacts/03_part2_output.ipynb \
    2>&1 | tail -3
echo "Done."

echo "[5/9] Running 03_ai_agent_analysis_part3.ipynb..."
papermill \
    03_ai_agent_analysis_part3_config_api.ipynb \
    artifacts/03_part3_output.ipynb \
    2>&1 | tail -3
echo "Done."
echo ""

# =============================================================================
# 6-8. Statistical Analysis (04 notebooks)
# =============================================================================
echo "[6/9] Running 04-1_config_and_data_preparation.ipynb..."
papermill \
    04-1_config_and_data_preparation.ipynb \
    artifacts/04-1_output.ipynb \
    2>&1 | tail -3
echo "Done."

echo "[7/9] Running 04-2_statistical_analysis.ipynb..."
papermill \
    "04-2_statistical_analysis_COMPAT_PATCHED_v2_skip_smoke_and_fix_known_domains.ipynb" \
    artifacts/04-2_output.ipynb \
    2>&1 | tail -3
echo "Done."

echo "[8/9] Running 04-3_llm_tools_setup.ipynb..."
papermill \
    04-3_llm_tools_setup.ipynb \
    artifacts/04-3_output.ipynb \
    2>&1 | tail -3
echo "Done."
echo ""

# =============================================================================
# 9. End-to-End Evaluation (AI Agent全件実行)
# =============================================================================
if [ "$RUN_E2E" = true ]; then
    echo "[9/9] Running evaluate_e2e.py --n-sample ALL..."
    echo "This will take approximately 39 hours for 17,000+ samples."
    echo "Started at: $(date)"
    echo ""

    python scripts/evaluate_e2e.py --n-sample ALL --verbose

    echo ""
    echo "Finished at: $(date)"
else
    echo "[9/9] evaluate_e2e.py skipped (--no-e2e option)"
fi

# =============================================================================
# 完了
# =============================================================================
echo ""
echo "============================================================"
echo "Pipeline Complete!"
echo "============================================================"
echo "RUN_ID: $NEW_RUN_ID"
echo "Artifacts: artifacts/$NEW_RUN_ID"
echo ""
echo "Output files:"
echo "  - artifacts/01_output.ipynb"
echo "  - artifacts/03_part{1,2,3}_output.ipynb"
echo "  - artifacts/04-{1,2,3}_output.ipynb"
echo "  - artifacts/$NEW_RUN_ID/results/"
if [ "$RUN_E2E" = true ]; then
    echo "  - artifacts/$NEW_RUN_ID/results/stage2_validation/*.csv"
fi
