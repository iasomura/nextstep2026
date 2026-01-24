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
#   8. 04-3.ipynb                 - LLMツール設定 (vLLM使用)
#   9. evaluate_e2e_parallel.py   - AI Agent並列評価 (~6時間/3GPU, vLLM使用)
#
# 使用方法:
#   ./scripts/run_full_pipeline.sh                  # 全体実行 (Worker 0のみ)
#   ./scripts/run_full_pipeline.sh --add-gpu 1,2    # Worker 0,1,2 で並列実行
#   ./scripts/run_full_pipeline.sh --no-e2e         # evaluate_e2e以外を実行
#   ./scripts/run_full_pipeline.sh --no-vllm        # vLLM自動管理を無効化
#
# vLLM自動管理:
#   - 04-3.ipynb 実行時に scripts/vllm.sh で自動起動
#   - evaluate_e2e_parallel.py は自身でvLLMを管理 (parallel_config.yaml)
#   - 処理完了後またはエラー時に自動停止
#
# 作成日: 2026-01-13
# 変更履歴:
#   - 2026-01-17: vLLM自動管理追加
#   - 2026-01-24: evaluate_e2e_parallel.py (複数GPU並列) に移行
# =============================================================================

set -e  # エラー時に停止

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# =============================================================================
# vLLM 管理関数
# =============================================================================
# vLLMの起動/停止は scripts/vllm.sh に委譲する。
# evaluate_e2e_parallel.py は自身のオーケストレーターでvLLMを管理するため、
# ここでは 04-3.ipynb 用のvLLM管理のみ行う。
# =============================================================================
VLLM_STARTED_BY_US=false

vllm_is_running() {
    bash "${SCRIPT_DIR}/vllm.sh" status >/dev/null 2>&1
}

vllm_start() {
    if vllm_is_running; then
        echo "   vLLM server already running"
        return 0
    fi

    echo "   Starting vLLM server via vllm.sh..."
    bash "${SCRIPT_DIR}/vllm.sh" start
    VLLM_STARTED_BY_US=true

    # 準備完了まで待機
    local timeout=120
    local elapsed=0
    echo "   Waiting for vLLM server to be ready (max ${timeout}s)..."
    while [ $elapsed -lt $timeout ]; do
        if curl -s "http://127.0.0.1:8000/v1/models" >/dev/null 2>&1; then
            echo "   vLLM server is ready!"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
        printf "\r   Waiting... %ds" $elapsed
    done
    echo ""
    echo "   ERROR: vLLM server failed to start within ${timeout}s"
    vllm_stop
    return 1
}

vllm_stop() {
    if [ "$VLLM_STARTED_BY_US" != "true" ]; then
        return 0
    fi

    echo "   Stopping vLLM server via vllm.sh..."
    bash "${SCRIPT_DIR}/vllm.sh" stop
    VLLM_STARTED_BY_US=false
    echo "   vLLM server stopped."
}

# Trap to ensure vLLM is stopped on exit/error
cleanup() {
    local exit_code=$?
    if [ "$VLLM_STARTED_BY_US" = "true" ]; then
        echo ""
        echo "Cleaning up..."
        vllm_stop
    fi
    exit $exit_code
}
trap cleanup EXIT INT TERM

# =============================================================================
# 引数処理
# =============================================================================
RUN_E2E=true
VLLM_AUTO_MANAGE=true
SKIP_CONFIRM=false
ADD_GPU=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-e2e)
            RUN_E2E=false
            echo "Note: evaluate_e2e_parallel.py will be skipped"
            ;;
        --no-vllm)
            VLLM_AUTO_MANAGE=false
            echo "Note: vLLM auto-management disabled"
            ;;
        --yes|-y)
            SKIP_CONFIRM=true
            echo "Note: Running in non-interactive mode (skip confirmations)"
            ;;
        --add-gpu=*)
            ADD_GPU="${1#*=}"
            echo "Note: Additional GPUs: $ADD_GPU"
            ;;
        --add-gpu)
            if [[ -n "$2" && "$2" != --* ]]; then
                ADD_GPU="$2"
                echo "Note: Additional GPUs: $ADD_GPU"
                shift
            fi
            ;;
    esac
    shift
done

# 非対話モード検出
if [ ! -t 0 ]; then
    SKIP_CONFIRM=true
    echo "Note: Non-interactive mode detected"
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
    if [ "$SKIP_CONFIRM" = true ]; then
        echo "artifacts/ folder exists (keeping existing data in non-interactive mode)"
    else
        read -p "artifacts/ フォルダをクリアしますか? (y/N): " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf artifacts/*
            echo "artifacts/ cleared"
        fi
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

# =============================================================================
# 8. LLMツール設定 (vLLM使用)
# =============================================================================
# 04-3.ipynb は vLLM (Port 8000) を使用するため、ここで起動する

if [ "$VLLM_AUTO_MANAGE" = true ]; then
    echo ""
    echo "============================================================"
    echo "Starting vLLM for 04-3_llm_tools_setup.ipynb"
    echo "============================================================"
    vllm_start
    echo ""
fi

echo "[8/9] Running 04-3_llm_tools_setup.ipynb..."
papermill \
    04-3_llm_tools_setup.ipynb \
    artifacts/04-3_output.ipynb \
    2>&1 | tail -3
echo "Done."

# 04-3完了後にvLLM停止（Step 9は自身でvLLMを管理する）
if [ "$VLLM_AUTO_MANAGE" = true ] && [ "$VLLM_STARTED_BY_US" = "true" ]; then
    echo ""
    echo "   Stopping vLLM (evaluate_e2e_parallel.py will manage its own vLLM)"
    vllm_stop
fi
echo ""

# =============================================================================
# 9. End-to-End Evaluation (AI Agent並列評価)
# =============================================================================
# evaluate_e2e_parallel.py は parallel_config.yaml に基づき、
# 各WorkerのvLLMを自動で起動/停止する（stop_on_complete機能あり）
if [ "$RUN_E2E" = true ]; then
    echo "[9/9] Running evaluate_e2e_parallel.py..."

    # 並列評価コマンド構築
    PARALLEL_CMD="python scripts/evaluate_e2e_parallel.py -y"
    if [ -n "$ADD_GPU" ]; then
        PARALLEL_CMD="$PARALLEL_CMD --add-gpu $ADD_GPU"
        echo "Workers: 0 + $ADD_GPU"
    else
        echo "Workers: 0 (single GPU mode)"
    fi
    echo "Started at: $(date)"
    echo ""

    eval $PARALLEL_CMD

    echo ""
    echo "Finished at: $(date)"
else
    echo "[9/9] evaluate_e2e_parallel.py skipped (--no-e2e option)"
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
    echo "  - artifacts/$NEW_RUN_ID/results/stage2_validation/eval_df__nALL__*.csv"
    echo "  - artifacts/$NEW_RUN_ID/logs/ (Worker logs)"
fi
