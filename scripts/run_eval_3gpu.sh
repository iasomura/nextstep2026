#!/bin/bash
# 3GPU並列評価スクリプト
# 使用方法: bash scripts/run_eval_3gpu.sh [サンプル数] [--resume]
# 例: bash scripts/run_eval_3gpu.sh 2000
#      bash scripts/run_eval_3gpu.sh 2000 --resume  # 中断から再開
#
# 変更履歴:
#   - 2026-02-02: RUN_IDをartifacts/_current/run_id.txtから動的に読み込むよう変更
#   - 2026-01-31: 評価完了後に自動リトライを追加（Step 5）
#   - 2026-01-31: --resume オプション追加（#11: 中断からの再開機能）

set -e

# 引数解析
N_SAMPLE=2000
RESUME_MODE=false

for arg in "$@"; do
    case $arg in
        --resume|-r)
            RESUME_MODE=true
            ;;
        [0-9]*|ALL)
            N_SAMPLE=$arg
            ;;
    esac
done

# RUN_IDを動的に取得
RUN_ID_FILE="artifacts/_current/run_id.txt"
if [ -f "$RUN_ID_FILE" ]; then
    RUN_ID=$(cat "$RUN_ID_FILE")
else
    echo "エラー: $RUN_ID_FILE が見つかりません"
    echo "先に 01_data_preparation と 02_main.py を実行してください"
    exit 1
fi

RESULTS_DIR="artifacts/${RUN_ID}/results/stage2_validation"

echo "=== 3GPU並列評価スクリプト ==="
echo "RUN_ID: $RUN_ID"
echo "サンプル数: $N_SAMPLE"
if [ "$RESUME_MODE" = true ]; then
    echo "モード: 中断からの再開"
fi
echo ""

# 1. チェックポイント確認・削除
echo "[1/5] チェックポイント確認..."

# 中断されたチェックポイントがあるか確認
CHECKPOINT_EXISTS=false
if ls ${RESULTS_DIR}/eval_*/worker_*_checkpoint.json 1>/dev/null 2>&1; then
    CHECKPOINT_EXISTS=true
    CHECKPOINT_DIR=$(ls -td ${RESULTS_DIR}/eval_*/ 2>/dev/null | head -1)
fi

if [ "$RESUME_MODE" = true ]; then
    if [ "$CHECKPOINT_EXISTS" = true ]; then
        echo "  ✓ チェックポイント発見: $(basename $CHECKPOINT_DIR)"
        echo "  → 中断位置から再開します"
    else
        echo "  ✗ チェックポイントが見つかりません"
        echo "  → 新規評価として開始します"
        RESUME_MODE=false
    fi
elif [ "$CHECKPOINT_EXISTS" = true ]; then
    # 中断されたチェックポイントがある場合、ユーザーに確認
    echo "  ⚠ 中断されたチェックポイントが見つかりました: $(basename $CHECKPOINT_DIR)"

    # チェックポイントの進捗を表示
    COMPLETED=$(cat ${CHECKPOINT_DIR}/worker_*_checkpoint.json 2>/dev/null | grep -o '"completed": [0-9]*' | awk -F': ' '{sum+=$2} END {print sum}')
    echo "  → 完了済みドメイン数: ${COMPLETED:-0}"
    echo ""
    read -p "  中断位置から再開しますか？ [Y/n]: " ANSWER
    case $ANSWER in
        [Nn]*)
            echo "  → 新規評価を開始します（古いデータを削除）"
            rm -rf ${RESULTS_DIR}/eval_*/
            ;;
        *)
            echo "  → 中断位置から再開します"
            RESUME_MODE=true
            ;;
    esac
else
    echo "  ✓ チェックポイントなし（新規評価）"
fi

# 2. vLLM起動確認・起動
echo ""
echo "[2/5] vLLM起動確認..."

# Port 8000 (ローカル)
if ! curl -s --connect-timeout 3 http://localhost:8000/v1/models | grep -qi qwen; then
    echo "  Port 8000: 起動中..."
    bash scripts/vllm.sh start
    for i in {1..30}; do
        if curl -s --connect-timeout 3 http://localhost:8000/v1/models | grep -qi qwen; then
            echo "  Port 8000: ✓ Ready"
            break
        fi
        sleep 5
    done
else
    echo "  Port 8000: ✓ Already running"
fi

# Port 8001 (外部サーバー - 常時起動)
if curl -s --connect-timeout 3 http://localhost:8001/v1/models | grep -qi qwen; then
    echo "  Port 8001: ✓ Running"
else
    echo "  Port 8001: ✗ Not available (外部サーバー)"
    echo "  警告: Port 8001が利用できません。2GPUで実行します。"
fi

# Port 8002 (リモートサーバー)
if ! curl -s --connect-timeout 3 http://localhost:8002/v1/models | grep -qi qwen; then
    echo "  Port 8002: 起動中..."
    ssh asomura@192.168.100.70 'bash -lc "/home/asomura/src/vllm.sh start"' 2>/dev/null || true

    # SSHトンネル確認・作成
    if ! pgrep -f "ssh.*8002.*192.168.100.70" > /dev/null; then
        ssh -fNT -L 8002:127.0.0.1:8000 asomura@192.168.100.70
    fi

    for i in {1..30}; do
        if curl -s --connect-timeout 3 http://localhost:8002/v1/models | grep -qi qwen; then
            echo "  Port 8002: ✓ Ready"
            break
        fi
        sleep 5
    done
else
    echo "  Port 8002: ✓ Already running"
fi

# 3. 全ポート確認
echo ""
echo "[3/5] 最終確認..."
AVAILABLE_GPUS=""
for port in 8000 8001 8002; do
    if curl -s --connect-timeout 3 http://localhost:$port/v1/models | grep -qi qwen; then
        echo "  Port $port: ✓"
        if [ "$port" != "8000" ]; then
            if [ -z "$AVAILABLE_GPUS" ]; then
                AVAILABLE_GPUS="${port: -1}"
            else
                AVAILABLE_GPUS="$AVAILABLE_GPUS,${port: -1}"
            fi
        fi
    else
        echo "  Port $port: ✗"
    fi
done

# 4. 評価実行
echo ""
echo "[4/5] 評価開始..."

# 再開モードの場合は --resume フラグを追加
RESUME_FLAG=""
if [ "$RESUME_MODE" = true ]; then
    RESUME_FLAG="--resume"
fi

if [ -n "$AVAILABLE_GPUS" ]; then
    echo "  使用GPU: 0,$AVAILABLE_GPUS"
    python scripts/evaluate_e2e_parallel.py --n-sample $N_SAMPLE --add-gpu $AVAILABLE_GPUS --yes $RESUME_FLAG
else
    echo "  使用GPU: 0のみ"
    python scripts/evaluate_e2e_parallel.py --n-sample $N_SAMPLE --yes $RESUME_FLAG
fi

# 5. 失敗ドメインのリトライ
echo ""
echo "[5/5] 失敗ドメインのリトライ..."
python scripts/evaluate_e2e_parallel.py --retry-failed --yes

echo ""
echo "=== 評価完了 ==="
