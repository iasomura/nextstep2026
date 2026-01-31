#!/bin/bash
# 3GPU並列評価スクリプト
# 使用方法: bash scripts/run_eval_3gpu.sh [サンプル数]
# 例: bash scripts/run_eval_3gpu.sh 2000

set -e

N_SAMPLE=${1:-2000}
RESULTS_DIR="artifacts/2026-01-24_213326/results/stage2_validation"

echo "=== 3GPU並列評価スクリプト ==="
echo "サンプル数: $N_SAMPLE"
echo ""

# 1. 古いデータを削除
echo "[1/4] 古い結果ファイルを削除..."
rm -f ${RESULTS_DIR}/worker_*_results.csv
rm -f ${RESULTS_DIR}/worker_*_checkpoint.json
echo "  完了"

# 2. vLLM起動確認・起動
echo ""
echo "[2/4] vLLM起動確認..."

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
echo "[3/4] 最終確認..."
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
echo "[4/4] 評価開始..."
if [ -n "$AVAILABLE_GPUS" ]; then
    echo "  使用GPU: 0,$AVAILABLE_GPUS"
    python scripts/evaluate_e2e_parallel.py --n-sample $N_SAMPLE --add-gpu $AVAILABLE_GPUS --yes
else
    echo "  使用GPU: 0のみ"
    python scripts/evaluate_e2e_parallel.py --n-sample $N_SAMPLE --yes
fi

echo ""
echo "=== 評価完了 ==="
