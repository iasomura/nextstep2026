#!/bin/bash
#
# vLLM Server Control Script
#
# Usage:
#   ./vllm.sh start   - Start vLLM server in background
#   ./vllm.sh stop    - Stop vLLM server
#   ./vllm.sh status  - Check server status
#   ./vllm.sh restart - Restart server
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="${SCRIPT_DIR}/.vllm.pid"
LOG_FILE="${SCRIPT_DIR}/vllm.log"

# vLLM configuration
MODEL="JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8"
HOST="127.0.0.1"
PORT="8000"

start_server() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "vLLM server is already running (PID: $PID)"
            return 1
        else
            rm -f "$PID_FILE"
        fi
    fi

    echo "Starting vLLM server..."
    echo "  Model: $MODEL"
    echo "  Host:  $HOST:$PORT"
    echo "  Log:   $LOG_FILE"

    nohup vllm serve "$MODEL" \
        --quantization gptq_marlin \
        --dtype half \
        --max-model-len 4096 \
        --max-num-seqs 4 \
        --max-num-batched-tokens 2048 \
        --enable-chunked-prefill \
        --gpu-memory-utilization 0.5 \
        --host "$HOST" --port "$PORT" \
        > "$LOG_FILE" 2>&1 &

    PID=$!
    echo "$PID" > "$PID_FILE"
    echo "vLLM server started (PID: $PID)"
    echo "Use 'tail -f $LOG_FILE' to view logs"
}

stop_server() {
    if [ ! -f "$PID_FILE" ]; then
        echo "PID file not found. Server may not be running."
        # Try to find and kill by process name
        PIDS=$(pgrep -f "vllm serve")
        if [ -n "$PIDS" ]; then
            echo "Found vLLM processes: $PIDS"
            echo "Stopping..."
            kill $PIDS 2>/dev/null
            sleep 2
            kill -9 $PIDS 2>/dev/null
            echo "Stopped."
        fi
        return 0
    fi

    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
        echo "Stopping vLLM server (PID: $PID)..."
        kill "$PID"

        # Wait for graceful shutdown
        for i in {1..10}; do
            if ! kill -0 "$PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done

        # Force kill if still running
        if kill -0 "$PID" 2>/dev/null; then
            echo "Force killing..."
            kill -9 "$PID" 2>/dev/null
        fi

        rm -f "$PID_FILE"
        echo "vLLM server stopped."
    else
        echo "Process $PID not found. Removing stale PID file."
        rm -f "$PID_FILE"
    fi
}

status_server() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "vLLM server is running (PID: $PID)"
            # Check if port is listening
            if command -v ss &>/dev/null; then
                ss -tlnp 2>/dev/null | grep ":$PORT" && echo "Port $PORT is listening"
            elif command -v netstat &>/dev/null; then
                netstat -tlnp 2>/dev/null | grep ":$PORT"
            fi
            return 0
        else
            echo "PID file exists but process is not running"
            rm -f "$PID_FILE"
            return 1
        fi
    else
        echo "vLLM server is not running"
        return 1
    fi
}

case "${1:-}" in
    start)
        start_server
        ;;
    stop)
        stop_server
        ;;
    restart)
        stop_server
        sleep 2
        start_server
        ;;
    status)
        status_server
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
