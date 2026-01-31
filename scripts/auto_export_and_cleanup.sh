#!/bin/bash
# 評価完了後に自動でCSVエクスポートとvLLM停止を行う

LOG_FILE="/data/hdd/asomura/nextstep/auto_export_$(date +%Y%m%d_%H%M%S).log"
RESULTS_DIR="/data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/results/stage2_validation"
TOTAL_DOMAINS=15670

echo "$(date): Auto export monitor started" | tee -a "$LOG_FILE"
echo "Monitoring for evaluation completion..." | tee -a "$LOG_FILE"

while true; do
    # Count processed domains
    PROCESSED=$(cat ${RESULTS_DIR}/worker_*_results.csv 2>/dev/null | wc -l)
    PROCESSED=$((PROCESSED - 3))  # Subtract headers
    
    PERCENT=$((PROCESSED * 100 / TOTAL_DOMAINS))
    
    echo "$(date '+%H:%M:%S'): Progress $PROCESSED/$TOTAL_DOMAINS ($PERCENT%)" | tee -a "$LOG_FILE"
    
    # Check if complete (within 99% to account for errors)
    if [ $PROCESSED -ge 15500 ]; then
        echo "$(date): Evaluation appears complete!" | tee -a "$LOG_FILE"
        
        # Wait a bit to ensure all files are written
        sleep 30
        
        # Run export script
        echo "$(date): Running FN/FP export..." | tee -a "$LOG_FILE"
        cd /data/hdd/asomura/nextstep
        python scripts/export_fnfp_analysis.py --analyze -o fnfp_analysis 2>&1 | tee -a "$LOG_FILE"
        
        echo "$(date): Export complete!" | tee -a "$LOG_FILE"
        
        # Stop vLLM on GPU0 (port 8000)
        echo "$(date): Stopping vLLM on port 8000 (GPU0)..." | tee -a "$LOG_FILE"
        bash scripts/vllm.sh stop 2>&1 | tee -a "$LOG_FILE"
        
        # Stop vLLM on GPU2 (port 8002) - via SSH tunnel and remote
        echo "$(date): Stopping vLLM on port 8002 (GPU2)..." | tee -a "$LOG_FILE"
        ssh asomura@192.168.100.70 'bash -lc "/home/asomura/src/vllm.sh stop"' 2>&1 | tee -a "$LOG_FILE"
        pkill -f "ssh.*8002.*192.168.100.70" 2>/dev/null
        
        echo "$(date): All tasks complete!" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        echo "Results saved to: fnfp_analysis/" | tee -a "$LOG_FILE"
        
        break
    fi
    
    # Check every 5 minutes
    sleep 300
done

echo "$(date): Monitor script finished" | tee -a "$LOG_FILE"
