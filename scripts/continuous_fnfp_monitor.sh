#!/bin/bash
# Continuous FN/FP monitoring with reasoning logs

OUTPUT_DIR="/data/hdd/asomura/nextstep/fnfp_logs"
mkdir -p "$OUTPUT_DIR"

echo "Starting continuous FN/FP monitoring..."
echo "Output directory: $OUTPUT_DIR"
echo "Press Ctrl+C to stop"

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_FILE="$OUTPUT_DIR/fnfp_reasoning_${TIMESTAMP}.jsonl"
    
    # Get current processed count
    TOTAL=$(cat /data/hdd/asomura/nextstep/artifacts/2026-01-24_213326/results/stage2_validation/worker_*_results.csv 2>/dev/null | wc -l)
    PROCESSED=$((TOTAL - 3))
    
    echo "[$(date '+%H:%M:%S')] Processing snapshot at $PROCESSED domains..."
    
    # Run the analysis
    python scripts/monitor_fnfp_with_reasoning.py --output "$OUTPUT_FILE" --max-analyze 50 2>&1 | grep -E "^(Total:|Recall:|FN:|FP:|INFO)" | head -5
    
    echo ""
    
    # Wait 5 minutes before next snapshot
    sleep 300
done
