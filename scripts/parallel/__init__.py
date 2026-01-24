# Parallel evaluation package for Stage3 AI Agent
"""
Stage3 並列評価システム

コンポーネント:
- config.py: 設定管理
- gpu_checker.py: GPU空き確認
- vllm_manager.py: vLLM管理（ローカル/リモート）
- ssh_manager.py: SSH+tmux管理
- checkpoint.py: チェックポイント管理
- worker.py: Worker実装
- health_monitor.py: ヘルスチェック
- orchestrator.py: 全体制御
"""

__version__ = "1.0.0"
