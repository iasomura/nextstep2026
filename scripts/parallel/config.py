"""
設定管理モジュール

parallel_config.yaml の読み込みと検証を行う
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import yaml


@dataclass
class SSHConfig:
    """SSH接続設定"""
    host: str
    user: str
    remote_port: int = 8000
    gpu: int = 0


@dataclass
class TmuxConfig:
    """tmuxセッション設定"""
    session_name: str
    auto_cleanup: bool = True


@dataclass
class WorkerConfig:
    """Worker設定"""
    id: int
    port: int
    type: str = "local"  # "local", "remote", or "external"
    gpu: int = 0
    ssh: Optional[SSHConfig] = None
    tmux: Optional[TmuxConfig] = None
    start_cmd: Optional[str] = None  # external用: 起動コマンド
    stop_cmd: Optional[str] = None   # external用: 停止コマンド
    # 変更履歴:
    #   - 2026-01-25: speed_weight追加（GPU帯域幅に基づく処理量割り当て）
    #   - 2026-01-24: stop_on_complete追加（共用GPUサーバでWorker完了時に即vLLM停止）
    stop_on_complete: bool = True     # Worker完了時にvLLMを停止するか
    speed_weight: float = 1.0         # 処理量割り当て重み (メモリ帯域幅比率)


@dataclass
class VLLMConfig:
    """vLLM設定"""
    model: str = "Qwen/Qwen3-4B"
    max_model_len: int = 8192
    max_num_seqs: int = 8
    gpu_memory_utilization: float = 0.85
    dtype: str = "auto"


@dataclass
class EvaluationConfig:
    """評価設定"""
    checkpoint_interval: int = 100
    timeout_per_domain: int = 60
    retry_count: int = 2


@dataclass
class HealthCheckConfig:
    """ヘルスチェック設定"""
    interval: int = 5
    timeout: int = 10
    max_failures: int = 3


@dataclass
class RetryConfig:
    """リトライ設定"""
    request_retries: int = 3
    request_delay: int = 5
    domain_retries: int = 2
    domain_delay: int = 10
    vllm_restarts: int = 3
    vllm_restart_delay: int = 30


@dataclass
class FailoverConfig:
    """フェイルオーバー設定"""
    enabled: bool = True
    redistribute_on_failure: bool = True
    min_workers: int = 1


@dataclass
class SharedServerConfig:
    """共有サーバー設定"""
    enabled: bool = True
    check_gpu_usage_before_start: bool = True
    gpu_memory_threshold_mb: int = 1000
    warn_if_other_users: bool = True
    require_confirmation: bool = True


@dataclass
class LoggingConfig:
    """ログ設定"""
    level: str = "INFO"
    separate_worker_logs: bool = True
    log_dir: Optional[str] = None


@dataclass
class ParallelConfig:
    """並列評価の全体設定"""
    num_workers: int = 1
    workers: List[WorkerConfig] = field(default_factory=list)
    vllm: VLLMConfig = field(default_factory=VLLMConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)
    health_check: HealthCheckConfig = field(default_factory=HealthCheckConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    failover: FailoverConfig = field(default_factory=FailoverConfig)
    shared_server: SharedServerConfig = field(default_factory=SharedServerConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    def get_active_workers(self, additional_gpus: Optional[List[int]] = None) -> List[WorkerConfig]:
        """
        アクティブなWorker設定を取得

        Args:
            additional_gpus: 追加で使用するGPU/Worker ID

        Returns:
            使用するWorker設定のリスト
        """
        # デフォルトはWorker 0のみ
        active_ids = {0}

        # 追加GPU指定があれば追加
        if additional_gpus:
            active_ids.update(additional_gpus)

        # 設定されているWorkerのみ返す
        return [w for w in self.workers if w.id in active_ids]


def load_config(config_path: Optional[str] = None) -> ParallelConfig:
    """
    設定ファイルを読み込む

    Args:
        config_path: 設定ファイルパス（省略時はデフォルト）

    Returns:
        ParallelConfig オブジェクト
    """
    if config_path is None:
        # デフォルトパス
        script_dir = Path(__file__).parent.parent
        config_path = script_dir / "parallel_config.yaml"

    config_path = Path(config_path)

    if not config_path.exists():
        print(f"Warning: Config file not found: {config_path}")
        print("Using default configuration.")
        return ParallelConfig()

    with open(config_path, 'r') as f:
        data = yaml.safe_load(f)

    return _parse_config(data)


def _parse_config(data: Dict[str, Any]) -> ParallelConfig:
    """設定データをパースしてParallelConfigを生成"""

    # Workers
    workers = []
    for w in data.get('workers', []):
        ssh_config = None
        if 'ssh' in w:
            ssh_config = SSHConfig(**w['ssh'])

        tmux_config = None
        if 'tmux' in w:
            tmux_config = TmuxConfig(**w['tmux'])

        workers.append(WorkerConfig(
            id=w['id'],
            port=w['port'],
            type=w.get('type', 'local'),
            gpu=w.get('gpu', 0),
            ssh=ssh_config,
            tmux=tmux_config,
            start_cmd=w.get('start_cmd'),
            stop_cmd=w.get('stop_cmd'),
            stop_on_complete=w.get('stop_on_complete', True),
            speed_weight=w.get('speed_weight', 1.0)
        ))

    # 各セクションをパース
    vllm = VLLMConfig(**data.get('vllm', {}))
    evaluation = EvaluationConfig(**data.get('evaluation', {}))
    health_check = HealthCheckConfig(**data.get('health_check', {}))
    retry = RetryConfig(**data.get('retry', {}))
    failover = FailoverConfig(**data.get('failover', {}))
    shared_server = SharedServerConfig(**data.get('shared_server', {}))
    logging_config = LoggingConfig(**data.get('logging', {}))

    return ParallelConfig(
        num_workers=data.get('num_workers', 1),
        workers=workers,
        vllm=vllm,
        evaluation=evaluation,
        health_check=health_check,
        retry=retry,
        failover=failover,
        shared_server=shared_server,
        logging=logging_config
    )


def save_config(config: ParallelConfig, config_path: str):
    """設定をファイルに保存"""
    # dataclassをdictに変換
    data = _config_to_dict(config)

    with open(config_path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True)


def _config_to_dict(config: ParallelConfig) -> Dict[str, Any]:
    """ParallelConfigを辞書に変換"""
    import dataclasses

    def to_dict(obj):
        if dataclasses.is_dataclass(obj):
            return {k: to_dict(v) for k, v in dataclasses.asdict(obj).items() if v is not None}
        elif isinstance(obj, list):
            return [to_dict(item) for item in obj]
        else:
            return obj

    return to_dict(config)
