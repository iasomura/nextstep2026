"""
Worker実装モジュール

AI Agentによるドメイン評価を実行する

変更履歴:
    - 2026-01-28: トレースフィールド追加 - AI Agentの判定理由を保存するように変更
    - 2026-01-26: 証明書データ統合 - cert_features_mapをAgentに渡すように変更
"""

import json
import os
import sys
import time
import tempfile
import threading
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Callable
import signal

import pandas as pd


@dataclass
class WorkerResult:
    """評価結果"""
    domain: str
    ml_probability: float
    ai_is_phishing: bool
    ai_confidence: float
    ai_risk_level: str
    processing_time: float
    error: Optional[str] = None
    # トレースフィールド (2026-01-28追加)
    ai_reasoning: Optional[str] = None
    ai_risk_factors: Optional[str] = None  # JSON string
    ai_detected_brands: Optional[str] = None  # JSON string
    trace_precheck_ml_category: Optional[str] = None
    trace_precheck_tld_category: Optional[str] = None
    trace_precheck_brand_detected: Optional[bool] = None
    trace_precheck_high_risk_hits: Optional[int] = None
    trace_precheck_quick_risk: Optional[float] = None
    trace_selected_tools: Optional[str] = None  # JSON string
    trace_brand_risk_score: Optional[float] = None
    trace_cert_risk_score: Optional[float] = None
    trace_domain_risk_score: Optional[float] = None
    trace_ctx_risk_score: Optional[float] = None
    trace_ctx_issues: Optional[str] = None  # JSON string
    trace_phase6_rules_fired: Optional[str] = None  # JSON string
    graph_state_slim_json: Optional[str] = None  # Full state for debugging
    # ツール出力の詳細 (2026-01-28追加: FP/FN分析用)
    tool_brand_output: Optional[str] = None  # brand_impersonation_check full output (JSON)
    tool_cert_output: Optional[str] = None   # certificate_analysis full output (JSON)
    tool_domain_output: Optional[str] = None # short_domain_analysis full output (JSON)
    tool_ctx_output: Optional[str] = None    # contextual_risk_assessment full output (JSON)


class EvaluationWorker:
    """
    ドメイン評価Worker

    指定されたvLLMエンドポイントを使用してドメインを評価する
    """

    def __init__(
        self,
        worker_id: int,
        vllm_port: int,
        base_dir: Path,
        checkpoint_manager: 'CheckpointManager',
        result_writer: 'ResultWriter',
        config_path: Optional[Path] = None,
        model_name: str = "Qwen/Qwen3-4B",
        cert_features_map: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        """
        Args:
            worker_id: Worker ID
            vllm_port: vLLMのポート番号
            base_dir: プロジェクトベースディレクトリ
            checkpoint_manager: チェックポイント管理
            result_writer: 結果書き込み
            config_path: 元のconfig.jsonパス
            model_name: モデル名
            cert_features_map: 証明書特徴量マップ {domain -> cert_info}
        """
        self.worker_id = worker_id
        self.vllm_port = vllm_port
        self.base_dir = Path(base_dir)
        self.checkpoint_manager = checkpoint_manager
        self.result_writer = result_writer
        self.config_path = config_path or (base_dir / "config.json")
        self.model_name = model_name
        self.cert_features_map = cert_features_map or {}

        self._agent = None
        self._temp_config_path: Optional[Path] = None
        self._running = False
        self._paused = False
        self._stop_requested = False

        # コールバック
        self._on_vllm_failure: Optional[Callable[[], None]] = None
        self._on_progress: Optional[Callable[[int, int], None]] = None

    def set_vllm_failure_callback(self, callback: Callable[[], None]):
        """vLLM障害時のコールバックを設定"""
        self._on_vllm_failure = callback

    def set_progress_callback(self, callback: Callable[[int, int], None]):
        """進捗コールバックを設定 (completed, total)"""
        self._on_progress = callback

    def initialize(self) -> bool:
        """
        Workerを初期化

        Returns:
            成功したか
        """
        try:
            # 一時的なconfig.jsonを作成（base_urlを変更）
            self._temp_config_path = self._create_worker_config()

            # 環境変数設定
            os.environ["CONFIG_JSON"] = str(self._temp_config_path)

            # パスを追加
            if str(self.base_dir) not in sys.path:
                sys.path.insert(0, str(self.base_dir))

            # Phase6 wiring
            from phishing_agent.phase6_wiring import wire_phase6
            wire_phase6(prefer_compat=True, fake_llm=False)

            # Agent初期化
            from phishing_agent.langgraph_module import LangGraphPhishingAgent
            self._agent = LangGraphPhishingAgent(
                strict_mode=True,
                use_llm_selection=True,
                use_llm_decision=True,
                config_path=str(self._temp_config_path),
            )

            print(f"[Worker {self.worker_id}] Initialized with vLLM port {self.vllm_port}")
            return True

        except Exception as e:
            print(f"[Worker {self.worker_id}] Initialization failed: {e}")
            return False

    def _create_worker_config(self) -> Path:
        """Worker用のconfig.jsonを作成（base_urlを変更）"""
        # 元のconfig読み込み
        with open(self.config_path) as f:
            config = json.load(f)

        # LLM設定を更新
        base_url = f"http://localhost:{self.vllm_port}/v1"
        if "llm" in config:
            config["llm"]["base_url"] = base_url
            config["llm"]["vllm_base_url"] = base_url

        # 一時ファイルに保存
        temp_dir = Path(tempfile.gettempdir())
        temp_config = temp_dir / f"config_worker_{self.worker_id}.json"

        with open(temp_config, 'w') as f:
            json.dump(config, f, indent=2)

        return temp_config

    def run(
        self,
        domains: List[Dict[str, Any]],
        start_index: int = 0,
        timeout_per_domain: int = 60
    ) -> Dict[str, Any]:
        """
        ドメイン評価を実行

        Args:
            domains: 評価対象ドメインのリスト [{domain, ml_probability, ...}, ...]
            start_index: 開始インデックス（再開用）
            timeout_per_domain: 1ドメインのタイムアウト

        Returns:
            実行結果サマリー
        """
        self._running = True
        self._stop_requested = False

        total = len(domains)
        completed = 0
        failed = 0
        start_time = time.time()

        print(f"[Worker {self.worker_id}] Starting evaluation: {total} domains from index {start_index}")

        for i in range(start_index, total):
            if self._stop_requested:
                print(f"[Worker {self.worker_id}] Stop requested, saving checkpoint...")
                break

            # 一時停止チェック
            while self._paused and not self._stop_requested:
                time.sleep(1)

            domain_info = domains[i]
            domain = domain_info["domain"]
            ml_prob = domain_info["ml_probability"]

            # 処理中マーク
            self.checkpoint_manager.mark_worker_processing(self.worker_id, domain, i)

            try:
                result = self._evaluate_single(domain, ml_prob, timeout_per_domain)

                # 結果保存 (2026-01-28: トレースフィールド追加)
                row = {
                    "domain": domain,
                    "ml_probability": ml_prob,
                    "ai_is_phishing": result.ai_is_phishing,
                    "ai_confidence": result.ai_confidence,
                    "ai_risk_level": result.ai_risk_level,
                    "processing_time": result.processing_time,
                    "worker_id": self.worker_id,
                    "error": result.error,
                    # トレースフィールド
                    "ai_reasoning": result.ai_reasoning,
                    "ai_risk_factors": result.ai_risk_factors,
                    "ai_detected_brands": result.ai_detected_brands,
                    "trace_precheck_ml_category": result.trace_precheck_ml_category,
                    "trace_precheck_tld_category": result.trace_precheck_tld_category,
                    "trace_precheck_brand_detected": result.trace_precheck_brand_detected,
                    "trace_precheck_high_risk_hits": result.trace_precheck_high_risk_hits,
                    "trace_precheck_quick_risk": result.trace_precheck_quick_risk,
                    "trace_selected_tools": result.trace_selected_tools,
                    "trace_brand_risk_score": result.trace_brand_risk_score,
                    "trace_cert_risk_score": result.trace_cert_risk_score,
                    "trace_domain_risk_score": result.trace_domain_risk_score,
                    "trace_ctx_risk_score": result.trace_ctx_risk_score,
                    "trace_ctx_issues": result.trace_ctx_issues,
                    "trace_phase6_rules_fired": result.trace_phase6_rules_fired,
                    "graph_state_slim_json": result.graph_state_slim_json,
                    # ツール出力詳細 (FP/FN分析用)
                    "tool_brand_output": result.tool_brand_output,
                    "tool_cert_output": result.tool_cert_output,
                    "tool_domain_output": result.tool_domain_output,
                    "tool_ctx_output": result.tool_ctx_output,
                    **{k: v for k, v in domain_info.items() if k not in ["domain", "ml_probability"]}
                }
                self.result_writer.append(row)

                # チェックポイント更新
                success = result.error is None
                self.checkpoint_manager.update_worker_progress(
                    self.worker_id, domain, i, success, result.error
                )

                if success:
                    completed += 1
                else:
                    failed += 1

                # 進捗コールバック
                if self._on_progress:
                    self._on_progress(completed, total)

                # 進捗表示
                if (i + 1) % 10 == 0 or i == total - 1:
                    elapsed = time.time() - start_time
                    rate = (completed + failed) / elapsed if elapsed > 0 else 0
                    eta = (total - i - 1) / rate if rate > 0 else 0
                    print(f"[Worker {self.worker_id}] {i+1}/{total} ({completed} ok, {failed} err) "
                          f"ETA: {eta/60:.1f}min")

            except VLLMConnectionError as e:
                print(f"[Worker {self.worker_id}] vLLM connection error: {e}")
                if self._on_vllm_failure:
                    self._on_vllm_failure()
                # 一時停止して復旧待ち
                self._paused = True

        self._running = False

        # 完了マーク
        if not self._stop_requested:
            self.checkpoint_manager.mark_worker_completed(self.worker_id)

        return {
            "worker_id": self.worker_id,
            "total": total,
            "completed": completed,
            "failed": failed,
            "elapsed": time.time() - start_time
        }

    def _evaluate_single(
        self,
        domain: str,
        ml_prob: float,
        timeout: int
    ) -> WorkerResult:
        """単一ドメインを評価"""
        start_time = time.time()

        try:
            # タイムアウト付き評価
            result = self._evaluate_with_timeout(domain, ml_prob, timeout)

            elapsed = time.time() - start_time

            # トレースフィールドの抽出 (2026-01-28追加)
            def _json_str(obj):
                """オブジェクトをJSON文字列に変換"""
                if obj is None:
                    return None
                try:
                    return json.dumps(obj, ensure_ascii=False)
                except:
                    return str(obj)

            # ツール出力の抽出 (graph_state_slimから取得)
            graph_state_slim = result.get("graph_state_slim") or {}
            tool_results = graph_state_slim.get("tool_results") or {}

            return WorkerResult(
                domain=domain,
                ml_probability=ml_prob,
                ai_is_phishing=result.get("ai_is_phishing", False),
                ai_confidence=result.get("ai_confidence", 0.0),
                ai_risk_level=result.get("ai_risk_level", "unknown"),
                processing_time=elapsed,
                error=None,
                # トレースフィールド (フィールド名はlanggraph_moduleの出力に合わせる)
                ai_reasoning=result.get("reasoning"),  # PhishingAssessment.reasoning
                ai_risk_factors=_json_str(result.get("risk_factors")),  # PhishingAssessment.risk_factors
                ai_detected_brands=_json_str(result.get("detected_brands")),  # PhishingAssessment.detected_brands
                trace_precheck_ml_category=result.get("trace_precheck_ml_category"),
                trace_precheck_tld_category=result.get("trace_precheck_tld_category"),
                trace_precheck_brand_detected=result.get("trace_precheck_brand_detected"),
                trace_precheck_high_risk_hits=result.get("trace_precheck_high_risk_hits"),
                trace_precheck_quick_risk=result.get("trace_precheck_quick_risk"),
                trace_selected_tools=result.get("trace_selected_tools_json"),  # already JSON string
                trace_brand_risk_score=result.get("trace_brand_risk_score"),
                trace_cert_risk_score=result.get("trace_cert_risk_score"),
                trace_domain_risk_score=result.get("trace_domain_risk_score"),
                trace_ctx_risk_score=result.get("trace_ctx_risk_score"),
                trace_ctx_issues=result.get("trace_ctx_issues_json"),  # already JSON string
                trace_phase6_rules_fired=result.get("trace_phase6_rules_fired_json"),  # already JSON string
                graph_state_slim_json=result.get("graph_state_slim_json"),  # already JSON string
                # ツール出力の詳細 (FP/FN分析用)
                tool_brand_output=_json_str(tool_results.get("brand")),
                tool_cert_output=_json_str(tool_results.get("cert")),
                tool_domain_output=_json_str(tool_results.get("domain")),
                tool_ctx_output=_json_str(tool_results.get("contextual_risk_assessment")),
            )

        except TimeoutError:
            return WorkerResult(
                domain=domain,
                ml_probability=ml_prob,
                ai_is_phishing=False,
                ai_confidence=0.0,
                ai_risk_level="timeout",
                processing_time=timeout,
                error="Evaluation timeout"
            )

        except Exception as e:
            elapsed = time.time() - start_time

            # vLLM接続エラーの検出
            error_str = str(e).lower()
            if "connection" in error_str or "refused" in error_str or "timeout" in error_str:
                raise VLLMConnectionError(str(e))

            return WorkerResult(
                domain=domain,
                ml_probability=ml_prob,
                ai_is_phishing=False,
                ai_confidence=0.0,
                ai_risk_level="error",
                processing_time=elapsed,
                error=str(e)
            )

    def _evaluate_with_timeout(self, domain: str, ml_prob: float, timeout: int) -> Dict[str, Any]:
        """タイムアウト付き評価"""
        result = [None]
        exception = [None]

        # 証明書データを準備
        external_data = {}
        if self.cert_features_map:
            external_data["cert_full_info_map"] = self.cert_features_map

        def target():
            try:
                result[0] = self._agent.evaluate(domain, ml_prob, external_data=external_data)
            except Exception as e:
                exception[0] = e

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            # タイムアウト - スレッドは放置（Pythonではスレッドを強制終了できない）
            raise TimeoutError(f"Evaluation timed out after {timeout}s")

        if exception[0]:
            raise exception[0]

        return result[0]

    def pause(self):
        """一時停止"""
        self._paused = True
        print(f"[Worker {self.worker_id}] Paused")

    def resume(self):
        """再開"""
        self._paused = False
        print(f"[Worker {self.worker_id}] Resumed")

    def stop(self):
        """停止要求"""
        self._stop_requested = True
        self._paused = False  # 一時停止解除して終了処理へ
        print(f"[Worker {self.worker_id}] Stop requested")

    def is_running(self) -> bool:
        """実行中か"""
        return self._running

    def cleanup(self):
        """クリーンアップ"""
        if self._temp_config_path and self._temp_config_path.exists():
            try:
                self._temp_config_path.unlink()
            except:
                pass

    def retry_failed(
        self,
        domains: List[Dict[str, Any]],
        timeout_per_domain: int = 120
    ) -> Dict[str, Any]:
        """
        失敗ドメインをリトライ

        Args:
            domains: 失敗ドメイン情報リスト（domain, ml_probabilityを含む）
            timeout_per_domain: タイムアウト（デフォルト120秒=通常の2倍）

        Returns:
            Dict: リトライ結果サマリー
                - total: 対象件数
                - success: 成功件数
                - failed: 失敗件数
                - results: 成功したドメインのリスト

        変更履歴:
            - 2026-01-31: リトライ機能追加
        """
        if not domains:
            return {"total": 0, "success": 0, "failed": 0, "results": []}

        print(f"[Worker {self.worker_id}] Retrying {len(domains)} failed domains (timeout={timeout_per_domain}s)")

        success_count = 0
        failed_count = 0
        success_domains = []

        for i, domain_info in enumerate(domains):
            domain = domain_info.get("domain")
            ml_prob = domain_info.get("ml_probability", 0.5)
            original_worker = domain_info.get("worker_id", self.worker_id)

            print(f"[Worker {self.worker_id}] Retry {i+1}/{len(domains)}: {domain}")

            try:
                result = self._evaluate_single(domain, ml_prob, timeout_per_domain)

                if result.error is None:
                    # 成功 - 結果を保存
                    row = {
                        "domain": domain,
                        "ml_probability": ml_prob,
                        "ai_is_phishing": result.ai_is_phishing,
                        "ai_confidence": result.ai_confidence,
                        "ai_risk_level": result.ai_risk_level,
                        "processing_time": result.processing_time,
                        "worker_id": self.worker_id,
                        "error": None,
                        "ai_reasoning": result.ai_reasoning,
                        "ai_risk_factors": result.ai_risk_factors,
                        "ai_detected_brands": result.ai_detected_brands,
                        "trace_precheck_ml_category": result.trace_precheck_ml_category,
                        "trace_precheck_tld_category": result.trace_precheck_tld_category,
                        "trace_precheck_brand_detected": result.trace_precheck_brand_detected,
                        "trace_precheck_high_risk_hits": result.trace_precheck_high_risk_hits,
                        "trace_precheck_quick_risk": result.trace_precheck_quick_risk,
                        "trace_selected_tools": result.trace_selected_tools,
                        "trace_brand_risk_score": result.trace_brand_risk_score,
                        "trace_cert_risk_score": result.trace_cert_risk_score,
                        "trace_domain_risk_score": result.trace_domain_risk_score,
                        "trace_ctx_risk_score": result.trace_ctx_risk_score,
                        "trace_ctx_issues": result.trace_ctx_issues,
                        "trace_phase6_rules_fired": result.trace_phase6_rules_fired,
                        "graph_state_slim_json": result.graph_state_slim_json,
                        "tool_brand_output": result.tool_brand_output,
                        "tool_cert_output": result.tool_cert_output,
                        "tool_domain_output": result.tool_domain_output,
                        "tool_ctx_output": result.tool_ctx_output,
                    }
                    self.result_writer.append(row)

                    # チェックポイントから失敗を削除
                    self.checkpoint_manager.clear_failed_domain(original_worker, domain)

                    success_count += 1
                    success_domains.append(domain)
                    print(f"[Worker {self.worker_id}]   ✓ {domain} succeeded on retry")
                else:
                    failed_count += 1
                    print(f"[Worker {self.worker_id}]   ✗ {domain} failed again: {result.error}")

            except Exception as e:
                failed_count += 1
                print(f"[Worker {self.worker_id}]   ✗ {domain} error: {str(e)[:50]}")

        print(f"[Worker {self.worker_id}] Retry complete: {success_count}/{len(domains)} succeeded")

        return {
            "total": len(domains),
            "success": success_count,
            "failed": failed_count,
            "results": success_domains
        }


class VLLMConnectionError(Exception):
    """vLLM接続エラー"""
    pass


def run_worker_process(
    worker_id: int,
    vllm_port: int,
    domains_file: Path,
    result_file: Path,
    checkpoint_dir: Path,
    base_dir: Path,
    start_index: int = 0,
    timeout_per_domain: int = 60,
    cert_features_file: Optional[Path] = None
):
    """
    Worker をサブプロセスとして実行

    Args:
        worker_id: Worker ID
        vllm_port: vLLMポート
        domains_file: 入力ドメインJSONファイル
        result_file: 結果出力CSVファイル
        checkpoint_dir: チェックポイントディレクトリ
        base_dir: プロジェクトベースディレクトリ
        start_index: 開始インデックス
        timeout_per_domain: タイムアウト
        cert_features_file: 証明書特徴量CSVファイル
    """
    from .checkpoint import CheckpointManager, ResultWriter

    # ドメイン読み込み
    with open(domains_file) as f:
        domains = json.load(f)

    # 証明書データ読み込み
    cert_features_map = {}
    if cert_features_file:
        cert_path = Path(cert_features_file)
        try:
            if cert_path.suffix == '.pkl' and cert_path.exists():
                # PKLファイルを直接読み込み
                import pickle
                with open(cert_path, 'rb') as f:
                    cert_features_map = pickle.load(f)
                print(f"[Worker {worker_id}] Loaded {len(cert_features_map)} certificate records from PKL")
            elif cert_path.suffix == '.csv' and cert_path.exists():
                # CSVファイルを読み込み
                cert_df = pd.read_csv(cert_path)
                for _, row in cert_df.iterrows():
                    domain = row.get("domain", "")
                    if domain:
                        cert_features_map[domain] = row.to_dict()
                print(f"[Worker {worker_id}] Loaded {len(cert_features_map)} certificate records from CSV")
            else:
                print(f"[Worker {worker_id}] Warning: Cert file not found: {cert_path}")
        except Exception as e:
            print(f"[Worker {worker_id}] Warning: Failed to load cert features: {e}")

    # チェックポイント・結果ライター初期化
    checkpoint_mgr = CheckpointManager(checkpoint_dir, run_id="")

    fieldnames = [
        # 基本フィールド
        "domain", "ml_probability", "ai_is_phishing", "ai_confidence",
        "ai_risk_level", "processing_time", "worker_id", "error",
        "source", "y_true", "stage1_pred", "tld",
        # トレースフィールド (2026-01-28追加)
        "ai_reasoning", "ai_risk_factors", "ai_detected_brands",
        "trace_precheck_ml_category", "trace_precheck_tld_category",
        "trace_precheck_brand_detected", "trace_precheck_high_risk_hits",
        "trace_precheck_quick_risk", "trace_selected_tools",
        "trace_brand_risk_score", "trace_cert_risk_score",
        "trace_domain_risk_score", "trace_ctx_risk_score",
        "trace_ctx_issues", "trace_phase6_rules_fired",
        "graph_state_slim_json",
        # ツール出力詳細 (2026-01-28追加: FP/FN分析用)
        "tool_brand_output", "tool_cert_output",
        "tool_domain_output", "tool_ctx_output",
    ]
    result_writer = ResultWriter(result_file, fieldnames)

    # Worker初期化
    worker = EvaluationWorker(
        worker_id=worker_id,
        vllm_port=vllm_port,
        base_dir=base_dir,
        checkpoint_manager=checkpoint_mgr,
        result_writer=result_writer,
        cert_features_map=cert_features_map
    )

    # シグナルハンドラ
    def signal_handler(signum, frame):
        print(f"\n[Worker {worker_id}] Received signal {signum}, stopping...")
        worker.stop()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # 初期化
    if not worker.initialize():
        sys.exit(1)

    try:
        # 実行
        summary = worker.run(domains, start_index, timeout_per_domain)
        print(f"[Worker {worker_id}] Completed: {summary}")

    finally:
        worker.cleanup()
