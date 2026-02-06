# -*- coding: utf-8 -*-
"""
LLMスクリーニングWorker

ドメイン名をLLMで分析し、高リスクドメインを抽出する。
Stage3のEvaluationWorkerと同じインフラ（CheckpointManager, ResultWriter）を使用。

変更履歴:
    - 2026-02-03: 初版作成 - Stage3インフラを再利用
"""
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable

from .checkpoint import CheckpointManager, ResultWriter
from .screening_schema import DomainScreeningResult


@dataclass
class ScreeningWorkerResult:
    """スクリーニング結果"""
    domain: str
    ml_probability: float
    risk_score: float
    is_typosquatting: bool
    target_brand: Optional[str]
    similarity_score: float
    legitimacy_score: float
    red_flags: str  # JSON string
    is_dga: bool
    dga_score: float
    impersonation_target: Optional[str]
    should_send_to_stage3: bool
    processing_time: float
    worker_id: int
    error: Optional[str] = None


class ScreeningWorker:
    """
    LLMスクリーニングWorker

    Stage3 EvaluationWorkerと同じインターフェースで、
    ドメイン名のLLM分析を行う軽量版Worker。
    """

    # ブランドコンテキスト（プロンプト用）
    BRAND_CONTEXT = """
主要ブランド（typosquatting検出用）:
- kuronekoyamato, yamato, kuronek: ヤマト運輸
- sagawa: 佐川急便
- japanpost, yubin: 日本郵便
- smbc: 三井住友銀行
- mufg: 三菱UFJ銀行
- rakuten: 楽天
- amazon: Amazon
- mercari: メルカリ
- paypay: PayPay
- line: LINE
- apple, icloud: Apple
- google, gmail: Google
- microsoft, outlook: Microsoft
- netflix, spotify: ストリーミング
- paypal: PayPal
"""

    SCREENING_PROMPT = """あなたはフィッシングドメイン分析の専門家です。

以下のドメイン名を分析し、フィッシングリスクを評価してください。

ドメイン: {domain}

{brand_context}

分析観点:
1. Typosquatting: 有名ブランドの綴り違いかどうか
2. 正当性: 正規のビジネスドメインとして自然かどうか
3. DGA: 自動生成ドメイン（ランダム文字列）の可能性
4. 総合リスク: 0.0（安全）〜 1.0（危険）で評価

注意: ドメイン名のみで判断してください。Webサイトの内容は考慮しません。
"""

    def __init__(
        self,
        worker_id: int,
        vllm_port: int,
        base_dir: Path,
        checkpoint_manager: 'CheckpointManager',
        result_writer: 'ResultWriter',
        model_name: str = "JunHowie/Qwen3-4B-Thinking-2507-GPTQ-Int8",
        risk_threshold: float = 0.70,
        typo_threshold: float = 0.80,
    ):
        """
        Args:
            worker_id: Worker ID
            vllm_port: vLLMのポート番号
            base_dir: プロジェクトベースディレクトリ
            checkpoint_manager: チェックポイント管理
            result_writer: 結果書き込み
            model_name: モデル名
            risk_threshold: Stage3送信のリスク閾値
            typo_threshold: ブランド類似度閾値
        """
        self.worker_id = worker_id
        self.vllm_port = vllm_port
        self.base_dir = Path(base_dir)
        self.checkpoint_manager = checkpoint_manager
        self.result_writer = result_writer
        self.model_name = model_name
        self.risk_threshold = risk_threshold
        self.typo_threshold = typo_threshold

        self._llm = None
        self._chain = None
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
        """Workerを初期化"""
        try:
            from langchain_openai import ChatOpenAI
            from langchain_core.prompts import ChatPromptTemplate

            # LLM初期化
            self._llm = ChatOpenAI(
                model=self.model_name,
                base_url=f"http://localhost:{self.vllm_port}/v1",
                api_key="EMPTY",
                temperature=0.0,
                max_tokens=1024,
                # Qwen3 thinking モードを無効化
                extra_body={"chat_template_kwargs": {"enable_thinking": False}},
            )

            # プロンプトテンプレート
            prompt = ChatPromptTemplate.from_template(self.SCREENING_PROMPT)

            # Structured Output チェーン
            self._chain = prompt | self._llm.with_structured_output(DomainScreeningResult)

            print(f"[ScreeningWorker {self.worker_id}] Initialized with vLLM port {self.vllm_port}")
            return True

        except Exception as e:
            print(f"[ScreeningWorker {self.worker_id}] Initialization failed: {e}")
            return False

    def _should_send_to_stage3(self, result: DomainScreeningResult) -> bool:
        """Stage3送信判定"""
        # 条件1: 高リスクスコア
        if result.risk_score >= self.risk_threshold:
            return True

        # 条件2: ブランド模倣（高類似度）
        if (result.typo_analysis.is_typosquatting and
            result.typo_analysis.similarity_score >= self.typo_threshold):
            return True

        return False

    def _screen_single(
        self,
        domain: str,
        ml_prob: float,
        retry: int = 3
    ) -> ScreeningWorkerResult:
        """単一ドメインをスクリーニング"""
        start_time = time.time()

        for attempt in range(retry):
            try:
                # LLM呼び出し (with_structured_output)
                result: DomainScreeningResult = self._chain.invoke({
                    "domain": domain,
                    "brand_context": self.BRAND_CONTEXT,
                })

                elapsed = time.time() - start_time

                return ScreeningWorkerResult(
                    domain=domain,
                    ml_probability=ml_prob,
                    risk_score=result.risk_score,
                    is_typosquatting=result.typo_analysis.is_typosquatting,
                    target_brand=result.typo_analysis.target_brand,
                    similarity_score=result.typo_analysis.similarity_score,
                    legitimacy_score=result.legitimacy_analysis.legitimacy_score,
                    red_flags=json.dumps(result.legitimacy_analysis.red_flags, ensure_ascii=False),
                    is_dga=result.dga_analysis.is_likely_dga,
                    dga_score=result.dga_analysis.dga_score,
                    impersonation_target=result.impersonation_target,
                    should_send_to_stage3=self._should_send_to_stage3(result),
                    processing_time=elapsed,
                    worker_id=self.worker_id,
                )

            except Exception as e:
                if attempt < retry - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue

                elapsed = time.time() - start_time
                return ScreeningWorkerResult(
                    domain=domain,
                    ml_probability=ml_prob,
                    risk_score=0.0,
                    is_typosquatting=False,
                    target_brand=None,
                    similarity_score=0.0,
                    legitimacy_score=0.5,
                    red_flags="[]",
                    is_dga=False,
                    dga_score=0.0,
                    impersonation_target=None,
                    should_send_to_stage3=False,
                    processing_time=elapsed,
                    worker_id=self.worker_id,
                    error=str(e)[:200],
                )

    def run(
        self,
        domains: List[Dict[str, Any]],
        start_index: int = 0,
        timeout_per_domain: int = 60  # 未使用（互換性のため）
    ) -> Dict[str, Any]:
        """
        ドメインスクリーニングを実行

        Args:
            domains: 評価対象ドメインのリスト [{domain, ml_probability, ...}, ...]
            start_index: 開始インデックス（再開用）
            timeout_per_domain: 1ドメインのタイムアウト（未使用）

        Returns:
            実行結果サマリー
        """
        self._running = True
        self._stop_requested = False

        total = len(domains)
        completed = 0
        failed = 0
        stage3_count = 0
        start_time = time.time()

        print(f"[ScreeningWorker {self.worker_id}] Starting screening: {total} domains from index {start_index}")

        for i in range(start_index, total):
            if self._stop_requested:
                print(f"[ScreeningWorker {self.worker_id}] Stop requested, saving checkpoint...")
                break

            # 一時停止チェック
            while self._paused and not self._stop_requested:
                time.sleep(1)

            domain_info = domains[i]
            domain = domain_info["domain"]
            ml_prob = domain_info.get("ml_probability", 0.0)

            # 処理中マーク
            self.checkpoint_manager.mark_worker_processing(self.worker_id, domain, i)

            try:
                result = self._screen_single(domain, ml_prob)

                # 結果保存
                row = {
                    "domain": result.domain,
                    "ml_probability": result.ml_probability,
                    "risk_score": result.risk_score,
                    "is_typosquatting": result.is_typosquatting,
                    "target_brand": result.target_brand,
                    "similarity_score": result.similarity_score,
                    "legitimacy_score": result.legitimacy_score,
                    "red_flags": result.red_flags,
                    "is_dga": result.is_dga,
                    "dga_score": result.dga_score,
                    "impersonation_target": result.impersonation_target,
                    "should_send_to_stage3": result.should_send_to_stage3,
                    "processing_time": result.processing_time,
                    "worker_id": result.worker_id,
                    "error": result.error,
                    # 元データの追加フィールドを保持
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
                    if result.should_send_to_stage3:
                        stage3_count += 1
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
                    print(f"[ScreeningWorker {self.worker_id}] {i+1}/{total} "
                          f"(ok:{completed}, err:{failed}, stage3:{stage3_count}) "
                          f"ETA: {eta/60:.1f}min")

            except Exception as e:
                # vLLM接続エラーの場合
                if "Connection" in str(e) or "timeout" in str(e).lower():
                    print(f"[ScreeningWorker {self.worker_id}] vLLM connection error: {e}")
                    if self._on_vllm_failure:
                        self._on_vllm_failure()
                    self._paused = True
                else:
                    # その他のエラー
                    failed += 1
                    self.checkpoint_manager.update_worker_progress(
                        self.worker_id, domain, i, False, str(e)
                    )

        self._running = False

        # 完了マーク
        if not self._stop_requested:
            self.checkpoint_manager.mark_worker_completed(self.worker_id)

        return {
            "worker_id": self.worker_id,
            "total": total,
            "completed": completed,
            "failed": failed,
            "stage3_count": stage3_count,
            "elapsed": time.time() - start_time
        }

    def pause(self):
        """一時停止"""
        self._paused = True

    def resume(self):
        """再開"""
        self._paused = False

    def stop(self):
        """停止要求"""
        self._stop_requested = True

    @property
    def is_running(self) -> bool:
        return self._running
