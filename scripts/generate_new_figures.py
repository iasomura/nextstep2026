#!/usr/bin/env python3
"""
論文用 新規図表生成スクリプト（P0-3, P0-4）

生成する図:
  fig04_latency.png          - Stage3 処理遅延CDF（p50/p90/p99注記付き）
  fig05_error_breakdown.png  - 誤り分析（Stage別 FN/FP 分布）

データソース:
  docs/paper/data/tables/fig4_processing_time.csv
  docs/paper/data/tables/fig5_error_categories.csv

Usage:
    python scripts/generate_new_figures.py           # 両方生成
    python scripts/generate_new_figures.py --fig 4   # Fig4のみ
    python scripts/generate_new_figures.py --fig 5   # Fig5のみ

変更履歴:
  - 2026-02-07: 初版作成（P0-3, P0-4）
"""

import argparse
import csv
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "docs" / "paper" / "data" / "tables"
OUTPUT_DIR = PROJECT_ROOT / "docs" / "paper" / "images"

# STYLE_GUIDE準拠: 日本語フォント設定
JAPANESE_FONTS = ['IPAexGothic', 'Noto Sans CJK JP', 'Hiragino Sans', 'MS Gothic']

def setup_japanese_font():
    """日本語フォントを設定する"""
    for font_name in JAPANESE_FONTS:
        try:
            fm.findfont(font_name, fallback_to_default=False)
            plt.rcParams['font.family'] = font_name
            print(f"フォント設定: {font_name}")
            return
        except Exception:
            continue
    # フォールバック: sans-serif
    plt.rcParams['font.family'] = 'sans-serif'
    print("警告: 日本語フォントが見つかりません。sans-serifを使用します。")


def load_fig4_data():
    """fig4_processing_time.csv からヒストグラムと分位点データを読み込む"""
    csv_path = DATA_DIR / "fig4_processing_time.csv"

    bins = []
    counts = []
    percentiles = {}

    with open(csv_path, 'r') as f:
        section = None
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith('#'):
                if row and 'Histogram' in row[0]:
                    section = 'histogram'
                elif row and 'Percentiles' in row[0]:
                    section = 'percentiles'
                elif row and 'Per-worker' in row[0]:
                    section = 'worker'
                continue
            if section == 'histogram' and row[0] != 'bin_start':
                bin_start = float(row[0])
                count = int(row[2])
                bins.append(bin_start)
                counts.append(count)
            elif section == 'percentiles' and row[0] != 'percentile':
                p = int(row[0])
                val = float(row[1])
                percentiles[p] = val

    return bins, counts, percentiles


def generate_fig04():
    """Fig4: Stage3 処理遅延CDF（p50/p90/p99注記付き）"""
    print("Fig4 (処理遅延CDF) を生成中...")

    bins, counts, percentiles = load_fig4_data()

    total = sum(counts)
    cumulative = np.cumsum(counts) / total

    # CDFプロット用のx座標（各ビンの右端）
    x = [b + 1.0 for b in bins]  # bin_end

    fig, ax = plt.subplots(figsize=(8, 5))

    # CDF曲線
    ax.plot(x, cumulative, color='#2c3e50', linewidth=2.0, zorder=3)
    ax.fill_between(x, cumulative, alpha=0.15, color='#3498db', zorder=2)

    # 分位点の縦線（p50, p90, p99）
    pct_styles = {
        50: {'color': '#27ae60', 'label': f'p50 = {percentiles[50]:.2f}s', 'ls': '--'},
        90: {'color': '#e67e22', 'label': f'p90 = {percentiles[90]:.2f}s', 'ls': '--'},
        99: {'color': '#e74c3c', 'label': f'p99 = {percentiles[99]:.2f}s', 'ls': '--'},
    }

    for p, style in pct_styles.items():
        val = percentiles[p]
        ax.axvline(x=val, color=style['color'], linestyle=style['ls'],
                   linewidth=1.5, label=style['label'], zorder=4)
        # 横のドット線で累積割合と接続
        ax.axhline(y=p/100, color=style['color'], linestyle=':',
                   linewidth=0.8, alpha=0.5, zorder=1)

    # STYLE_GUIDE準拠: 日本語ラベル
    ax.set_xlabel('処理時間（秒）', fontsize=12)
    ax.set_ylabel('累積割合', fontsize=12)
    ax.set_title('Stage 3 処理遅延の累積分布', fontsize=13, fontweight='bold')

    # n表記（STYLE_GUIDE: 図中にnを明示）
    ax.text(0.98, 0.02, f'n = {total:,}',
            transform=ax.transAxes, ha='right', va='bottom',
            fontsize=10, bbox=dict(boxstyle='round,pad=0.3',
                                    facecolor='white', edgecolor='gray', alpha=0.8))

    ax.set_xlim(0, 35)
    ax.set_ylim(0, 1.02)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0])
    ax.set_yticklabels(['0%', '25%', '50%', '75%', '90%', '99%', '100%'])
    ax.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
    ax.legend(loc='center right', fontsize=10, framealpha=0.9)

    plt.tight_layout()

    # PNG + PDF
    png_path = OUTPUT_DIR / "fig04_latency.png"
    pdf_path = OUTPUT_DIR / "fig04_latency.pdf"
    fig.savefig(png_path, dpi=300, bbox_inches='tight')
    fig.savefig(pdf_path, bbox_inches='tight')
    plt.close(fig)

    print(f"  出力: {png_path}")
    print(f"  出力: {pdf_path}")
    print(f"  n = {total:,}")
    print(f"  p50 = {percentiles[50]:.2f}s, p90 = {percentiles[90]:.2f}s, p99 = {percentiles[99]:.2f}s")


def load_fig5_data():
    """fig5_error_categories.csv からFN/FPのStage別データを読み込む"""
    csv_path = DATA_DIR / "fig5_error_categories.csv"

    fn_data = {}
    fp_data = {}
    metadata = {}

    with open(csv_path, 'r') as f:
        section = None
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            if raw_line.startswith('# False Negatives'):
                section = 'fn'
                continue
            elif raw_line.startswith('# False Positives'):
                section = 'fp'
                continue
            elif raw_line.startswith('# Stage3'):
                # メタデータ行（JSON含むためCSV readerは使わない）
                import json
                # JSON部分は最初の '{' から抽出
                brace_idx = raw_line.index('{')
                json_str = raw_line[brace_idx:]
                if 'FN by source' in raw_line:
                    metadata['fn_source'] = json.loads(json_str)
                elif 'FP by source' in raw_line:
                    metadata['fp_source'] = json.loads(json_str)
                elif 'FN top TLDs' in raw_line:
                    metadata['fn_tlds'] = json.loads(json_str)
                continue

            if raw_line.startswith('stage,'):
                continue  # ヘッダスキップ

            parts = raw_line.split(',')
            if len(parts) < 3:
                continue

            stage_raw = parts[0]
            count = int(parts[1])
            stage = stage_raw.split(' (')[0]

            if section == 'fn' and stage != 'Total':
                fn_data[stage] = count
            elif section == 'fp' and stage != 'Total':
                fp_data[stage] = count

    return fn_data, fp_data, metadata


def generate_fig05():
    """Fig5: 誤り分析（Stage別 FN/FP 分布）"""
    print("Fig5 (誤り分析) を生成中...")

    fn_data, fp_data, metadata = load_fig5_data()

    stages = ['Stage1', 'Stage2', 'Stage3']
    fn_counts = [fn_data.get(s, 0) for s in stages]
    fp_counts = [fp_data.get(s, 0) for s in stages]
    fn_total = sum(fn_counts)
    fp_total = sum(fp_counts)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    # 色設定
    colors = ['#3498db', '#e67e22', '#e74c3c']
    stage_labels = ['Stage 1', 'Stage 2', 'Stage 3']

    # === 左パネル: FN（偽陰性）===
    bars1 = ax1.bar(stage_labels, fn_counts, color=colors, edgecolor='white',
                    linewidth=0.5, width=0.6)
    ax1.set_title(f'偽陰性（FN）の Stage 別分布', fontsize=12, fontweight='bold')
    ax1.set_ylabel('件数', fontsize=11)

    # 件数と割合のアノテーション
    for bar, count in zip(bars1, fn_counts):
        pct = count / fn_total * 100 if fn_total > 0 else 0
        if count > 0:
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 10,
                     f'{count:,}\n({pct:.1f}%)',
                     ha='center', va='bottom', fontsize=9)

    ax1.set_ylim(0, max(fn_counts) * 1.25)
    ax1.text(0.02, 0.98, f'合計 {fn_total:,}件',
             transform=ax1.transAxes, ha='left', va='top',
             fontsize=10, fontweight='bold',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow',
                       edgecolor='gray', alpha=0.8))

    # === 右パネル: FP（偽陽性）===
    bars2 = ax2.bar(stage_labels, fp_counts, color=colors, edgecolor='white',
                    linewidth=0.5, width=0.6)
    ax2.set_title(f'偽陽性（FP）の Stage 別分布', fontsize=12, fontweight='bold')
    ax2.set_ylabel('件数', fontsize=11)

    for bar, count in zip(bars2, fp_counts):
        pct = count / fp_total * 100 if fp_total > 0 else 0
        if count > 0:
            ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 5,
                     f'{count:,}\n({pct:.1f}%)',
                     ha='center', va='bottom', fontsize=9)

    ax2.set_ylim(0, max(fp_counts) * 1.25)
    ax2.text(0.02, 0.98, f'合計 {fp_total:,}件',
             transform=ax2.transAxes, ha='left', va='top',
             fontsize=10, fontweight='bold',
             bbox=dict(boxstyle='round,pad=0.3', facecolor='lightyellow',
                       edgecolor='gray', alpha=0.8))

    # FN Source内訳をFNパネルに追記
    if 'fn_source' in metadata:
        src = metadata['fn_source']
        src_text = '  '.join([f'{k}: {v:,}' for k, v in src.items()])
        ax1.text(0.5, -0.15, f'※ Stage 3 FN内訳: {src_text}',
                 transform=ax1.transAxes, ha='center', va='top', fontsize=8,
                 color='#555555')

    plt.suptitle('誤り分析: 残存 FN と増加 FP の Stage 別分布',
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout()

    # PNG + PDF
    png_path = OUTPUT_DIR / "fig05_error_breakdown.png"
    pdf_path = OUTPUT_DIR / "fig05_error_breakdown.pdf"
    fig.savefig(png_path, dpi=300, bbox_inches='tight')
    fig.savefig(pdf_path, bbox_inches='tight')
    plt.close(fig)

    print(f"  出力: {png_path}")
    print(f"  出力: {pdf_path}")
    print(f"  FN合計: {fn_total:,}件 (Stage1={fn_counts[0]}, Stage2={fn_counts[1]}, Stage3={fn_counts[2]})")
    print(f"  FP合計: {fp_total:,}件 (Stage1={fp_counts[0]}, Stage2={fp_counts[1]}, Stage3={fp_counts[2]})")


def main():
    parser = argparse.ArgumentParser(description='論文用新規図表生成')
    parser.add_argument('--fig', type=int, choices=[4, 5],
                        help='生成する図番号（省略で両方生成）')
    args = parser.parse_args()

    setup_japanese_font()

    if args.fig is None or args.fig == 4:
        generate_fig04()
    if args.fig is None or args.fig == 5:
        generate_fig05()

    print("\n完了")


if __name__ == '__main__':
    main()
