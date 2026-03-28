#!/usr/bin/env python3
"""
scripts/train_models.py
Standalone ML model training and evaluation script.

Run from the project root:
    python scripts/train_models.py
    python scripts/train_models.py --dataset csic2010 --normal normal.txt --attack anomalous.txt
    python scripts/train_models.py --synthetic --n-attack 1000 --n-clean 1000

Output:
    - Prints per-model metrics table
    - Saves comparison chart to reports/model_comparison.png (if matplotlib available)
    - Prints best model recommendation
"""

import argparse
import sys
import os
import json
import time

# Allow running from project root or scripts/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def parse_args():
    p = argparse.ArgumentParser(description="WAF Bypass Lab — ML Model Trainer")
    p.add_argument("--dataset", choices=["builtin", "csic2010", "unswnb15", "synthetic"],
                   default="builtin", help="Dataset to use for training")
    p.add_argument("--normal", help="Path to normal traffic file (CSIC 2010)")
    p.add_argument("--attack", help="Path to attack traffic file (CSIC 2010)")
    p.add_argument("--csv", help="Path to UNSW-NB15 CSV file")
    p.add_argument("--n-attack", type=int, default=500, help="Synthetic attack samples")
    p.add_argument("--n-clean", type=int, default=500, help="Synthetic clean samples")
    p.add_argument("--output-json", help="Save metrics to this JSON file")
    p.add_argument("--plot", action="store_true", help="Generate comparison chart")
    return p.parse_args()


def print_metrics_table(metrics: dict):
    """Print a formatted comparison table to stdout."""
    models = metrics.get("models", {})
    if not models:
        print("No model metrics available.")
        return

    headers = ["Model", "Accuracy", "Precision", "Recall", "F1", "AUC-ROC", "CV Mean", "Train(s)"]
    col_widths = [22, 10, 10, 8, 8, 9, 9, 9]

    separator = "+" + "+".join("-" * w for w in col_widths) + "+"
    header_row = "|" + "|".join(h.center(w) for h, w in zip(headers, col_widths)) + "|"

    print()
    print("=" * 90)
    print("  ML MODEL COMPARISON — WAF Attack Classification")
    print("=" * 90)
    print(separator)
    print(header_row)
    print(separator)

    for name, m in models.items():
        row = [
            name[:20].ljust(20),
            f"{m['accuracy']:.2f}%",
            f"{m['precision']:.2f}%",
            f"{m['recall']:.2f}%",
            f"{m['f1_score']:.2f}%",
            f"{m['auc_roc']:.2f}%",
            f"{m['cv_mean']:.2f}%",
            f"{m['train_time_sec']:.3f}s",
        ]
        print("|" + "|".join(v.center(w) for v, w in zip(row, col_widths)) + "|")

    print(separator)
    print()


def generate_comparison_chart(metrics: dict, output_path: str):
    """Generate a bar chart comparing all models across key metrics."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        models_data = metrics.get("models", {})
        model_names = list(models_data.keys())
        metric_keys = ["accuracy", "precision", "recall", "f1_score", "auc_roc"]
        metric_labels = ["Accuracy", "Precision", "Recall", "F1 Score", "AUC-ROC"]

        x = np.arange(len(metric_keys))
        width = 0.25
        colors = ["#00e5ff", "#7c4dff", "#69f0ae"]

        fig, axes = plt.subplots(1, 2, figsize=(14, 6))
        fig.patch.set_facecolor("#0a0e1a")

        # -- Bar chart: metric comparison --
        ax1 = axes[0]
        ax1.set_facecolor("#12172b")
        for i, (model_name, color) in enumerate(zip(model_names, colors)):
            vals = [models_data[model_name][k] for k in metric_keys]
            bars = ax1.bar(x + i * width, vals, width, label=model_name,
                           color=color, alpha=0.85, edgecolor="#1e2642")
            for bar, val in zip(bars, vals):
                ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                         f"{val:.1f}", ha="center", va="bottom",
                         fontsize=7, color="white")

        ax1.set_xticks(x + width)
        ax1.set_xticklabels(metric_labels, color="white", fontsize=9)
        ax1.set_ylabel("Score (%)", color="white")
        ax1.set_title("Model Performance Comparison", color="#00e5ff", fontsize=12, fontweight="bold")
        ax1.set_ylim(0, 115)
        ax1.legend(facecolor="#1a1f36", edgecolor="#00e5ff",
                   labelcolor="white", fontsize=9)
        ax1.tick_params(colors="white")
        for spine in ax1.spines.values():
            spine.set_edgecolor("#1e2642")

        # -- Training time bar chart --
        ax2 = axes[1]
        ax2.set_facecolor("#12172b")
        train_times = [models_data[m]["train_time_sec"] for m in model_names]
        bars = ax2.bar(model_names, train_times, color=colors[:len(model_names)],
                       alpha=0.85, edgecolor="#1e2642")
        for bar, t in zip(bars, train_times):
            ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.001,
                     f"{t:.3f}s", ha="center", va="bottom", color="white", fontsize=9)

        ax2.set_ylabel("Training Time (seconds)", color="white")
        ax2.set_title("Training Time per Model", color="#7c4dff", fontsize=12, fontweight="bold")
        ax2.tick_params(colors="white")
        for spine in ax2.spines.values():
            spine.set_edgecolor("#1e2642")

        dataset_info = metrics.get("dataset", {})
        fig.suptitle(
            f"WAF Bypass Lab — ML Comparison  |  Dataset: {dataset_info.get('total_samples', '?')} samples  "
            f"({dataset_info.get('attack_samples', '?')} attack, {dataset_info.get('clean_samples', '?')} clean)",
            color="#8892b0", fontsize=10, y=0.02,
        )

        plt.tight_layout(rect=[0, 0.04, 1, 1])
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        plt.savefig(output_path, dpi=150, bbox_inches="tight",
                    facecolor=fig.get_facecolor())
        plt.close()
        print(f"[+] Chart saved to: {output_path}")

    except ImportError:
        print("[!] matplotlib not available — skipping chart generation")
    except Exception as exc:
        print(f"[!] Chart generation failed: {exc}")


def main():
    args = parse_args()

    print("\n[*] WAF Bypass Lab — ML Model Trainer")
    print(f"[*] Dataset mode: {args.dataset}")

    # -- Load or generate dataset --
    texts, labels = [], []

    if args.dataset == "builtin":
        print("[*] Using built-in synthetic training dataset...")
        from ml_engine import MLEngine
        engine = MLEngine()

    elif args.dataset == "synthetic":
        from dataset_utils import generate_synthetic, preprocess, class_balance_report
        print(f"[*] Generating synthetic dataset ({args.n_attack} attack, {args.n_clean} clean)...")
        texts, labels = generate_synthetic(n_attack=args.n_attack, n_clean=args.n_clean)
        texts = preprocess(texts)
        balance = class_balance_report(labels)
        print(f"[*] Dataset balance: {balance}")

        from ml_engine import MLEngine
        engine = MLEngine()
        print("[*] Retraining models on synthetic dataset...")
        success = engine.retrain(texts, labels)
        if not success:
            print("[!] Retraining failed. Check logs.")
            sys.exit(1)

    elif args.dataset == "csic2010":
        if not args.normal or not args.attack:
            print("[!] CSIC 2010 requires --normal and --attack file paths")
            sys.exit(1)
        from dataset_utils import load_csic2010, preprocess, class_balance_report
        print(f"[*] Loading CSIC 2010 from {args.normal} and {args.attack}...")
        texts, labels = load_csic2010(args.normal, args.attack)
        texts = preprocess(texts)
        balance = class_balance_report(labels)
        print(f"[*] Dataset balance: {balance}")

        from ml_engine import MLEngine
        engine = MLEngine()
        success = engine.retrain(texts, labels)
        if not success:
            print("[!] Retraining failed.")
            sys.exit(1)

    elif args.dataset == "unswnb15":
        if not args.csv:
            print("[!] UNSW-NB15 requires --csv file path")
            sys.exit(1)
        from dataset_utils import load_unswnb15, preprocess, class_balance_report
        print(f"[*] Loading UNSW-NB15 from {args.csv}...")
        texts, labels = load_unswnb15(args.csv)
        texts = preprocess(texts)
        balance = class_balance_report(labels)
        print(f"[*] Dataset balance: {balance}")

        from ml_engine import MLEngine
        engine = MLEngine()
        success = engine.retrain(texts, labels)
        if not success:
            print("[!] Retraining failed.")
            sys.exit(1)
    else:
        from ml_engine import MLEngine
        engine = MLEngine()

    # -- Get and display metrics --
    metrics = engine.get_metrics()
    print_metrics_table(metrics)

    dataset_info = metrics.get("dataset", {})
    print(f"[*] Dataset: {dataset_info.get('total_samples','?')} total samples "
          f"({dataset_info.get('attack_samples','?')} attack, "
          f"{dataset_info.get('clean_samples','?')} clean)")
    print(f"[*] Train/test split: {dataset_info.get('train_size','?')} train, "
          f"{dataset_info.get('test_size','?')} test")

    best = engine.get_best_model()
    if best:
        best_m = metrics["models"][best]
        print(f"\n[+] Best model: {best}")
        print(f"    F1={best_m['f1_score']:.2f}%  AUC-ROC={best_m['auc_roc']:.2f}%  "
              f"Accuracy={best_m['accuracy']:.2f}%")
        print()

    # -- Optional: save metrics JSON --
    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"[+] Metrics saved to: {args.output_json}")

    # -- Optional: generate chart --
    if args.plot:
        generate_comparison_chart(metrics, "reports/model_comparison.png")

    print("[+] Training complete.")


if __name__ == "__main__":
    main()
