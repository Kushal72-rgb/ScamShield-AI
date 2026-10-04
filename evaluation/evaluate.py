import json
import os
import sys
import time
from typing import Dict, List, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evaluation.dataset import MESSAGE_DATASET, URL_DATASET, DEGRADED_MODE_DATASET, CONVERSATION_DATASET
from app.analyzer import analyze_message, analyze_conversation, _screen_message_offline
from app.url_analyzer import analyze_url, analyze_all_urls
from app.models import ConversationMessage
from app.evidence_fusion import fuse_evidence
from app.config import GEMINI_API_KEY


def calculate_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Calculate standard binary classification metrics."""
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "total": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
    }


def run_local_url_evaluation(dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate Part 1: Local URL Security Analyzer (deterministic heuristics)."""
    print("\n" + "=" * 70)
    print("PART 1: LOCAL URL ANALYZER EVALUATION (Heuristics)")
    print("=" * 70)

    tp = fp = tn = fn = 0
    results = []
    fps = []
    fns = []

    for item in dataset:
        url = item["url"]
        expected = item["expected_label"]  # "SUSPICIOUS" or "LEGITIMATE"
        analysis = analyze_url(url)

        pred_label = "SUSPICIOUS" if analysis.is_suspicious else "LEGITIMATE"

        if expected == "SUSPICIOUS" and pred_label == "SUSPICIOUS":
            tp += 1
            verdict = "CORRECT (TP)"
        elif expected == "LEGITIMATE" and pred_label == "LEGITIMATE":
            tn += 1
            verdict = "CORRECT (TN)"
        elif expected == "LEGITIMATE" and pred_label == "SUSPICIOUS":
            fp += 1
            verdict = "FALSE POSITIVE (FP)"
            fps.append({
                "id": item["id"],
                "url": url,
                "expected": expected,
                "predicted": pred_label,
                "signals": analysis.suspicious_signals,
            })
        else:  # expected == "SUSPICIOUS" and pred_label == "LEGITIMATE"
            fn += 1
            verdict = "FALSE NEGATIVE (FN)"
            fns.append({
                "id": item["id"],
                "url": url,
                "expected": expected,
                "predicted": pred_label,
                "signals": analysis.suspicious_signals,
            })

        print(f"[{item['id']}] Expected: {expected:<10} | Predicted: {pred_label:<10} | {verdict} | URL: {url}")
        results.append({
            "id": item["id"],
            "url": url,
            "category": item["category"],
            "ground_truth": expected,
            "prediction": pred_label,
            "signals": analysis.suspicious_signals,
            "is_correct": expected == pred_label,
        })

    metrics = calculate_metrics(tp, fp, tn, fn)
    return {
        "metrics": metrics,
        "results": results,
        "false_positives": fps,
        "false_negatives": fns,
    }


def run_message_evaluation(dataset: List[Dict[str, Any]], delay_between_calls: float = 2.0) -> Dict[str, Any]:
    """Evaluate Part 2: Message Detection Pipeline (Gemini + Local URLs + PhishTank)."""
    print("\n" + "=" * 70)
    print("PART 2: MESSAGE PIPELINE EVALUATION (Gemini AI + ScamShield)")
    print("=" * 70)

    tp = fp = tn = fn = 0
    results = []
    fps = []
    fns = []
    completed_count = 0
    stopped_early = False
    stop_reason = ""

    for i, item in enumerate(dataset):
        msg_id = item["id"]
        expected = item["expected_label"]  # "SCAM" or "LEGITIMATE"
        text = item["text"]

        print(f"Testing [{msg_id}] ({i + 1}/{len(dataset)}) ...", end=" ", flush=True)

        try:
            res = analyze_message(text)
            pred_risk = res.risk_level.value  # "LOW", "MEDIUM", "HIGH"

            # In ScamShield, MEDIUM and HIGH risk map to SCAM; LOW maps to LEGITIMATE
            pred_label = "SCAM" if pred_risk in ["MEDIUM", "HIGH"] else "LEGITIMATE"

            if expected == "SCAM" and pred_label == "SCAM":
                tp += 1
                verdict = "CORRECT (TP)"
            elif expected == "LEGITIMATE" and pred_label == "LEGITIMATE":
                tn += 1
                verdict = "CORRECT (TN)"
            elif expected == "LEGITIMATE" and pred_label == "SCAM":
                fp += 1
                verdict = "FALSE POSITIVE (FP)"
                fps.append({
                    "id": msg_id,
                    "text": text,
                    "expected": expected,
                    "predicted": pred_label,
                    "predicted_risk": pred_risk,
                    "explanation": res.explanation,
                })
            else:
                fn += 1
                verdict = "FALSE NEGATIVE (FN)"
                fns.append({
                    "id": msg_id,
                    "text": text,
                    "expected": expected,
                    "predicted": pred_label,
                    "predicted_risk": pred_risk,
                    "explanation": res.explanation,
                })

            print(f"Expected: {expected:<10} | Predicted: {pred_label:<10} ({pred_risk}) | {verdict}")

            results.append({
                "id": msg_id,
                "category": item["category"],
                "text": text,
                "ground_truth": expected,
                "prediction": pred_label,
                "predicted_risk": pred_risk,
                "scam_category": res.scam_category,
                "explanation": res.explanation,
                "is_correct": expected == pred_label,
            })
            completed_count += 1

            # Pacing delay to avoid burst rate limits on free-tier Gemini API
            time.sleep(delay_between_calls)

        except Exception as exc:
            err_msg = str(exc)
            print(f"FAILED (Error: {err_msg[:80]})")
            stopped_early = True
            stop_reason = f"Encountered API error on case {msg_id}: {err_msg}"
            print(f"\n[!] Gracefully stopping evaluation to prevent invalid results: {stop_reason}")
            break

    metrics = calculate_metrics(tp, fp, tn, fn)
    return {
        "completed_count": completed_count,
        "total_attempted": len(dataset),
        "stopped_early": stopped_early,
        "stop_reason": stop_reason,
        "metrics": metrics,
        "results": results,
        "false_positives": fps,
        "false_negatives": fns,
    }


def print_summary_table(title: str, metrics: Dict[str, Any], fps: List[Any], fns: List[Any]):
    """Pretty-print formatted metrics and confusion matrix."""
    print("\n" + "-" * 70)
    print(f"EVALUATION RESULTS: {title}")
    print("NOTE: Synthetic/Internal Benchmark (Does not claim real-world generalization)")
    print("-" * 70)
    print(f"Total Cases Evaluated: {metrics['total']}")
    print(f"Accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision: {metrics['precision'] * 100:.2f}%")
    print(f"Recall:    {metrics['recall'] * 100:.2f}%")
    print(f"F1-Score:  {metrics['f1_score'] * 100:.2f}%")

    print("\nCONFUSION MATRIX:")
    print("                  Predicted Positive (Scam)   Predicted Negative (Legit)")
    print(f"Actual Positive:  TP = {metrics['true_positives']:<22}  FN = {metrics['false_negatives']:<22}")
    print(f"Actual Negative:  FP = {metrics['false_positives']:<22}  TN = {metrics['true_negatives']:<22}")

    print("\nFALSE POSITIVES (FP):", len(fps))
    for fp_case in fps:
        print(f"  - [{fp_case.get('id')}]: Expected {fp_case.get('expected')}, Predicted {fp_case.get('predicted')}")
        if "url" in fp_case:
            print(f"    URL: {fp_case.get('url')}")
        if "text" in fp_case:
            print(f"    Text: {fp_case.get('text')}")

    print("\nFALSE NEGATIVES (FN):", len(fns))
    for fn_case in fns:
        print(f"  - [{fn_case.get('id')}]: Expected {fn_case.get('expected')}, Predicted {fn_case.get('predicted')}")
        if "url" in fn_case:
            print(f"    URL: {fn_case.get('url')}")
        if "text" in fn_case:
            print(f"    Text: {fn_case.get('text')}")
    print("-" * 70)


def run_degraded_mode_evaluation(dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate Part 3: Offline Degraded Mode / API Failure Resilience."""
    print("\n" + "=" * 70)
    print("PART 3: OFFLINE DEGRADED MODE EVALUATION (API-Down Resilience)")
    print("=" * 70)

    tp = fp = tn = fn = 0
    results = []
    fps = []
    fns = []

    for item in dataset:
        msg_id = item["id"]
        expected = item["expected_label"]
        text = item["text"]

        # Simulate Gemini being completely unavailable across all models
        offline_result = _screen_message_offline(text)
        urls = analyze_all_urls(text)
        res = fuse_evidence(
            gemini_response=None,
            urls_detected=urls,
            raw_message=text,
            gemini_error="Simulated Complete API Outage (Degraded Mode Benchmark)",
            offline_assessment=offline_result,
        )

        pred_risk = res.risk_level.value
        pred_label = "SCAM" if pred_risk in ["MEDIUM", "HIGH"] else "LEGITIMATE"

        if expected == "SCAM" and pred_label == "SCAM":
            tp += 1
            verdict = "CORRECT (TP)"
        elif expected == "LEGITIMATE" and pred_label == "LEGITIMATE":
            tn += 1
            verdict = "CORRECT (TN)"
        elif expected == "LEGITIMATE" and pred_label == "SCAM":
            fp += 1
            verdict = "FALSE POSITIVE (FP)"
            fps.append({
                "id": msg_id,
                "text": text,
                "expected": expected,
                "predicted": pred_label,
                "signals": res.suspicious_indicators,
            })
        else:
            fn += 1
            verdict = "FALSE NEGATIVE (FN)"
            fns.append({
                "id": msg_id,
                "text": text,
                "expected": expected,
                "predicted": pred_label,
                "signals": res.suspicious_indicators,
            })

        print(f"[{msg_id}] Expected: {expected:<10} | Predicted: {pred_label:<10} ({pred_risk}) | {verdict}")
        results.append({
            "id": msg_id,
            "category": item["category"],
            "text": text,
            "ground_truth": expected,
            "prediction": pred_label,
            "predicted_risk": pred_risk,
            "scam_category": res.scam_category,
            "signals": res.suspicious_indicators,
            "is_correct": expected == pred_label,
        })

    metrics = calculate_metrics(tp, fp, tn, fn)
    return {
        "metrics": metrics,
        "results": results,
        "false_positives": fps,
        "false_negatives": fns,
    }


def run_conversation_evaluation(dataset: List[Dict[str, Any]], offline: bool = False) -> Dict[str, Any]:
    """Evaluate Part 4: Multi-Turn Conversation Thread Analysis."""
    mode_text = "OFFLINE HEURISTICS" if offline else "GEMINI AI + HEURISTICS"
    print("\n" + "=" * 70)
    print(f"PART 4: CONVERSATION THREAD EVALUATION ({mode_text})")
    print("=" * 70)

    tp = fp = tn = fn = 0
    results = []
    fps = []
    fns = []

    for item in dataset:
        cid = item["id"]
        name = item["name"]
        expected = item["expected_label"]
        messages = [ConversationMessage(**m) for m in item["messages"]]

        if offline or not GEMINI_API_KEY:
            from unittest.mock import patch
            with patch("app.analyzer.GEMINI_API_KEY", ""):
                res = analyze_conversation(messages)
        else:
            res = analyze_conversation(messages)

        pred_risk = res.risk_level.value
        pred_label = "SCAM" if pred_risk in ["MEDIUM", "HIGH"] else "LEGITIMATE"

        if expected == "SCAM" and pred_label == "SCAM":
            tp += 1
            verdict = "CORRECT (TP)"
        elif expected == "LEGITIMATE" and pred_label == "LEGITIMATE":
            tn += 1
            verdict = "CORRECT (TN)"
        elif expected == "LEGITIMATE" and pred_label == "SCAM":
            fp += 1
            verdict = "FALSE POSITIVE (FP)"
            fps.append({"id": cid, "name": name, "expected": expected, "predicted": pred_label})
        else:
            fn += 1
            verdict = "FALSE NEGATIVE (FN)"
            fns.append({"id": cid, "name": name, "expected": expected, "predicted": pred_label})

        tactics_summary = (
            f"Trust={res.conversation_tactics.trust_building_observed}, "
            f"Urgency={res.conversation_tactics.urgency_escalation_observed}, "
            f"Demand={res.conversation_tactics.payment_or_credential_demanded}"
            if res.conversation_tactics else "N/A"
        )
        print(f"[{cid}] Expected: {expected:<10} | Predicted: {pred_label:<10} ({pred_risk}) | {verdict} | Tactics: {tactics_summary}", flush=True)
        results.append({
            "id": cid,
            "name": name,
            "ground_truth": expected,
            "prediction": pred_label,
            "predicted_risk": pred_risk,
            "scam_category": res.scam_category,
            "tactics": res.conversation_tactics.model_dump() if res.conversation_tactics else None,
            "is_correct": expected == pred_label,
        })

    metrics = calculate_metrics(tp, fp, tn, fn)
    return {
        "metrics": metrics,
        "results": results,
        "false_positives": fps,
        "false_negatives": fns,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ScamShield AI Synthetic Evaluation Benchmark")
    parser.add_argument("--url-only", action="store_true", help="Run only the 40-case local URL evaluation")
    parser.add_argument("--degraded-only", action="store_true", help="Run only the degraded mode API-down evaluation")
    parser.add_argument("--conversation-only", action="store_true", help="Run only the multi-turn conversation evaluation")
    parser.add_argument("--message-only", action="store_true", help="Run only the message pipeline evaluation")
    parser.add_argument("--offline", action="store_true", help="Run URL, Degraded Mode, and Conversation evaluations offline")
    args = parser.parse_args()

    print("Starting ScamShield AI Synthetic Evaluation Benchmark...", flush=True)

    output_path = os.path.join(os.path.dirname(__file__), "evaluation_results.json")
    existing_output = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                existing_output = json.load(f)
        except Exception:
            existing_output = {}

    run_all = not (args.url_only or args.degraded_only or args.conversation_only or args.message_only or args.offline)

    # 1. URL Evaluation (Deterministic heuristics, 40 cases)
    url_eval = None
    if run_all or args.url_only or args.offline:
        url_eval = run_local_url_evaluation(URL_DATASET)
        print_summary_table(
            f"Local URL Security Analyzer Heuristics ({len(URL_DATASET)} Cases)",
            url_eval["metrics"],
            url_eval["false_positives"],
            url_eval["false_negatives"],
        )

    # 2. Degraded Mode Evaluation (Offline API-Down Heuristics, 10 cases)
    degraded_eval = None
    if run_all or args.degraded_only or args.offline:
        degraded_eval = run_degraded_mode_evaluation(DEGRADED_MODE_DATASET)
        print_summary_table(
            f"Offline Degraded Mode / API Failure Resilience ({len(DEGRADED_MODE_DATASET)} Cases)",
            degraded_eval["metrics"],
            degraded_eval["false_positives"],
            degraded_eval["false_negatives"],
        )

    # 3. Conversation Thread Evaluation (Multi-turn Grooming, 4 cases)
    conv_eval = None
    if run_all or args.conversation_only or args.offline:
        conv_eval = run_conversation_evaluation(CONVERSATION_DATASET, offline=args.offline)
        print_summary_table(
            f"Multi-Turn Conversation Evaluation ({len(CONVERSATION_DATASET)} Cases)",
            conv_eval["metrics"],
            conv_eval["false_positives"],
            conv_eval["false_negatives"],
        )

    # 4. Message Pipeline Evaluation (Gemini AI + ScamShield, 30 cases)
    msg_eval = None
    if (run_all or args.message_only) and not args.offline:
        if GEMINI_API_KEY:
            msg_eval = run_message_evaluation(MESSAGE_DATASET, delay_between_calls=2.0)
            print_summary_table(
                f"Message Pipeline Analysis ({msg_eval['completed_count']}/{msg_eval['total_attempted']} Cases)",
                msg_eval["metrics"],
                msg_eval["false_positives"],
                msg_eval["false_negatives"],
            )
        else:
            print("\n[NOTE] Skipping live Gemini API message evaluation (GEMINI_API_KEY not configured).")
            print("To benchmark message pipeline live, configure GEMINI_API_KEY in .env.")

    # Save evaluation output to JSON
    final_output = {
        "evaluation_type": "Synthetic Internal Evaluation Benchmark",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "disclaimer": "This synthetic benchmark provides comparative metrics for development and validation. It does not represent real-world generalization or operational accuracy.",
        "url_heuristics_evaluation": url_eval if url_eval is not None else existing_output.get("url_heuristics_evaluation"),
        "degraded_mode_evaluation": degraded_eval if degraded_eval is not None else existing_output.get("degraded_mode_evaluation"),
        "conversation_evaluation": conv_eval if conv_eval is not None else existing_output.get("conversation_evaluation"),
        "message_pipeline_evaluation": msg_eval if msg_eval is not None else existing_output.get("message_pipeline_evaluation"),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2)

    print(f"\n[OK] Detailed evaluation results saved to: {output_path}")


if __name__ == "__main__":
    main()
