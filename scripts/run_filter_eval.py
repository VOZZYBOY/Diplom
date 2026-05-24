"""Run corpus evaluation for fallback and semantic model variants."""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import time
from collections import defaultdict
from pathlib import Path

from app.core.config import load_config
from app.core.ensemble import EnsembleEngine
from app.core.types import Direction, FilterMessage, FilterRequest, Verdict
from app.models.behavioral import BehavioralModel
from app.models.pattern import PatternModel
from app.models.semantic import SemanticModel
from evals.corpus import EvalCase, build_corpus


DEFAULT_MODELS = [
    "openai/openai/gpt-oss-120b",
    "google/gemma-4-31b-it",
    "gpt-5.4-mini",
    "ai-sage/GigaChat3-10B-A1.8B",
    "openai/GigaChat/GigaChat-2-Max",
    "deepseek-v4-flash",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", default=",".join(DEFAULT_MODELS))
    parser.add_argument("--base-url", default=os.environ.get("LLM_FILTER_BASE_URL", "https://litellm.mlops.itlabs.io"))
    parser.add_argument("--api-key", default=os.environ.get("LLM_FILTER_API_KEY", ""))
    parser.add_argument("--sample-per-group", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--out-dir", default="eval-results")
    parser.add_argument("--fallback-only", action="store_true")
    return parser.parse_args()


def select_cases(corpus: list[EvalCase], sample_per_group: int) -> list[EvalCase]:
    if sample_per_group <= 0:
        return corpus
    selected: list[EvalCase] = []
    by_group: dict[str, list[EvalCase]] = defaultdict(list)
    for case in corpus:
        by_group[case.group].append(case)
    for group in sorted(by_group):
        selected.extend(by_group[group][:sample_per_group])
    return selected


def make_engine(model: str | None, api_key: str, base_url: str, timeout_ms: int) -> EnsembleEngine:
    config = load_config()
    config.semantic.api_key = api_key
    config.semantic.base_url = base_url
    config.semantic.timeout = timeout_ms
    if model:
        config.semantic.model = model

    engine = EnsembleEngine(config)
    engine.register(BehavioralModel())
    engine.register(PatternModel())
    if model and api_key:
        engine.register(SemanticModel(config.semantic))
        engine.llm_available = True
    else:
        engine.llm_available = False
    return engine


def make_request(case: EvalCase) -> FilterRequest:
    role = "assistant" if case.direction == "output" else "user"
    return FilterRequest(
        messages=[FilterMessage(role=role, content=case.text)],
        direction=Direction(case.direction),
        session_id=f"eval-{case.case_id}",
    )


def expected_positive(expected: str) -> bool:
    return expected in {"review", "block"}


def actual_positive(verdict: Verdict) -> bool:
    return verdict in {Verdict.REVIEW, Verdict.BLOCK}


async def run_one(engine: EnsembleEngine, model_label: str, case: EvalCase) -> dict[str, object]:
    start = time.monotonic()
    try:
        result = await engine.analyze(make_request(case))
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "model": model_label,
            "case_id": case.case_id,
            "group": case.group,
            "direction": case.direction,
            "expected": case.expected,
            "verdict": result.verdict.value,
            "risk_score": result.risk_score,
            "semantic_score": result.scores.semantic,
            "behavioral_score": result.scores.behavioral,
            "pattern_score": result.scores.pattern,
            "latency_ms": elapsed,
            "categories": ",".join(result.categories),
            "error": "",
        }
    except Exception as e:
        elapsed = int((time.monotonic() - start) * 1000)
        return {
            "model": model_label,
            "case_id": case.case_id,
            "group": case.group,
            "direction": case.direction,
            "expected": case.expected,
            "verdict": "error",
            "risk_score": None,
            "semantic_score": None,
            "behavioral_score": None,
            "pattern_score": None,
            "latency_ms": elapsed,
            "categories": "",
            "error": f"{type(e).__name__}: {e}",
        }


async def run_model(
    model_label: str, engine: EnsembleEngine, cases: list[EvalCase], concurrency: int
) -> list[dict[str, object]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def guarded(case: EvalCase) -> dict[str, object]:
        async with semaphore:
            return await run_one(engine, model_label, case)

    return await asyncio.gather(*(guarded(case) for case in cases))


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_model: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_model[str(row["model"])].append(row)

    summary: list[dict[str, object]] = []
    for model, model_rows in by_model.items():
        valid = [row for row in model_rows if row["verdict"] != "error"]
        errors = len(model_rows) - len(valid)
        tp = fp = tn = fn = 0
        latencies: list[int] = []
        for row in valid:
            expected = expected_positive(str(row["expected"]))
            actual = actual_positive(Verdict(str(row["verdict"])))
            if expected and actual:
                tp += 1
            elif expected and not actual:
                fn += 1
            elif not expected and actual:
                fp += 1
            else:
                tn += 1
            latencies.append(int(row["latency_ms"]))

        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        accuracy = (tp + tn) / len(valid) if valid else 0.0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        p95_latency = sorted(latencies)[int(0.95 * (len(latencies) - 1))] if latencies else 0
        summary.append(
            {
                "model": model,
                "cases": len(model_rows),
                "valid": len(valid),
                "errors": errors,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "false_positive_rate": round(fpr, 4),
                "accuracy": round(accuracy, 4),
                "avg_latency_ms": round(avg_latency, 1),
                "p95_latency_ms": p95_latency,
            }
        )
    return summary


def write_outputs(out_dir: Path, rows: list[dict[str, object]], summary: list[dict[str, object]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = [
        "model",
        "case_id",
        "group",
        "direction",
        "expected",
        "verdict",
        "risk_score",
        "semantic_score",
        "behavioral_score",
        "pattern_score",
        "latency_ms",
        "categories",
        "error",
    ]
    with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")


async def main() -> None:
    args = parse_args()
    corpus = build_corpus()
    cases = select_cases(corpus, args.sample_per_group)
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    all_rows: list[dict[str, object]] = []
    print(f"Corpus size: {len(corpus)}; selected cases: {len(cases)}", flush=True)
    fallback = make_engine(None, "", args.base_url, args.timeout_ms)
    print("Running fallback_no_llm...", flush=True)
    fallback_rows = await run_model("fallback_no_llm", fallback, cases, args.concurrency)
    all_rows.extend(fallback_rows)
    print(json.dumps(summarize(fallback_rows), ensure_ascii=False), flush=True)

    if not args.fallback_only:
        if not args.api_key:
            raise SystemExit("LLM_FILTER_API_KEY is required unless --fallback-only is set")
        for model in models:
            print(f"Running {model}...", flush=True)
            engine = make_engine(model, args.api_key, args.base_url, args.timeout_ms)
            model_rows = await run_model(model, engine, cases, args.concurrency)
            all_rows.extend(model_rows)
            print(json.dumps(summarize(model_rows), ensure_ascii=False), flush=True)

    summary = summarize(all_rows)
    write_outputs(Path(args.out_dir), all_rows, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
