#!/usr/bin/env python3
"""OT Scout assessment copilot — ask a local (or cloud) language model about an assessment.

Stand-alone proof of concept. It reads an assessment export and never touches capture,
parsing or the database schema. Examples:

  python3 copilot.py --database data/demo.db                      interactive, Ollama qwen2.5:7b
  python3 copilot.py assessment.json --ask "What should I investigate first?"
  python3 copilot.py --database data/demo.db --eval               the eight standard questions, logged
  python3 copilot.py --database data/demo.db --dry-run --ask "..."  print the prompt, call nothing
  python3 copilot.py --database data/demo.db --backend anthropic --model claude-sonnet-4-5 --eval
  python3 copilot.py --database data/demo.db --backend llamacpp --url http://127.0.0.1:8080 --eval
  python3 copilot.py --log-summary data/copilot-log.jsonl         compare models from the log

Backends: ollama (default, local), llamacpp (local llama-server), openai (OPENAI_API_KEY or any
OpenAI-compatible --url), anthropic (ANTHROPIC_API_KEY). Every exchange is appended to the JSONL
log with backend, model, evidence ids sent, latency and grounding checks.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from ot_scout import __version__  # noqa: E402
from ot_scout.copilot import (STANDARD_QUESTIONS, Copilot, export_from_database, load_export,  # noqa: E402
                              summarize_log)
from ot_scout.llm_backends import BACKENDS, DEFAULT_MODELS, BackendError, ScriptedBackend, make_backend  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("export", nargs="?", help="assessment.json exported by OT Scout (or use --database)")
    p.add_argument("--database", help="read the assessment straight from an OT Scout database (e.g. data/demo.db)")
    p.add_argument("--backend", default="ollama", choices=sorted(BACKENDS))
    p.add_argument("--model", help=f"model name (defaults: {', '.join(f'{k}={v}' for k, v in DEFAULT_MODELS.items())})")
    p.add_argument("--url", help="backend base URL (override the default for the backend)")
    p.add_argument("--api-key", default="", help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY)")
    p.add_argument("--ask", action="append", help="ask one question and exit (repeatable)")
    p.add_argument("--eval", action="store_true", help="run the eight standard evaluation questions")
    p.add_argument("--dry-run", action="store_true", help="build and print the prompt; do not call a model")
    p.add_argument("--budget", type=int, default=12000, help="max characters of evidence per prompt (default 12000)")
    p.add_argument("--max-tokens", type=int, default=1500)
    p.add_argument("--no-json-mode", action="store_true", help="do not ask the backend for JSON-constrained output")
    p.add_argument("--no-stream", action="store_true", help="print the answer only when complete")
    p.add_argument("--raw", action="store_true", help="print the model's raw JSON instead of the rendered sections")
    p.add_argument("--log", default="data/copilot-log.jsonl", help="JSONL log path ('' to disable)")
    p.add_argument("--log-prompts", action="store_true", help="include the full prompt in each log row")
    p.add_argument("--log-summary", metavar="LOGFILE", help="summarise a log by backend/model and exit")
    return p.parse_args(argv)


def load(args) -> dict:
    if args.database:
        return export_from_database(args.database)
    if args.export:
        return load_export(args.export)
    sys.exit("Give an assessment.json path or --database data/<file>.db")


def print_summary(rows):
    print(f"{'backend':10} {'model':28} {'answers':>7} {'json':>5} {'grounded':>9} {'median s':>9} {'1st tok s':>9}")
    for r in rows:
        print(f"{r['backend']:10} {r['model'][:28]:28} {r['answers']:>7} {r['parsed_json']:>5} {r['grounded']:>9} "
              f"{r['median_latency_s'] if r['median_latency_s'] is not None else '-':>9} {r['median_first_token_s'] if r['median_first_token_s'] is not None else '-':>9}")


def run_question(copilot: Copilot, question: str, args) -> None:
    print(f"\n> {question}")
    if args.dry_run:
        prompt, records = copilot.prompt_for(question)
        print(f"[dry run] {len(records)} evidence records, {len(prompt) + len(copilot.system_prompt):,} prompt characters "
              f"(~{(len(prompt) + len(copilot.system_prompt)) // 4:,} tokens)")
        print(f"[dry run] evidence: {', '.join(r.id for r in records)}")
        print("-" * 78); print(copilot.system_prompt); print("-" * 78); print(prompt); print("-" * 78)
        return
    streamed = {"any": False}

    def on_token(tok):
        if not args.no_stream and args.raw:
            streamed["any"] = True
            sys.stdout.write(tok); sys.stdout.flush()

    try:
        answer = copilot.ask(question, on_token if not args.no_stream else None)
    except BackendError as exc:
        print(f"[backend error] {exc}")
        return
    if streamed["any"]:
        print()
    elif args.raw:
        print(answer.reply_text)
    else:
        print(answer.render())
    ttfb = f", first token {answer.first_token_seconds}s" if answer.first_token_seconds is not None else ""
    toks = f", {answer.prompt_tokens} in / {answer.completion_tokens} out tokens" if answer.prompt_tokens else ""
    print(f"[{answer.backend}:{answer.model}] {answer.latency_seconds}s{ttfb}{toks}; {len(answer.evidence_ids)} evidence records sent")
    print(f"[check] {answer.validation.summary()}")


def main(argv=None):
    args = parse_args(argv)
    if args.log_summary:
        print_summary(summarize_log(args.log_summary))
        return
    export = load(args)
    if args.dry_run:
        backend = ScriptedBackend()
    else:
        try:
            backend = make_backend(args.backend, args.model, args.url, args.api_key, json_mode=not args.no_json_mode, max_tokens=args.max_tokens)
        except BackendError as exc:
            sys.exit(str(exc))
    copilot = Copilot(export, backend, args.log or None, args.budget, args.log_prompts)
    stats = copilot.evidence.stats()
    print(f"OT Scout Assessment Copilot (OT Scout v{__version__}) — {backend.describe()}")
    ctx = copilot.evidence.context
    print(f"Loaded: {ctx.get('assessment', 'assessment')} — {stats.get('asset', 0)} assets, {stats.get('relationship', 0)} relationships, "
          f"{stats.get('flow', 0)} flows, {stats.get('capture', 0)} captures, {stats.get('finding', 0)} findings")
    print(f"        {stats['undocumented_assets']} undocumented assets, {stats['unexpected_relationships']} unexpected + "
          f"{stats['unreviewed_relationships']} unreviewed relationships, {stats['external_relationships']} external, "
          f"{stats['levels_unassigned']} without a Purdue level")
    if args.log:
        print(f"Log: {args.log}")

    questions = list(args.ask or [])
    if args.eval:
        questions += STANDARD_QUESTIONS
    if questions:
        for q in questions:
            run_question(copilot, q, args)
        return
    print("\nAsk a question (blank line or Ctrl-D to quit). Type 'eval' to run the standard set.")
    while True:
        try:
            q = input("\nask> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not q:
            break
        if q.lower() == "eval":
            for sq in STANDARD_QUESTIONS:
                run_question(copilot, sq, args)
            continue
        run_question(copilot, q, args)


if __name__ == "__main__":
    main()
