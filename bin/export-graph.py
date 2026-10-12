#!/usr/bin/env python3
"""Export NockBrain facts as a Graphify-compatible conversation-memory graph."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from _projection import write_with_receipt
from _store import secure_mkdir

# Operator names that are not concepts in a full-install store; the standalone
# release rewrites this line to the value after the marker.
OPERATOR_STOPWORDS = frozenset()
STOPWORDS = {
    "about", "after", "also", "code", "fact", "fixed", "found", "from", "into",
    "nockbrain", "should", "that", "the", "this", "user", "with",
} | OPERATOR_STOPWORDS


def load_facts(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def node(node_id: str, node_type: str, label: str, **props) -> dict[str, Any]:
    return {"id": node_id, "type": node_type, "label": label, **props}


def edge(source: str, target: str, edge_type: str, **props) -> dict[str, Any]:
    return {"id": f"{source}->{edge_type}->{target}", "source": source, "target": target, "type": edge_type, **props}


def concepts(text: str) -> list[str]:
    terms = []
    for term in re.findall(r"[a-z0-9]{4,}", text.lower()):
        if term not in STOPWORDS and term not in terms:
            terms.append(term)
    return terms[:8]


def graph_from_facts(facts: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(item: dict[str, Any]) -> None:
        nodes[item["id"]] = item

    def add_edge(item: dict[str, Any]) -> None:
        edges[item["id"]] = item

    for fact in facts:
        fact_id = f"fact:{fact.get('id', '')}"
        session_id = f"session:{fact.get('session', 'unknown') or 'unknown'}"
        source_name = fact.get("source_file", "unknown") or "unknown"
        source_id = f"source:{source_name}"

        add_node(node(
            fact_id,
            "fact",
            fact.get("content", "")[:120],
            kind=fact.get("kind", ""),
            status=fact.get("status", ""),
            confidence=fact.get("confidence", 0),
        ))
        add_node(node(session_id, "session", fact.get("session", "unknown") or "unknown"))
        add_node(node(source_id, "source", source_name))
        add_edge(edge(fact_id, source_id, "DERIVED_FROM"))
        add_edge(edge(session_id, fact_id, "SUPPORTS"))

        for concept in concepts(fact.get("content", "")):
            concept_id = f"concept:{concept}"
            add_node(node(concept_id, "concept", concept))
            add_edge(edge(fact_id, concept_id, "MENTIONS"))

    return {
        "format": "graphify-compatible",
        "schema_version": "nockbrain.graph.v1",
        "nodes": sorted(nodes.values(), key=lambda item: item["id"]),
        "edges": sorted(edges.values(), key=lambda item: item["id"]),
    }


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a Graphify-compatible memory graph")
    parser.add_argument("--facts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, default=None,
                        help="projection-receipts.jsonl (default: next to --facts)")
    args = parser.parse_args(argv)

    if not args.facts.exists():
        print(f"Facts file not found: {args.facts}")
        return 1

    graph = graph_from_facts(load_facts(args.facts))
    secure_mkdir(args.output.parent)
    # Route the principal artifact write through a readback receipt so a
    # silently failed/stale graph write is flagged, not lost (S4).
    receipts = args.receipts or args.facts.parent / "projection-receipts.jsonl"
    receipt = write_with_receipt(
        args.output, json.dumps(graph, indent=2, ensure_ascii=False), receipts, kind="text")
    print(f"Wrote graph with {len(graph['nodes'])} node(s) and "
          f"{len(graph['edges'])} edge(s) [{receipt['status']}]")
    return 0


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
