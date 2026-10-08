"""
Deterministic Ranking Engine for Protocol Brain Context Engine.
Scores and prioritizes symbols, files, and tests without LLM latency or costs.
"""

import re
from typing import Any, Dict, List, Optional, Set

from .storage import DatabaseManager, db_manager

# Common programming and natural language stopwords to ignore during query tokenization
STOPWORDS: Set[str] = {
    "the", "a", "an", "in", "on", "at", "for", "to", "of", "and", "or", "is", "are",
    "with", "by", "from", "how", "what", "why", "where", "fix", "update", "add", "make",
    "get", "set", "do", "does", "did", "can", "could", "should", "would", "please",
}


def tokenize_query(query: str) -> Set[str]:
    """Tokenize a task query into normalized keywords and code identifiers."""
    raw_tokens = re.findall(r"[A-Za-z0-9_]+", query.lower())
    tokens = set()
    for tok in raw_tokens:
        if len(tok) >= 2 and tok not in STOPWORDS:
            tokens.add(tok)
            # Handle camelCase or snake_case sub-tokens
            parts = re.findall(r"[a-z0-9]+|[A-Z][a-z0-9]*", tok)
            for p in parts:
                p_lower = p.lower()
                if len(p_lower) >= 2 and p_lower not in STOPWORDS:
                    tokens.add(p_lower)
    return tokens


class CandidateSymbol:
    """Represents a candidate code element considered for the context packet."""

    def __init__(
        self,
        symbol_id: int,
        file_path: str,
        name: str,
        container: Optional[str],
        sym_type: str,
        line_start: int,
        line_end: int,
        signature: Optional[str],
        docstring: Optional[str],
    ):
        self.symbol_id = symbol_id
        self.file_path = file_path
        self.name = name
        self.container = container
        self.sym_type = sym_type
        self.line_start = line_start
        self.line_end = line_end
        self.signature = signature
        self.docstring = docstring
        self.score: float = 0.0
        self.is_test: bool = "test" in sym_type or name.startswith("test")
        self.reasons: List[str] = []


class DeterministicRanker:
    """Ranks symbols, dependencies, and test targets deterministically."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        storage: Optional[DatabaseManager] = None,
        workspace_root: Optional[Any] = None,
    ):
        self.db = storage or db or db_manager
        self.workspace_root = workspace_root

    def rank_symbols(
        self,
        query: str,
        max_candidates: int = 30,
        expand_graph: bool = False,
        git_modified_files: Optional[Set[str]] = None,
    ) -> List[CandidateSymbol]:
        return self.search_and_rank_candidates(
            task=query,
            git_modified_files=git_modified_files,
            max_candidates=max_candidates,
        )

    def search_and_rank_candidates(
        self,
        task: str,
        git_modified_files: Optional[Set[str]] = None,
        max_candidates: int = 30,
    ) -> List[CandidateSymbol]:
        """
        Finds matching candidates in SQLite index and scores them deterministically.
        """
        query_tokens = tokenize_query(task)
        if not query_tokens:
            return []

        git_files = {f.replace("\\", "/").lower() for f in (git_modified_files or set())}
        candidates: Dict[int, CandidateSymbol] = {}

        with self.db.get_connection() as conn:
            cur = conn.cursor()

            # Search symbols matching query tokens
            for token in query_tokens:
                pattern = f"%{token}%"
                query_sql = """
                    SELECT s.id, f.path, s.name, s.container, s.type, s.line_start, s.line_end, s.signature, s.docstring
                    FROM symbols s
                    JOIN files f ON s.file_id = f.id
                    WHERE s.name LIKE ? OR f.path LIKE ?
                    LIMIT 50
                """
                for row in cur.execute(query_sql, (pattern, pattern)):
                    sym_id = row["id"]
                    if sym_id not in candidates:
                        candidates[sym_id] = CandidateSymbol(
                            symbol_id=sym_id,
                            file_path=row["path"],
                            name=row["name"],
                            container=row["container"],
                            sym_type=row["type"],
                            line_start=row["line_start"],
                            line_end=row["line_end"],
                            signature=row["signature"],
                            docstring=row["docstring"],
                        )

            # Score candidates
            for cand in candidates.values():
                name_lower = cand.name.lower()
                path_lower = cand.file_path.lower()

                # 1. Exact symbol match
                if name_lower in query_tokens:
                    cand.score += 100.0
                    cand.reasons.append("exact_symbol_match")
                elif any(q in name_lower for q in query_tokens):
                    cand.score += 50.0
                    cand.reasons.append("partial_symbol_match")

                # 2. File path match
                if any(q in path_lower for q in query_tokens):
                    cand.score += 40.0
                    cand.reasons.append("filename_match")

                # 3. Recent Git modifications
                if path_lower in git_files or any(gf in path_lower for gf in git_files):
                    cand.score += 30.0
                    cand.reasons.append("git_modified")

                # 4. Container match
                if cand.container and cand.container.lower() in query_tokens:
                    cand.score += 35.0
                    cand.reasons.append("container_match")

                # 5. Test priority
                if cand.is_test:
                    cand.score += 25.0
                    cand.reasons.append("test_coverage")

        sorted_candidates = sorted(candidates.values(), key=lambda c: c.score, reverse=True)
        return sorted_candidates[:max_candidates]


deterministic_ranker = DeterministicRanker()
Ranker = DeterministicRanker
