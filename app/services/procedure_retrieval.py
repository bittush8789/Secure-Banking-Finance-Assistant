"""Local keyword and token-overlap retrieval engine for approved banking procedures.

Treats all retrieved document content as untrusted data when passing to LLM prompts,
preventing secondary prompt injection via document poisoning.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

from app.core.config import settings
from app.core.logging import logger


class DocumentSnippet(NamedTuple):
    """Retrieved procedure snippet."""

    doc_id: str
    title: str
    content: str
    score: float


class ProcedureRetrievalService:
    """In-memory local document retrieval engine suitable for POC requirements."""

    def __init__(self, docs_dir: Optional[str] = None):
        self.docs_dir = Path(docs_dir or settings.PROCEDURE_DOCS_DIRECTORY)
        self._documents: Dict[str, Dict[str, str]] = {}
        self._load_documents()

    def _load_documents(self) -> None:
        """Scan and index procedure documents from filesystem."""
        if not self.docs_dir.exists():
            logger.warning(f"Procedure documents directory not found at: {self.docs_dir}")
            return

        for filepath in self.docs_dir.glob("*.md"):
            try:
                content = filepath.read_text(encoding="utf-8")
                # Extract title from markdown H1 if present
                title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
                title = title_match.group(1).strip() if title_match else filepath.stem.replace("_", " ").title()

                self._documents[filepath.name] = {
                    "doc_id": filepath.name,
                    "title": title,
                    "content": content,
                }
            except Exception as exc:
                logger.error(f"Failed to read procedure document {filepath}: {str(exc)}")

    def reload(self) -> None:
        """Reload document cache from disk."""
        self._documents.clear()
        self._load_documents()

    def retrieve_relevant(
        self,
        query: str,
        topic_filter: Optional[str] = None,
        top_k: int = 2,
    ) -> List[DocumentSnippet]:
        """Match query terms against procedure documents using token-overlap scoring.

        Treats all retrieved content as UNTRUSTED context for the prompt.
        """
        if not self._documents:
            self._load_documents()

        if not query or not self._documents:
            return []

        # Tokenize query into alphanumeric keywords (lowercased)
        query_terms = set(re.findall(r"\b[a-z]{3,}\b", query.lower()))
        # Remove common non-informative English stop words
        stopwords = {
            "the", "and", "for", "that", "this", "with", "what", "how", "can",
            "are", "about", "from", "when", "where", "does", "have", "been",
        }
        filtered_query_terms = query_terms - stopwords
        if not filtered_query_terms:
            filtered_query_terms = query_terms

        scored_snippets: List[DocumentSnippet] = []

        for doc_id, doc in self._documents.items():
            # If topic filter provided, require match in doc_id or title
            if topic_filter:
                filter_term = topic_filter.lower().replace("-", "_")
                if filter_term not in doc_id.lower() and filter_term not in doc["title"].lower():
                    continue

            content = doc["content"]
            content_lower = content.lower()
            title_lower = doc["title"].lower()

            # Scoring: Match count in title (weighted x3) + match count in content
            score = 0.0
            for term in filtered_query_terms:
                if term in title_lower:
                    score += 3.0
                # Count frequency capped at 5 to avoid keyword stuffing bias
                count = min(content_lower.count(term), 5)
                score += count * 0.5

            if score > 0:
                scored_snippets.append(
                    DocumentSnippet(
                        doc_id=doc_id,
                        title=doc["title"],
                        content=content,
                        score=score,
                    )
                )

        # Sort by relevance score descending
        scored_snippets.sort(key=lambda s: s.score, reverse=True)
        return scored_snippets[:top_k]

    @staticmethod
    def format_untrusted_context(snippets: List[DocumentSnippet]) -> str:
        """Format retrieved documents inside explicit untrusted boundary tags.

        This signals clearly to the LLM system prompt that document content is
        passive reference material and must NOT be interpreted as executable instructions.
        """
        if not snippets:
            return "[No relevant approved procedure documents found.]"

        formatted = []
        for s in snippets:
            formatted.append(
                f'<approved_procedure_document id="{s.doc_id}" title="{s.title}">\n'
                f"{s.content}\n"
                f"</approved_procedure_document>"
            )
        return "\n\n".join(formatted)


# Global procedure retrieval instance
procedure_retrieval_service = ProcedureRetrievalService()
