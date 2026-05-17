#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import tiktoken
from typing import List, Dict, Any


class RFCDocumentSplitter:
    """Module 2: Intelligent document splitting"""

    def __init__(self, max_tokens: int = 6000, model: str = "gpt-4"):
        self.max_tokens = max_tokens
        try:
            self.encoding = tiktoken.encoding_for_model(model)
        except Exception:
            self.encoding = tiktoken.get_encoding("cl100k_base")

    def count_tokens(self, text: str) -> int:
        """Count the number of tokens in text"""
        return len(self.encoding.encode(text))

    def split_by_sections(self, text: str) -> List[Dict[str, Any]]:
        """Split the document by section headings"""
        lines = text.split("\n")
        chunks: List[Dict[str, Any]] = []
        current_chunk: List[str] = []
        current_section = "Introduction"

        section_patterns = [
            r"^#+\s+(\d+(?:\.\d+)+)\s+(.+)$",
            r"^(\d+(?:\.\d+)+)\.?\s+(.+)$",
        ]

        for line in lines:
            matched = False

            for pattern in section_patterns:
                match = re.match(pattern, line)
                if match:
                    if current_chunk:
                        chunk_text = "\n".join(current_chunk)
                        token_count = self.count_tokens(chunk_text)
                        chunks.append({
                            "section": current_section,
                            "content": chunk_text,
                            "tokens": token_count,
                        })

                    current_section = f"{match.group(1)} {match.group(2)}" if len(match.groups()) == 2 else match.group(1)
                    current_chunk = [line]
                    matched = True
                    break

            if not matched:
                current_chunk.append(line)

        if current_chunk:
            chunk_text = "\n".join(current_chunk)
            chunks.append({
                "section": current_section,
                "content": chunk_text,
                "tokens": self.count_tokens(chunk_text),
            })

        return self._merge_small_chunks(chunks)

    def _merge_small_chunks(self, chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge chunks smaller than the threshold"""
        merged: List[Dict[str, Any]] = []
        buffer: Dict[str, Any] | None = None

        for chunk in chunks:
            if buffer is None:
                buffer = chunk
            else:
                combined_tokens = buffer["tokens"] + chunk["tokens"]
                if combined_tokens <= self.max_tokens:
                    buffer["content"] += "\n\n" + chunk["content"]
                    buffer["section"] += f" + {chunk['section']}"
                    buffer["tokens"] = combined_tokens
                else:
                    merged.append(buffer)
                    buffer = chunk

        if buffer:
            merged.append(buffer)

        return merged