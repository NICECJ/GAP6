#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from typing import List


class RFCDocumentCleaner:
    """Module 1: Document cleaning module (for plain-text RFC files)"""

    def __init__(self):
        self.header_patterns = [
            r"^RFC\s+\d+.*$",
            r"^Internet Engineering Task Force.*$",
            r"^Request for Comments:.*$",
            r"^\s*\d{4}\s*$",
            r"^[A-Z][a-z]+\s+\d{4}$",
        ]

        self.footer_patterns = [
            r"^\s*\[Page\s+\d+\]\s*$",
            r"^\s*\d+\s*$",
            r"^[A-Z][a-z]+(\s+&\s+[A-Z][a-z]+)*\s+(Standards Track|Informational|Experimental).*$",
        ]

        self.toc_patterns = [
            r"^Table of Contents\s*$",
            r"^\s*\d+(\.\d+)*\s+[A-Za-z].*\.\s*\d+\s*$",
            r"^\s*Appendix [A-Z]\..*\d+\s*$",
        ]

    def clean_document(self, text: str) -> str:
        """Clean RFC documents by removing headers, footers, TOC, and irrelevant sections"""
        lines = text.split("\n")
        cleaned_lines: List[str] = []
        in_skip_section = False
        in_toc = False

        skip_section_patterns = [
            r"^Table of Contents\s*$",
            r"^Acknowledgments?\s*$",
            r"^Acknowledgements?\s*$",
            r"^Author'?s'? Addresses?\s*$",
            r"^References\s*$",
            r"^\d+\.?\s*References\s*$",
            r"^\d+\.?\s*Normative References\s*$",
            r"^\d+\.?\s*Informative References\s*$",
            r"^Appendix\s+[A-Z]",
            r"^\d+\.?\s*Appendix",
            r"^Full Copyright Statement\s*$",
            r"^Copyright Statement\s*$",
            r"^Intellectual Property\s*$",
            r"^\d+\.?\s*IANA Considerations\s*$",
            r"^IANA Considerations\s*$",
            r"^\d+\.?\s*Security Considerations\s*$",
            r"^Security Considerations\s*$",
            r"^\d+\.?\s*Privacy Considerations\s*$",
            r"^Privacy Considerations\s*$",
        ]

        for _, line in enumerate(lines):
            stripped = line.strip()

            if re.match(r"^Table of Contents\s*$", stripped, re.IGNORECASE):
                in_toc = True
                continue

            if in_toc:
                if re.match(r"^\s+\d+(\.\d+)*\.?\s+", line):
                    continue
                elif stripped == "":
                    continue
                elif re.match(r"^\d+\.  [A-Z]", line):
                    in_toc = False
                elif re.match(r"^[A-Z][a-z]+", stripped) and len(stripped) < 40:
                    in_toc = False
                else:
                    continue

            if any(re.match(pattern, stripped, re.IGNORECASE) for pattern in skip_section_patterns):
                in_skip_section = True
                continue

            if in_skip_section:
                if re.match(r"^\d+\.  [A-Z]", line):
                    is_skip_section = any(re.match(pattern, stripped, re.IGNORECASE) for pattern in skip_section_patterns)
                    if not is_skip_section:
                        in_skip_section = False
                    else:
                        continue
                else:
                    continue

            is_header = any(re.match(pattern, line, re.IGNORECASE) for pattern in self.header_patterns)
            is_footer = any(re.match(pattern, line) for pattern in self.footer_patterns)
            is_toc_line = any(re.match(pattern, line) for pattern in self.toc_patterns)

            if not (is_header or is_footer or is_toc_line):
                cleaned_lines.append(line)

        return "\n".join(cleaned_lines)