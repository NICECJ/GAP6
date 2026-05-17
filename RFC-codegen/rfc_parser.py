#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import List


class RFCXMLParser:
    """Parser for XML-format RFC documents"""

    def __init__(self):
        self.namespaces = {
            "rfc": "http://www.rfc-editor.org/rfc-index"
        }

    def parse_xml(self, xml_content: str) -> str:
        """Parse RFC XML and extract plain text content"""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            xml_content = re.sub(r"<\?xml[^>]+\?>", "", xml_content)
            root = ET.fromstring(xml_content)

        text_parts: List[str] = []

        title = root.find(".//title")
        if title is not None and title.text:
            text_parts.append(f"# {title.text}\n")

        skip_sections = {
            "table of contents",
            "acknowledgments",
            "acknowledgements",
            "author's address",
            "authors' addresses",
            "references",
            "normative references",
            "informative references",
            "appendix",
            "full copyright statement",
            "copyright statement",
            "intellectual property",
            "iana considerations",
        }

        # Only process top-level sections to avoid duplicate extraction.
        # Child sections are handled recursively inside _extract_section().
        top_sections = self._get_top_level_sections(root)

        for section in top_sections:
            section_title = (section.get("title") or section.get("name") or "").lower().strip()

            if any(skip in section_title for skip in skip_sections):
                continue

            if section_title.startswith("appendix"):
                continue

            section_text = self._extract_section(section)
            if section_text:
                text_parts.append(section_text)

        return "\n\n".join(text_parts)

    def _get_top_level_sections(self, root) -> List:
        """Get only top-level body/middle sections to avoid duplicate traversal"""
        top_sections: List = []

        # RFC XML usually stores main content under <middle>
        middle = root.find("./middle")
        if middle is not None:
            for child in middle:
                if child.tag == "section":
                    top_sections.append(child)

        # Fallback for uncommon XML layouts
        if not top_sections:
            for child in root:
                if child.tag == "section":
                    top_sections.append(child)

        # Final fallback: if structure is unusual, use all sections once
        # This is less ideal, but prevents complete parsing failure.
        if not top_sections:
            top_sections = root.findall(".//section")

        return top_sections

    def _extract_section(self, section, level: int = 1) -> str:
        """Recursively extract section content"""
        parts: List[str] = []

        title = section.get("title") or section.get("name")
        anchor = section.get("anchor", "")

        if title:
            section_num = section.get("numbered", "true") == "true"
            if section_num and anchor:
                match = re.match(r"section-(\d+(?:\.\d+)*)", anchor)
                if match:
                    parts.append(f"\n{'#' * level} {match.group(1)} {title}\n")
                else:
                    parts.append(f"\n{'#' * level} {title}\n")
            else:
                parts.append(f"\n{'#' * level} {title}\n")

        for elem in section:
            if elem.tag == "t":
                text = self._extract_text(elem)
                if text:
                    parts.append(text)

            elif elem.tag == "figure":
                continue

            elif elem.tag == "artwork":
                continue

            elif elem.tag == "ul" or elem.tag == "ol":
                list_text = self._extract_list(elem)
                if list_text:
                    parts.append(list_text)

            elif elem.tag == "section":
                subsection_text = self._extract_section(elem, level + 1)
                if subsection_text:
                    parts.append(subsection_text)

        return "\n".join(parts)

    def _extract_text(self, elem) -> str:
        """Extract all text inside an XML element"""
        text_parts = [elem.text or ""]

        for child in elem:
            text_parts.append(child.text or "")
            text_parts.append(child.tail or "")

        text_parts.append(elem.tail or "")

        return " ".join(text_parts).strip()

    def _extract_list(self, list_elem) -> str:
        """Extract list items"""
        items: List[str] = []
        for li in list_elem.findall("li"):
            text = self._extract_text(li)
            if text:
                prefix = "- " if list_elem.tag == "ul" else f"{len(items) + 1}. "
                items.append(f"{prefix}{text}")

        return "\n".join(items) if items else ""