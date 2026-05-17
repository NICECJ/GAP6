#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, Any, List


class RFCMetadataFilter:
    """RFC metadata filtering module"""

    def __init__(self):
        self.namespaces = {
            "rfc": "http://www.rfc-editor.org/rfc-index"
        }

    def extract_metadata_from_xml(self, xml_file: str) -> Dict[str, Any] | None:
        """Extract metadata from an RFC XML file"""
        try:
            with open(xml_file, "r", encoding="utf-8") as f:
                content = f.read()

            root = ET.fromstring(content)

            metadata: Dict[str, Any] = {
                "file": xml_file,
                "category": None,
                "stream": None,
                "obsoleted_by": None,
                "status": None,
                "rfc_number": None,
                "submissionType": None,
            }

            series_info = root.findall(".//front/seriesInfo")
            for info in series_info:
                name = info.get("name", "")
                value = info.get("value", "")

                if name == "RFC":
                    metadata["rfc_number"] = value
                elif name == "Internet-Draft":
                    metadata["status"] = "Draft"

            metadata["category"] = root.get("category", "")
            metadata["submissionType"] = root.get("submissionType", "")

            obsoleted_by = root.findall('.//seriesInfo[@name="Obsoleted-By"]')
            if obsoleted_by:
                metadata["obsoleted_by"] = obsoleted_by[0].get("value")

            boilerplate = root.find(".//boilerplate")
            if boilerplate is not None:
                text = ET.tostring(boilerplate, encoding="unicode", method="text")
                if "Historic" in text:
                    metadata["status"] = "Historic"
                elif "Standards Track" in text:
                    metadata["status"] = "Standards Track"
                elif "Informational" in text:
                    metadata["status"] = "Informational"
                elif "Experimental" in text:
                    metadata["status"] = "Experimental"
                elif "Best Current Practice" in text:
                    metadata["status"] = "Best Current Practice"

            if metadata["category"] and "std" in metadata["category"].lower():
                metadata["status"] = "Standards Track"

            if metadata["submissionType"]:
                metadata["stream"] = metadata["submissionType"]
            else:
                metadata["stream"] = "IETF"

            return metadata

        except Exception as e:
            print(f"  Warning: Failed to extract metadata - {e}")
            return None

    def should_process(self, metadata: Dict[str, Any] | None) -> tuple[bool, str]:
        """Determine whether the RFC document should be processed"""
        if not metadata:
            return False, "Failed to extract metadata"

        reasons: List[str] = []

        status = (metadata.get("status", "") or "").lower()
        category = (metadata.get("category", "") or "").lower()

        if "historic" in status:
            return False, "Status is Historic (deprecated)"

        if status and ("standards track" not in status) and ("std" not in category):
            reasons.append(f"Not Standards Track (current: {metadata.get('status', 'Unknown')})")

        stream = (metadata.get("stream", "") or "").upper()
        submission_type = (metadata.get("submissionType", "") or "").upper()

        if stream and ("IETF" not in stream) and submission_type and ("IETF" not in submission_type):
            reasons.append(f"Not IETF Stream (current: {stream or submission_type})")

        if metadata.get("obsoleted_by"):
            return False, f"Obsoleted by RFC {metadata['obsoleted_by']}"

        if reasons:
            return False, "; ".join(reasons)

        return True, "Pass filtering conditions"