#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import datetime
import time

from config import REQUEST_INTERVAL, ENABLE_REQUEST_INTERVAL
from pathlib import Path
from typing import List, Dict, Any

from rfc_parser import RFCXMLParser
from cleaner import RFCDocumentCleaner
from splitter import RFCDocumentSplitter
from analyzer import ProtocolAnalyzer
from aggregator import RFCAggregator
from classifier import RFCCandidateClassifier


class RFCPipeline:
    """Complete RFC processing pipeline with two-stage extraction"""

    def __init__(self, api_key: str, base_url: str | None = None, max_tokens: int = 6000, model: str = "gpt-3.5-turbo"):
        self.xml_parser = RFCXMLParser()
        self.cleaner = RFCDocumentCleaner()
        self.splitter = RFCDocumentSplitter(max_tokens=max_tokens)
        self.analyzer = ProtocolAnalyzer(api_key, base_url, model)
        self.aggregator = RFCAggregator(api_key, base_url, model)
        self.classifier = RFCCandidateClassifier(api_key, base_url, model)

    def load_rfc(self, file_path: str) -> str:
        """Load RFC document and automatically detect format"""
        path = Path(file_path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        if path.suffix.lower() == ".xml" or content.strip().startswith("<?xml") or content.strip().startswith("<rfc"):
            cleaned_content = self.xml_parser.parse_xml(content)
        else:
            cleaned_content = self.cleaner.clean_document(content)

        return cleaned_content

    def process_rfc(self, rfc_file: str, output_dir: str = "./output") -> Dict[str, Any]:
        """Run the complete two-stage RFC processing workflow with classification"""
        text = self.load_rfc(rfc_file)

        if self.splitter.count_tokens(text) > self.splitter.max_tokens:
            chunks = self.splitter.split_by_sections(text)
        else:
            chunks = [{
                "section": "Full Document",
                "content": text,
                "tokens": self.splitter.count_tokens(text),
            }]

        all_candidates: List[Dict[str, Any]] = []

        for i, chunk in enumerate(chunks):
            result = self.analyzer.extract_candidate_rules(
                rfc_content=chunk["content"],
                chunk_index=i,
                chunk_section=chunk["section"],
            )

            if ENABLE_REQUEST_INTERVAL and REQUEST_INTERVAL > 0:
                time.sleep(REQUEST_INTERVAL)

            if result.get("candidates"):
                all_candidates.extend(result["candidates"])

        # 第一阶段聚合：将分片结果合并
        aggregated_result = self.aggregator.aggregate_candidates(
            rfc_file=rfc_file,
            candidates=all_candidates,
        )

        if ENABLE_REQUEST_INTERVAL and REQUEST_INTERVAL > 0:
            time.sleep(REQUEST_INTERVAL)

        raw_protocols = aggregated_result.get("protocols", [])
        rfc_summary = aggregated_result.get("summary", "No usable IPv6 probing behaviors found")

        # --- 新增步骤：使用 Classifier 进行逻辑去重 ---
        if raw_protocols:
            print(f"  [Pipeline] 原始提取机制数量: {len(raw_protocols)}")
            final_protocols = self.classifier.classify_and_deduplicate(raw_protocols)
            print(f"  [Pipeline] 去重后有效机制数量: {len(final_protocols)}")
            # 更新 summary 信息
            if len(final_protocols) != len(raw_protocols):
                rfc_summary = f"Found {len(final_protocols)} unique mechanisms (deduplicated from {len(raw_protocols)})"
        else:
            final_protocols = []
        # ------------------------------------------

        if not final_protocols:
            return {
                "rfc_file": rfc_file,
                "summary": rfc_summary,
                "protocols": [],
                "output_file": None,
            }

        os.makedirs(output_dir, exist_ok=True)

        rfc_basename = os.path.splitext(os.path.basename(rfc_file))[0]
        output_filename = f"{output_dir}/{rfc_basename}.txt"

        # 返回去重后的结果
        results = {
            "rfc_file": rfc_file,
            "summary": rfc_summary,
            "protocols": final_protocols,
            "output_file": output_filename,
        }

        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(f"RFC Document: {rfc_file}\n")
            f.write(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Analysis Summary (Deduplicated):\n{rfc_summary}\n\n")
            f.write("=" * 80 + "\n\n")

            for i, protocol in enumerate(final_protocols):
                protocol_name = protocol.get("name", "Unknown")
                protocol_desc = protocol.get("description", "")
                # 如果分类器提取了指纹，也可以写入文件方便调试
                fingerprint = protocol.get("logic_fingerprint", "N/A")

                f.write(f"Mechanism {i + 1}: {protocol_name}\n")
                f.write(f"Logic Fingerprint: {fingerprint}\n") # 可选：记录逻辑指纹
                f.write("-" * 80 + "\n")
                f.write(protocol_desc)
                f.write("\n\n" + "=" * 80 + "\n\n")

        return results