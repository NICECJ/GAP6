#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import glob
import json
import os
from typing import List, Dict, Any

from config import (
    API_KEY,
    BASE_URL,
    MODEL,
    RFC_FOLDER,
    OUTPUT_DIR,
    MAX_FILES_TO_PROCESS,
    MAX_TOKENS,
    DOWNLOAD_START_RFC,
    DOWNLOAD_END_RFC,
    PROCESS_LOG_FILE,
    SKIP_ALREADY_ANALYZED_RFC,
    RETRY_FAILED_RFC,
)
from downloader import download_rfc_range
from metadata_filter import RFCMetadataFilter
from pipeline import RFCPipeline


def load_process_log(log_file: str) -> Dict[str, Any]:
    """Load process log from JSON file"""
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load process log '{log_file}': {e}")
            return {}
    return {}


def save_process_log(log_file: str, log_data: Dict[str, Any]) -> None:
    """Save process log to JSON file"""
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(log_data, f, indent=2, ensure_ascii=False)


def should_skip_rfc(rfc_file: str, process_log: Dict[str, Any]) -> tuple[bool, str]:
    """Determine whether an RFC file should be skipped based on process log"""
    if not SKIP_ALREADY_ANALYZED_RFC:
        return False, ""

    if rfc_file not in process_log:
        return False, ""

    record = process_log[rfc_file]
    status = record.get("status", "")

    if status in {"success_with_output", "success_no_output"}:
        return True, f"already analyzed: {status}"

    if status == "failed" and not RETRY_FAILED_RFC:
        return True, "previously failed"

    return False, ""


def main() -> None:
    print("Step 0: Downloading RFCs...")
    download_rfc_range(DOWNLOAD_START_RFC, DOWNLOAD_END_RFC, RFC_FOLDER)

    pipeline = RFCPipeline(
        api_key=API_KEY,
        base_url=BASE_URL,
        max_tokens=MAX_TOKENS,
        model=MODEL,
    )

    process_log = load_process_log(PROCESS_LOG_FILE)

    xml_files = glob.glob(f"{RFC_FOLDER}/*.xml")
    txt_files = glob.glob(f"{RFC_FOLDER}/*.txt")
    all_files = xml_files + txt_files

    if MAX_FILES_TO_PROCESS is not None and len(all_files) > MAX_FILES_TO_PROCESS:
        print(f"Note: Total files = {len(all_files)}; limiting to the first {MAX_FILES_TO_PROCESS}")
        all_files = all_files[:MAX_FILES_TO_PROCESS]

    if not all_files:
        print(f"Error: No RFC documents found in folder '{RFC_FOLDER}' (supported: .xml and .txt)")
        raise SystemExit(1)

    xml_count = len([f for f in all_files if f.endswith(".xml")])
    txt_count = len([f for f in all_files if f.endswith(".txt")])

    print(f"Found {len(all_files)} RFC documents (XML: {xml_count}, TXT: {txt_count})")
    print("=" * 80)

    print("\nStep 1: Pre-filtering...")

    filter_engine = RFCMetadataFilter()
    files_to_process: List[str] = []
    filtered_out: List[Dict[str, str]] = []

    for rfc_file in all_files:
        if rfc_file.endswith(".xml"):
            metadata = filter_engine.extract_metadata_from_xml(rfc_file)
            should_process, reason = filter_engine.should_process(metadata)
        else:
            should_process = True
            reason = "Plain-text file: metadata filtering skipped"

        if should_process:
            files_to_process.append(rfc_file)
        else:
            filtered_out.append({"file": rfc_file, "reason": reason})

    print(f"Filtering result: {len(files_to_process)}/{len(all_files)} passed | {len(filtered_out)} filtered")

    if not files_to_process:
        print("No documents to process")
        raise SystemExit(0)

    print(f"\nStep 2: Processing {len(files_to_process)} documents...")
    print("=" * 80)

    total_protocols = 0
    successful_rfcs: List[Dict[str, Any]] = []
    empty_rfcs: List[Dict[str, Any]] = []
    failed_rfcs: List[Dict[str, Any]] = []
    skipped_rfcs: List[Dict[str, Any]] = []

    actual_index = 0
    total_candidates = len(files_to_process)

    for rfc_file in files_to_process:
        skip, skip_reason = should_skip_rfc(rfc_file, process_log)
        if skip:
            print(f"\n[SKIP] {rfc_file} → {skip_reason}")
            skipped_rfcs.append({
                "file": rfc_file,
                "reason": skip_reason,
            })
            continue

        actual_index += 1
        print(f"\n[{actual_index}/{total_candidates}] {rfc_file}", end=" ")

        try:
            results = pipeline.process_rfc(
                rfc_file=rfc_file,
                output_dir=OUTPUT_DIR,
            )

            if results["protocols"]:
                print(f"→ ✓ Found {len(results['protocols'])} mechanisms")
                successful_rfcs.append({
                    "file": rfc_file,
                    "count": len(results["protocols"]),
                    "protocols": [p.get("name", "Unknown") for p in results["protocols"]],
                })
                total_protocols += len(results["protocols"])

                process_log[rfc_file] = {
                    "status": "success_with_output",
                    "output_file": results.get("output_file"),
                    "mechanism_count": len(results["protocols"]),
                }
                save_process_log(PROCESS_LOG_FILE, process_log)

            else:
                print("→ ○ No mechanisms found")
                empty_rfcs.append({
                    "file": rfc_file,
                    "summary": results.get("summary", "No usable mechanisms found"),
                })

                process_log[rfc_file] = {
                    "status": "success_no_output",
                    "output_file": None,
                    "mechanism_count": 0,
                    "summary": results.get("summary", "No usable mechanisms found"),
                }
                save_process_log(PROCESS_LOG_FILE, process_log)

        except Exception as e:
            print(f"→ ✗ Failed: {str(e)[:50]}")
            failed_rfcs.append({
                "file": rfc_file,
                "error": str(e),
            })

            process_log[rfc_file] = {
                "status": "failed",
                "error": str(e),
            }
            save_process_log(PROCESS_LOG_FILE, process_log)

    print("\n" + "=" * 80)
    print("Processing completed")
    print("=" * 80)
    print(f"Total documents: {len(all_files)} | Passed filtering: {len(files_to_process)}")
    print(
        f"Successful: {len(successful_rfcs)} | "
        f"No mechanisms: {len(empty_rfcs)} | "
        f"Failed: {len(failed_rfcs)} | "
        f"Skipped: {len(skipped_rfcs)}"
    )
    print(f"Total mechanisms extracted: {total_protocols}")

    if successful_rfcs:
        print(f"\n✓ Documents with extracted mechanisms ({len(successful_rfcs)}):")
        for rfc in successful_rfcs[:5]:
            print(f"  • {rfc['file']}: {rfc['count']} mechanisms")
        if len(successful_rfcs) > 5:
            print(f"  ... and {len(successful_rfcs) - 5} more documents")

    if empty_rfcs:
        print(f"\n○ Documents with no mechanisms ({len(empty_rfcs)}):")
        for rfc in empty_rfcs[:5]:
            print(f"  • {rfc['file']}")
        if len(empty_rfcs) > 5:
            print(f"  ... and {len(empty_rfcs) - 5} more documents")

    if failed_rfcs:
        print(f"\n✗ Failed documents ({len(failed_rfcs)}):")
        for rfc in failed_rfcs[:5]:
            print(f"  • {rfc['file']}: {rfc['error'][:50]}")
        if len(failed_rfcs) > 5:
            print(f"  ... and {len(failed_rfcs) - 5} more documents")

    if skipped_rfcs:
        print(f"\n→ Skipped documents ({len(skipped_rfcs)}):")
        for rfc in skipped_rfcs[:5]:
            print(f"  • {rfc['file']}: {rfc['reason']}")
        if len(skipped_rfcs) > 5:
            print(f"  ... and {len(skipped_rfcs) - 5} more documents")

    if filtered_out:
        print(f"\n○ Pre-filtered out: {len(filtered_out)} documents")

    print(f"\n✓ Output directory: {OUTPUT_DIR}/")
    print(f"✓ Process log: {PROCESS_LOG_FILE}")
    print("=" * 80)


if __name__ == "__main__":
    main()