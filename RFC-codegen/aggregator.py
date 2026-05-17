#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
import openai
from typing import Dict, Any, List, Tuple


class RFCAggregator:
    """Stage 2: RFC-level candidate aggregation and final selection"""

    def __init__(self, api_key: str, base_url: str | None = None, model: str = "gpt-3.5-turbo"):
        self.api_key = api_key
        self.model = model
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)

    def aggregate_candidates(self, rfc_file: str, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate chunk-level candidates into final RFC-level probing mechanisms"""
        candidates = self._deduplicate_candidates(candidates)
        candidates = self._filter_invalid_candidates(candidates)

        if not candidates:
            return {
                "has_protocols": False,
                "summary": "No usable IPv6 probing behaviors found",
                "protocols": [],
            }

        final_rules = self._llm_finalize_rules(rfc_file, candidates)

        if not final_rules:
            return {
                "has_protocols": False,
                "summary": "No usable IPv6 probing behaviors found",
                "protocols": [],
            }

        protocols: List[Dict[str, Any]] = []
        for rule in final_rules:
            if not isinstance(rule, dict):
                continue

            protocol_name = self._infer_protocol_name(rule)
            description = self._build_description(rule, protocol_name)

            protocols.append({
                "name": protocol_name,
                "description": description.strip(),
                "rule": {
                    "mechanism_name": rule.get("mechanism_name", ""),
                    "condition": rule.get("condition", ""),
                    "packet_flow": rule.get("packet_flow", ""),
                    "network_layer_protocol": rule.get("network_layer_protocol", ""),
                    "transport_layer_protocol": rule.get("transport_layer_protocol", ""),
                    "application_layer_protocol": rule.get("application_layer_protocol", ""),
                    "template_base": rule.get("template_base", ""),
                    "fields_to_modify": self._normalize_required_fields(
                        rule.get("fields_to_modify", {})
                    ),
                    "receive_filter": rule.get("receive_filter", ""),
                    "success_condition": rule.get("success_condition", ""),
                    "failure_condition": rule.get("failure_condition", ""),
                    "prerequisites": rule.get("prerequisites", []),
                    "rfc_sentence": rule.get("rfc_sentence", ""),
                    "confidence": rule.get("confidence", ""),
                    "source_chunks": rule.get("source_chunks", []),
                    "protocol": protocol_name,
                },
            })

        if not protocols:
            return {
                "has_protocols": False,
                "summary": "No usable IPv6 probing behaviors found",
                "protocols": [],
            }

        return {
            "has_protocols": True,
            "summary": f"Found {len(protocols)} usable IPv6 probing behavior(s)",
            "protocols": protocols,
        }

    def _deduplicate_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate obvious duplicate candidates before final aggregation"""
        unique_candidates: List[Dict[str, Any]] = []
        seen: set[Tuple[str, str, str, str, str, str]] = set()

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue

            key = (
                self._normalize_text(str(candidate.get("rfc_sentence", ""))),
                self._normalize_text(str(candidate.get("probe_packet", ""))),
                self._normalize_text(str(candidate.get("response_packet", ""))),
                self._normalize_text(str(candidate.get("network_layer_protocol", ""))),
                self._normalize_text(str(candidate.get("transport_layer_protocol", ""))),
                self._normalize_text(str(candidate.get("application_layer_protocol", ""))),
            )

            if key in seen:
                continue

            seen.add(key)
            unique_candidates.append(candidate)

        return unique_candidates

    def _filter_invalid_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out clearly invalid or unusable probing candidates"""
        filtered: List[Dict[str, Any]] = []

        for candidate in candidates:
            response_packet = str(candidate.get("response_packet", "")).strip().lower()
            template_base = str(candidate.get("template_base", "")).strip()
            rfc_sentence = str(candidate.get("rfc_sentence", "")).strip()

            if not response_packet or response_packet == "none":
                continue

            if not template_base:
                continue

            if not rfc_sentence:
                continue

            combined_text = " ".join([
                str(candidate.get("mechanism_name", "")),
                str(candidate.get("probe_goal", "")),
                str(candidate.get("condition", "")),
                str(candidate.get("probe_packet", "")),
                str(candidate.get("response_packet", "")),
                str(candidate.get("probing_value", "")),
                str(candidate.get("success_condition", "")),
                str(candidate.get("failure_condition", "")),
                rfc_sentence,
            ]).lower()

            invalid_markers = [
                "generate a new temporary address",
                "update a timer",
                "remove an address",
                "change local state",
                "record the packet",
                "silently discard",
                "address deprecation",
                "cache maintenance",
                "routing table",
                "local state update",
            ]

            if any(marker in combined_text for marker in invalid_markers):
                continue

            fields = self._normalize_required_fields(
                candidate.get("required_fields_to_modify", candidate.get("fields_to_modify", {}))
            )
            if (
                not fields["network_layer"]
                and not fields["transport_layer"]
                and not fields["application_layer"]
            ):
                continue

            filtered.append(candidate)

        return filtered

    def _llm_finalize_rules(self, rfc_file: str, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use LLM to merge, deduplicate, and finalize RFC-level probing mechanisms"""
        prompt = """You are performing RFC-level aggregation for IPv6 active probing rule extraction.

You are given a list of candidate probing mechanisms extracted from multiple chunks of the SAME RFC document.

Your task is to produce the FINAL RFC-LEVEL probing mechanisms in a format that is directly useful for a second LLM that will generate packet sending and receiving code.

IMPORTANT:
These candidates may contain:
- duplicates
- near-duplicates
- multiple variants derived from the same RFC sentence
- chunk-local misinterpretations
- service negotiation or session-dependent behaviors that are not suitable as practical probing methods
- mechanisms that are not robust enough for downstream packet send/receive code generation

Your job:
1. Remove duplicates and near-duplicates.
2. Merge candidates that come from the same RFC sentence and describe the same underlying probing behavior.
3. Do NOT split one RFC sentence into multiple hypothetical variants unless the RFC explicitly enumerates them as separate probing rules.
4. Keep only mechanisms that are suitable for downstream packet sending/receiving code generation.
5. Exclude mechanisms that are too session-dependent, too capability-negotiation-specific, or not practical as active IPv6 liveness probes.
6. Keep only rules where a probe packet can be sent to a target IPv6 address and a response packet can be observed and used to infer liveness or protocol responsiveness.
7. Convert the final result into a CODE-GENERATION-ORIENTED format.

STRICT EXCLUSION:
Exclude any candidate if:
- response_packet is NONE
- it mainly describes internal behavior
- it mainly describes address generation, timer updates, logging, or local state
- it is only a capability negotiation detail and not a practical probing mechanism
- it requires complex hidden session context and is not suitable for straightforward send/receive code generation
- it is only a chunk-local variant of another candidate from the same RFC sentence

When multiple candidates are derived from the same RFC sentence, prefer:
- the most general valid probing mechanism
- the version that is most directly useful for packet generation
- the version that best matches a standard send/receive packet template

VERY IMPORTANT OUTPUT REQUIREMENTS:
The final output will be consumed by another LLM that writes actual packet send/receive code.
Therefore:
- Be concrete.
- Prefer code-generation-friendly descriptions over abstract protocol analysis.
- Clearly identify the packet template base.
- Clearly identify which fields must be modified.
- Clearly identify the receive-side matching logic.
- Clearly identify success and failure conditions.
- Clearly identify prerequisites when the mechanism depends on connection state, session state, authentication state, or other context.
- If a mechanism is not practical without complex hidden session state, exclude it.

OUTPUT RULES:
- Output JSON list only.
- Do not output markdown.
- Do not output explanation outside JSON.
- Keep only final usable mechanisms.
- Do not output duplicate mechanisms.
- Prefer direct packet-construction and packet-matching language.

Output format:
[
  {
    "mechanism_name": "",
    "condition": "",
    "packet_flow": "",
    "network_layer_protocol": "",
    "transport_layer_protocol": "",
    "application_layer_protocol": "",
    "template_base": "",
    "fields_to_modify": {
      "network_layer": [],
      "transport_layer": [],
      "application_layer": []
    },
    "receive_filter": "",
    "success_condition": "",
    "failure_condition": "",
    "prerequisites": [],
    "rfc_sentence": "",
    "confidence": "",
    "source_chunks": []
  }
]

Field guidance:
- mechanism_name: short canonical name
- condition: exact condition for the response behavior
- packet_flow: short request-response form
- template_base: standard send-packet template name suitable for code generation
- fields_to_modify: concrete packet fields that must be set or changed
- receive_filter: what packet(s) the sniffer/receiver should match
- success_condition: exact observable packet behavior indicating success
- failure_condition: exact observable packet behavior indicating failure or inconclusive result
- prerequisites: list any required connection/session/protocol context; use [] if none
- confidence: use one of "high", "medium", "low"

If no final usable probing mechanisms remain, return exactly:
NONE

RFC file:
"""

        payload = {
            "rfc_file": rfc_file,
            "candidates": candidates,
        }

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a networking protocol expert with strong expertise in IPv6 active measurement, "
                            "RFC interpretation, deduplication of extracted rules, and practical packet-generation workflows. "
                            "You consolidate chunk-level candidates into final RFC-level probing mechanisms."
                        ),
                    },
                    {"role": "user", "content": prompt + json.dumps(payload, ensure_ascii=False, indent=2)},
                ],
                temperature=0.0,
            )

            content = (response.choices[0].message.content or "").strip()

            if content.strip().upper() == "NONE" or "NONE" in content[:20].upper():
                return []

            content = self._extract_json_array(content)

            rules = json.loads(content)
            if isinstance(rules, list):
                return rules

            return []

        except Exception as e:
            print(f"Aggregation failed: {e}")
            return []

    def _extract_json_array(self, content: str) -> str:
        """Extract the first complete JSON array from model output"""
        if "```json" in content:
            json_match = re.search(r"```json\s*(\[.*?\])\s*```", content, re.DOTALL)
            if json_match:
                return json_match.group(1)

        if "```" in content:
            json_match = re.search(r"```\s*(\[.*?\])\s*```", content, re.DOTALL)
            if json_match:
                return json_match.group(1)

        start = content.find("[")
        if start == -1:
            return content

        depth = 0
        in_string = False
        escape = False

        for i in range(start, len(content)):
            ch = content[i]

            if escape:
                escape = False
                continue

            if ch == "\\" and in_string:
                escape = True
                continue

            if ch == '"':
                in_string = not in_string
                continue

            if in_string:
                continue

            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    return content[start:i + 1]

        return content

    def _normalize_required_fields(self, fields: Any) -> Dict[str, List[str]]:
        """Normalize fields_to_modify into a stable structure"""
        normalized = {
            "network_layer": [],
            "transport_layer": [],
            "application_layer": [],
        }

        if not isinstance(fields, dict):
            return normalized

        for key in normalized.keys():
            value = fields.get(key, [])
            if isinstance(value, list):
                normalized[key] = [str(v) for v in value if str(v).strip()]
            elif isinstance(value, str) and value.strip():
                normalized[key] = [value.strip()]

        return normalized

    def _infer_protocol_name(self, rule: Dict[str, Any]) -> str:
        """Infer a compact protocol name for summary display"""
        app = str(rule.get("application_layer_protocol", "")).strip()
        transport = str(rule.get("transport_layer_protocol", "")).strip()
        network = str(rule.get("network_layer_protocol", "")).strip()

        if app and app.lower() != "none":
            return app
        if transport and transport.lower() != "none":
            return transport
        if network:
            return network
        return "Unknown Protocol"

    def _build_description(self, rule: Dict[str, Any], protocol_name: str) -> str:
        """Build code-generation-oriented description for final output"""
        prerequisites = rule.get("prerequisites", [])
        if not isinstance(prerequisites, list):
            prerequisites = [str(prerequisites)] if str(prerequisites).strip() else []

        return f"""Mechanism Name: {rule.get('mechanism_name', 'N/A')}

Protocol: {protocol_name}

Condition: {rule.get('condition', 'N/A')}

Packet Flow: {rule.get('packet_flow', 'N/A')}

Network Layer Protocol: {rule.get('network_layer_protocol', 'N/A')}

Transport Layer Protocol: {rule.get('transport_layer_protocol', 'N/A')}

Application Layer Protocol: {rule.get('application_layer_protocol', 'N/A')}

Template Base: {rule.get('template_base', 'N/A')}

Fields To Modify: {json.dumps(self._normalize_required_fields(rule.get('fields_to_modify', {})), ensure_ascii=False)}

Receive Filter: {rule.get('receive_filter', 'N/A')}

Success Condition: {rule.get('success_condition', 'N/A')}

Failure Condition: {rule.get('failure_condition', 'N/A')}

Prerequisites: {json.dumps(prerequisites, ensure_ascii=False)}

Confidence: {rule.get('confidence', 'N/A')}

RFC Sentence: {rule.get('rfc_sentence', 'N/A')}
"""

    def _normalize_text(self, text: str) -> str:
        """Normalize text for robust matching"""
        text = text.strip().lower()
        text = re.sub(r"\s+", " ", text)
        return text