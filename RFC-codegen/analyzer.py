#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import json
import openai
from typing import Dict, Any, List
from config import LLM_TEMPERATURE


class ProtocolAnalyzer:
    """Stage 1: LLM-based chunk-level candidate extraction for IPv6 probing"""

    def __init__(self, api_key: str, base_url: str | None = None, model: str = "gpt-3.5-turbo"):
        self.api_key = api_key
        self.model = model
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)

    def extract_candidate_rules(
        self,
        rfc_content: str,
        chunk_index: int,
        chunk_section: str,
    ) -> Dict[str, Any]:
        """Extract chunk-level probing candidates for downstream RFC-level aggregation"""
        try:
            rfc_content_clean = rfc_content.encode("ascii", errors="ignore").decode("ascii")
        except Exception:
            rfc_content_clean = rfc_content

        prompt = """You are a networking protocol expert analyzing RFC specifications for IPv6 active address probing and packet-generation workflow design.

Your task is to extract ONLY protocol behaviors that can be used for active IPv6 probing, where a prober sends a packet to a target IPv6 address and determines that the target is active/alive by observing a response packet.

IMPORTANT:
This is only a CHUNK-LEVEL candidate extraction step.
The final decision will be made later after candidates from all chunks of the same RFC are aggregated.
So in this step, extract plausible candidates conservatively, but still obey the filtering rules below.

STRICT INCLUSION RULES:
Include a rule ONLY if all of the following are true:
1. A prober can actively send a packet to a target IPv6 address.
2. The target is required or clearly expected by the RFC text to send a response packet over the network.
3. The response packet is externally observable by the prober.
4. Observing that response can help infer that the target IPv6 address, interface, or node is active, reachable, or protocol-responsive.
5. The RFC text explicitly describes the response behavior, or makes it directly explicit enough for packet construction without relying on external protocol knowledge.

STRICT EXCLUSION RULES:
Exclude any rule that involves:
- internal processing only
- local state updates
- timer updates
- address generation
- address deprecation
- address removal
- logging
- cache maintenance
- routing table changes
- local policy decisions without a response packet
- multicast housekeeping behavior that is not directly useful for probing a target
- silent discard behaviors
- any case where the response packet is NONE
- any case where the trigger/response pair is inferred mainly from external knowledge rather than explicit RFC text

CRITICAL JUDGMENT RULE:
Before including a rule, ask:
"Can a scanner send a concrete packet to a target IPv6 address based on this RFC text, and use a directly observable returned packet to infer that the target is active?"
- If YES, include it.
- If NO, exclude it.

For each valid candidate, output the following fields:

- mechanism_name
- probe_goal
- condition
- probe_packet
- response_packet
- packet_flow
- network_layer_protocol
- transport_layer_protocol
- application_layer_protocol
- template_base
- required_fields_to_modify
- receive_filter
- success_condition
- failure_condition
- probing_value
- rfc_sentence
- confidence

IMPORTANT OUTPUT RULES:
- Output JSON list only.
- Do not output markdown.
- Do not output explanation outside JSON.
- If response_packet is NONE, exclude the rule.
- If the mechanism cannot be mapped to a standard send/receive code template, exclude it.
- If the RFC text does not make the response packet sufficiently explicit, exclude it.

Output format:

[
  {
    "mechanism_name": "",
    "probe_goal": "",
    "condition": "",
    "probe_packet": "",
    "response_packet": "",
    "packet_flow": "",
    "network_layer_protocol": "",
    "transport_layer_protocol": "",
    "application_layer_protocol": "",
    "template_base": "",
    "required_fields_to_modify": {
      "network_layer": [],
      "transport_layer": [],
      "application_layer": []
    },
    "receive_filter": "",
    "success_condition": "",
    "failure_condition": "",
    "probing_value": "",
    "rfc_sentence": "",
    "confidence": ""
  }
]

If the section contains no usable candidate, return exactly:
NONE

RFC Section:
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a networking protocol expert with 20 years of experience in IETF standards, "
                            "IPv6 protocol analysis, and active network measurement. "
                            "You specialize in extracting chunk-level candidate probing behaviors that may later be "
                            "aggregated into final RFC-level probing mechanisms."
                        ),
                    },
                    {"role": "user", "content": prompt + rfc_content_clean},
                ],
                temperature=LLM_TEMPERATURE,
            )

            content = (response.choices[0].message.content or "").strip()

            if content.strip().upper() == "NONE" or "NONE" in content[:20].upper():
                return {
                    "has_candidates": False,
                    "summary": "No usable candidate probing behaviors found",
                    "candidates": [],
                }

            content = self._extract_json_array(content)

            try:
                rules = json.loads(content)
            except json.JSONDecodeError as e:
                print(f"JSON parsing failed: {e}")
                return {
                    "has_candidates": False,
                    "summary": f"Failed to parse JSON response: {str(e)}",
                    "candidates": [],
                }

            if not rules:
                return {
                    "has_candidates": False,
                    "summary": "No usable candidate probing behaviors found",
                    "candidates": [],
                }

            if not isinstance(rules, list):
                return {
                    "has_candidates": False,
                    "summary": "Model output is not a JSON list",
                    "candidates": [],
                }

            candidates: List[Dict[str, Any]] = []

            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                if not self._is_valid_rule(rule):
                    continue

                normalized_rule = {
                    "mechanism_name": rule.get("mechanism_name", ""),
                    "probe_goal": rule.get("probe_goal", ""),
                    "condition": rule.get("condition", ""),
                    "probe_packet": rule.get("probe_packet", ""),
                    "response_packet": rule.get("response_packet", ""),
                    "packet_flow": rule.get("packet_flow", ""),
                    "network_layer_protocol": rule.get("network_layer_protocol", ""),
                    "transport_layer_protocol": rule.get("transport_layer_protocol", ""),
                    "application_layer_protocol": rule.get("application_layer_protocol", ""),
                    "template_base": rule.get("template_base", ""),
                    "required_fields_to_modify": self._normalize_required_fields(
                        rule.get("required_fields_to_modify", {})
                    ),
                    "receive_filter": rule.get("receive_filter", ""),
                    "success_condition": rule.get("success_condition", ""),
                    "failure_condition": rule.get("failure_condition", ""),
                    "probing_value": rule.get("probing_value", ""),
                    "rfc_sentence": rule.get("rfc_sentence", ""),
                    "confidence": rule.get("confidence", ""),
                    "chunk_index": chunk_index,
                    "chunk_section": chunk_section,
                }

                candidates.append(normalized_rule)

            if not candidates:
                return {
                    "has_candidates": False,
                    "summary": "No usable candidate probing behaviors found",
                    "candidates": [],
                }

            return {
                "has_candidates": True,
                "summary": f"Found {len(candidates)} candidate probing behavior(s)",
                "candidates": candidates,
            }

        except Exception as e:
            print(f"Analysis failed: {e}")
            return {
                "has_candidates": False,
                "summary": f"Analysis failed: {str(e)}",
                "candidates": [],
            }

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
        """Normalize required_fields_to_modify into a stable structure"""
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

    def _is_valid_rule(self, rule: Dict[str, Any]) -> bool:
        """Apply lightweight post-filtering to reduce clearly invalid outputs"""
        response_packet = str(rule.get("response_packet", "")).strip().lower()
        template_base = str(rule.get("template_base", "")).strip()
        rfc_sentence = str(rule.get("rfc_sentence", "")).strip()

        if not response_packet or response_packet == "none":
            return False

        if not template_base:
            return False

        if not rfc_sentence:
            return False

        invalid_markers = [
            "generate a new temporary address",
            "update a timer",
            "remove an address",
            "change local state",
            "record the packet",
            "silently discard",
        ]

        combined_text = " ".join(
            [
                str(rule.get("probe_goal", "")),
                str(rule.get("condition", "")),
                str(rule.get("probe_packet", "")),
                str(rule.get("response_packet", "")),
                str(rule.get("probing_value", "")),
                rfc_sentence,
            ]
        ).lower()

        if any(marker in combined_text for marker in invalid_markers):
            return False

        fields = self._normalize_required_fields(rule.get("required_fields_to_modify", {}))
        if (
            not fields["network_layer"]
            and not fields["transport_layer"]
            and not fields["application_layer"]
        ):
            return False

        return True