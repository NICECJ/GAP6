#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import json
import openai
import re
from typing import List, Dict, Any, Optional

class RFCCandidateClassifier:
    """
    中间层：对聚合后的探测机制进行语义分类和深度去重。
    """

    def __init__(self, api_key: str, base_url: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.model = model

    def classify_and_deduplicate(self, protocols: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not protocols:
            return []

        print(f"  [Classifier] 正在处理 {len(protocols)} 个机制...")
        
        unique_mechanisms = []
        seen_fingerprints = set()

        for proto in protocols:
            # 获取结构化的指纹
            fingerprint = self._get_logic_fingerprint(proto)
            
            # 这里的 Key 包含了协议层级和逻辑指纹
            # 如果逻辑指纹相同，就认为是重复的
            logic_key = (
                str(proto['rule'].get('network_layer_protocol', '')).lower(),
                str(proto['rule'].get('transport_layer_protocol', '')).lower(),
                fingerprint.lower().strip()
            )

            if logic_key not in seen_fingerprints:
                seen_fingerprints.add(logic_key)
                proto['logic_fingerprint'] = fingerprint
                unique_mechanisms.append(proto)
            else:
                # 打印日志方便查看哪些被去重了
                print(f"  [Classifier] 发现并过滤重复: {proto.get('name')} -> 匹配指纹: {fingerprint}")

        return unique_mechanisms

    def _get_logic_fingerprint(self, protocol_dict: Dict[str, Any]) -> str:
        """
        强化版 Prompt：强制 LLM 归纳核心逻辑，忽略文字润色差异。
        """
        # 提取关键字段，减少干扰
        rule = protocol_dict.get('rule', {})
        fields = json.dumps(rule.get('fields_to_modify', {}))
        
        prompt = f"""分析以下 IPv6 探测机制，输出一个极简的“逻辑指纹”。
核心规则：
1. 忽略所有描述性的文字差异。
2. 专注于：修改了哪个协议字段 + 触发了哪个响应报文。
3. 格式必须为：字段名_触发动作_响应类型。

待分析数据：
- 机制名: {protocol_dict.get('name')}
- 修改字段: {fields}
- 成功条件: {rule.get('success_condition')}
- 响应报文: {rule.get('receive_filter')}

示例输出：
HopLimit_1_ICMPv6TimeExceeded
FlowLabel_Modified_NoResponse
ExtensionHeader_Unknown_ICMPv6ParameterProblem

只输出指纹，不要解释。"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0, # 必须为 0 保证一致性
            )
            content = response.choices[0].message.content.strip()
            # 移除可能存在的引号或句号
            return re.sub(r'[.\"\']', '', content)
        except Exception as e:
            print(f"  [Classifier] LLM 请求失败: {e}")
            return f"fallback_{protocol_dict.get('name')}"