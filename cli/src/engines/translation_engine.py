from __future__ import annotations
import json
import logging
import os
import re
from typing import Any, Optional
from ..models.finding import AudienceMode, NormalizedFinding, Translation
from ..prompts.audience_prompts import build_finding_prompt, get_system_prompt

logger = logging.getLogger(__name__)
DEFAULT_MODEL = os.getenv("TRANSLATOR_MODEL", "gemini-2.5-flash")
DEFAULT_MAX_TOKENS = int(os.getenv("TRANSLATOR_MAX_TOKENS", "4000"))


class TranslationEngine:
    def __init__(self, api_key=None, model=DEFAULT_MODEL, max_tokens=DEFAULT_MAX_TOKENS):
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self._api_key:
            raise ValueError("Gemini API key required. Set GEMINI_API_KEY environment variable.")
        self._client = self._init_client()

    def _init_client(self):
        try:
            from google import genai
            return genai.Client(api_key=self._api_key)
        except ImportError:
            raise ImportError("google-genai package not installed. Run: pip install google-genai")

    def translate(self, finding, audience, risk_score=None):
        system_prompt = get_system_prompt(audience)
        user_prompt = build_finding_prompt(finding, risk_score=risk_score)
        instruction_lines = [
            "YOU MUST respond with pure JSON only. Do not use markdown. Do not use code fences. Do not use backticks anywhere, including inside field values.",
            "FORMATTING RULES:",
            "- threat_scenario: write as a single string but separate each step with a real newline character (the two-character sequence backslash-n inside the JSON string). Do NOT number the steps inline in one paragraph. Do NOT use markdown numbering like 1. 2. 3. inside this field - just put each step on its own line separated by a newline.",
            "- remediation_steps: this is a JSON array. Each array item is ONE plain action sentence only. Do NOT start any item with a number like 1. or 2. Do NOT use markdown bold like **1.** Do NOT include any numbering or bold markup at the start of each item, since numbering is added automatically afterward. Just write the action directly, for example: Isolate the compromised instance by modifying its security group.",
        ]
        instruction = chr(10).join(instruction_lines)
        full_prompt = system_prompt + chr(10) + chr(10) + instruction + chr(10) + chr(10) + user_prompt
        try:
            from google.genai import types
            response = self._client.models.generate_content(
                model=self.model,
                contents=full_prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=self.max_tokens,
                    temperature=0.1,
                ),
            )
            raw_content = response.text
            parsed = self._parse_response(raw_content)
            return Translation(
                finding_id=finding.id,
                audience=audience,
                executive_summary=parsed.get("executive_summary", ""),
                technical_explanation=parsed.get("technical_explanation", ""),
                business_impact=parsed.get("business_impact", ""),
                threat_scenario=self._clean_field(parsed.get("threat_scenario", "")),
                risk_rating=parsed.get("risk_rating", ""),
                remediation_steps=[self._clean_step(s) for s in parsed.get("remediation_steps", [])],
                terraform_example=parsed.get("terraform_example"),
                aws_cli_example=parsed.get("aws_cli_example"),
                kubernetes_example=parsed.get("kubernetes_example"),
                policy_recommendation=parsed.get("policy_recommendation"),
                jira_ticket=parsed.get("jira_ticket"),
                model_used=self.model,
                prompt_tokens=0,
                completion_tokens=0,
            )
        except Exception as e:
            logger.error(f"Translation failed for finding {finding.id}: {e}")
            return Translation(
                finding_id=finding.id,
                audience=audience,
                executive_summary=f"Translation failed: {str(e)}",
                model_used=self.model,
            )

    def _clean_step(self, step):
        cleaned = step.strip()
        cleaned = re.sub(r"^\*\*\d+\.\s*", "", cleaned)
        cleaned = re.sub(r"^\d+\.\s*", "", cleaned)
        cleaned = re.sub(r"^\*\*", "", cleaned)
        cleaned = cleaned.strip()
        return cleaned

    def _clean_field(self, text):
        if not text:
            return text
        cleaned = re.sub(r"(\d+)\.\s+\*\*", r"PARABREAK\1. **", text)
        cleaned = re.sub(r"\.\s+(\d+)\.\s+", r".\nPARABREAK\1. ", cleaned)
        cleaned = cleaned.replace("PARABREAK", "")
        return cleaned.strip()

    def _parse_response(self, raw):
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            first_newline = cleaned.find(chr(10))
            if first_newline != -1:
                cleaned = cleaned[first_newline + 1:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            start = cleaned.find("{")
            end = cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(cleaned[start:end+1])
                except json.JSONDecodeError:
                    pass
            return {"executive_summary": raw, "technical_explanation": raw}
