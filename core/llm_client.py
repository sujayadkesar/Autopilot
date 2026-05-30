"""
LLMClient — generic local-LLM interface.

Model spec format: "ollama:<model_name>"
Examples: ollama:phi3:mini  ollama:llama3:8b  ollama:qwen2.5:7b

v1 ships Ollama only. Backend is selected from the prefix, keeping the door
open for future: llamacpp:model  lmstudio:model
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from .case_context import CaseContext
from .finding import Finding

log = logging.getLogger("dfir.llm")

OLLAMA_TIMEOUT = 300
DEFAULT_MAX_TOKENS = 800
DATA_TRUNCATE = 3500


@dataclass
class AnalysisResult:
    summary: str = ""
    findings_raw: List[Dict[str, Any]] = None  # type: ignore[assignment]
    iocs: List[str] = None  # type: ignore[assignment]
    risk_score: int = 0

    def __post_init__(self):
        if self.findings_raw is None:
            self.findings_raw = []
        if self.iocs is None:
            self.iocs = []


@dataclass
class EvidenceRef:
    finding_title: str
    csv_path: Path
    row_indices: List[int]
    highlight_columns: List[str]


class OllamaBackend:
    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base = base_url.rstrip("/")
        self._verified_model: Optional[str] = None

    def health_check(self) -> tuple[bool, str]:
        """
        Returns (ok, error_message).
        Validates both Ollama connectivity AND that the requested model is pulled.
        """
        try:
            r = requests.get(f"{self.base}/api/tags", timeout=5)
        except Exception as e:
            return False, f"Ollama is not reachable at {self.base}: {e}\nRun: ollama serve"

        if not r.ok:
            return False, f"Ollama returned HTTP {r.status_code}"

        models = [m["name"] for m in r.json().get("models", [])]
        if not models:
            return False, (
                "Ollama is running but has no models pulled.\n"
                f"Pull your model: ollama pull {self.model}"
            )

        # Exact match
        if self.model in models:
            self._verified_model = self.model
            log.info("Ollama: model '%s' ready", self.model)
            return True, ""

        # Prefix match (e.g. "phi3:mini" → "phi3:mini:latest" or "phi3:latest")
        prefix = self.model.split(":")[0]
        prefix_match = next((m for m in models if m.startswith(prefix)), None)
        if prefix_match:
            log.warning("Ollama: model '%s' not found, using '%s'", self.model, prefix_match)
            self._verified_model = prefix_match
            self.model = prefix_match
            return True, ""

        available = ", ".join(models[:8]) + ("..." if len(models) > 8 else "")
        return False, (
            f"Model '{self.model}' is not pulled in Ollama.\n"
            f"Available: {available}\n"
            f"Pull it with: ollama pull {self.model}"
        )

    def ask(self, system_prompt: str, user_prompt: str, max_tokens: int = DEFAULT_MAX_TOKENS) -> str:
        payload = {
            "model": self._verified_model or self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": 0.1,
                "top_p": 0.9,
            },
        }
        try:
            r = requests.post(f"{self.base}/api/generate", json=payload, timeout=OLLAMA_TIMEOUT)
            if r.ok:
                return r.json().get("response", "").strip()
            log.warning(f"Ollama HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log.warning(f"Ollama ask failed: {e}")
        return ""


class LLMClient:
    def __init__(self, model_spec: str, ctx: CaseContext, ollama_base: str = "http://localhost:11434"):
        # Parse "ollama:phi3:mini" → backend="ollama", model="phi3:mini"
        parts = model_spec.split(":", 1)
        backend = parts[0].lower() if len(parts) > 1 else "ollama"
        model = parts[1] if len(parts) > 1 else model_spec

        if backend == "ollama":
            self._backend = OllamaBackend(model, base_url=ollama_base)
        else:
            raise ValueError(f"Unknown LLM backend '{backend}'. Supported: ollama")

        self._ctx = ctx

    def health_check(self) -> tuple[bool, str]:
        """Returns (ok, error_message). Checks Ollama connectivity + model availability."""
        return self._backend.health_check()

    @staticmethod
    def validate_model_spec(model_spec: str, ollama_base: str = "http://localhost:11434") -> tuple[bool, str]:
        """
        Standalone validation — usable without a full CaseContext.
        Returns (ok, error_message).
        """
        if not model_spec or not model_spec.strip():
            return False, "LLM model is required (e.g. ollama:phi3:mini)."
        parts = model_spec.strip().split(":", 1)
        backend = parts[0].lower()
        model = parts[1] if len(parts) > 1 else model_spec
        if backend != "ollama":
            return False, f"Unknown backend '{backend}'. Only 'ollama:' is supported (e.g. ollama:phi3:mini)."
        return OllamaBackend(model, base_url=ollama_base).health_check()

    def _base_system_prompt(self, agent_name: str) -> str:
        prompt = (
            "You are a senior Windows DFIR analyst. You are reviewing a forensic image.\n\n"
            "STRICT RULES — violating any of these is worse than returning []:\n"
            "1. ONLY flag entries that are GENUINELY suspicious based on concrete evidence in the data.\n"
            "2. DO NOT flag: system32 paths, Windows-signed executables, svchost, lsass, standard services,\n"
            "   Microsoft scheduled tasks, common software (Office, Chrome, Adobe, Defender).\n"
            "3. REQUIRE specifics: cite the EXACT path, hash, value, or timestamp from the data.\n"
            "4. Severities: CRITICAL=active malware/rootkit, HIGH=strong IOC/persistence,\n"
            "   MEDIUM=suspicious but possibly legitimate, LOW=noteworthy anomaly.\n"
            "5. If data looks normal for a Windows system — return an empty findings list.\n"
            "6. Maximum 5 findings per call. Quality over quantity.\n"
            "7. Output ONLY valid JSON — no markdown, no explanation outside JSON.\n"
        )
        if self._ctx.investigation_prompt:
            prompt += (
                f"\nINVESTIGATION BRIEF (prioritise findings relevant to this):\n"
                f"{self._ctx.investigation_prompt[:600]}\n"
            )
        prompt += f"\nAgent analysing: {agent_name}"
        return prompt

    def analyze_chunk(
        self,
        agent_name: str,
        artifact_name: str,
        data: Any,
        schema_hint: str = "default",
    ) -> AnalysisResult:
        if not data:
            return AnalysisResult(summary="No data available.")

        data_str = json.dumps(data, indent=2, default=str)
        if len(data_str) > DATA_TRUNCATE:
            data_str = data_str[:DATA_TRUNCATE] + "\n...(truncated)"

        system = self._base_system_prompt(agent_name)
        user = (
            f"Artifact: {artifact_name}\n\n"
            f"DATA:\n{data_str}\n\n"
            "Return ONLY this JSON structure (no text before or after):\n"
            "{\n"
            '  "summary": "1-sentence factual overview of what this data shows",\n'
            '  "findings": [\n'
            '    {"severity":"HIGH","title":"Concise title","detail":"Exact evidence: specific path/value/timestamp from data","ioc":"exact IOC value or empty string"}\n'
            "  ],\n"
            '  "iocs": [],\n'
            '  "risk_score": 0\n'
            "}\n\n"
            "findings[] must contain ONLY real anomalies with specific evidence. "
            "ioc must be a concrete value (path/hash/IP/domain/serial) or \"\". "
            "Return findings:[] if nothing is suspicious. risk_score is 0-100."
        )

        response = self._backend.ask(system, user, max_tokens=DEFAULT_MAX_TOKENS)
        return self._parse_analysis(response)

    def _parse_analysis(self, response: str) -> AnalysisResult:
        if not response:
            return AnalysisResult(summary="LLM unavailable.")
        try:
            parsed = json.loads(response)
        except Exception:
            match = re.search(r"\{[\s\S]*\}", response)
            if match:
                try:
                    parsed = json.loads(match.group())
                except Exception:
                    return AnalysisResult(summary=response[:300])
            else:
                return AnalysisResult(summary=response[:300])
        return AnalysisResult(
            summary=str(parsed.get("summary", "")),
            findings_raw=parsed.get("findings", []),
            iocs=parsed.get("iocs", []),
            risk_score=int(parsed.get("risk_score", 0)),
        )

    def executive_summary(
        self,
        all_findings: List[Finding],
        system_info: dict,
        agents_run: List[str],
    ) -> str:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            if f.severity in counts:
                counts[f.severity] += 1

        computer = system_info.get("ComputerName", "Unknown")
        os_name = system_info.get("os_info", {}).get("ProductName", "Windows")

        system = (
            "You are a senior forensic analyst writing an executive summary for a legal/investigative report.\n"
            "Be factual, professional, and clear. Base your summary ONLY on the provided findings data.\n"
            "Plain text only. No JSON. No markdown."
        )
        if self._ctx.investigation_prompt:
            system += f"\n\nCASE CONTEXT:\n{self._ctx.investigation_prompt}"

        top = [f.to_dict() for f in sorted(all_findings, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x.severity,99))[:30]]
        user = (
            f"Customer: {self._ctx.customer_name}\n"
            f"Computer: {computer} | OS: {os_name}\n"
            f"Agents run: {', '.join(agents_run)}\n"
            f"Findings — CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, "
            f"MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']}\n\n"
            f"Top findings:\n{json.dumps(top, indent=2, default=str)[:4000]}\n\n"
            "Write a 3-4 paragraph executive summary for a forensic report covering:\n"
            "1. Overall risk level and assessment\n"
            "2. Key findings (be specific with values/paths/names)\n"
            "3. Recommended immediate actions"
        )
        return self._backend.ask(system, user, max_tokens=700) or "Executive summary unavailable (LLM not reachable)."

    def select_evidence(
        self,
        findings: List[Finding],
        parsed_files: List[Path],
    ) -> List[EvidenceRef]:
        """Ask LLM which CSV files / columns contain the strongest evidence."""
        high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        if not high or not parsed_files:
            return []

        file_list = "\n".join(f"  {p.name}" for p in parsed_files[:30])
        finding_list = json.dumps([{"severity": f.severity, "title": f.title, "ioc": f.ioc} for f in high[:20]], indent=2)

        system = "You are a forensic analyst. Given a list of high-severity findings and available CSV files, identify which files are most relevant evidence. Return JSON only."
        user = (
            f"High-severity findings:\n{finding_list}\n\n"
            f"Available parsed files:\n{file_list}\n\n"
            'Return JSON: {"evidence": [{"finding_title": "...", "file": "filename.csv", "columns_to_highlight": ["col1","col2"]}]}'
        )
        response = self._backend.ask(system, user, max_tokens=600)
        refs: List[EvidenceRef] = []
        try:
            parsed_r = json.loads(response)
            for item in parsed_r.get("evidence", []):
                fname = item.get("file", "")
                matched = next((p for p in parsed_files if p.name == fname), None)
                if matched:
                    refs.append(EvidenceRef(
                        finding_title=item.get("finding_title", ""),
                        csv_path=matched,
                        row_indices=[],
                        highlight_columns=item.get("columns_to_highlight", []),
                    ))
        except Exception:
            pass
        return refs
