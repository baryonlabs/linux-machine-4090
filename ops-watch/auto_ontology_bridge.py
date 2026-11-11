#!/usr/bin/env python3
"""NVIDIA Auto-Ontology Bridge for ops-watch.

Integrates ops-watch with NVIDIA Auto-Ontology (https://github.com/NVIDIA/auto-ontology):
- Connects to Auto-Ontology REST / FastMCP gateway when available.
- Falls back gracefully to local semantic model (ontology.json).
- Exports operational knowledge into Apache Ossie / Auto-Ontology model format.
"""

from __future__ import annotations

import json
import os
import pathlib
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

ONTOLOGY_PATH = pathlib.Path(__file__).with_name("ontology.json")
ROOT_DIR = pathlib.Path(__file__).parent
DEFAULT_API_URL = os.environ.get("AUTO_ONTOLOGY_API_URL", "http://localhost:3000")
DEFAULT_API_TOKEN = os.environ.get("AUTO_ONTOLOGY_API_TOKEN", "")


class AutoOntologyBridge:
    def __init__(self, api_url: str = DEFAULT_API_URL, api_token: str = DEFAULT_API_TOKEN):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token

    def _request(self, endpoint: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
        url = f"{self.api_url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["x-api-key"] = self.api_token
            headers["Authorization"] = f"Bearer {self.api_token}"

        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            return None

    def check_connection(self) -> Dict[str, Any]:
        """Check if remote NVIDIA Auto-Ontology is reachable and compiled."""
        status = self._request("/api/semantic-compilation/status")
        if status is not None:
            return {"connected": True, "type": "remote-auto-ontology", "status": status}

        # Check alternative health endpoint
        health = self._request("/api/health")
        if health is not None:
            return {"connected": True, "type": "remote-auto-ontology-health", "status": health}

        return {
            "connected": False,
            "type": "local-fallback",
            "message": f"NVIDIA Auto-Ontology at {self.api_url} is unreachable; operating with local semantic model."
        }

    def load_local_ontology(self) -> Dict[str, Any]:
        """Load local semantic ontology."""
        if ONTOLOGY_PATH.exists():
            try:
                return json.loads(ONTOLOGY_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def get_terms(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch glossary terms from Auto-Ontology or fallback to local ontology."""
        # Try remote Auto-Ontology first if connected
        remote = self._request(f"/api/terms?search={urllib.parse.quote(search)}" if search else "/api/terms")
        if isinstance(remote, list):
            return remote
        if isinstance(remote, dict) and "items" in remote:
            return remote["items"]

        # Local fallback
        local = self.load_local_ontology()
        terms = local.get("terms", [])
        if search:
            q = search.lower()
            return [t for t in terms if q in t.get("name", "").lower() or any(q in s.lower() for s in t.get("synonyms", []))]
        return terms

    def export_ossie_model(self) -> Dict[str, Any]:
        """Export local ontology as an Apache Ossie / Auto-Ontology semantic model."""
        local = self.load_local_ontology()
        model_dict = {
            "name": local.get("metadata", {}).get("name", "ops-watch-model"),
            "version": local.get("metadata", {}).get("version", "1.4.0"),
            "description": local.get("metadata", {}).get("description", ""),
            "terms": [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "synonyms": t.get("synonyms", [])
                }
                for t in local.get("terms", [])
            ],
            "relationships": local.get("relationships", []),
            "decision_policies": local.get("decision_policy", {}),
            "incident_signals": local.get("incident_signals", [])
        }

        ossie_spec = ROOT_DIR / "auto-ontology" / "llm_finetuning_ossie_model.json"
        if ossie_spec.exists():
            try:
                spec_data = json.loads(ossie_spec.read_text(encoding="utf-8"))
                model_dict["datasets"] = spec_data.get("datasets", [])
                model_dict["metrics"] = spec_data.get("metrics", [])
                model_dict["ai_context"] = spec_data.get("ai_context", {})
            except Exception:
                pass

        return {
            "$schema": "https://ossie.apache.org/schemas/model.json",
            "model": model_dict
        }


if __name__ == "__main__":
    bridge = AutoOntologyBridge()
    conn = bridge.check_connection()
    print("Auto-Ontology Status:", json.dumps(conn, indent=2, ensure_ascii=False))
    terms = bridge.get_terms()
    print(f"Loaded {len(terms)} semantic term(s).")
