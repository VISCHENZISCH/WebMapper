#!/usr/bin/env python3
# coding:utf-8
import json as json_lib
from datetime import datetime


def generate(data: dict, filepath: str):
    """Génère un rapport JSON à partir des findings unifiés."""
    output = {
        "generated_at": datetime.now().isoformat(),
        "tool": "WebMapper v2.0",
        "total": data.get("total", 0),
        "summary": data.get("summary", {}),
        "findings": data.get("findings", []),
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json_lib.dump(output, fh, ensure_ascii=False, indent=2)
