# core/analyzer.py
# -*- coding: utf-8 -*-
"""
Forensic analyzer: basic + pattern search logic.
يتعامل مع مخرجات FileHandlers.read(...) ويعطي نتائج قابلة للطباعة أو الاستخدام لاحقاً.
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional

# قواعد افتراضية بسيطة (يمكن توسيعها لاحقاً أو تحميلها من JSON)
DEFAULT_RULES = {
    "high": [
        {"name": "Ransomware", "pattern": r"\bransomware\b", "score": 10, "desc": "برمجية فدية"},
        {"name": "SQL Injection", "pattern": r"\bsql\s+injection\b", "score": 10, "desc": "محاولة حقن SQL"}
    ],
    "medium": [
        {"name": "Malware", "pattern": r"\bmalware\b", "score": 5, "desc": "برامج ضارة"},
        {"name": "Unauthorized Access", "pattern": r"\bunauthorized\b|\bunauthorized\s+access\b", "score": 5, "desc": "وصول غير مصرح به"},
        {"name": "Failed Login", "pattern": r"\bfailed\s+login\b|\blogin\s+failed\b", "score": 5, "desc": "محاولات دخول فاشلة"}
    ],
    "low": [
        {"name": "Warning", "pattern": r"\bwarning\b", "score": 1, "desc": "تحذير نظام"},
        {"name": "Timeout", "pattern": r"\btimeout\b", "score": 1, "desc": "انتهاء مهلة اتصال"}
    ]
}


class ForensicAnalyzer:
    def __init__(self, rules: Optional[Dict[str, List[Dict[str, Any]]]] = None):
        self.rules = rules if rules is not None else DEFAULT_RULES

    def analyze_basic(self, text: str) -> Dict[str, Any]:
        """تحليل أساسي — أحصاء أسطر / أخطاء / تحذيرات / معلومات"""
        lines = text.splitlines()
        errors = sum(1 for l in lines if re.search(r'\berror\b', l, re.IGNORECASE))
        warnings = sum(1 for l in lines if re.search(r'\bwarning\b', l, re.IGNORECASE))
        infos = sum(1 for l in lines if re.search(r'\binfo\b', l, re.IGNORECASE))
        return {
            "total_lines": len(lines),
            "errors": errors,
            "warnings": warnings,
            "info_events": infos,
            "timestamp": datetime.now().isoformat()
        }

    def search_patterns(self, text: str) -> List[Dict[str, Any]]:
        """بحث عن الأنماط بحسب القواعد — يرتّب النتائج حسب النقاط (score*count) تنازلياً."""
        found = []
        for level in ("high", "medium", "low"):
            for rule in self.rules.get(level, []):
                try:
                    matches = re.findall(rule["pattern"], text, flags=re.IGNORECASE)
                except re.error:
                    matches = []
                if matches:
                    entry = {
                        "level": level,
                        "name": rule.get("name"),
                        "pattern": rule.get("pattern"),
                        "count": len(matches),
                        "score": rule.get("score", 1),
                        "desc": rule.get("desc", "")
                    }
                    found.append(entry)
        # ترتيب حسب الأهمية (score * count)
        found.sort(key=lambda e: e["score"] * e["count"], reverse=True)
        return found

    def summarize(self, basic: Dict[str, Any], patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """ترجيع ملخص منظم جاهز للطباعة أو للتصدير"""
        total_score = sum(p["score"] * p["count"] for p in patterns)
        if total_score >= 20:
            overall = "HIGH"
            action = "Immediate response required"
        elif total_score >= 10:
            overall = "MEDIUM"
            action = "Continuous monitoring suggested"
        else:
            overall = "LOW"
            action = "Normal - no urgent action"
        return {
            "basic": basic,
            "patterns": patterns,
            "total_score": total_score,
            "overall_level": overall,
            "recommended_action": action
        }

    def analyze(self, text: str) -> Dict[str, Any]:
        """دمج التحليل الأساسي، البحث عن الأنماط، وإنشاء الملخص"""
        basic = self.analyze_basic(text)
        patterns = self.search_patterns(text)
        summary = self.summarize(basic, patterns)
        return summary
