# core/analyzer.py
# -*- coding: utf-8 -*-
import re
from datetime import datetime
from typing import Dict, List, Any, Optional

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
        found.sort(key=lambda e: e["score"] * e["count"], reverse=True)
        return found

    def summarize(self, basic: Dict[str, Any], patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
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

    # --- دالة التحليل الذكي والمتقدم ---
    def advanced_analysis(self, text: str) -> List[Dict[str, Any]]:
        """تحليل متقدم: كشف أنماط الشبكة والمحاولات المتكررة"""
        # مثال بسيط: اكتشاف IP مكرر ومحاولات مشبوهة
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        suspicious_ips = {}
        for ip in ips:
            suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

        # مثال آخر: اكتشاف محاولات SQL Injection
        sql_pattern = r"(select\s+.*from|union\s+select|drop\s+table)"
        sql_matches = re.findall(sql_pattern, text, re.IGNORECASE)

        result = []

        # إضافة الأحداث المشبوهة من IP
        for ip, count in suspicious_ips.items():
            if count > 1:
                result.append({
                    "type": "Suspicious IP",
                    "detail": ip,
                    "count": count,
                    "risk": "medium"
                })

        # إضافة أحداث SQL Injection
        if sql_matches:
            result.append({
                "type": "SQL Injection Attempt",
                "detail": f"{len(sql_matches)} potential attacks",
                "count": len(sql_matches),
                "risk": "high"
            })

        return result
