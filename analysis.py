# analysis.py
"""
Digital Forensics Tool — Central Analysis Engine
Developer: Leen & Haila
Version: 4.0 (Professional + Risk Engine)
"""

import traceback
from datetime import datetime
from typing import Dict, Any

from core.analyzer import ForensicAnalyzer
from core.file_handlers import FileHandlers


# ==========================================================
# 🔥 نظام تقييم الخطورة (LOW - MEDIUM - HIGH)
# ==========================================================
def calculate_risk_level(basic, suspicious, stats):
    score = 0

    # بناءً على الأخطاء والتحذيرات
    score += basic.get("errors", 0) * 3
    score += basic.get("warnings", 0) * 1

    # بناءً على الأنماط المشبوهة
    for item in suspicious:
        score += item.get("score", 0)

    # بناءً على التحليل المتقدم
    for item in stats:
        if item.get("risk", "").lower() == "high":
            score += 5
        elif item.get("risk", "").lower() == "medium":
            score += 2

    # مستوى الخطورة
    if score <= 5:
        level = "LOW"
        bar = "🟩🟩🟩🟩🟩⬜⬜⬜⬜⬜"
    elif 6 <= score <= 15:
        level = "MEDIUM"
        bar = "🟩🟩🟩🟨🟨⬜⬜⬜⬜⬜"
    else:
        level = "HIGH"
        bar = "🟥🟥🟥🟥🟥🟧🟧⬜⬜⬜"

    return level, score, bar


# ==========================================================
def analyze_file(file_path: str) -> Dict[str, Any]:
    start_time = datetime.now()
    analyzer = ForensicAnalyzer()
    reader = FileHandlers()

    try:
        read_result = reader.read(file_path)
        if read_result.get("error"):
            return {"error": read_result["error"], "file_path": file_path}

        content = read_result["text"]

        basic = analyzer.analyze_basic(content)
        suspicious = analyzer.search_patterns(content)
        advanced_stats = analyzer.advanced_analysis(content)

        analysis_time = (datetime.now() - start_time).total_seconds()

        risk_level, risk_score, risk_bar = calculate_risk_level(
            basic, suspicious, advanced_stats
        )

        return {
            "file_path": file_path,
            "basic_analysis": basic,
            "suspicious_items": suspicious,
            "advanced_stats": advanced_stats,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "risk_bar": risk_bar,
            "analysis_time": analysis_time,
            "text_report": "See PDF for complete report."
        }

    except Exception as e:
        return {
            "error": f"Unexpected analysis error: {e}",
            "trace": traceback.format_exc(),
            "file_path": file_path
        }
