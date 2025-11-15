"""
Digital Forensics Tool — Central Analysis Engine
Developer: Leen & Haila
Version: 3.0 (Professional Edition)

This module:
- Reads files safely
- Runs forensic analysis
- Uses the SUPER ForensicAnalyzer (from core/analyzer.py)
- Integrates PDF report generator
- Returns unified results to GUI (app.py)
"""

import os
import traceback
from datetime import datetime
from typing import Dict, Any

from core.analyzer import ForensicAnalyzer
from core.file_handlers import FileHandlers
from reportgen import PDFReportGenerator


# ============================================================
# 🔧 وظيفة تحليل كاملة (تستخدمها الواجهة + run_analysis + PDF)
# ============================================================
def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    تحليل ملف واحد وإرجاع جميع النتائج في Dict واحد:
    {
        "basic_analysis": {...},
        "suspicious_items": [...],
        "advanced_stats": {...},
        "analysis_time": float,
        "file_path": "...",
        "full_text_report": "...",
    }
    """

    start_time = datetime.now()
    analyzer = ForensicAnalyzer()
    file_reader = FileHandlers()

    try:
        # -------------------------------
        # 1) قراءة الملف
        # -------------------------------
        read_result = file_reader.read(file_path)
        if read_result.get("error"):
            return {
                "error": read_result["error"],
                "file_path": file_path
            }

        content = read_result["text"]

        # -------------------------------
        # 2) التحليل الأساسي
        # -------------------------------
        basic = analyzer.analyze_basic(content)

        # -------------------------------
        # 3) البحث عن الأنماط (النسخة المتقدمة بالعربي)
        # -------------------------------
        suspicious = analyzer.search_suspicious_patterns(content)

        # -------------------------------
        # 4) التحليل الإحصائي المتقدم
        # -------------------------------
        advanced_stats = analyzer.advanced_statistical_analysis(content)

        # -------------------------------
        # 5) الوقت المستغرق للتحليل
        # -------------------------------
        analysis_time = (datetime.now() - start_time).total_seconds()

        # -------------------------------
        # 6) بناء تقرير نصي منسّق (للعرض في الواجهة + حفظ txt)
        # -------------------------------
        full_report_text = build_text_report(
            file_path=file_path,
            basic=basic,
            suspicious=suspicious,
            stats=advanced_stats,
            analysis_time=analysis_time
        )

        return {
            "file_path": file_path,
            "basic_analysis": basic,
            "suspicious_items": suspicious,
            "advanced_stats": advanced_stats,
            "analysis_time": analysis_time,
            "full_text_report": full_report_text
        }

    except Exception as e:
        return {
            "error": f"Unexpected analysis error: {e}",
            "trace": traceback.format_exc(),
            "file_path": file_path
        }


# ============================================================
#  منشئ تقرير نصي منسق (للواجهة + الحفظ)
# ============================================================
def build_text_report(file_path: str,
                      basic: Dict[str, Any],
                      suspicious: Dict[str, Any],
                      stats: Dict[str, Any],
                      analysis_time: float) -> str:

    lines = []
    lines.append("╔" + "═" * 68 + "╗")
    lines.append("║ 🛡  Digital Forensics Report - Professional Edition  ║")
    lines.append("╚" + "═" * 68 + "╝")
    lines.append(f"📁 File: {file_path}")
    lines.append(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"⏱️  Analysis Time: {analysis_time:.2f} sec")
    lines.append("─" * 70)

    # ========== Basic ==========
    lines.append("📊 BASIC ANALYSIS:")
    lines.append(f"   • Total Lines: {basic.get('total_lines', 0)}")
    lines.append(f"   • Errors: {basic.get('errors', 0)}")
    lines.append(f"   • Warnings: {basic.get('warnings', 0)}")
    lines.append(f"   • Info Events: {basic.get('info_events', 0)}")
    lines.append("─" * 70)

    # ========== Suspicious ==========
    if suspicious:
        lines.append("⚠️  SUSPICIOUS ACTIVITIES DETECTED:")
        for item in suspicious:
            lines.append(f"\n{item['risk_icon']} {item['risk_level']}")
            lines.append(f"   • Name: {item['name']}")
            lines.append(f"   • Count: {item['count']}")
            lines.append(f"   • Description: {item['description']}")
            lines.append(f"   • Category: {item['category']}")
            if item.get("examples"):
                lines.append(f"   • Examples: {', '.join(item['examples'])}")
    else:
        lines.append("✅ No suspicious patterns detected.")
    lines.append("─" * 70)

    # ========== Advanced Stats ==========
    lines.append("📈 ADVANCED ANALYSIS:")
    for section, data in stats.items():
        lines.append(f"\n🔹 {section.replace('_', ' ')}:")
        for k, v in data.items():
            lines.append(f"   • {k.replace('_', ' ')}: {v}")

    lines.append("─" * 70)
    lines.append("🏁 END OF REPORT")
    lines.append("╚" + "═" * 68 + "╝")
    return "\n".join(lines)


# ============================================================
#  واجهة توليد PDF — تُستخدم من app.py
# ============================================================
def generate_pdf_report(result_dict: Dict[str, Any]) -> str:
    """
    ينشئ تقرير PDF من نتائج التحليل.
    - يستخدم PDFReportGenerator
    - يرجع مسار الملف المُنشأ
    """
    try:
        pdf = PDFReportGenerator()
        return pdf.generate_pdf(result_dict)
    except Exception as e:
        return f"PDF generation failed: {e}"
