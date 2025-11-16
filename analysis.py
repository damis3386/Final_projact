# analysis.py
"""
Digital Forensics Tool — Central Analysis Engine
Developer: Leen & Haila
Version: 3.0 (Professional Edition)
"""

import traceback
from datetime import datetime
from typing import Dict, Any

from core.analyzer import ForensicAnalyzer
from core.file_handlers import FileHandlers
from reportgen import PDFReportGenerator


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    تحليل ملف واحد وإرجاع جميع النتائج في Dict واحد.
    """

    start_time = datetime.now()
    analyzer = ForensicAnalyzer()
    reader = FileHandlers()

    try:
        # قراءة الملف
        read_result = reader.read(file_path)
        if read_result.get("error"):
            return {
                "error": read_result["error"],
                "file_path": file_path
            }

        content = read_result["text"]

        # التحليل الأساسي
        basic = analyzer.analyze_basic(content)

        # أنماط مشبوهة (الدالة الموجودة في analyzer.py)
        suspicious = analyzer.search_patterns(content)

        # التحليل المتقدم
        advanced_stats = analyzer.advanced_analysis(content)

        analysis_time = (datetime.now() - start_time).total_seconds()

        # نص التقرير
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
            "full_text_report": full_report_text,
            "text_report": full_report_text,  # تستخدمه الواجهة و reportgen
        }

    except Exception as e:
        return {
            "error": f"Unexpected analysis error: {e}",
            "trace": traceback.format_exc(),
            "file_path": file_path
        }


def build_text_report(
    file_path: str,
    basic: Dict[str, Any],
    suspicious,
    stats,
    analysis_time: float
) -> str:
    """تقرير نصي بسيط للعرض داخل الواجهة."""
    lines = []
    lines.append("╔" + "═" * 68 + "╗")
    lines.append("║ 🛡  Digital Forensics Report - Professional Edition  ║")
    lines.append("╚" + "═" * 68 + "╝")
    lines.append(f"📁 File: {file_path}")
    lines.append(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"⏱  Analysis Time: {analysis_time:.2f} sec")
    lines.append("─" * 70)

    lines.append("📊 BASIC ANALYSIS:")
    lines.append(f"   • Total Lines: {basic.get('total_lines', 0)}")
    lines.append(f"   • Errors: {basic.get('errors', 0)}")
    lines.append(f"   • Warnings: {basic.get('warnings', 0)}")
    lines.append(f"   • Info Events: {basic.get('info_events', 0)}")
    lines.append("─" * 70)

    if suspicious:
        lines.append("⚠  SUSPICIOUS ACTIVITIES:")
        for item in suspicious:
            lines.append(f"\n[ {item.get('name', '')} ]")
            lines.append(f"   • Count: {item.get('count', 0)}")
            lines.append(f"   • Description: {item.get('desc', '')}")
            lines.append(f"   • Pattern: {item.get('pattern', '')}")
            lines.append(f"   • Score: {item.get('score', 0)}")
    else:
        lines.append("✅ No suspicious patterns detected.")
    lines.append("─" * 70)

    lines.append("📈 ADVANCED ANALYSIS:")
    if stats:
        for entry in stats:
            lines.append(f"\n- Type: {entry.get('type','')}")
            lines.append(f"  • Detail: {entry.get('detail','')}")
            lines.append(f"  • Count: {entry.get('count','')}")
            lines.append(f"  • Risk: {entry.get('risk','')}")
    else:
        lines.append("No advanced suspicious behavior detected.")

    lines.append("─" * 70)
    lines.append("🏁 END OF REPORT")
    lines.append("╚" + "═" * 68 + "╝")

    return "\n".join(lines)


def generate_pdf_report(result_dict: Dict[str, Any]) -> str:
    """واجهة بسيطة لاستدعاء مولّد الـ PDF."""
    pdf = PDFReportGenerator()
    return pdf.generate_pdf(result_dict)
