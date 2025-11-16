# reportgen.py
# -*- coding: utf-8 -*-

import os
from datetime import datetime
from typing import Dict, Any, List
import arabic_reshaper
from bidi.algorithm import get_display

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.colors import Color, white, cyan

import tkinter as tk
from tkinter import filedialog


# ============ Arabic Fix ============
def fix_ar(text: str) -> str:
    """Fix Arabic for correct PDF rendering."""
    try:
        reshaped = arabic_reshaper.reshape(text)
        bidi_text = get_display(reshaped)
        return bidi_text
    except:
        return text


class PDFReportGenerator:

    def __init__(self):
        # Register Amiri font (must exist in project folder)
        self.font_name = "ArabicFont"
        try:
            pdfmetrics.registerFont(TTFont("ArabicFont", "Amiri-Regular.ttf"))
        except Exception:
            self.font_name = "Helvetica"

        self.bg = Color(0.06, 0.08, 0.12)

        # Styles
        self.title = ParagraphStyle("title", fontName=self.font_name,
                                    fontSize=22, alignment=1,
                                    textColor=cyan, leading=28)

        self.section = ParagraphStyle("section", fontName=self.font_name,
                                      fontSize=18, alignment=2,
                                      textColor=cyan, leading=26)

        self.normal = ParagraphStyle("normal", fontName=self.font_name,
                                     fontSize=14, alignment=2,
                                     textColor=white, leading=22)

        self.small = ParagraphStyle("small", fontName=self.font_name,
                                    fontSize=12, alignment=2,
                                    textColor=white, leading=18)

        self.good = ParagraphStyle("good", fontName=self.font_name,
                                   fontSize=14, alignment=2,
                                   textColor=Color(0, 1, 0.4),
                                   leading=22)

        self.warn = ParagraphStyle("warn", fontName=self.font_name,
                                   fontSize=14, alignment=2,
                                   textColor=Color(1, 0.8, 0),
                                   leading=22)

        self.center = ParagraphStyle("center", fontName=self.font_name,
                                     fontSize=14, alignment=1,
                                     textColor=white, leading=20)

    # ============ Background + Footer ============
    def _decorate(self, canv, doc):
        # background
        canv.saveState()
        canv.setFillColor(self.bg)
        canv.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
        canv.restoreState()

        # footer
        canv.saveState()
        canv.setFont(self.font_name, 10)
        w, h = A4
        canv.setFillColor(white)
        canv.drawCentredString(w / 2, 25, fix_ar("© 2025 — تقرير التحليل الجنائي الرقمي"))
        canv.drawCentredString(w / 2, 12, fix_ar("جامعة القصيم — برنامج الأمن السيبراني"))
        canv.restoreState()

    # ============ Main PDF Builder ============
    def generate_pdf(self, results: Dict[str, Any], filename: str = None):

        # Save dialog
        if filename is None:
            root = tk.Tk()
            root.withdraw()
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF", "*.pdf")],
                initialfile="Digital_Forensics_Report.pdf",
            )
            root.destroy()

        if not filename:
            return ""

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            leftMargin=45, rightMargin=45,
            topMargin=70, bottomMargin=50,
        )

        basic = results.get("basic_analysis", {})
        suspicious = results.get("suspicious_items", [])
        adv = results.get("advanced_stats", [])
        file_path = results.get("file_path", "")
        file_name = os.path.basename(file_path) if file_path else "غير معروف"

        story: List[Any] = []

        # ========= Title =========
        story.append(Paragraph(fix_ar("تقرير التحليل الجنائي الرقمي"), self.title))
        story.append(Spacer(1, 20))

        story.append(Paragraph(fix_ar(f"اسم الملف: {file_name}"), self.small))
        story.append(Paragraph(fix_ar(f"تاريخ التقرير: {datetime.now().strftime('%Y-%m-%d %H:%M')}"), self.small))
        story.append(Spacer(1, 20))

        # ========= Summary =========
        story.append(Paragraph(fix_ar("ملخص مبسط"), self.section))
        story.append(Spacer(1, 12))

        if suspicious:
            story.append(Paragraph(fix_ar("تم العثور على إشارات قد تكون مرتبطة بسلوك غير طبيعي داخل الملف."), self.normal))
            story.append(Paragraph(fix_ar("ننصح بمراجعة التحليل بالتفصيل في الأقسام التالية."), self.normal))
        else:
            story.append(Paragraph(fix_ar("لم يتم العثور على نشاطات غير طبيعية داخل الملف."), self.normal))
            story.append(Paragraph(fix_ar("يبدو الملف سليمًا ويمكن استخدامه بشكل اعتيادي."), self.normal))

        story.append(Spacer(1, 18))

        # ========= Risk =========
        if adv:
            risk_text = "مستوى الخطر: مرتفع (80%)"
        elif suspicious:
            risk_text = "مستوى الخطر: متوسط (50%)"
        else:
            risk_text = "مستوى الخطر: منخفض (10%)"

        story.append(Paragraph(fix_ar(risk_text), self.normal))
        story.append(Spacer(1, 22))

        # ========= Quick Summary =========
        story.append(Paragraph(fix_ar("الملخص السريع"), self.section))
        story.append(Spacer(1, 10))

        story.append(Paragraph(fix_ar(f"• عدد الأسطر: {basic.get('total_lines', 0)}"), self.normal))
        story.append(Paragraph(fix_ar(f"• الأخطاء: {basic.get('errors', 0)}"), self.normal))
        story.append(Paragraph(fix_ar(f"• التحذيرات: {basic.get('warnings', 0)}"), self.normal))
        story.append(Paragraph(fix_ar(f"• معلومات: {basic.get('info_events', 0)}"), self.normal))
        story.append(Spacer(1, 18))

        # ========= Suspicious =========
        story.append(Paragraph(fix_ar("التهديدات المكتشفة"), self.section))
        story.append(Spacer(1, 10))

        if suspicious:
            for item in suspicious:
                story.append(Paragraph(fix_ar(f"• {item['name']} — مرات الظهور: {item['count']}"), self.normal))
                if item.get("desc"):
                    story.append(Paragraph(fix_ar(f"الوصف: {item['desc']}"), self.small))
                story.append(Spacer(1, 12))
        else:
            story.append(Paragraph(fix_ar("لا توجد تهديدات مكتشفة."), self.good))
            story.append(Spacer(1, 16))

        # ========= Advanced =========
        story.append(Paragraph(fix_ar("الإحصائيات المتقدمة"), self.section))
        story.append(Spacer(1, 10))

        if adv:
            for item in adv:
                story.append(Paragraph(fix_ar(f"• النوع: {item['type']}"), self.normal))
                story.append(Paragraph(fix_ar(f"- التفاصيل: {item['detail']}"), self.small))
                story.append(Paragraph(fix_ar(f"- العدد: {item['count']}"), self.small))
                story.append(Paragraph(fix_ar(f"- مستوى الخطورة: {item['risk']}"), self.small))
                story.append(Spacer(1, 14))
        else:
            story.append(Paragraph(fix_ar("لا توجد نتائج تحليلية متقدمة."), self.normal))

        story.append(Spacer(1, 26))
        story.append(Paragraph(fix_ar("تم اكتمال التحليل."), self.center))

        # build
        doc.build(story, onFirstPage=self._decorate, onLaterPages=self._decorate)

        return filename
