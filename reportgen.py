# reportgen.py
# -*- coding: utf-8 -*-

import os
from datetime import datetime
from typing import Dict, Any, List
import arabic_reshaper
from bidi.algorithm import get_display

from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import Color, white

import tkinter as tk
from tkinter import filedialog


# ------------- Arabic Fix -------------
def fix_ar(text: str) -> str:
    return get_display(arabic_reshaper.reshape(str(text)))


class PDFReportGenerator:

    def __init__(self):

        pdfmetrics.registerFont(TTFont("ArabicFont", "Amiri-Regular.ttf"))
        self.font_name = "ArabicFont"

        # Colors
        self.page_bg = Color(0.06, 0.08, 0.12)
        self.cyan = Color(0.0, 1.0, 1.0)
        self.green = Color(0.2, 1.0, 0.4)
        self.orange = Color(1.0, 0.6, 0.2)
        self.red = Color(1.0, 0.2, 0.2)
        self.dark_blue = Color(0.1, 0.15, 0.30)
        self.dark_green = Color(0.0, 0.25, 0.0)

        # Text Styles
        self.style_title = ParagraphStyle(
            name="title", fontName=self.font_name,
            fontSize=24, alignment=1, textColor=self.cyan, leading=30
        )
        self.style_section = ParagraphStyle(
            name="section", fontName=self.font_name,
            fontSize=18, alignment=2, textColor=self.cyan, leading=26
        )
        self.style_normal = ParagraphStyle(
            name="normal", fontName=self.font_name,
            fontSize=14, alignment=2, textColor=white, leading=22
        )
        self.style_small = ParagraphStyle(
            name="small", fontName=self.font_name,
            fontSize=12, alignment=2, textColor=white, leading=18
        )
        self.style_center = ParagraphStyle(
            name="center", fontName=self.font_name,
            fontSize=14, alignment=1, textColor=white, leading=24
        )
        self.style_table_header = ParagraphStyle(
            name="header", fontName=self.font_name,
            fontSize=13, alignment=1, textColor=white, leading=18
        )
        self.style_table_cell = ParagraphStyle(
            name="cell", fontName=self.font_name,
            fontSize=12, alignment=1, textColor=white, leading=16
        )

    # Background fill
    def _draw_background(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(self.page_bg)
        canvas.rect(0, 0, A4[0], A4[1], fill=True)
        canvas.restoreState()

    # ------------ Main PDF Builder ------------
    def generate_pdf(self, results: Dict[str, Any], filename: str = None):

        if filename is None:
            root = tk.Tk()
            root.withdraw()
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf")],
                initialfile="Digital_Forensics_Report.pdf"
            )
            root.destroy()

        if not filename:
            return ""

        doc = SimpleDocTemplate(
            filename, pagesize=A4,
            leftMargin=40, rightMargin=40, topMargin=60, bottomMargin=40
        )

        story: List[Any] = []

        basic = results.get("basic_analysis", {})
        suspicious = results.get("suspicious_items", [])
        stats = results.get("advanced_stats", {})

        file_name = os.path.basename(results.get("file_path", ""))
        date_str = datetime.now().strftime("%Y-%m-%d  %H:%M")

        # ------------ Title Page ------------
        story.append(Paragraph(fix_ar("تقرير التحليل الجنائي الرقمي"), self.style_title))
        story.append(Spacer(1, 20))
        story.append(Paragraph(fix_ar(f"اسم الملف: {file_name}"), self.style_small))
        story.append(Paragraph(fix_ar(f"تاريخ التقرير: {date_str}"), self.style_small))
        story.append(Spacer(1, 25))

        # ------------ Summary ------------
        story.append(Paragraph(fix_ar("ملخص مبسط"), self.style_section))
        story.append(Spacer(1, 10))

        if suspicious:
            story.append(Paragraph(fix_ar("تم العثور على إشارات قد تكون مرتبطة بسلوك غير طبيعي داخل الملف."), self.style_normal))
            story.append(Paragraph(fix_ar("ننصح بمراجعة التحليل بالتفصيل في الأقسام التالية."), self.style_normal))
        else:
            story.append(Paragraph(fix_ar("لم يتم العثور على نشاطات غير طبيعية داخل الملف."), self.style_normal))
            story.append(Paragraph(fix_ar("يبدو الملف سليمًا ويمكن استخدامه بشكل اعتيادي."), self.style_normal))

        story.append(Spacer(1, 25))

        # ------------ Quick Stats ------------
        story.append(Paragraph(fix_ar("الملخص السريع"), self.style_section))
        story.append(Spacer(1, 10))
        story.append(Paragraph(fix_ar(f"• عدد الأسطر: {basic.get('total_lines', 0)}"), self.style_normal))
        story.append(Paragraph(fix_ar(f"• الأخطاء: {basic.get('errors', 0)}"), self.style_normal))
        story.append(Paragraph(fix_ar(f"• التحذيرات: {basic.get('warnings', 0)}"), self.style_normal))
        story.append(Paragraph(fix_ar(f"• معلومات: {basic.get('info_events', 0)}"), self.style_normal))
        story.append(Spacer(1, 30))

        # ------------ THREATS TABLE ------------
        story.append(Paragraph(fix_ar("التهديدات المكتشفة"), self.style_section))
        story.append(Spacer(1, 10))

        if suspicious:

            # HEADER — reversed order (الوصف يسار - اسم التهديد يمين)
            table_data = [[
                Paragraph(fix_ar("الوصف"), self.style_table_header),
                Paragraph(fix_ar("درجة الخطورة"), self.style_table_header),
                Paragraph(fix_ar("مرات الظهور"), self.style_table_header),
                Paragraph(fix_ar("اسم التهديد"), self.style_table_header)
            ]]

            # DATA ROWS — reversed
            for item in suspicious:

                level = item.get("level", "").lower()
                color = (
                    self.green if level == "low" else
                    self.orange if level == "medium" else
                    self.red
                )

                risk_style = ParagraphStyle(
                    name="risk_style",
                    fontName=self.font_name,
                    fontSize=12,
                    alignment=1,
                    textColor=color
                )

                table_data.append([
                    Paragraph(fix_ar(item.get("desc", "")), self.style_table_cell),
                    Paragraph(fix_ar(item.get("level", "").upper()), risk_style),
                    Paragraph(fix_ar(str(item.get("count", ""))), self.style_table_cell),
                    Paragraph(fix_ar(item.get("name", "")), self.style_table_cell)
                ])

            # SMALL TABLE WIDTHS
            col_widths = [160, 90, 70, 140]

            table = Table(table_data, colWidths=col_widths, hAlign="CENTER")

            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), self.dark_blue),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),

                ("BACKGROUND", (0, 1), (-1, -1), self.dark_green),
                ("GRID", (0, 0), (-1, -1), 1, white),

                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))

            story.append(table)
            story.append(Spacer(1, 30))

        else:
            story.append(Paragraph(fix_ar("لا توجد تهديدات مكتشفة."), self.style_normal))
            story.append(Spacer(1, 20))

        # ------------ Advanced Stats ------------
        story.append(Paragraph(fix_ar("الإحصائيات المتقدمة"), self.style_section))
        story.append(Spacer(1, 10))

        if not stats:
            story.append(Paragraph(fix_ar("لا توجد نتائج تحليلية متقدمة."), self.style_normal))

        story.append(PageBreak())

        # ------------ NEXT STEPS ------------
        story.append(Paragraph(fix_ar("ما الخطوات القادمة؟"), self.style_section))
        story.append(Spacer(1, 10))

        next_steps = [
            "مراجعة مصدر السجلات لمعرفة النظام المتأثر.",
            "تحليل نوع النشاط المشبوه وتحديد تأثيره.",
            "تغيير كلمات المرور للحسابات المتضررة.",
            "تفعيل المصادقة الثنائية (2FA).",
            "مراقبة النظام خلال الساعات القادمة.",
            "التواصل مع مختص سيبراني إذا تكرر النشاط."
        ]

        for step in next_steps:
            story.append(Paragraph(fix_ar(f"• {step}"), self.style_normal))

        story.append(Spacer(1, 25))

        # ------------ Recommendations ------------
        story.append(Paragraph(fix_ar("التوصيات بناءً على التحليل"), self.style_section))
        story.append(Spacer(1, 10))

        recs = [
            "تغيير كلمات المرور فورًا للحسابات المتأثرة.",
            "تفعيل المصادقة الثنائية (2FA).",
            "مراقبة محاولات الدخول المستقبلية.",
            "التحقق من عدم مشاركة بيانات الدخول."
        ]

        for r in recs:
            story.append(Paragraph(fix_ar(f"• {r}"), self.style_normal))

        story.append(Spacer(1, 30))

        story.append(Paragraph(fix_ar("________________________________________________________"), self.style_center))
        story.append(Spacer(1, 6))
        story.append(Paragraph(fix_ar("تم اكتمال التحليل."), self.style_center))

        doc.build(story, onFirstPage=self._draw_background, onLaterPages=self._draw_background)

        return filename

