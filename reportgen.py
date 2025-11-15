# reportgen.py
# -*- coding: utf-8 -*-

import os
from datetime import datetime
from typing import Dict, Any, List
import arabic_reshaper
from bidi.algorithm import get_display

from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import registerFontFamily
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import Color, white, cyan
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Frame, PageTemplate, KeepTogether
)

import tkinter as tk
from tkinter import filedialog


# ================= Arabic Fix =================
def fix_ar(text: str) -> str:
    """Fix Arabic text for PDF (reshaper + bidi)."""
    if not isinstance(text, str):
        text = str(text)
    try:
        return get_display(arabic_reshaper.reshape(text))
    except:
        return text


class PDFReportGenerator:

    def __init__(self):
        # Register Arabic font
        pdfmetrics.registerFont(TTFont("ArabicFont", "NotoNaskhArabic-Regular.ttf"))

        registerFontFamily(
            "ArabicFont",
            normal="ArabicFont",
            bold="ArabicFont",
            italic="ArabicFont",
            boldItalic="ArabicFont"
        )

        self.font_name = "ArabicFont"
        self.bg_color = Color(0.06, 0.08, 0.12)

    # ================= PAGE BACKGROUND =================
    def _draw_background(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(self.bg_color)
        canvas.rect(0, 0, A4[0], A4[1], fill=True, stroke=False)
        canvas.restoreState()

    # ================= PAGE FOOTER =================
    def _draw_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(white)
        canvas.setFont("ArabicFont", 10)

        line1 = fix_ar("© 2025 — تقرير التحليل الجنائي الرقمي")
        line2 = fix_ar("جامعة القصيم — برنامج الأمن السيبراني")

        canvas.drawCentredString(A4[0] / 2, 28, line1)
        canvas.drawCentredString(A4[0] / 2, 14, line2)

        canvas.restoreState()

    # ============ PDF Builder ============

    def generate_pdf(self, results: Dict[str, Any], filename: str = None) -> str:

        if filename is None:
            root = tk.Tk()
            root.withdraw()
            filename = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf")],
                initialfile="Digital_Forensics_Report.pdf"
            )
            root.destroy()

        if not filename:
            return ""

        doc = SimpleDocTemplate(
            filename,
            pagesize=A4,
            leftMargin=40,
            rightMargin=40,
            topMargin=60,
            bottomMargin=40
        )

        frame = Frame(40, 100, A4[0] - 80, A4[1] - 160, id="frame")

        template = PageTemplate(
            id="DarkPage",
            frames=[frame],
            onPage=self._draw_background
        )

        doc.addPageTemplates([template])

        # ========= Received Results =========
        story: List[Any] = []

        basic = results.get("basic_analysis", {})
        suspicious = results.get("suspicious_items", [])
        adv = results.get("advanced_stats", {})
        full_text = results.get("text_report", "")

        # ===== Risk Level =====
        risk_info = adv.get("تقييم_الخطورة", {})
        risk_level = risk_info.get("مستوى_الخطورة_الشامل", "غير محدد")

        if risk_level == "منخفض":
            risk_emoji, risk_score = "🟢", 20
        elif risk_level == "متوسط":
            risk_emoji, risk_score = "🟡", 60
        elif risk_level == "مرتفع":
            risk_emoji, risk_score = "🔴", 90
        else:
            risk_emoji = "🟡" if suspicious else "🟢"
            risk_score = 50 if suspicious else 10

        # ============ Styles ============
        title = ParagraphStyle("title", fontName=self.font_name, fontSize=22,
                               alignment=1, textColor=cyan, leading=30)
        section = ParagraphStyle("section", fontName=self.font_name, fontSize=18,
                                 alignment=2, textColor=cyan, leading=30)
        normal = ParagraphStyle("normal", fontName=self.font_name, fontSize=14,
                                alignment=2, textColor=white, leading=26)
        small = ParagraphStyle("small", fontName=self.font_name, fontSize=12,
                               alignment=2, textColor=white, leading=22)
        warn = ParagraphStyle("warn", fontName=self.font_name, fontSize=14,
                              alignment=2, textColor=Color(1,0.7,0), leading=24)
        good = ParagraphStyle("good", fontName=self.font_name, fontSize=14,
                              alignment=2, textColor=Color(0,1,0.4), leading=24)
        center_text = ParagraphStyle("center_text", fontName=self.font_name, fontSize=18,
                                     alignment=1, textColor=cyan, leading=28)
        center_small = ParagraphStyle("center_small", fontName=self.font_name, fontSize=13,
                                      alignment=1, textColor=white, leading=22)

        # ============ Title ============  
        story.append(Paragraph(fix_ar("تقرير التحليل الجنائي الرقمي"), title))
        story.append(Spacer(1, 15))

        date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
        story.append(Paragraph(fix_ar(f"تاريخ إنشاء التقرير: {date_str}"), small))
        story.append(Spacer(1, 25))

        # ============ Summary ============  
        story.append(Paragraph(fix_ar("ملخص مبسط لغير المختصين"), section))
        story.append(Spacer(1, 12))

        if suspicious:
            summary = (
                "تم الكشف عن نشاطات غير طبيعية داخل الملف، مما يشير إلى احتمال وجود سلوك مشبوه. "
                "يُنصح بمراجعة التفاصيل في الأقسام التالية ومشاركة التقرير مع مختص في الأمن السيبراني."
            )
        else:
            summary = (
                "لم يتم العثور على نشاطات مشبوهة داخل الملف. "
                "يبدو الملف طبيعيًا ويمكن استخدامه بشكل اعتيادي، مع توصية بالاحتفاظ بنسخة احتياطية."
            )

        story.append(Paragraph(fix_ar(summary), normal))
        story.append(Spacer(1, 15))

        risk_line = f"تقييم الحالة: {risk_emoji} (درجة الخطورة التقريبية: {risk_score}٪)"
        story.append(Paragraph(fix_ar(risk_line), normal))
        story.append(Spacer(1, 25))

        # ============ General Explanation ============  
        story.append(Paragraph(fix_ar("شرح عام"), section))
        story.append(Spacer(1, 12))

        story.append(Paragraph(
            fix_ar(
                "يقوم هذا التقرير بتحليل سجل الأحداث (Logs) للتحقق من وجود أي نشاط غير طبيعي، "
                "مثل محاولات الدخول الفاشلة أو الروابط المشبوهة أو الأوامر الضارة. "
                "ويتم عرض النتائج بشكل مفصل في الأقسام التالية."
            ),
            small
        ))
        story.append(Spacer(1, 25))

        # ============ Quick Summary ============  
        story.append(Paragraph(fix_ar("الملخص السريع"), section))
        story.append(Spacer(1, 10))

        story.append(Paragraph(fix_ar(f"• عدد الأسطر: {basic.get('total_lines','0')}"), normal))
        story.append(Paragraph(fix_ar(f"• الأخطاء: {basic.get('errors','0')}"), normal))
        story.append(Paragraph(fix_ar(f"• التحذيرات: {basic.get('warnings','0')}"), normal))
        story.append(Paragraph(fix_ar(f"• معلومات: {basic.get('info_events','0')}"), normal))
        story.append(Spacer(1, 30))

        # ============ File Status ============  
        story.append(Paragraph(fix_ar("حالة الملف"), section))
        story.append(Spacer(1, 10))

        if suspicious:
            story.append(Paragraph(fix_ar("يحتوي الملف على نشاطات مشبوهة قد تحتاج متابعة."), warn))
        else:
            story.append(Paragraph(fix_ar("الملف سليم ولا يحتوي على أي مؤشرات تهديد."), good))
        story.append(Spacer(1, 30))

        # ============ Detected Threats ============  
        story.append(Paragraph(fix_ar("التهديدات المكتشفة"), section))
        story.append(Spacer(1, 10))

        if suspicious:
            for item in suspicious:
                block = []
                header = f"{item.get('risk_icon','')} {item['name']} — مرات الظهور: {item['count']}"
                block.append(Paragraph(fix_ar(header), normal))

                if item.get("description"):
                    block.append(Paragraph(fix_ar(f"الوصف: {item['description']}"), small))

                if item.get("category"):
                    block.append(Paragraph(fix_ar(f"التصنيف الأمني: {item['category']}"), small))

                block.append(Paragraph(
                    fix_ar("مثال: تكرار محاولات تسجيل الدخول قد يشير إلى محاولة تخمين كلمة مرور."),
                    small
                ))

                block.append(Spacer(1, 18))
                story.append(KeepTogether(block))
        else:
            story.append(Paragraph(fix_ar("لا توجد أي تهديدات مكتشفة في هذا الملف."), normal))

        story.append(Spacer(1, 30))

        # ============ Advanced Stats ============  
        story.append(Paragraph(fix_ar("الإحصائيات المتقدمة"), section))
        story.append(Spacer(1, 10))

        for sec, data in adv.items():
            block = [Paragraph(fix_ar(f"• {sec}"), normal)]
            for k, v in data.items():
                block.append(Paragraph(fix_ar(f"   - {k}: {v}"), small))
            block.append(Spacer(1, 18))
            story.append(KeepTogether(block))

        # ============ End Section ============  
        story.append(Spacer(1, 25))
        story.append(Paragraph(fix_ar("تم اكتمال التحليل الرقمي."), center_text))
        story.append(Spacer(1, 10))
        story.append(Paragraph(fix_ar("لا توجد عناصر إضافية لمعالجتها."), center_small))
        story.append(Spacer(1, 30))

        # ===== Build =====
        doc.build(story, onFirstPage=self._draw_background, onLaterPages=self._draw_background)

        return filename
