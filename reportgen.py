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

    # -------- Helper: overall risk from suspicious items --------
    def _compute_overall_risk(self, suspicious: List[Dict[str, Any]]) -> str:
        """
        يحسب مستوى الخطورة الكلي من قائمة التهديدات:
        يرجع: "low" أو "medium" أو "high"
        """
        if not suspicious:
            return "low"

        score = 0
        for item in suspicious:
            level = str(item.get("level", "")).lower()
            count = int(item.get("count", 1) or 1)
            if level == "high":
                score += 3 * count
            elif level == "medium":
                score += 2 * count
            else:
                score += 1 * count

        if score >= 15:
            return "high"
        elif score >= 7:
            return "medium"
        else:
            return "low"

    # -------- Helper: threat-based recommendations --------
    def _build_threat_recommendations(self, suspicious: List[Dict[str, Any]]) -> List[str]:
        """
        يبني توصيات حسب نوع التهديد.
        يرجع قائمة نصوص عربية (كل عنصر نقطة مستقلة).
        """
        if not suspicious:
            return []

        recs: List[str] = []
        seen_names = set()

        for item in suspicious:
            name = str(item.get("name", "")).strip()
            if not name:
                continue

            key = name.lower()
            if key in seen_names:
                continue
            seen_names.add(key)

            level = str(item.get("level", "")).lower()

            # توصيات مخصصة لأنواع معينة
            if "ransomware" in key:
                recs.append("بالنسبة لمؤشرات برمجيات الفدية (Ransomware): عزل الجهاز أو الخادم المشبوه عن الشبكة فورًا.")
                recs.append("إجراء فحص أمني شامل باستخدام أداة موثوقة لمكافحة البرمجيات الخبيثة.")
                recs.append("التحقق من وجود نسخ احتياطية سليمة قبل أي استعادة للبيانات.")
            elif "sql injection" in key or "sql" in key:
                recs.append("بالنسبة لمؤشرات هجمات SQL Injection: مراجعة الأكواد التي تتعامل مع قاعدة البيانات والتأكد من استخدام الاستعلامات المُهيكلة (Prepared Statements).")
                recs.append("تمكين سجلات قاعدة البيانات (Database Logs) ومراقبة الاستعلامات غير الاعتيادية.")
            elif "unauthorized" in key:
                recs.append("بالنسبة لمحاولات الوصول غير المصرح به: مراجعة صلاحيات المستخدمين والتأكد من عدم وجود حسابات غير معروفة.")
                recs.append("تفعيل مبدأ أقل صلاحية (Least Privilege) للحسابات الحساسة.")
            elif "failed login" in key or "login" in key:
                recs.append("بالنسبة لمحاولات الدخول الفاشلة المتكررة: تفعيل قفل الحساب مؤقتًا بعد عدد معين من المحاولات.")
                recs.append("تفعيل المصادقة الثنائية (2FA) للحسابات المهمة.")
            elif "malware" in key:
                recs.append("بالنسبة لمؤشرات برمجيات خبيثة (Malware): إجراء فحص شامل للأجهزة التي تتعامل مع هذا النظام.")
                recs.append("التأكد من تحديث برنامج الحماية من الفيروسات بشكل مستمر.")
            elif "warning" in key or "timeout" in key:
                recs.append("بالنسبة لتحذيرات النظام أو انتهاء المهلة: مراقبة السجلات لفترة أطول للتأكد من عدم تطور المشكلة إلى تهديد حقيقي.")
            else:
                # توصيات عامة إن لم نعرف نوع التهديد بشكل صريح
                if level == "high":
                    recs.append("تم رصد تهديد عالي الخطورة: يُنصح برفع بلاغ عاجل إلى فريق الأمن السيبراني ومتابعة الحالة فورًا.")
                elif level == "medium":
                    recs.append("تم رصد تهديد متوسط الخطورة: يُنصح بمراقبة السجلات والإجراءات المرتبطة بهذا التهديد بشكل دوري.")
                else:
                    recs.append("تم رصد مؤشرات منخفضة الخطورة: يُنصح بالاستمرار في المراقبة وتوثيق أي تغيّرات غير اعتيادية.")

        # إزالة التكرار لو صار فيه نصوص مكررة
        unique_recs = []
        seen_texts = set()
        for txt in recs:
            if txt not in seen_texts:
                seen_texts.add(txt)
                unique_recs.append(txt)

        return unique_recs

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

        overall_risk = self._compute_overall_risk(suspicious)

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
            story.append(Paragraph(
                fix_ar("تم العثور على إشارات قد تكون مرتبطة بسلوك غير طبيعي داخل الملف."),
                self.style_normal
            ))
            story.append(Paragraph(
                fix_ar("ننصح بمراجعة التحليل بالتفصيل في الأقسام التالية."),
                self.style_normal
            ))
        else:
            story.append(Paragraph(
                fix_ar("لم يتم العثور على نشاطات غير طبيعية داخل الملف."),
                self.style_normal
            ))
            story.append(Paragraph(
                fix_ar("يبدو الملف سليمًا ويمكن استخدامه بشكل اعتيادي."),
                self.style_normal
            ))

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

            table_data = [[
                Paragraph(fix_ar("الوصف"), self.style_table_header),
                Paragraph(fix_ar("درجة الخطورة"), self.style_table_header),
                Paragraph(fix_ar("مرات الظهور"), self.style_table_header),
                Paragraph(fix_ar("اسم التهديد"), self.style_table_header)
            ]]

            for item in suspicious:
                level = str(item.get("level", "")).lower()
                color = (
                    self.green if level == "low"
                    else self.orange if level == "medium"
                    else self.red
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
            story.append(Paragraph(fix_ar("لا توجد تهديدات مكتشفة في هذا الملف."), self.style_normal))
            story.append(Spacer(1, 20))

        # ------------ Advanced Stats (Placeholder) ------------
        story.append(Paragraph(fix_ar("الإحصائيات المتقدمة"), self.style_section))
        story.append(Spacer(1, 10))

        if not stats:
            story.append(Paragraph(fix_ar("لا توجد نتائج تحليلية متقدمة متاحة لهذا الملف."), self.style_normal))

        story.append(PageBreak())

        # ------------ Threat-based Recommendations ------------
        story.append(Paragraph(fix_ar("التوصيات حسب نوع التهديد"), self.style_section))
        story.append(Spacer(1, 10))

        threat_recs = self._build_threat_recommendations(suspicious)

        if not suspicious:
            story.append(Paragraph(
                fix_ar("لم يتم رصد تهديدات مباشرة في هذا الملف، لذلك لا توجد توصيات خاصة بنوع تهديد محدد."),
                self.style_normal
            ))
        elif not threat_recs:
            story.append(Paragraph(
                fix_ar("تم رصد تهديدات، لكن لم يتم التعرف على نوع محدد لتقديم توصيات مخصصة. يُنصح بمراجعة فريق الأمن السيبراني."),
                self.style_normal
            ))
        else:
            for rec in threat_recs:
                story.append(Paragraph(fix_ar(f"• {rec}"), self.style_normal))

        story.append(Spacer(1, 25))

        # ------------ Overall Risk Recommendations ------------
        story.append(Paragraph(fix_ar("التوصيات حسب مستوى خطورة الملف بالكامل"), self.style_section))
        story.append(Spacer(1, 10))

        if overall_risk == "high":
            overall_lines = [
                "مستوى الخطورة الكلي: مرتفع.",
                "يُوصى بالتعامل مع الملف والسجلات المرتبطة به كحالة أمنية عاجلة.",
                "عزل الأنظمة أو الأجهزة المرتبطة بهذه السجلات عن الشبكة إذا لزم الأمر.",
                "رفع بلاغ عاجل إلى فريق الأمن السيبراني أو الجهة المختصة.",
                "الاحتفاظ بنسخ من السجلات لأغراض التحقيق الرقمي."
            ]
        elif overall_risk == "medium":
            overall_lines = [
                "مستوى الخطورة الكلي: متوسط.",
                "يُوصى بمراقبة النظام والسجلات خلال الفترة القادمة للتأكد من عدم تطور النشاط.",
                "تنفيذ الإجراءات التصحيحية المقترحة في هذا التقرير (مثل تفعيل 2FA ومراجعة الصلاحيات).",
                "توثيق أي تغيّرات جديدة قد تظهر في السجلات."
            ]
        else:
            overall_lines = [
                "مستوى الخطورة الكلي: منخفض.",
                "لا توجد مؤشرات قوية على تهديد مباشر، لكن يُنصح بالاستمرار في المراقبة الدورية للسجلات.",
                "الحرص على تحديث الأنظمة والبرمجيات بشكل منتظم.",
                "تطبيق أفضل الممارسات العامة في الأمن السيبراني لحماية الأنظمة."
            ]

        for line in overall_lines:
            story.append(Paragraph(fix_ar(f"• {line}"), self.style_normal))

        story.append(Spacer(1, 30))

        # ------------ END ------------
        story.append(Paragraph(fix_ar("________________________________________________________"), self.style_center))
        story.append(Spacer(1, 6))
        story.append(Paragraph(fix_ar("تم اكتمال التحليل."), self.style_center))

        doc.build(story, onFirstPage=self._draw_background, onLaterPages=self._draw_background)

        return filename
