# run_analysis.py
# -*- coding: utf-8 -*-

"""
تشغيل التحليل الجنائي الرقمي على جميع الملفات داخل مجلد data/
يدعم:
- Multi-threading
- Color Output
- Logging
- حفظ تقارير نصية منفصلة لكل ملف
"""

import os
import logging
from concurrent.futures import ThreadPoolExecutor

from colorama import init, Fore, Style

from analysis import analyze_file   # نستخدم المحرك الرئيسي
from core.file_handlers import FileHandlers


# ==========================
# 🔧 Logging
# ==========================
logging.basicConfig(
    filename='analysis.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

init(autoreset=True)  # colorama


# ==========================
# دوال مساعدة
# ==========================
def is_blocked_type(path: str) -> bool:
    """حظر الملفات التنفيذية الضارة"""
    blocked = (".exe", ".bat", ".cmd", ".vbs", ".js")
    return path.lower().endswith(blocked)


def print_colored_summary(file_path: str, report: str):
    """طباعة ملخص بسيط من التقرير في التيرمنال مع ألوان"""

    if "🟥" in report:
        level = Fore.RED + "HIGH RISK"
    elif "🟨" in report:
        level = Fore.YELLOW + "MEDIUM RISK"
    else:
        level = Fore.GREEN + "LOW RISK"

    print(Fore.CYAN + f"\n=== Analyzing File: {file_path} ===")
    print("Risk Level:", level)
    print(Fore.CYAN + "====================================\n")


def save_report_to_file(file_path: str, report: str):
    """حفظ تقرير نصي منفصل لكل ملف"""
    os.makedirs("results", exist_ok=True)

    base = os.path.basename(file_path)
    name = os.path.splitext(base)[0]

    out = os.path.join("results", f"{name}_report.txt")

    with open(out, "w", encoding="utf-8") as f:
        f.write(report)

    logging.info(f"Saved report: {out}")


# ==========================
# الدالة الرئيسية لتحليل ملف
# ==========================
def analyze_single_file(file_path: str):
    """تحليل ملف واحد"""
    if is_blocked_type(file_path):
        print(Fore.RED + f"⚠️ تخطي الملف (غير مسموح): {file_path}")
        return

    print(Fore.CYAN + f"\n🔍 Now Analyzing: {file_path}")

    report = analyze_file(file_path)

    print_colored_summary(file_path, report)
    save_report_to_file(file_path, report)


# ==========================
# تشغيل التحليل على جميع الملفات
# ==========================
def run_batch_analysis(folder="data"):
    """تحليل جميع الملفات في مجلد معين"""

    if not os.path.exists(folder):
        print(Fore.RED + f"❌ المجلد غير موجود: {folder}")
        return

    all_files = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, f))
    ]

    if not all_files:
        print(Fore.YELLOW + f"⚠️ لا توجد ملفات لتحليلها داخل: {folder}")
        return

    print(Fore.GREEN + f"\n🚀 بدء التحليل لـ {len(all_files)} ملف(ات)...")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(analyze_single_file, all_files)

    print(Fore.GREEN + "\n🎉 اكتمل تحليل جميع الملفات!")
    print(Fore.GREEN + "📂 تم حفظ التقارير داخل مجلد results/\n")


# ==========================
# تشغيل مباشر
# ==========================
if __name__ == "__main__":
    run_batch_analysis("data")
