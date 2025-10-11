# analysis.py
import os
import re
from datetime import datetime

# 🟢 قراءة الملف
def read_file(file_path):
    """تقرأ الملف وترجع محتواه كسطر نصي"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

# 🟢 تحليل السجل
def analyze_log(content):
    lines = content.splitlines()
    error_lines = [line for line in lines if "error" in line.lower()]
    warning_lines = [line for line in lines if "warning" in line.lower()]

    return {
        "total_lines": len(lines),
        "errors": len(error_lines),
        "warnings": len(warning_lines)
    }

# 🟢 البحث عن الأنماط المشبوهة
def search_suspicious(content):
    patterns = [
        r"hacked", r"attack", r"malware", r"unauthorized",
        r"login failed", r"breach", r"error code \d+"
    ]
    found = []
    for p in patterns:
        matches = re.findall(p, content, flags=re.IGNORECASE)
        if matches:
            found.append({p: len(matches)})
    return found

# 🟢 تنسيق وطباعة التقرير
def format_report(result, suspicious):
    report = []
    report.append("="*50)
    report.append("📊 تقرير التحليل الجنائي الرقمي")
    report.append("="*50)
    report.append(f"🔸 عدد الأسطر: {result['total_lines']}")
    report.append(f"🔸 عدد الأخطاء: {result['errors']}")
    report.append(f"🔸 عدد التحذيرات: {result['warnings']}")
    report.append("-"*50)
    report.append("🔍 الكلمات والأنماط المشبوهة:")
    if suspicious:
        for item in suspicious:
            for k, v in item.items():
                report.append(f"  • {k} ← {v} مرة")
    else:
        report.append("✅ لا توجد أنماط مشبوهة")
    report.append("="*50)
    return "\n".join(report)

# 🟢 حفظ التقرير داخل مجلد النتائج
def save_report(report_text):
    if not os.path.exists("results"):
        os.makedirs("results")
    filename = f"results/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\n💾 تم حفظ التقرير في: {filename}")

# 🧩 التشغيل
if __name__ == "__main__":
    path = "data/sample_log.txt"
    if not os.path.exists(path):
        print("❌ الملف غير موجود:", path)
    else:
        text = read_file(path)
        result = analyze_log(text)
        suspicious = search_suspicious(text)
        report_text = format_report(result, suspicious)
        print(report_text)
        save_report(report_text)
