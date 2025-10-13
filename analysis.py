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

# 🟢 البحث عن الأنماط والكلمات المشبوهة (مع تصنيفها)
def search_suspicious(content):
    # الأنماط مصنفة حسب الخطورة
    patterns = {
        "Critical": [
            r"attack", r"malware", r"ransomware", r"trojan",
            r"sql injection", r"ddos", r"data breach"
        ],
        "Unauthorized": [
            r"unauthorized", r"access denied", r"bruteforce",
            r"invalid user", r"failed login", r"login failed"
        ],
        "Warning": [
            r"warning", r"timeout", r"connection lost", r"error code \d+"
        ],
        "Info": [
            r"scan", r"xss", r"port scan", r"ping", r"success"
        ]
    }

    found = []
    for category, regex_list in patterns.items():
        for pattern in regex_list:
            matches = re.findall(pattern, content, flags=re.IGNORECASE)
            if matches:
                found.append({
                    "category": category,
                    "pattern": pattern,
                    "count": len(matches)
                })
    return found

# 🟢 تنسيق التقرير بشكل احترافي
def format_report(result, suspicious):
    report = []
    report.append("="*55)
    report.append("📊 تقرير التحليل الجنائي الرقمي")
    report.append("="*55)
    report.append(f"🔸 عدد الأسطر: {result['total_lines']}")
    report.append(f"🔸 عدد الأخطاء: {result['errors']}")
    report.append(f"🔸 عدد التحذيرات: {result['warnings']}")
    report.append("-"*55)
    report.append("🔍 النتائج المصنفة:")
    
    if suspicious:
        for item in suspicious:
            cat_icon = {
                "Critical": "🔴",
                "Unauthorized": "🟠",
                "Warning": "🟡",
                "Info": "⚪"
            }.get(item["category"], "⚪")
            report.append(f"  {cat_icon} [{item['category']}]  {item['pattern']} ← {item['count']} مرة")
    else:
        report.append("✅ لا توجد أنماط مشبوهة")
    
    report.append("="*55)
    return "\n".join(report)

# 🟢 حفظ التقرير
def save_report(report_text):
    if not os.path.exists("results"):
        os.makedirs("results")
    filename = f"results/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\n💾 تم حفظ التقرير في: {filename}")

# 🧩 التشغيل التجريبي
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
