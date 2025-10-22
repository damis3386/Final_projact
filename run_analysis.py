# run_analysis.py
from core.file_handlers import FileHandlers
from core.analyzer import ForensicAnalyzer
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import logging
import os

# ----------------------------
# إعداد Logging
# ----------------------------
logging.basicConfig(
    filename='analysis.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ----------------------------
# تهيئة Colorama
# ----------------------------
init(autoreset=True)

# ----------------------------
# دوال مساعدة
# ----------------------------
def safe_read_file(file_path):
    """يقرأ الملفات بطريقة آمنة بدون تنفيذ أي كود"""
    if file_path.endswith(('.exe', '.bat', '.cmd', '.js', '.vbs')):
        print(Fore.RED + f"⚠️ تم حظر فتح الملف: {file_path} (ملفات تنفيذية غير مسموح بها)")
        return ""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def print_risk_item(item):
    level = item["level"].lower()
    if level == "high":
        color = Fore.RED
        symbol = "🔴"
    elif level == "medium":
        color = Fore.YELLOW
        symbol = "🟠"
    else:
        color = Fore.GREEN
        symbol = "🟢"
    print(color + f" - [{level}] {symbol} {item['name']} x{item['count']} (score {item['score']})  desc: {item['desc']}")

def log_analysis(file_path, summary):
    logging.info(f"تم تحليل الملف: {file_path}")
    logging.info(f"عدد الأسطر: {summary['basic']['total_lines']}, Errors: {summary['basic']['errors']}, Warnings: {summary['basic']['warnings']}")
    logging.info(f"Total risk score: {summary['total_score']}, Overall: {summary['overall_level']}")

def analyze_file(file_path):
    text_content = safe_read_file(file_path)
    if not text_content:
        return None

    analyzer = ForensicAnalyzer()
    basic_summary = analyzer.analyze_basic(text_content)
    patterns_summary = analyzer.search_patterns(text_content)
    summary = analyzer.summarize(basic_summary, patterns_summary)

    # طباعة النتائج على الشاشة
    print(f"\n=== Forensic Summary: {file_path} ===")
    print(f"Lines: {summary['basic']['total_lines']}  Errors: {summary['basic']['errors']}  Warnings: {summary['basic']['warnings']}")
    print(f"Total risk score: {summary['total_score']}  Overall: {summary['overall_level']}")
    print(f"Recommended action: {summary['recommended_action']}\n")
    print("Detected patterns:")
    for item in summary["patterns"]:
        print_risk_item(item)

    # حفظ التقرير في ملف
    os.makedirs("results", exist_ok=True)
    base_name = os.path.basename(file_path)
    report_path = os.path.join("results", f"forensic_report_{base_name}.txt")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(f"File: {file_path}\n")
        f.write(f"Lines: {summary['basic']['total_lines']}  Errors: {summary['basic']['errors']}  Warnings: {summary['basic']['warnings']}\n")
        f.write(f"Total risk score: {summary['total_score']}  Overall: {summary['overall_level']}\n")
        f.write(f"Recommended action: {summary['recommended_action']}\n\n")
        f.write("Detected patterns:\n")
        for item in summary["patterns"]:
            f.write(f" - [{item['level']}] {item['name']} x{item['count']} (score {item['score']})  desc: {item['desc']}\n")

    log_analysis(file_path, summary)
    return summary

# ----------------------------
# تحليل جميع الملفات في مجلد محدد
# ----------------------------
folder_path = "data"
all_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]

with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(analyze_file, all_files))

print("\n✅ تم تحليل جميع الملفات وحفظ التقارير في مجلد results/")
