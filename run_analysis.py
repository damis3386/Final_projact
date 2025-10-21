# run_analysis.py
from core.file_handlers import FileHandlers
from core.analyzer import ForensicAnalyzer
from colorama import init, Fore, Style

# تهيئة Colorama
init(autoreset=True)

# إنشاء المعالج وقراءة الملف
handler = FileHandlers()
file_path = "data/sample_log.txt"
result = handler.read(file_path)

# التحقق من وجود خطأ
if result["error"]:
    print(Fore.RED + f"❌ Error: {result['error']}")
    exit(1)

# إنشاء محلل الأدلة الجنائية
analyzer = ForensicAnalyzer()
basic = analyzer.analyze_basic(result["text"])
patterns = analyzer.search_patterns(result["text"])
summary = analyzer.summarize(basic, patterns)

# طباعة ملخص رئيسي
print("\n=== Forensic Summary ===")
print(f"File: {file_path}  Size: {result['meta']['size']} bytes  Ext: {result['meta']['ext']}")
print(f"Lines: {summary['basic']['total_lines']}  Errors: {summary['basic']['errors']}  Warnings: {summary['basic']['warnings']}")
print(f"Total risk score: {summary['total_score']}  Overall: {summary['overall_level']}")
print(f"Recommended action: {summary['recommended_action']}\n")

# دالة لطباعة مستوى الخطورة بالألوان والرموز
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

# طباعة الأنماط المكتشفة
print("Detected patterns:")
for item in summary["patterns"]:
    print_risk_item(item)