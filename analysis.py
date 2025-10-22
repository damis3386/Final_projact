#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة التحليل الجنائي الرقمي - Digital Forensics Tool
إصدار: 2.0
المطور: هيلة و لين
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

# --------------------------
# إعداد المجلدات اللازمة
# --------------------------
os.makedirs("results", exist_ok=True)
os.makedirs("logs", exist_ok=True)
os.makedirs("data", exist_ok=True)   # للتأكد من وجود مجلد البيانات
# --------------------------

# ==========================
# 🔧 إعداد التسجيل (Logging)
# ==========================
LOG_PATH = os.path.join("logs", "forensics.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==========================
# 🎯 الثوابت والإعدادات
# ==========================
class Config:
    """إعدادات التطبيق"""
    SUPPORTED_EXTENSIONS = {'.log', '.txt', '.csv', '.json', '.zip'}
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    RISK_THRESHOLDS = {
        'HIGH': 20,
        'MEDIUM': 10,
        'LOW': 0
    }

# ==========================
# 🟢 إدارة القواعد
# ==========================
class RuleManager:
    """مدير قواعد التحليل"""
    def __init__(self, rules_file: str = 'rules.json'):
        self.rules_file = rules_file
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """تحميل القواعد من ملف JSON أو استخدام القواعد الافتراضية"""
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                count = sum(len(v) for v in rules.values()) if isinstance(rules, dict) else 0
                logger.info(f"✅ تم تحميل {count} قاعدة من {self.rules_file}")
                return rules
            else:
                logger.warning(f"⚠️  ملف القواعد {self.rules_file} غير موجود، استخدام القواعد الافتراضية")
                return self._get_default_rules()
        except json.JSONDecodeError as e:
            logger.error(f"❌ خطأ في تنسيق ملف القواعد: {e}")
            return self._get_default_rules()
        except Exception as e:
            logger.error(f"❌ فشل تحميل قواعد: {e}")
            return self._get_default_rules()

    def _get_default_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """القواعد الافتراضية (موسعة)"""
        return {
            "high_risk_patterns": [
                {"name": "Ransomware", "pattern": r"\bransomware\b", "description": "برمجية فدية", "score": 10, "category": "برامج ضارة"},
                {"name": "SQL Injection", "pattern": r"sql\s+injection|\binjection\b", "description": "محاولة حقن SQL", "score": 10, "category": "هجوم تطبيقي"},
                {"name": "Privilege Escalation", "pattern": r"privilege\s+escalation", "description": "محاولة تصعيد صلاحيات", "score": 8, "category": "هجوم تطبيقي"}
            ],
            "medium_risk_patterns": [
                {"name": "Malware", "pattern": r"\bmalware\b|\bvirus\b|\btrojan\b", "description": "برامج ضارة", "score": 5, "category": "برامج ضارة"},
                {"name": "Unauthorized Access", "pattern": r"\bunauthorized\b|\bunauthorized\s+access\b", "description": "وصول غير مصرح به", "score": 5, "category": "أمن الشبكات"},
                {"name": "Failed Login", "pattern": r"\bfailed\s+login\b|\blogin\s+failed\b|\bauthentication\s+failed\b", "description": "محاولات دخول فاشلة", "score": 5, "category": "أمان النظام"},
                {"name": "Brute Force Pattern", "pattern": r"(failed\s+login.*){3,}", "description": "نمط يشير إلى هجوم تخمين متكرر", "score": 6, "category": "هجوم شبكي"}
            ],
            "low_risk_patterns": [
                {"name": "Warning", "pattern": r"\bwarning\b", "description": "تحذير نظام", "score": 1, "category": "مراقبة النظام"},
                {"name": "Timeout", "pattern": r"\btimeout\b|\btime\s?out\b", "description": "انتهاء مهلة اتصال", "score": 1, "category": "أداء النظام"},
                {"name": "Scan", "pattern": r"\bscan\b|\bscanning\b", "description": "نشاط فحص/مسح", "score": 1, "category": "مراقبة الشبكة"}
            ]
        }

    def get_all_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """الحصول على جميع القواعد"""
        return self.rules

# ==========================
# 🟢 إدارة الملفات
# ==========================
import io
import zipfile
import csv

class FileManager:
    """مدير عمليات الملفات — يدعم txt/csv/json/zip (محتوى نصي)"""
    @staticmethod
    def read_file(file_path: str, encoding: str = 'utf-8') -> Dict[str, Optional[object]]:
        """
        يَرجع dict:
        { "text": str|None, "meta": {...}, "error": None|str }
        """
        try:
            if not os.path.exists(file_path):
                return {"text": None, "meta": None, "error": f"الملف غير موجود: {file_path}"}
            size = os.path.getsize(file_path)
            if size > Config.MAX_FILE_SIZE:
                return {"text": None, "meta": None, "error": f"حجم الملف كبير جداً: {size} بايت"}
            name = os.path.basename(file_path)
            _, ext = os.path.splitext(name.lower())
            meta = {"path": file_path, "size": size, "ext": ext, "files_in_archive": None}

            if ext in ('.txt', '.log'):
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    text = f.read()
                logger.info(f"📖 تم قراءة الملف: {file_path} ({size} بايت، {len(text.splitlines())} سطر)")
                return {"text": text, "meta": meta, "error": None}

            if ext == '.csv':
                rows = []
                with open(file_path, 'r', encoding=encoding, errors='replace', newline='') as f:
                    reader = csv.DictReader(f)
                    for r in reader:
                        rows.append(json.dumps(r, ensure_ascii=False))
                text = "\n".join(rows)
                return {"text": text, "meta": meta, "error": None}

            if ext == '.json':
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    text = "\n".join(json.dumps(it, ensure_ascii=False) for it in data)
                else:
                    text = json.dumps(data, ensure_ascii=False)
                return {"text": text, "meta": meta, "error": None}

            if ext == '.zip':
                contents = []
                names = []
                with zipfile.ZipFile(file_path, 'r') as z:
                    for info in z.infolist():
                        names.append(info.filename)
                        _, e = os.path.splitext(info.filename.lower())
                        if e in ('.txt', '.log'):
                            try:
                                with z.open(info) as f:
                                    data = f.read().decode(encoding, errors='replace')
                                contents.append(f"--- FILE: {info.filename} ---\n{data}")
                            except Exception:
                                contents.append(f"--- FILE: {info.filename} (unreadable) ---")
                        elif e == '.csv':
                            try:
                                with z.open(info) as f:
                                    text = f.read().decode(encoding, errors='replace')
                                reader = csv.DictReader(io.StringIO(text))
                                rows = [json.dumps(r, ensure_ascii=False) for r in reader]
                                contents.append("\n".join(rows))
                            except Exception:
                                contents.append(f"--- FILE: {info.filename} (csv parse error) ---")
                        elif e == '.json':
                            try:
                                with z.open(info) as f:
                                    text = f.read().decode(encoding, errors='replace')
                                    data = json.loads(text)
                                if isinstance(data, list):
                                    contents.append("\n".join(json.dumps(it, ensure_ascii=False) for it in data))
                                else:
                                    contents.append(json.dumps(data, ensure_ascii=False))
                            except Exception:
                                contents.append(f"--- FILE: {info.filename} (json parse error) ---")
                        else:
                            contents.append(f"--- FILE: {info.filename} (skipped - unsupported) ---")
                meta["files_in_archive"] = names
                return {"text": "\n\n".join(contents), "meta": meta, "error": None}

            return {"text": None, "meta": meta, "error": f"Unsupported extension: {ext}"}

        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    text = f.read()
                return {"text": text, "meta": meta, "error": None}
            except Exception as e:
                return {"text": None, "meta": None, "error": str(e)}
        except Exception as e:
            logger.error(f"❌ خطأ في قراءة الملف: {e}")
            return {"text": None, "meta": None, "error": str(e)}

# ==========================
# 🟢 المحلل الرئيسي
# ==========================
class ForensicAnalyzer:
    """المحلل الجنائي الرئيسي"""
    def __init__(self, rules_file: str = 'rules.json'):
        self.rule_manager = RuleManager(rules_file=rules_file)
        self.file_manager = FileManager()

    def analyze_log_basic(self, content: str) -> Dict[str, Any]:
        """التحليل الأساسي للسجلات"""
        lines = content.splitlines()
        error_lines = [line for line in lines if re.search(r'\berror\b', line, re.IGNORECASE)]
        warning_lines = [line for line in lines if re.search(r'\bwarning\b', line, re.IGNORECASE)]
        info_lines = [line for line in lines if re.search(r'\binfo\b', line, re.IGNORECASE)]
        return {
            "total_lines": len(lines),
            "errors": len(error_lines),
            "warnings": len(warning_lines),
            "info_events": len(info_lines),
            "analysis_timestamp": datetime.now().isoformat()
        }

    def search_suspicious_patterns(self, content: str) -> List[Dict[str, Any]]:
        """البحث عن الأنماط المشبوهة باستخدام القواعد"""
        rules = self.rule_manager.get_all_rules()
        found_items: List[Dict[str, Any]] = []
        risk_levels_mapping = {
            "high_risk_patterns": {"icon": "🟥", "level": "عالي الخطورة"},
            "medium_risk_patterns": {"icon": "🟨", "level": "متوسط الخطورة"},
            "low_risk_patterns": {"icon": "🟩", "level": "منخفض الخطورة"}
        }

        for rule_category, risk_info in risk_levels_mapping.items():
            for rule in rules.get(rule_category, []):
                try:
                    matches = re.findall(rule['pattern'], content, flags=re.IGNORECASE)
                except re.error as e:
                    logger.error(f"❌ خطأ في النمط {rule.get('pattern')}: {e}")
                    matches = []
                if matches:
                    examples = []
                    # إذا كانت الـ matches عبارة عن tuples أو قوائم بسبب مجموعات التقاط في ال regex
                    for m in matches[:3]:
                        if isinstance(m, (list, tuple)):
                            examples.append(" ".join([str(x) for x in m if x]))
                        else:
                            examples.append(str(m))
                    found_items.append({
                        "risk_icon": risk_info["icon"],
                        "risk_level": risk_info["level"],
                        "name": rule.get('name'),
                        "pattern": rule.get('pattern'),
                        "count": len(matches),
                        "score": rule.get('score', 1),
                        "description": rule.get('description', 'لا يوجد وصف'),
                        "category": rule.get('category', 'غير مصنف'),
                        "examples": examples,
                        "first_occurrence": examples[0] if examples else ""
                    })
                    logger.info(f"🔍 عُثر على: {rule.get('name')} ({len(matches)} مرة)")
        # ترتيب النتائج حسب النقاط (score * count) تنازلياً
        found_items.sort(key=lambda x: x['score'] * x['count'], reverse=True)
        return found_items

    def advanced_statistical_analysis(self, content: str) -> Dict[str, Any]:
        """تحليل إحصائي متقدم"""
        lines = content.splitlines()
        # أنماط التوقيت والتواريخ وعناوين IP و URLs
        times = re.findall(r'(\d{1,2}:\d{2}:\d{2})', content)
        dates = re.findall(r'(\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})', content)
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
        urls = re.findall(r'https?://[^\s]+', content)
        suspicious_patterns = self.search_suspicious_patterns(content)
        total_risk_score = sum(item['score'] * item['count'] for item in suspicious_patterns)

        if total_risk_score >= Config.RISK_THRESHOLDS['HIGH']:
            overall_risk = "🟥 عالي"
            action_required = "نعم - تدخل فوري مطلوب"
        elif total_risk_score >= Config.RISK_THRESHOLDS['MEDIUM']:
            overall_risk = "🟨 متوسط"
            action_required = "مراقبة مستمرة"
        else:
            overall_risk = "🟩 منخفض"
            action_required = "لا - ضمن المعدل الطبيعي"

        return {
            "التحليل_الزمني": {
                "أول_حدث": times[0] if times else "غير معروف",
                "آخر_حدث": times[-1] if times else "غير معروف",
                "الفترة_الزمنية": f"{times[0]} - {times[-1]}" if times else "غير معروف",
                "عدد_الأوقات_المسجلة": len(times)
            },
            "التحليل_الشبكي": {
                "عناوين_IP_مختلفة": len(set(ips)),
                "إجمالي_عناوين_IP": len(ips),
                "عناوين_URL_مكتشفة": len(urls)
            },
            "تقييم_الخطورة": {
                "نقاط_الخطورة_الإجمالية": total_risk_score,
                "مستوى_الخطورة_الشامل": overall_risk,
                "يتطلب_تدخل": action_required,
                "عدد_التهديدات_المكتشفة": len(suspicious_patterns)
            },
            "الإحصائيات_العامة": {
                "إجمالي_الأحداث": len(lines),
                "التواريخ_المختلفة": len(set(dates)),
                "معدل_الأحداث_في_الساعة": len(lines) / 24 if times else 0
            }
        }

# ==========================
# 🟢 مولد التقارير
# ==========================
class ReportGenerator:
    """مولد التقارير المتقدم"""
    @staticmethod
    def generate_text_report(basic_analysis: Dict[str, Any], suspicious_items: List[Dict[str, Any]],
                             stats: Dict[str, Any], analysis_time: float) -> str:
        """توليد تقرير نصي مفصل"""
        report = []
        report.append("╔" + "═" * 68 + "╗")
        report.append("║ 🛡  تقرير التحليل الجنائي الرقمي - النسخة الاحترافية v2.0  ║")
        report.append("╚" + "═" * 68 + "╝")
        report.append(f"📅 تاريخ التقرير: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"⏱️  وقت التحليل: {analysis_time:.2f} ثانية")
        report.append("─" * 70)
        report.append("📊 النتائج الأساسية:")
        report.append(f"   • 📄 إجمالي الأسطر: {basic_analysis['total_lines']:,}")
        report.append(f"   • ❌ عدد الأخطاء: {basic_analysis['errors']}")
        report.append(f"   • ⚠️  عدد التحذيرات: {basic_analysis['warnings']}")
        report.append(f"   • ℹ️  أحداث معلومات: {basic_analysis['info_events']}")
        report.append("─" * 70)

        if suspicious_items:
            report.append("🔍 التهديدات المكتشفة (مصنفة حسب الخطورة):")
            threats_by_level: Dict[str, List[Dict[str, Any]]] = {}
            for item in suspicious_items:
                level = item['risk_level']
                threats_by_level.setdefault(level, []).append(item)
            for level in ["عالي الخطورة", "متوسط الخطورة", "منخفض الخطورة"]:
                if level in threats_by_level:
                    report.append(f"\n{threats_by_level[level][0]['risk_icon']} {level}:")
                    for threat in threats_by_level[level]:
                        report.append(f"   • {threat['name']} ← {threat['count']} مرة")
                        report.append(f"     📝 {threat['description']}")
                        report.append(f"     🏷  التصنيف: {threat['category']}")
                        report.append(f"     📊 نقاط الخطورة: {threat['score']} لكل حدث")
                        if threat.get('examples'):
                            report.append(f"     🔍 أمثلة: {', '.join(threat['examples'][:2])}")
        else:
            report.append("✅ لا توجد تهديدات مشبوهة مكتشفة")

        report.append("─" * 70)
        report.append("📈 الإحصائيات المتقدمة:")
        for section, data in stats.items():
            report.append(f"\n   {section.replace('_', ' ')}:")
            for key, value in data.items():
                report.append(f"      • {key.replace('_', ' ')}: {value}")

        report.append("─" * 70)
        report.append("💡 التوصيات:")
        risk_action = stats["تقييم_الخطورة"]["يتطلب_تدخل"]
        if "فوري" in risk_action:
            report.append("   🚨 تدخل فوري مطلوب - تم اكتشاف تهديدات عالية الخطورة")
            report.append("   📞 اتصل بفريق الأمن السيبراني فوراً")
        elif "مراقبة" in risk_action:
            report.append("   👀 مراقبة مستمرة مطلوبة - تهديدات متوسطة الخطورة")
            report.append("   📊 تتبع النشاط المشبوه")
        else:
            report.append("   ✅ الوضع طبيعي - لا توجد تهديدات خطيرة")

        report.append("╔" + "═" * 68 + "╗")
        report.append("║                    🏁 نهاية التقرير                     ║")
        report.append("╚" + "═" * 68 + "╝")
        return "\n".join(report)

    @staticmethod
    def save_report(report_text: str, output_dir: str = "results") -> Optional[str]:
        """حفظ التقرير في ملف"""
        try:
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(output_dir, f"forensic_report_{timestamp}.txt")
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report_text)
            logger.info(f"💾 تم حفظ التقرير في: {filename}")
            return filename
        except Exception as e:
            logger.error(f"❌ فشل حفظ التقرير: {e}")
            return None

# ==========================
# 🧩 التشغيل الرئيسي
# ==========================
def main():
    print("🚀 بدء أداة التحليل الجنائي الرقمي...")
    analyzer = ForensicAnalyzer()
    report_gen = ReportGenerator()

    # مثال: تحليل ملف افتراضي
    file_path = "data/sample_log.txt"
    try:
        start_time = datetime.now()

        # قراءة الملف
        read_result = analyzer.file_manager.read_file(file_path)
        if read_result["error"]:
            logger.error(f"❌ خطأ: {read_result['error']}")
            print(f"❌ خطأ: {read_result['error']}")
            return

        content = read_result["text"]
        basic_analysis = analyzer.analyze_log_basic(content)
        suspicious_items = analyzer.search_suspicious_patterns(content)
        advanced_stats = analyzer.advanced_statistical_analysis(content)

        analysis_time = (datetime.now() - start_time).total_seconds()
        report_text = report_gen.generate_text_report(basic_analysis, suspicious_items, advanced_stats, analysis_time)

        print("\n" + report_text)
        saved_file = report_gen.save_report(report_text)
        if saved_file:
            print(f"\n🎉 اكتمل التحليل بنجاح! التقرير محفوظ في: {saved_file}")

    except Exception as e:
        logger.exception("❌ فشل التحليل:")
        print(f"❌ حدث خطأ: {e}")

if __name__ == "__main__":
    main()
