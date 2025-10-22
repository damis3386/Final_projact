#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة التحليل الجنائي الرقمي - Digital Forensics Tool
إصدار: 2.0
المطور: هيلة لين
"""

import os
import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Any

# ==========================
# 🔧 إعداد التسجيل (Logging)
# ==========================
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/forensics.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==========================
# 🎯 الثوابت والإعدادات
# ==========================
class Config:
    """إعدادات التطبيق"""
    SUPPORTED_EXTENSIONS = {'.log', '.txt', '.csv'}
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
    
    def _load_rules(self) -> Dict[str, List[Dict]]:
        """تحميل القواعد من ملف JSON"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                rules = json.load(f)
                logger.info(f"✅ تم تحميل {sum(len(v) for v in rules.values())} قاعدة من {self.rules_file}")
                return rules
        except FileNotFoundError:
            logger.warning(f"⚠️  ملف القواعد {self.rules_file} غير موجود، استخدام القواعد الافتراضية")
            return self._get_default_rules()
        except json.JSONDecodeError as e:
            logger.error(f"❌ خطأ في تنسيق ملف القواعد: {e}")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> Dict[str, List[Dict]]:
        """القواعد الافتراضية للطوارئ"""
        return {
            "high_risk_patterns": [
                {"name": "SQL Injection", "pattern": r"sql\s+injection", "description": "محاولة حقن أوامر SQL خبيثة", "score": 10, "category": "هجوم تطبيقي"},
                {"name": "Ransomware", "pattern": r"ransomware", "description": "اكتشاف برامج الفدية", "score": 10, "category": "برامج ضارة"}
            ],
            "medium_risk_patterns": [
                {"name": "Failed Login", "pattern": r"failed\s+login", "description": "محاولات دخول فاشلة متكررة", "score": 5, "category": "أمان النظام"},
                {"name": "Malware", "pattern": r"malware", "description": "برامج ضارة", "score": 5, "category": "برامج ضارة"},
                {"name": "Unauthorized Access", "pattern": r"unauthorized\s+access", "description": "وصول غير مصرح به", "score": 5, "category": "أمان النظام"}
            ],
            "low_risk_patterns": [
                {"name": "Warning", "pattern": r"warning", "description": "تحذيرات نظام", "score": 1, "category": "مراقبة النظام"},
                {"name": "Timeout", "pattern": r"timeout", "description": "انتهاء مهلة اتصال", "score": 1, "category": "أمان الشبكة"}
            ]
        }
    
    def get_all_rules(self) -> Dict[str, List[Dict]]:
        """الحصول على جميع القواعد"""
        return self.rules
# ==========================
# 🟢 إدارة الملفات
# ==========================
class FileManager:
    """مدير عمليات الملفات"""
    
    @staticmethod
    def read_file(file_path: str) -> str:
        """قراءة الملف مع معالجة الأخطاء"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"الملف غير موجود: {file_path}")
            
            file_size = os.path.getsize(file_path)
            if file_size > Config.MAX_FILE_SIZE:
                raise ValueError(f"حجم الملف كبير جداً: {file_size} بايت")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.info(f"📖 تم قراءة الملف: {file_path} ({file_size} بايت، {len(content.splitlines())} سطر)")
            return content
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
            logger.warning("⚠️  تم قراءة الملف بتشفير latin-1")
            return content
        except Exception as e:
            logger.error(f"❌ خطأ في قراءة الملف: {e}")
            raise

# ==========================
# 🟢 المحلل الرئيسي
# ==========================
class ForensicAnalyzer:
    """المحلل الجنائي الرئيسي"""
    
    def __init__(self):
        self.rule_manager = RuleManager()
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
        found_items = []
        risk_levels_mapping = {
            "high_risk_patterns": {"icon": "🟥", "level": "عالي الخطورة"},
            "medium_risk_patterns": {"icon": "🟠", "level": "متوسط الخطورة"},
            "low_risk_patterns": {"icon": "🟢", "level": "منخفض الخطورة"}
        }
        for rule_category, risk_info in risk_levels_mapping.items():
            for rule in rules.get(rule_category, []):
                try:
                    matches = re.findall(rule['pattern'], content, re.IGNORECASE)
                    if matches:
                        found_items.append({
                            "risk_icon": risk_info["icon"],
                            "risk_level": risk_info["level"],
                            "name": rule['name'],
                            "pattern": rule['pattern'],
                            "count": len(matches),
                            "score": rule.get('score', 1),
                            "description": rule.get('description', 'لا يوجد وصف'),
                            "category": rule.get('category', 'غير مصنف'),
                            "examples": matches[:3],
                            "first_occurrence": matches[0] if matches else ""
                        })
                        logger.info(f"🔍 عُثر على: {rule['name']} ({len(matches)} مرة)")
                except re.error as e:
                    logger.error(f"❌ خطأ في النمط {rule['pattern']}: {e}")
        return sorted(found_items, key=lambda x: x['score'], reverse=True)
    
    def advanced_statistical_analysis(self, content: str) -> Dict[str, Any]:
        """تحليل إحصائي متقدم"""
        lines = content.splitlines()
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
            overall_risk = "🟠 متوسط"
            action_required = "مراقبة مستمرة"
        else:
            overall_risk = "🟢 منخفض"
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
    def generate_text_report(basic_analysis: Dict, suspicious_items: List[Dict], 
                             stats: Dict, analysis_time: float) -> str:
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
            threats_by_level = {}
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
                        report.append(f"     📊 نقاط الخطورة: {threat['score']}")
                        report.append(f"     أمثلة: {', '.join(threat['examples'])}")
        
        report.append("─" * 70)
        report.append("📈 التحليل الإحصائي المتقدم:")
        report.append(f"   • أول حدث: {stats['التحليل_الزمني']['أول_حدث']}")
        report.append(f"   • آخر حدث: {stats['التحليل_الزمني']['آخر_حدث']}")
        report.append(f"   • إجمالي نقاط الخطورة: {stats['تقييم_الخطورة']['نقاط_الخطورة_الإجمالية']}")
        report.append(f"   • مستوى الخطورة الشامل: {stats['تقييم_الخطورة']['مستوى_الخطورة_الشامل']}")
        report.append(f"   • يتطلب تدخل: {stats['تقييم_الخطورة']['يتطلب_تدخل']}")
        report.append(f"   • إجمالي الأحداث: {stats['الإحصائيات_العامة']['إجمالي_الأحداث']}")
        report.append(f"   • التواريخ المختلفة: {stats['الإحصائيات_العامة']['التواريخ_المختلفة']}")
        report.append(f"   • معدل الأحداث في الساعة: {stats['الإحصائيات_العامة']['معدل_الأحداث_في_الساعة']:.2f}")
        report.append("─" * 70)
        report.append("✅ تم إنشاء التقرير بنجاح.")
        return "\n".join(report)
