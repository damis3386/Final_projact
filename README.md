# Digital Forensics Tool

## 1️⃣ عن المشروع
أداة التحليل الجنائي الرقمي مع توليد تقارير آلية تساعد على جمع وتحليل الأدلة الرقمية بسرعة ودقة.  
تهدف إلى تسهيل عمليات التحقيق في الملفات والسجلات الرقمية (Logs) وإنشاء تقارير PDF/Word احترافية.

---

## 2️⃣ خطوات التشغيل

1. تثبيت Python وVS Code وGit.  
2. إنشاء المجلد الرئيسي: digital_forensics_tool.  
3. إعداد البيئة الافتراضية:
`bash
python -m venv venv
.\venv\Scripts\Activate

4. تثبيت المكتبات الأساسية:



pip install pandas flask reportlab

5. إنشاء ملفات المشروع:



app.py

analysis.py

reportgen.py

rules.json


6. إنشاء المجلدات الفرعية:



data/ → لحفظ الملفات الخام (Logs، الملفات المرفوعة).

results/ → لتخزين نتائج التحليل والتقارير.

uploads/ → لتحميل الملفات من المستخدمين.

tests/ → للاختبارات وتجربة الأكواد.



---

3️⃣ كيفية استخدام المشروع

1. تفعيل البيئة الافتراضية:



.\venv\Scripts\Activate

2. تشغيل البرنامج:



python app.py

3. رفع الملفات أو تحليل الـ Logs داخل مجلد uploads/.


4. استخراج التقارير من results/ بصيغة PDF أو Word.




---

4️⃣ هيكل المشروع

digital_forensics_tool/
│
├── app.py
├── analysis.py
├── reportgen.py
├── rules.json
├── README.md
├── venv/
├── data/
├── results/
├── uploads/
└── tests/


---

5️⃣ المصادر والمكتبات

Python 3.x

VS Code

Git

pandas

flask

reportlab
