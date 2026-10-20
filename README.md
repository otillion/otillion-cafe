# Otillion

منصة إدارة كافيهات ومطاعم **متعددة المنشآت والفروع**: كاشير وطاولات، مطبخ وبار، مخزون ووصفات، تقارير، مراقبة عن بُعد، وإدارة موظفين. الواجهة عربي / تركي (RTL / LTR) وتعمل على الكمبيوتر والموبايل.

Otillion is a multi-tenant, multi-branch café management system (POS, kitchen/bar display, recipe-based inventory, reports, remote monitoring, staff management). UI: Arabic / Turkish.

## الحالة الحالية: نموذج تجريبي (demo)

`index.html` ملف واحد يعمل مباشرة في المتصفح. دخول الأدمن الرئيسي عبر Google **محاكى**، والبيانات تُحفظ في `localStorage` داخل متصفح المستخدم فقط. هذا النموذج لعرض الفكرة والتصميم وسير العمل. **لا تستعمله ببيانات حقيقية للزبائن.**

التشغيل الحقيقي يحتاج backend (الخطوات في `SECURITY.md`، والمخطط الجاهز للمراجعة في `backend/supabase/schema.sql`).

## طريقة الدخول

- **الأدمن الرئيسي (صاحب المنصة):** يدخل بإيميله (Google)، ويرى كل المنشآت، وينشئ منشأة جديدة، وينشئ حسابات (اسم مستخدم + كلمة سر + دور + فرع) لكل منشأة، ويعيّن كلمات السر، ويوقف أو يفعّل حساباً أو منشأة بأكملها، ويفتح أي منشأة كمالك.
- **الموظفون والكافيهات:** يدخلون باسم المستخدم وكلمة السر فقط، ويدخلون مباشرة على منشأتهم وبدورهم، بدون Google وبدون اختيار منشأة. لا يقدرون يغيّروا دورهم أو يدخلوا منشأة غيرهم.
- الحسابات تُنشأ من الأدمن فقط. كلمات السر تُخزَّن مجزّأة (hash مع salt)، والقفل المؤقت بعد 5 محاولات خاطئة.

## الوحدات

| الوحدة | الوصف |
|---|---|
| نظرة عامة | كل الفروع في شاشة واحدة: مبيعات اليوم، المفتوح، مخزون قليل، الموظفون في الوردية، تنبيهات، آخر المبيعات |
| الكاشير | طاولات وتيك أواي، تعديل الطلب، نقل طاولة، دمج حسابات، تقسيم بالتساوي أو حسب الأصناف، دفع نقدي/بطاقة |
| المطبخ | توجيه الأصناف للمطبخ أو البار، شاشة KDS، شاشة دور للزبائن، توجيه الطابعات |
| المخزون | خصم حسب الوصفة، تنبيه الحد الأدنى، تكلفة وهامش، جرد ومقارنة النظري بالفعلي |
| التقارير | حسب الساعة واليوم والتصنيف، الأكثر مبيعاً، أداء الموظفين، الصندوق |
| الموظفون | دوام، ورديات، إجازات بالموافقة، أداء، ملفات الموظفين والدعوات |
| الإعدادات | رمز المدير، مصفوفة الصلاحيات، الطابعات، سجل العمليات |

## الأمان (ما هو مطبّق في النموذج)

- خمسة أدوار: مالك، مدير، محاسب، كاشير، مطبخ. كل عملية تُفحص صلاحيتها في الكود، وليس بإخفاء الأزرار فقط.
- عمليات حساسة تتطلب **رمز PIN للمدير** (إلغاء صنف مُرسل، اعتماد الجرد، دعوة موظف، تغيير دور أو فرع، توجيه الطابعات، تعطيل حساب، رفع الصلاحية). التأكيد صالح دقيقتين، ويُلغى عند خفض الدور.
- قفل بعد 5 محاولات PIN خاطئة لمدة دقيقة، وقفل تلقائي للشاشة بعد 5 دقائق بلا نشاط (عدا شاشة المطبخ).
- الموظف العادي لا يقدر يرفع صلاحيته: الدور الأعلى من دور الحساب مرفوض أصلاً، وما دونه يحتاج PIN.
- التكلفة والهامش مخفية عن الأدوار التي لا تملك `costView`.
- كل العمليات الحساسة والمحاولات المرفوضة تُسجَّل في سجل العمليات.

**رمز المدير في المنشآت التجريبية الجاهزة (Mavi وLiman):** `1234`. المنشآت التي تنشئها أنت تأخذ رمزاً تختاره أنت (ثابت `DEMO_PIN` في `index.html`، وللعرض فقط).

## التشغيل محلياً

افتح `index.html` في المتصفح، أو شغّل خادماً بسيطاً:

```
python3 -m http.server 8080
```

## الخطوات التالية

1. إنشاء مشروع Supabase، وتشغيل `backend/supabase/schema.sql`، وتفعيل Google كمزوّد دخول.
2. استبدال طبقة `localStorage` في `index.html` باستدعاءات Supabase (الدخول، والقراءة والكتابة عبر RLS).
3. نقل العمليات الحساسة (إرسال الطلب وخصم المخزون، الجرد، تغيير الأدوار) إلى دوال في قاعدة البيانات.
4. ربط الطابعات وشاشات المطبخ فعلياً، ثم الرواتب والاشتراكات.

## Live setup (Supabase)

- Backend: Supabase project `mrlkatgniijrlkkkqfgk` (schema in `backend/supabase/schema.sql`, RLS on every table, security-definer RPCs).
- Public sign-up is disabled. The first authenticated user with no membership becomes the platform admin (`me()` bootstrap).
- The admin creates cafés and staff accounts (username + password) from the admin console; staff sign in and land directly in their café.
- LIVE mode activates automatically on github.io / localhost; elsewhere the app runs as a local demo.
- Limits: tenant data is one JSON blob per café (last-write-wins, polled every 10 s). Table-by-table RPCs are planned for phase 2.

## Loyalty module (نقاط الولاء)

- Run `backend/supabase/loyalty.sql` in the Supabase SQL editor **after** `schema.sql`.
- Platform admin: Admin console → "Loyalty" panel → per café: enable, slug, brand name, color, logo, goal (2–30 points), reward text, earn mode (per visit / per amount).
- Café staff (owner / manager / cashier): "Loyalty" tab → search or add customer, add a point, redeem a ready reward, copy the join link / QR.
- Customers (no Auth account): `?c=<slug>` to join (name + phone), `?card=<token>` to open their card. The token lives in the URL and localStorage.
- Not included: Apple/Google Wallet, NFC, push notifications, per-IP rate limit on join (only 30 joins / 10 min per café).
