# الأمان / Security

## الحقيقة الأهم

الفحص الذي يتم في `index.html` (الصلاحيات، PIN، القفل) **ليس حماية حقيقية**. أي شخص يفتح أدوات المتصفح يقدر يعدّل `localStorage` أو يقرأ الكود. هو موجود لعرض سلوك النظام وتجربة الأدوار. الحماية الفعلية تكون **من جهة الخادم** فقط، وهذا ما يغطيه المخطط في `backend/supabase/schema.sql`.

## حدود النسخة التجريبية في الحسابات

- الحسابات وكلمات السر (مجزّأة) تُحفظ في `localStorage` داخل متصفح الأدمن فقط. يعني أن موظفاً على جهاز آخر **لن يقدر يدخل** حتى يوجد خادم مشترك.
- زر Google للأدمن محاكى، وأي شخص يفتح الصفحة يقدر يضغطه. في النسخة الفعلية يتحقق الخادم من إيميل الأدمن عبر Google OAuth.
- في الخادم الفعلي: حسابات الموظفين تُنشأ بدالة خادم تستعمل مفتاح `service_role` (لا يوضع في الواجهة أبداً)، ويُحوَّل اسم المستخدم إلى بريد داخلي `user@cafe.otillion.local` لتعمل كلمة السر عبر Supabase Auth، وجدول `platform_admins` يحصر لوحة الأدمن بإيميلك.

## نموذج التهديد

| الخطر | الحل في النسخة الفعلية |
|---|---|
| موظف عادي يعدّل بيانات أو يرفع صلاحيته | Row Level Security: كل جدول مربوط بـ `memberships(role)` عبر `auth.uid()`؛ لا توجد سياسة تسمح بتعديل الدور إلا للمالك مع step-up |
| موظف يشوف بيانات شركة أخرى | كل صف يحمل `tenant_id`، وكل سياسة تتحقق من العضوية |
| موظف فرع يشوف فرعاً آخر | `can_see_branch()` تحصر الكاشير والمطبخ بفرعهم |
| تخمين PIN المدير | `verify_admin_pin()` تخزّن bcrypt، وتقفل بعد 5 محاولات خاطئة، وتسجّل step-up قصير العمر في الجدول `step_ups` |
| إخفاء آثار التلاعب | `audit_log` للإضافة فقط (بدون update/delete)، وتشغّله triggers وليس العميل |
| سرقة جلسة | Supabase Auth (Google OAuth)، مدة جلسة قصيرة، تسجيل خروج عن بُعد |
| التكلفة والهوامش | جدول `inventory_costs` منفصل ولا يقرأه إلا المالك والمدير والمحاسب |

## قبل التشغيل مع زبائن حقيقيين

- راجع `schema.sql` وجرّبه على قاعدة اختبار. **لم يُختبر على قاعدة فعلية بعد.**
- فعّل المصادقة الثنائية على حسابات Supabase وGitHub ومزوّد الدومين.
- لا تضع أي مفتاح `service_role` في الواجهة الأمامية أبداً؛ المفتاح العام `anon` فقط، والباقي عبر RLS.
- فعّل النسخ الاحتياطي اليومي (PITR) واختبر الاستعادة.
- راجع قوانين حماية البيانات المحلية (KVKK في تركيا) بخصوص بيانات الموظفين.
- أضف rate limiting على دوال الدخول وعلى `verify_admin_pin`.
- النقل المهم من العميل إلى الخادم: إرسال الطلب وخصم المخزون، اعتماد الجرد، تغيير الأدوار، إغلاق الحساب. كلها دوال `security definer` تتحقق من الدور والـ step-up.

## الإبلاغ عن ثغرة

أبلغ المالك مباشرة وبشكل خاص، ولا تنشر التفاصيل علناً قبل الإصلاح.

## Loyalty (الولاء)

- Customers are not Auth users: a 64-hex random card token is the only credential. Anyone with the link can view that card, so treat it like a password.
- Loyalty tables have RLS with no policies; everything goes through security-definer RPCs. `anon` can call only `loyalty_public_cafe`, `loyalty_public_join`, `loyalty_public_card`.
- Join is limited per café (30 / 10 min), not per IP. Add a CDN/WAF rule before heavy public use.
- Phone numbers are personal data (KVKK): tell customers what is stored and offer deletion.
