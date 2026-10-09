# راهنمای ادامه کار

## ابتدا
۱. README و app/TLS-TEST-fa.md را بخوان. هدف دفاعی و بررسی دستگاه خود کاربر است؛ نتیجه را به سرقت/جاسوسی قطعی تبدیل نکن.
۲. فایل فعلی اجرا app/Start-TLS-Test.cmd است. بازی را با ادمین اجرا نکن؛ Root فقط CurrentUser با تأیید جدا و گواهی تازه است.
۳. کاربر برای آماده‌سازی بازرسی محدود موافقت کرده است؛ برای هر اجرای CA پیام رضایت مستقل باقی بماند.
۴. در صورت شکست TLS متوقف شو. از ssl_insecure، غیرفعال‌کردن pinning، تزریق/استخراج حافظه، خاموش‌کردن AV یا تغییر سیاست امنیتی استفاده نکن.

## بررسی گزارش بعدی
- نوع مورد انتظار ScopedTelemetryTLSInspection / TelemetryReport است، نه NetworkReport.
- Cleanup.CertificateAbsent و ProxyStopped را قبل از ادامه بررسی کن. اگر false/unknown بود، Cleanup-TLS.cmd همان حساب و بررسی خطا اولویت دارد.
- Summary.ClientTLSFailures/ServerTLSFailures، AttributionFailures و تعداد Requests را کنترل کن.
- TLSClientEstablished، قالب BodyFormat، FieldCategories، LocalIdentifierMatches و ResponseStatus را جدا تفسیر کن. مشاهده request در پروکسی قبل از ارسال، رسیدن به سرور را به‌تنهایی ثابت نمی‌کند.
- FieldCategories تنها نام دسته‌ها هستند؛ مقدارهای واقعی یا اینکه آن‌ها متعلق به سیستم کاربرند مشخص نیست مگر تطبیق معتبر یا شواهد مستقل.
- برای protobuf/encoding ناشناخته، نبود فیلد را امن/خالی محسوب نکن. raw capture/key یا لاگ کامل را به مخزن عمومی نیاور.

## کارهای مهندسی باقی‌مانده
- آزمون زنده Windows 11 برای CurrentUser Root import/removal، ACL خصوصی، PID attribution، PyInstaller process-tree shutdown، guard و recovery پس از خاموشی.
- QA واقعی WinForms/Explorer/STA و رفتار timeout روی دستگاه واقعی؛ تصویر قبلی فقط نسخه قدیمی را نشان داده بود.
- portable کردن test harnessهای تاریخی؛ برخی مسیرهای sandbox برای نگهداری سابقه مانده‌اند و CI آماده نیست.
- افزودن واحدهای شمارش روشن برای CONNECT: تفکیک تونل از نشست TLS و فریم از درخواست/byte.
- ارزیابی عدم ذخیره flow/raw body توسط تنظیمات vendor و رفتار limit/streaming؛ fuzz حد اندازه/عمق و encoding.
- تست رد SNI/HTTP authority خارج از دامنه و جلوگیری از SAN اضافی؛ upstream_cert=false و upstream validation روشن بمانند.
- ارائه package/release پس از تأیید Windows؛ فایل باینری vendor در Git نیست و downloader هش پین‌شده را کنترل می‌کند.

## نکات معماری
- Normalize فقط وقتی همه فریم‌های interface قالب سخت‌گیرانه پشتیبانی‌شده دارند؛ کپی مشتق و hash، نه تغییر raw.
- Sysmon موجود را خودکار overwrite نکن. Readable بودن log به معنی فعال بودن event 3/22 نیست.
- native stderr در PS5 باید از error pipeline جدا باشد؛ exit nonzero گزارش موفق نمی‌سازد. quarantine warning گزارش را partial می‌کند.
- هیچ ادعای پوشش همه مقصدها، decode همه payloadها یا مستقل‌بودن EXE بدون اسکریپت‌ها نکن.
