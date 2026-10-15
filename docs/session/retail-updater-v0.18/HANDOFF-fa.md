# راهنمای ادامه

## واقعیت فعلی
- نمونه‌های direct، archive Range، استفاده از کش، پیشروی، و مکث/ادامهٔ برنامه بین فایل‌های کامل آزمایش شده‌اند.[^https://github.com/kokononox/check-spy-app/blob/main/docs/session/retail-updater-v0.18/EVIDENCE-SUMMARY.json]
- آخرین نتیجه: Range >=1 MiB با هش‌های کامل؛ scope همین یک نمونه است.[^https://github.com/kokononox/check-spy-app/blob/main/docs/session/retail-updater-v0.18/EVIDENCE-SUMMARY.json]
- نصب فعلی در تمام گزارش‌های این بخش تغییر نکرده است. updater کامل، CASC writer و rollback نداریم.

## از چه چیزی شروع نکنیم
- آزمون‌های موفق را صرفاً با شمارهٔ نسخهٔ جدید تکرار نکنید؛ prefix match را به صحت فایل یا کل محتوای نصب تبدیل نکنید.
- موفقیت این نمونه‌ها را به ارسال یا عدم ارسال محتوای تلمتری، قطع شبکه در وسط فایل، تمام فایل‌ها یا آخرین نسخهٔ روز تعمیم ندهید.
- فایل گزارش چت را جای ورودی اصلی کنار staging نگذارید. Private SQLite/state/objects را به Git نفرستید.
- queue.lock یا state خراب را برای موفقیت ظاهری پاک نکنید؛ دلیل توقف و احتمال اجرای هم‌زمان باید بررسی شود.

## گام توسعهٔ بعدی — هنوز ساخته نشده
۱. برنامهٔ نصب read-only در کپی جداگانه را طراحی کنید: چه metadata/CASC index تغییر می‌کند، چه اشیایی باید exact-target باشند و چه چیزهایی نامعلوم است.
۲. مرز اعتماد محتوای نصب را روشن کنید؛ prefix+size و نسل‌های تاریخی journal جای payload verification/active generation را نمی‌گیرند.
۳. قالب‌های نصب، ثبت اتمی، تأیید readback، نگه‌داری نسخهٔ قبلی و rollback را قبل از هر writer آزمایش کنید.
۴. ابتدا fixtureهای ساختگی و کپی آزمایشی؛ نصب اصلی را بدون مجوز صریح تغییر ندهید. سقف‌های محدود نمونه را بی‌صدا به دانلود حجیم تبدیل نکنید.

## تجربهٔ کاربر و ایمنی
کاربر دستورهای فارسی کوتاه و یک اقدام در هر نوبت می‌خواهد. دسترسی کنترل دسکتاپ/RustDesk در این جلسه وجود ندارد؛ نصب آن قابلیت اتصال به ما نمی‌دهد. درخواست پشتیبانی را مطرح نکنید. اتصال، اجرای vendor/game، injection یا protection bypass بخشی از مسیر حاضر نیست.

## مرجع‌ها
[TACT](https://wowdev.wiki/TACT)، [CASC](https://wowdev.wiki/CASC)، [BLTE](https://wowdev.wiki/BLTE)، [NGDP](https://wowdev.wiki/NGDP)، [TACTSharp](https://github.com/wowdev/TACTSharp). مرجع ساختارند، نه اثبات نصب‌کنندهٔ کامل بودن نمونه‌ها.
