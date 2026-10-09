# مسیرهای رسمی پس از شکست بازرسی TLS

## نتیجه تحقیق
در منابع عمومی رسمی بررسی‌شده، دستور پشتیبانی‌شده‌ای برای صدور کلید TLS یا export متن دقیق payload تله‌متری WoW پیدا نشد. این نتیجه جست‌وجوی محدود است، نه اثبات نبود هرگونه ابزار داخلی یا قابلیت پشتیبانی. پارامتر حدسی برای EXE، combat logging یا صرفاً بزرگ‌ترکردن لاگ به عنوان راه خواندن تله‌متری معرفی نمی‌شود.

## ۱. LogGoblin — جمع‌آوری لاگ، نه رمزگشایی
منبع رسمی: https://us.battle.net/support/en/article/28923
عنوان: Gathering Battle.net Desktop App Logs

مقاله رسمی می‌گوید این ابزار لاگ‌های Battle.net desktop app را برای عیب‌یابی جمع‌آوری می‌کند. روال Windows در مقاله: دریافت ابزار از لینک خود مقاله، بستن بازی‌ها و Battle.net، اجرای LogGoblin، انتظار برای جمع‌آوری، Enter برای پایان؛ ZIP در محل همان ابزار ساخته می‌شود. این ابزار لاگ لانچر است و مستند مذکور ادعای capture متن تمام payloadهای WoW ندارد.

خروجی می‌تواند حساس باشد. ZIP خام را در GitHub عمومی یا گفتگو منتشر نکن. ابتدا تنها فهرست نام فایل‌ها/نوع بخش‌ها بدون مسیر شخصی و مقدارها بررسی شود. به علت روشن‌نبودن شرایط بازتوزیع ابزار، باینری LogGoblin در مخزن یا بسته خودمان کپی نمی‌شود؛ از لینک رسمی دریافت شود. دستورهای قدیمی انجمن مثل ارسال به ایمیل مشخص یا تغییر WMI به این مورد تعمیم داده نمی‌شوند.

## ۲. درخواست داده‌های حساب و بازی — مسیر پیشنهادی برای دانستن داده‌های نگهداری‌شده
منبع رسمی: https://support.blizzard.com/en/help/product/services/1327/1329
مسیر صفحه: Data Protection → Request my data → Access my Battle.net Account and game data

کاربر در مرورگر خودش وارد حساب شود و درخواست را خودش ثبت کند. در این تحقیق هیچ حسابی وارد نشد و هیچ درخواست یا لاگی به Blizzard ارسال نشد.

این export ممکن است روشن کند چه داده‌های شخصی تحت پاسخ دسترسی داده ارائه می‌شوند، اما تضمینی نیست که همه تله‌متری، داده‌های ضدتقلب، اطلاعات حذف‌شده یا تمام بسته‌های شبکه در آن باشند. export را معادل ضبط شبکه یا فهرست کامل اطلاعات هر اجرا ندان.

پاسخ خام می‌تواند شامل اطلاعات حساب/ارتباط/خرید باشد؛ در مخزن عمومی منتشر نشود. برای کمک تحلیلی ابتدا فقط فهرست نام بخش‌ها یا schema بدون مقدارهای شخصی استفاده شود. اگر بخش‌های مرتبط با device/system/telemetry وجود داشتند، مقدارها قبل از اشتراک پوشانده شوند.

## ۳. آنچه شرکت اعلام کرده — نه اثبات capture کاربر
منابع:
- https://www.blizzard.com/privacy
- https://www.blizzard.com/en-us/legal/a4380ee5-5c8d-4e3b-83b7-ea26d01a9918/blizzard-entertainment-online-privacy-policy

سیاست عمومی به IP، اطلاعات سخت‌افزار/نرم‌افزار، gameplay و usage data و در شرایط مربوط ارتباط‌های بازی اشاره می‌کند. Privacy World نیز اطلاعات عمومی دستگاه و نحوه بازی را توضیح می‌دهد. دامنه سند کل محصولات/سرویس‌هاست؛ نمی‌توان از آن نتیجه گرفت هر دسته در همین اتصال telemetry-in.battle.net از این EXE ارسال شده است.

ثبت محلی CPU/GPU/OS در لاگ‌های قبلی ثابت بود؛ ارسال همان مقدارها همچنان از capture کاربر اثبات نشده است. CA آزمایشی در گزارش آخر نصب شد، client TLS شکست خورد و هیچ HTTP خوانایی ثبت نشد؛ cleanup موفق طبق همان گزارش ثبت شد. pinning تشخیص قطعی نیست.

## متن پیشنهادی پرسش از پشتیبانی / تیم حفاظت داده
این متن را می‌توان در تیکت خود کاربر کپی کرد؛ هنوز ارسال نشده است:

> I am trying to understand what system and device information World of Warcraft on Windows 11 sends to telemetry-in.battle.net. Please explain the categories or schema of telemetry data collected, including whether CPU/GPU/OS details, device identifiers, computer or Windows user names, motherboard/BIOS identifiers, serial numbers, or installed application information are collected. I am asking whether these categories are collected, not asserting that they are.
>
> Is there a supported local diagnostic log or export that lets me review the outgoing telemetry without disabling TLS validation or bypassing client protections? Does a Battle.net Account and game data access export include this telemetry, and what are the applicable retention periods or exclusions?
>
> A local proxy tunnel test worked for some connections, but the client-side TLS handshake failed during a separate certificate-based inspection test. This does not establish certificate pinning. I do not want to bypass security controls. Please advise on the supported method.

هیچ نام حساب، ایمیل، شناسه، raw log یا اطلاعات سخت‌افزار واقعی در متن عمومی بالا قرار داده نشده است.
