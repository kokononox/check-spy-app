# کیت پیش از رمزگذاری — نسخهٔ آسان آزمایشی ۰.۲

**برای استفاده، START-HERE-fa.md را بخوان و Start.cmd را باز کن.** مسیر عادی بدون دستور دستی یا ورود PID است.

رابط فارسی فایل EXE را می‌گیرد، پردازشِ در حال اجرا با مسیر یکسان را پیدا می‌کند، CDB را در مسیر پیش‌فرض می‌یابد و دو تأیید ضروری را می‌گیرد. هویت پردازش، زمان ایجاد، x64، hash فایل و امضای Microsoft برای CDB پیش از اتصال بررسی می‌شوند. میان آخرین بررسی و attach هنوز race کوچکی ممکن است.

توقف در حدود ۳۰ ثانیه یا با دکمهٔ توقف امن درخواست می‌شود. helper جداگانه فقط console با CDB ثبت‌شده و خودش را می‌پذیرد؛ با حضور پردازش اضافی، وقفه ارسال نمی‌کند. فرمان ثابت پاک‌کردن breakpoint، بستن لاگ و detach ارسال می‌شود؛ هیچ force-kill در رابط یا helper نیست. اگر توقف تأیید نشود، راهنمای دستی لازم است. خروج خود CDB به‌تنهایی اثبات detach موفق نیست.

## مشاهده چه معنایی دارد؟

کیت حداکثر ۶۴ ورود API و ۱۶ KiB از هر بافر، با سقف مجموع ۲۵۶ KiB، در ورودی عمومی SSPI EncryptMessage می‌خواند. symbol پیش‌فرض sspicli!EncryptMessage است. دیباگر برنامه را موقتاً متوقف می‌کند و breakpoint آن کد اجرا را تغییر می‌دهد؛ مانیتور منفعل نیست.

در کاربرد Schannel، SECBUFFER_DATA ورودی شامل داده پیش از رمزگذاری است؛ اما کیت نوع context را Schannel تأیید نمی‌کند و موفقیت رمزگذاری، ارسال socket یا دریافت سرور را ثابت نمی‌کند. نتیجه «نامزد درخواست» است.

- parser محدود HTTP/1.x: Host، request-target و Content-Length.
- HTTPS بازسازی‌شده از Host/target فرض است، مگر URL مطلق در request-line دیده شود؛ destination socket تأیید نشده است.
- HTTP/2/HPACK، HTTP/3، chunked، فشرده‌سازی و protobuf تفسیر نمی‌شوند.
- بافرهای یک handle محدود کنار هم گذاشته می‌شوند؛ reuse، retry، duplicate یا ترتیب قطعات ممکن است نتیجه را محدود کند. دادهٔ بریده‌شده کامل نامیده نمی‌شود.
- صفر نتیجه، اثبات نبود ارسال نیست؛ مسیر TLS دیگر، symbol، یا نبود فراخوانی در بازه ممکن است دلیل باشد.

## حریم خصوصی و محدودیت اجرای واقعی

فقط محیط ویندوز x64 آزمایشی جداگانه، برنامهٔ مجاز، بدون حساب واقعی/جلسهٔ آنلاین ضدتقلب. اگر محافظت اجازه نمی‌دهد، متوقف شو؛ هیچ دورزدن یا تغییر گواهی/proxy در کیت نیست. تیک‌ها تأیید کاربرند، نه بررسی واقعیِ جدا بودن محیط.

فایل‌های PRIVATE، raw log و body حساس‌اند، حتی اگر گزینهٔ بدنه خاموش باشد. فقط Report-to-share.json پس از بازبینی برای اشتراک طراحی شده؛ URL، هدر، handle و بدنه ندارد. دادهٔ خصوصی نشست در LOCALAPPDATA زیر ExeRouteMonitor/PreTLS-PRIVATE نگه‌داری می‌شود.

## آزمون‌ها

اجرای ویندوز: https://github.com/kokononox/check-spy-app/actions/runs/38140791990

- ۲۴ آزمون مصنوعی هسته در Windows PowerShell 5.1 و PowerShell 7 موفق.
- آزمون ساخت رابط، حدود کنترل‌ها و غیرفعال‌بودن شروع بدون شرایط اولیه موفق؛ آزمون تعامل واقعی کاربر نیست.
- آزمون واقعی CDB روی fixture متعلق به کیت با context عمداً نامعتبر موفق؛ بدون شبکه/TLS handshake/اعتبارنامه.
- helper توقف روی CDB و fixture متعلق به کیت موفق؛ fixture پس از detach زنده ماند. این آزمون CDB-launch بود، نه اتصال رابط به بازی.
- اجرای بازی، حساب/ضدتقلب، همهٔ خطاهای attach و stop، Schannel واقعی و ارسال شبکه تأیید نشده‌اند. مسیرهای Unicode در CDB به‌طور جداگانه آزموده نشده‌اند.

Prepare-Session.ps1 برای کاربران فنی از نسخهٔ قبلی حفظ شده، اما مسیر سادهٔ جدید Start.cmd است. مسیر دستی قدیمی محدودیت ASCII دارد؛ رابط جدید با آن launcher کار نمی‌کند.

منابع رسمی:
- https://learn.microsoft.com/en-us/windows/win32/secauthn/encryptmessage--schannel
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/q--qq--quit-
