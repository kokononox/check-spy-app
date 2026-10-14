# پوشش واقعی آرشیو

## داخل Git عمومی
- شرح جامع مراحل، مرزهای شواهد و نیازهای باقی‌مانده.
- source snapshotهای موجود Retail ۰٫۱ تا ۰٫۹، راهنماها، license text و QAهای همراه.
- آزمون‌های تاریخی موجود (ممکن است مسیر sandbox داشته باشند).
- خلاصهٔ مشتق و whitelist‌شدهٔ نتیجه‌های کاربر، نه اصل گزارش‌ها.
- Mermaid/HTML/JSON گراف، manifest با SHA256 فایل‌های منتقل‌شده.

## عمداً خارج Git عمومی
اصل فایل HTML/text گفتگوی قبلی، گزارش‌های اصلی، PCAP/ETL، لاگ واقعی، فایل بازی، private SQLite، اطلاعات حساب/مسیر شخصی/شناسهٔ Notion، توکن/کوکی، کلید TLS/private key و تمام دستورهای داخلی عامل. vendor/TACTTool.exe از بستهٔ ۰٫۲ منتقل نشده؛ license و hash provenance آن نگه داشته شده‌اند. snapshot ۰٫۲ بدون vendor باینریِ مناسب مستقل و قابل اجرا نیست.

## هنوز در دسترس/تولید نشده
- export کامل verbatim پیام‌های این چت جاری. این checkpoint خلاصهٔ جامع عمومی است، نه آن export.
- source همهٔ prototypeهای قدیمی Observer/control-helper در این checkpoint جدید بازگردانی نشده؛ آنچه موجود است از پوشه‌های legacy مخزن و شرح جلسه متمایز است.
- کد/ZIP/QA نسخهٔ ۰٫۱۰، طرح دانلود نهایی، patch chain، CASC writer، rollback و تست نصب کامل Windows.

READMEهای snapshotها توصیف همان بستهٔ تاریخی‌اند، نه ضمانت runnable بودن checkoutِ عمومی بدون binary/dependency. فایل‌های قبلی مخزن حذف/بازنویسی نشده‌اند؛ فقط README ریشه یک پیوند checkpoint جدید می‌گیرد. برای رونوشت کامل خصوصی، فایل export را خصوصی نگه دارید و این snapshot را به آن ضمیمه کنید؛ این پوشش را «تمام گفتگو بدون حذف» معرفی نکنید.
