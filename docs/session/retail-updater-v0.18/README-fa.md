# checkpoint جلسه — WoW Retail تا ۰٫۱۸

**دریافت و اعتبارسنجی نمونه‌ها موفق شده؛ نصب بازی هنوز پیاده نشده است.** این انتقال، ادامهٔ فنی checkpoint تا ۰٫۹ است، نه رونوشت لفظ‌به‌لفظ چت.

- [شرح جلسه و تصمیم‌ها](SESSION-fa.md)
- [راهنمای ادامه](HANDOFF-fa.md)
- [گراف قابل‌ویرایش](GRAPH.md)، [نسخهٔ آفلاین HTML](graph.html)، [دادهٔ گراف](graph.json)
- [خلاصهٔ پاک‌سازی‌شدهٔ شواهد](EVIDENCE-SUMMARY.json)
- [پوشش و موارد حذف‌شده](COVERAGE-fa.md)، [فهرست و هش فایل‌ها](MANIFEST.json)، [کنترل کیفیت آرشیو](ARCHIVE-QA.json)
- [کدهای ۰٫۱۰ تا ۰٫۱۸](../../../archive/retail-updater/README-fa.md)
- [checkpoint تاریخی تا ۰٫۹](../retail-updater-v0.9/README-fa.md)

## آخرین نتیجه
نسخهٔ ۰٫۱۸ یک نمونهٔ آرشیوی 1,049,821 بایتی را با HTTP 206، Content-Range دقیق، طول صحیح و تأیید EKey/چانک‌ها و CKey بازشده دریافت کرده است. نمونه فقط کمی بیش از ۱ MiB است، نه کل آرشیو یا آزمون تمام اندازه‌ها.[^https://github.com/kokononox/check-spy-app/blob/main/docs/session/retail-updater-v0.18/EVIDENCE-SUMMARY.json]

در ۰٫۱۷ مکث برنامه پس از دو فایل و ادامهٔ شش فایل همان دسته تأیید شد؛ این آزمون بین فایل‌های کامل است، نه قطع واقعی شبکه در وسط پاسخ.[^https://github.com/kokononox/check-spy-app/blob/main/docs/session/retail-updater-v0.18/EVIDENCE-SUMMARY.json]

## مرز نتیجه
هیچ نصب CASC، patch chain، rollback یا نسخهٔ به‌روزشدهٔ قابل بازی تأیید نشده است. مانیتور قبلی ۲٫۷ و آرشیو ۰٫۱ تا ۰٫۹ دست‌نخورده باقی مانده‌اند. گزارش‌های خام، کلیدها/اطلاعات حساب، دادهٔ بازی و فایل‌های خصوصی منتشر نمی‌شوند.
