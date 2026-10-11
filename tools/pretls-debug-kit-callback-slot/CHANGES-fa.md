# تغییرات ۰.۸.۲ — مقایسهٔ محدود کد

- EntryRVA اختیاری در پروفایل؛ تطبیق دو پنجرهٔ executable و file-backed با hash منطبقِ فایل loader.
- خواندن ۳۲+۱۶ بایت پس از guard قبلی و تطبیق دوبارهٔ مقدار slot با entry.
- خروجی امن فقط hash/وضعیت/offset اختلاف و byteهای cc؛ بدون raw code یا pointer.
- ۱۷ آزمون parser/PE-range/privacy؛ آزمون واقعی CDB برای کد یکسان و یک بایت اختلاف عمدی در fixture خودمان.
- دروازهٔ ادامه، observer، UI اصلاح‌شده، helper توقف و خطا بدون تغییر.
- هیچ فایل/کد/پروفایل/hash اختصاصی کاربر به CI فرستاده نشده است.
