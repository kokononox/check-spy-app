# تغییرات ۰.۸ — آزمایشی

- خواندن یک qword از خانهٔ محدود stack فقط پس از تطبیق loader، محل توقف، return address، TID، RIP و RSP فریم.
- انتخاب موقت local override context دیباگر و درخواست بازگشت به فریم صفر؛ بدون تغییر حافظه/رجیستر هدف یا ادامه.
- خروجی امن CandidatePoint: فقط دستهٔ ماژول و RVA؛ نه pointer/stack/مسیر خام.
- helper جداگانه، یک‌بار و پشت‌سرهم با metadata؛ بدون retry خودکار.
- ۲۱ آزمون مصنوعی guard/parser/privacy و آزمون واقعی CDB با asm و DLL متعلق به کیت.
- gate ادامه، observer، diagnostic و helper توقف بدون تغییر.
- هیچ گزارش، hash یا تنظیم اختصاصی کاربر به GitHub/CI فرستاده نشده است.
