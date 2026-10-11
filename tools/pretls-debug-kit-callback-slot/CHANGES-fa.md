# تغییرات ۰.۸.۳

- مقایسهٔ مستقل در توقف اولیهٔ مورد انتظار ntdll و breakpoint ناشناختهٔ loader، بدون نیاز به callback/frame1/slot.
- رسید code-windows-result مستقل و تفسیر موفقیت بدون CallbackSlot.
- نام دقیق ConfiguredStopSite: محدودهٔ ثابت loader، نه لزوماً exception فعلی.
- بازنشانی local override با انتخاب مجدد همان نخ در دیباگر؛ بدون اجرای هدف، با TID/RIP guards دقیق.
- زمان‌بندی مستقل و انتظار پایان helper در رابط؛ آزمون تازهٔ تایمر برای هر دو gate.
- آزمون واقعی CDB: normal initial بدون callback، custom DLL breakpoint، کد یکسان و یک بایت اختلاف عمدی در fixture خودمان.
- دروازهٔ ادامه، observer و helper توقف بدون تغییر؛ هیچ دادهٔ کاربر روی GitHub/CI نیست.
