# تغییرات ۰.۷ — آزمایشی

- جمع‌آوری خواندنی در first-chance AccessViolation اولیه، نه فقط breakpoint اولیه.
- تطبیق کد رخداد با exception record و هدف؛ رد second-chance/تغییر رخداد/رکورد ناقص/ادامهٔ قبلی.
- ثبت .exr در همان helper آغاز همراه مشخصات loader و stack محدود.
- بدون تغییر شرط ادامه؛ بدون g/gn/interrupt/patch در helper خواندنی.
- ۳۳ آزمون مصنوعی parser/حریم خصوصی/شرایط پذیرش؛ آزمون واقعی CDB با AV مصنوعی اولیه و DLL خود کیت.
- هیچ فایل یا گزارش کاربر به مخزن عمومی یا Actions فرستاده نشده است.
