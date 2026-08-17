# راهنمای سئو سایت MQL5 Expert — README-SEO

**دامنه:** https://mql5expert.ir — **میزبان:** GitHub Pages + Cloudflare — **زبان:** فارسی/انگلیسی

این راهنما مرجع سریع تنظیمات و نگهداری سئوی سایت است. بسته کاملتر: `SEO-PACKAGE-COMPLETE.md`.

---

## ۱) وضعیت فنی (تأییدشده)

| مورد | وضعیت |
|------|--------|
| HTTPS / CDN | ✅ Cloudflare |
| robots.txt | ✅ گوگل مجاز (مدیریتشده Cloudflare) |
| sitemap.xml | ✅ ۲۸ آدرس (فارسی + انگلیسی + مستندات) |
| Canonical / OG / Twitter | ✅ در head صفحات |
| Schema.org | ✅ WebSite، Organization، Product، FAQPage، Article |
| ایندکس در گوگل | ✅ صفحه اصلی Index شده |
| زبان پیشفرض | ✅ فارسی (`lang="fa" dir="rtl"`) |

## ۲) فایلهای کلیدی

| فایل | نقش |
|------|------|
| `index.html` | صفحه اصلی (دوزبانه، منوی کشویی، Schema) |
| `sitemap.xml` | نقشه سایت — بعد از هر صفحه جدید بهروز شود |
| `blog/index.html` | فهرست مقالات و گزارشها |
| `docs/*.html` | مشخصات و تحلیل محصولات (فارسی/انگلیسی) |

## ۳) Google Search Console

1. **تایید دامنه:** Domain property → رکورد DNS در Cloudflare
2. **سابمیت sitemap:** `https://mql5expert.ir/sitemap.xml`
3. **URL Inspection:** `https://mql5expert.ir/` → Request Indexing
4. بعد از هر محتوای جدید: URL Inspection صفحه → Request Indexing

## ۴) Cloudflare (تنظیمات پیشنهادی)

- **Caching → Configuration → Crawler Hints:** روشن ✅
- **Caching → Configuration → Purge Everything:** بعد از هر آپلود
- **SSL/TLS:** Full
- **Bots:** مطمئن شوید Bot Fight Mode ربات گوگل را بلاک نمیکند

## ۵) استراتژی محتوا (کلید رتبه گرفتن)

سایت یکصفحهای بهتنهایی برای «ربات فارکس» رتبه نمیگیرد؛ محتوا لازم است:

- هر ماه ۲ تا ۴ مقاله فارسی + نسخه انگلیسی در `blog/` و `blog/en/`
- کلمات هدف: ربات فارکس، اکسپرت، نصب اکسپرت در متاتریدر 5، سوپرترند، فارکس فیوری، گلد آپکس
- هر مقاله: عنوان/متا بهینه + Schema Article + لینک داخلی به صفحه اصلی و محصول مرتبط
- هر مقاله جدید = ۳ اقدام: فایل مقاله + یک خط در `blog/index.html` + یک خط در `sitemap.xml`

## ۶) چکلیست هر ماه

- [ ] ۲–۴ مقاله جدید (فارسی + انگلیسی)
- [ ] آپلود + Purge Cache
- [ ] درخواست ایندکس در GSC
- [ ] بررسی Performance در GSC و اصلاح کلمات ضعیف

## ۷) نکات مهم

- ⚠️ از «سود تضمینی» در هیچ متنی استفاده نکنید.
- ⚠️ صفحه اصلی فقط یک H1 داشته باشد.
- ⚠️ محتوای محصولات (کارکن Cloudflare Worker) در HTML نیست؛ نام و توضیح محصولات بهصورت متن ثابت در صفحه اصلی مانده است — حفظ کنید.
- ✅ سلب مسئولیت و هشدار ریسک در همه صفحات باشد.

---

© All rights reserved K_M 2025 | info@tsgcoltd.ir
