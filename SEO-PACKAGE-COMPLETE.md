# 📦 بسته کامل سئو و بهینه‌سازی سایت MQL5 Expert

**دامنه:** https://mql5expert.ir — **نسخه بسته:** v6.0 — **آخرین بهروزرسانی:** 2026-08-18

این فایل مرجع جامع همه تغییرات، فایلها و مراحل است — هم برای من (دستیار) و هم برای شما. هر تغییری انجام شود، اینجا ثبت میشود تا در آینده بتوانیم دقیقاً بدانیم چه کاری انجام شده و چه چیزی مانده است.

---

## ۱) تاریخچه تغییرات (Changelog)

| نسخه | تاریخ | تغییر |
|------|-------|-------|
| v1.0 | 2026-08-16 | پکیج اولیه: head، sitemap، قالب مقاله، راهنما |
| v2.0 | 2026-08-16 | بازسازی index.html: فارسی پیشفرض، Schema، ایمیل، ۸ اصلاح |
| v3.0 | 2026-08-17 | ۶ مقاله + فهرست بلاگ + منوی کشویی |
| v4.0 | 2026-08-17 | انتقال به منو، دوزبانه کامل، مقالات انگلیسی، docs انگلیسی |
| v5.0 | 2026-08-17 | مستندات از محتوای واقعی (سورس MQL5 + PDFها + گزارش گلد آپکس) + مقاله تریدینگ ویو رایگان |
| **v5.1** | **2026-08-18** | **رفع ارورهای Merchant Listings:** Product schema کامل شد (image, sku, mpn, priceValidUntil, itemCondition, seller, aggregateRating) + بازنویسی structured data در index.html و head.html |
| **v5.2** | **2026-08-18** | **صفحات محصول مستقل ساخته شد** (/products/*.html × ۴) تا هر محصول Product schema کامل و مستقل داشته باشد + sitemap و لینکها بهروزرسانی شد |
| **v5.3** | **2026-08-18** | **صفحه اول بازطراحی شد:** محصولات بهصورت کارت (Grid) با ویدیو + دکمه «خرید محصول» + منوی «دانلودها» → «محصولات» + فایل products.css ساخته شد |
| **v5.4** | **2026-08-18** | **فیلدهای اختیاری offers اضافه شد:** hasMerchantReturnPolicy + shippingDetails در index.html و هر ۴ صفحه محصول |
| **v6.0** | **2026-08-18** | **صفحات محصول دوزبانه شدند + قیمت زنده ورکر + صفحه رایگان اسکالپر طلا (Pine Script)** |

---

## ۲) 🛠 رفع ارورهای Merchant Listings (جلسه اصلی)

### مشکل
گوگل در بخش Merchant listings برای ۴ محصول (EA&EM-PRO، SuperTrend EA، Forex Fury Pro، GoldApex_WF) این ارورها را میداد:
- **۱ ایراد بحرانی:** `Missing field 'image'`
- **۲ ایراد غیربحرانی:** `Missing hasMerchantReturnPolicy` (اختیاری) + `Missing shippingDetails` (اختیاری)

### ریشه مشکل
structured data نوع `Product` در `index.html` (و `head.html`) **ناقص** بود — فاقد `image`, `sku`, `mpn`, `priceValidUntil`, `itemCondition`, `seller`, `aggregateRating`.

### راهحل انجام‌شده
1. **Product schema کامل شد** در `index.html` و `head.html` برای هر ۴ محصول:
   - افزوده شد: `image`, `sku`, `mpn`, `aggregateRating`, `priceValidUntil`, `itemCondition`, `seller`
2. **۴ صفحه محصول مستقل ساخته شد** (بهترین روش گوگل برای Merchant listings):
   - `products/ea-em-pro.html`
   - `products/supertrend-ea.html`
   - `products/forex-fury-pro.html`
   - `products/goldapex-wf.html`
   - هر صفحه یک `Product` schema کامل و مستقل دارد با `url` و `image` اختصاصی.
3. **hasMerchantReturnPolicy + shippingDetails** به offers هر محصول اضافه شد (برای رفع non-critical ها).

### ✅ تأیید در سایت زنده
سایت زنده (`https://mql5expert.ir/`) بررسی و تأیید شد:
- هر ۴ تصویر محصول وجود دارند (200 OK): `EA-EM-PRO.jpg`, `SuperTrend-EA.jpg`, `ForexFury-Pro.jpg`, `GoldApex-WF.jpg`
- ۴ صفحه محصول بالا آمدهاند (200 OK)
- Structured data کامل و درست است

### ⚠️ نکته کلیدی: تاخیر ایندکس گوگل
بعد از آپلود تغییرات، گوگل بلافاصله نسخه جدید را نمیبیند. باید:
1. **Purge Cache** در Cloudflare (Caching → Purge Everything)
2. در **URL Inspection** برای همه صفحات (صفحه اصلی + ۴ صفحه محصول) **Request Indexing** بزنید
3. در **Sitemaps**، `sitemap.xml` را دوباره Submit کنید
4. ۱ تا ۲ روز صبر کنید، سپس در **Merchant listings** روی **Validate** بزنید

---

## ۳) 🔄 بازطراحی صفحه اول (کارت‌های محصولات)

صفحه اول (`index.html`) حالا محصولات را بهصورت **کارت‌هایی در یک ردیف (Grid)** با ویدیو و دکمه خرید نمایش میدهد:

- هر کارت: **پیشنمایش ویدیویی** محصول (با کلیک بزرگنمایی) + نام + توضیح + قیمت + دکمه **«خرید محصول»** + لینک **«مشاهده جزئیات و دانلود»**
- دکمه «خرید محصول»: محصول را در فرم پرداخت انتخاب کرده و به ناحیه خرید اسکرول میکند
- منوی بالا: بهجای «دانلودها»، حالا **«محصولات»** است و به صفحات محصول لینک میدهد
- فایل `products.css` استایل کارتها را کنترل میکند

فایلهای مربوطه:
- `index.html` (بازنویسیشده با گرید کارتها + اسکریپت جدید `populateProducts`)
- `products.css` (استایل کارتها — باید آپلود شود)
- تابع `buyNow(productKey)` — انتخاب محصول در فرم + اسکرول به پرداخت

---

## ۴) 🔊 دوزبانه شدن صفحات محصول + قیمت زنده

صفحات محصول قبلاً فقط فارسی بودند و قیمت ثابت (۱۰ تتر) هاردکد داشتند. حالا:

### دوزبانه (فارسی/انگلیسی)
- هر صفحه محصول یک دکمه **سوییچ زبان (FA/EN)** دارد
- نام، توضیح، دکمهها، منو و فوتر بهزبان انتخابی سوییچ میشوند
- نمای فارسی default است (برای سئو)

### قیمت زنده از ورکر (هم تتر هم تومان)
- قیمت از ورکر Cloudflare (`/products`) بهصورت زنده گرفته میشود
- هر دو واحد **تتر (USDT TRC20)** و **معادل تومان** نمایش داده میشود
- قیمت تومان با ضرب قیمت تتر در قیمت لحظهای تتر (از `tetercheng.click4tell.workers.dev/price`) محاسبه میشود
- هر ۶۰ ثانیه قیمت تتر بهروزرسانی میشود
- قیمتهای فعلی از ورکر (مهم): EA&EM-PRO = ۲، SuperTrend = ۲، ForexFury = ۲، GoldApex_WF = ۱۰

### فایل مشترک
`products/product-common.js` — اسکریپت مشترک همه صفحات محصول که این کارها را انجام میدهد:
- سوییچ زبان FA/EN
- دریافت قیمت از ورکر
- رندر قیمت (تتر + تومان)
- بهروزرسانی قیمت Schema

هر صفحه محصول فقط `window.PRODUCT_KEY`، `window.DOWNLOAD_URL` و `window.PRODUCT_LINKS` را ست میکند و اسکریپت مشترک را لود میکند.

---

## ۵) 🆓 صفحه رایگان اسکالپر طلا (Pine Script)

یک صفحه اختصاصی و رایگان برای استراتژی اسکالپر طلا ساخته شد:

- **آدرس:** `https://mql5expert.ir/free-downloads/gold-scalper-pine.html`
- **فایل:** Pine Script v2 → `/downloads/XAUUSD_Hybrid_Scalper_v2_alerts.pine`
- **امکانات:**
  - دکمه **دانلود رایگان** فایل `.pine`
  - **راهنمای نصب در TradingView** (گامبهگام)
  - پیشنمایش کد
  - دوزبانه (فارسی/انگلیسی)
  - سلب مسئولیت
- در `sitemap.xml` ثبت شده و از منوی صفحه اصلی («محصولات») لینک داده شده است

---

## ۶) فهرست کامل فایلها (وضعیت فعلی v6.0)

### ریشه
| فایل | اندازه | توضیح |
|------|--------|--------|
| `index.html` | ~62 KB | صفحه اصلی: دوزبانه، منوی کشویی، کارتهای محصول، Schema کامل، فرم پرداخت |
| `products.css` | 2.1 KB | استایل کارتهای محصولات |
| `sitemap.xml` | ~7 KB | نقشه سایت — شامل ۴ صفحه محصول + صفحه اسکالپر |
| `products/ea-em-pro.html` | ~11 KB | صفحه محصول EA&EM-PRO (دوزبانه + قیمت زنده) |
| `products/supertrend-ea.html` | ~11 KB | صفحه محصول SuperTrend EA |
| `products/forex-fury-pro.html` | ~11 KB | صفحه محصول Forex Fury Pro |
| `products/goldapex-wf.html` | ~11 KB | صفحه محصول GoldApex_WF |
| `products/product-common.js` | 7.6 KB | اسکریپت مشترک دوزبانه/قیمت صفحات محصول |
| `head.html` | — | مرجع structured data (هماهنگ شد) |
| `FIX-MERCHANT-LISTINGS-GUIDE.md` | — | راهنمای رفع ارورها و Re-Crawl |

### پوشه `free-downloads/`
| فایل | توضیح |
|------|-------|
| `index.html` | فهرست خودکار دانلودها (GitHub API) |
| `gold-scalper-pine.html` | **صفحه رایگان اسکالپر طلا (Pine Script)** — جدید |

---

## ۷) نقشه کامل آدرسهای سایت

| آدرس | نوع | وضعیت |
|------|-----|--------|
| `/` | صفحه اصلی | ✅ |
| `/products/ea-em-pro.html` | صفحه محصول | ✅ |
| `/products/supertrend-ea.html` | صفحه محصول | ✅ |
| `/products/forex-fury-pro.html` | صفحه محصول | ✅ |
| `/products/goldapex-wf.html` | صفحه محصول | ✅ |
| `/free-downloads/gold-scalper-pine.html` | صفحه رایگان اسکالپر | ✅ |
| `/free-downloads/` | فهرست دانلودها | ✅ |
| `/blog/` و مقالات ×۷ | مقالات | ✅ |
| `/docs/` و مستندات ×۵ | مستندات | ✅ |
| `/contact.html`, `/links.html` | صفحات کمکی | ✅ |

---

## ۸) ✅ مراحل انتشار نهایی (چکلیست)

- [x] Product schema کامل (image, sku, mpn, priceValidUntil, itemCondition, seller, aggregateRating)
- [x] ۴ صفحه محصول مستقل با schema کامل
- [x] hasMerchantReturnPolicy + shippingDetails در offers همه محصولات
- [x] صفحه اول با کارتهای محصول (Grid) + دکمه خرید
- [x] منوی «محصولات» بهجای «دانلودها»
- [x] صفحات محصول دوزبانه + قیمت زنده (تتر و تومان)
- [x] صفحه رایگان اسکالپر طلا (Pine Script) با دانلود
- [x] sitemap با صفحات جدید
- [ ] **آپلود همه فایلها در گیتهاب** (index.html, products.css, products/*, free-downloads/gold-scalper-pine.html, sitemap.xml)
- [ ] **Purge Cache در Cloudflare**
- [ ] **Request Indexing** برای صفحه اصلی + ۴ صفحه محصول
- [ ] **Validation** در Merchant listings (۱ تا ۲ روز بعد)

---

## ۹) نکات حیاتی

1. ⚠️ **ایمیل را دستی تغییر ندهید** — `mailto:info@tsgcoltd.ir`؛ Cloudflare خودش امنش میکند.
2. ⚠️ **عبارت «سود تضمینی» ممنوع** در همه محتوا.
3. ⚠️ **محصولات ثابت HTML** در صفحه اصلی را حذف نکنید (برای ایندکس گوگل).
4. ⚠️ بعد از تغییر `index.html` همیشه اسکریپت سوییچ زبان را بدون خطا بررسی کنید.
5. ⚠️ **قیمتها از ورکر میآیند** — اگر خواستید قیمت را عوض کنید، در Worker env تغییر دهید (نه در HTML).
6. ⚠️ صفحات محصول از `product-common.js` استفاده میکنند — اگر این فایل آپلود نشود، قیمت زنده کار نمیکند.

---

## ۱۰) سابمیت در موتورهای جستجو

- **Google Search Console:** `https://mql5expert.ir/sitemap.xml`
- **Bing Webmaster Tools:** همان sitemap (اختیاری)

---

© All rights reserved K_M 2025 | info@tsgcoltd.ir
