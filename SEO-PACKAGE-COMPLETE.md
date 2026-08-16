# 📦 پکیج کامل سئو — سایت MQL5 Expert (mql5expert.ir)

> **تاریخ تهیه:** ۱۶ مرداد ۱۴۰۵
> **هدف:** بهبود رتبه سایت در گوگل برای کلمات «ربات فارکس»، «اکسپرت»، «متاتریدر 5» و...
> **میزبان:** GitHub Pages + Cloudflare

---

## 📑 فهرست مطالب

1. [فهرست فایل‌ها و محل قرارگیری](#1-فهرست-فایل‌ها)
2. [راهنمای گام‌به‌گام راه‌اندازی](#2-راهنمای-گامبهگام)
3. [کد فوتر: سلب مسئولیت + کپی‌رایت](#3-کد-فوتر)
4. [کد کامل head.html](#4-کد-کامل-headhtml)
5. [کد کامل index.html (نسخه بهینه‌شده)](#5-کد-کامل-indexhtml)
6. [کد کامل sitemap.xml](#6-کد-کامل-sitemapxml)
7. [مقالات بلاگ](#7-مقالات-بلاگ)
8. [نکات مهم و یادآوری‌ها](#8-نکات-مهم)

---

## 1. فهرست فایل‌ها

| فایل | محل قرارگیری در ریپو | توضیح |
|------|----------------------|--------|
| `index.html` | ریشه (جایگزین فایل فعلی) | نسخه کامل بهینه‌شده سایت + بخش بلاگ |
| `sitemap.xml` | ریشه | نقشه سایت (۷ آدرس) |
| `head.html` | مرجع (اختیاری) | بخش head بهینه |
| `blog/index.html` | پوشه `blog/` | فهرست همه مقالات (دکمه بلاگ به اینجا لینک است) |
| `blog/what-is-forex-robot.html` | پوشه `blog/` | مقاله: ربات فارکس چیست |
| `blog/how-to-install-expert-in-metatrader5.html` | پوشه `blog/` | مقاله: آموزش نصب اکسپرت |
| `blog/supertrend-expert-advisor.html` | پوشه `blog/` | مقاله: اکسپرت سوپرترند |
| `blog/best-forex-trading-robots-2026.html` | پوشه `blog/` | مقاله: بهترین ربات فارکس 2026 |
| `blog/expert-vs-indicator-mt5.html` | پوشه `blog/` | مقاله: فرق اکسپرت و اندیکاتور |
| `blog/forex-fury-review.html` | پوشه `blog/` | مقاله: بررسی فارکس فیوری |
| `blog-article-template.html` | مرجع (اختیاری) | قالب مقاله برای مقالات بعدی |
| `README-SEO.md` | مرجع (اختیاری) | راهنمای کوتاه |
| `SEO-PACKAGE-COMPLETE.md` | مرجع (اختیاری) | همین فایل جامع |

---

## 2. راهنمای گام‌به‌گام

### قدم ۱ — آپلود فایل‌ها در گیت‌هاب
1. `index.html` جدید را جایگزین فایل فعلی ریشه ریپو کنید (فایل قبلی را برای پشتیبان نگه دارید).
2. `sitemap.xml` را در ریشه قرار دهید.
3. پوشه `blog/` بسازید و فایل `index.html` + ۶ مقاله را داخل آن بگذارید.
4. Commit و Push.

### قدم ۲ — Cloudflare
1. داشبورد Cloudflare → دامنه `mql5expert.ir` → **Caching → Configuration → Crawler Hints** را روشن کنید.
2. **Caching → Purge Everything** بزنید (بعد از هر تغییر سایت).

### قدم ۳ — Google Search Console
1. دامنه را وریفای کنید (DNS یا HTML file).
2. **Sitemaps** → آدرس کامل `https://mql5expert.ir/sitemap.xml` را سابمیت کنید (برای Domain property باید آدرس کامل باشد).
3. **URL Inspection** → آدرس هر صفحه جدید → **Request Indexing**.
4. پیام «URL is on Google» یعنی ایندکس شده ✅.

### قدم ۴ — افزودن مقاله جدید (برای آینده)
1. مقاله را با قالب `blog-article-template.html` در پوشه `blog/` بسازید.
2. یک خط لینک به `blog/index.html` اضافه کنید.
3. آدرس مقاله را به `sitemap.xml` اضافه کنید.
4. Push + Purge Cache + درخواست ایندکس.
> ✅ نیازی به تغییر صفحه اصلی نیست — دکمه بلاگ به `blog/` لینک شده.

### قدم ۵ — سابمیت در موتورهای دیگر (اختیاری)
- Bing Webmaster Tools: `bing.com/webmasters` → سابمیت sitemap.

---

## 3. کد فوتر

### HTML (سلب مسئولیت + کپی‌رایت)

```html
<footer>
    <div class="footer-container">

        <!-- ═══ باکس سلب مسئولیت ═══ -->
        <div class="disclaimer-box">
            <p class="disclaimer-title" data-fa="سلب مسئولیت" data-en="Disclaimer">سلب مسئولیت</p>
            <p class="disclaimer" data-fa="مسئولیت سود و زیان ناشی از تصمیمات معاملاتی کاملاً بر عهده کاربر است و تجارت فارکس مسئولیتی در قبال زیان‌های احتمالی ندارد. معرفی و بررسی بروکرها کاملاً بی‌طرفانه است. ما هیچ‌گونه مسئولیتی در قبال عملکرد، تخلفات یا مشکلات احتمالی بروکرها نداریم." data-en="Responsibility for profits and losses arising from trading decisions rests entirely with the user, and Forex trading bears no responsibility for any potential losses. Broker introductions and reviews are completely impartial. We accept no responsibility for the performance, violations, or potential problems of brokers.">
                مسئولیت سود و زیان ناشی از تصمیمات معاملاتی کاملاً بر عهده کاربر است و تجارت فارکس مسئولیتی در قبال زیان‌های احتمالی ندارد.<br>
                معرفی و بررسی بروکرها کاملاً بی‌طرفانه است.<br>
                ما هیچ‌گونه مسئولیتی در قبال عملکرد، تخلفات یا مشکلات احتمالی بروکرها نداریم.
            </p>
        </div>

        <!-- ═══ کپی‌رایت ═══ -->
        <p class="copyright" data-fa="© All rights reserved K_M 2025 | info@tsgcoltd.ir" data-en="© All rights reserved K_M 2025 | info@tsgcoltd.ir">
            © All rights reserved K_M 2025 <span class="separator">|</span>
            <a href="mailto:info@tsgcoltd.ir">info@tsgcoltd.ir</a>
        </p>

    </div>
</footer>
```

### CSS فوتر

```css
footer {
    background-color: #f9fafb;
    padding: 15px 20px;
    text-align: center;
    border-top: 1px solid #e5e7eb;
    box-shadow: 0 -2px 4px rgba(0, 0, 0, 0.1);
    font-family: 'Arial', sans-serif;
    font-size: 14px;
    color: #374151;
    margin-top: 20px;
    width: 100%;
    box-sizing: border-box;
}

.footer-container {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;   /* باکس سلب مسئولیت بالا، کپی‌رایت پایین */
    align-items: center;
    justify-content: center;
    white-space: normal;      /* اجازه شکستن خط به متن بلند */
}

/* خط کپی‌رایت — فقط این یک‌خطی و افقی بماند */
.copyright {
    margin: 0;
    display: inline-flex;
    align-items: center;
    flex-wrap: nowrap;
}

footer a {
    color: #1d4ed8;
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s ease;
}

footer a:hover {
    color: #1e40af;
    text-decoration: underline;
}

.separator {
    margin: 0 10px;
    color: #9ca3af;
}

/* ═══ باکس سلب مسئولیت ═══ */
.disclaimer-box {
    border: 1px solid #e0e0e0;
    border-radius: 10px;
    background: #f3f4f6;
    padding: 14px 20px;
    margin-bottom: 14px;
    max-width: 900px;
    width: 100%;
    box-sizing: border-box;
}

.disclaimer-title {
    font-size: 13px;
    font-weight: bold;
    color: #555;
    margin: 0 0 8px 0;
}

.disclaimer {
    font-size: 12px;
    color: #6b7280;
    line-height: 2;
    text-align: center;
    margin: 0;
    display: block;
    white-space: normal;
}

/* حالت فارسی: راست‌چین */
html[lang="fa"] .disclaimer { direction: rtl; text-align: right; }
html[lang="fa"] .copyright  { direction: rtl; }

@media (max-width: 600px) {
    footer { font-size: 12px; padding: 10px 15px; }
    .footer-container { flex-wrap: nowrap; }
    .separator { margin: 0 5px; }
    .disclaimer-box { padding: 10px 12px; }
}

@media (min-width: 768px) {
    header { height: 300px; padding-top: 120px; }
}
```

---

## 4. کد کامل head.html

> بخش `<head>` بهینه‌شده — قبلاً داخل `index.html` اعمال شده است. (عنوان، Canonical، Open Graph، Twitter Card و ۴ نوع Schema: WebSite، Organization، ItemList محصولات، FAQPage)

```html
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>خرید اکسپرت و ربات فارکس برای متاتریدر 5 | ربات معاملاتی MT5</title>
    <meta name="description" content="خرید اکسپرت و ربات فارکس برای متاتریدر 5: ربات سوپرترند، اکسپرت فارکس فیوری، ربات گلد آپکس و اندیکاتور معاملاتی با پشتیبانی کامل و معرفی بی‌طرفانه ربات‌های معاملاتی فارکس.">
    <link rel="canonical" href="https://mql5expert.ir/">
    <!-- Open Graph -->
    <meta property="og:title" content="خرید اکسپرت و ربات فارکس برای متاتریدر 5">
    <meta property="og:description" content="فروش اکسپرت و ربات معاملاتی فارکس برای MT5 با پشتیبانی کامل">
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://mql5expert.ir/">
    <meta property="og:site_name" content="MQL5 Expert">
    <meta property="og:locale" content="fa_IR">
    <meta property="og:locale:alternate" content="en_US">
    <meta property="og:image" content="https://mql5expert.ir/logo.ico">
    <!-- Twitter -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="خرید اکسپرت و ربات فارکس برای متاتریدر 5">
    <meta name="twitter:description" content="فروش اکسپرت و ربات معاملاتی فارکس برای MT5 با پشتیبانی کامل">
    <link rel="icon" type="image/x-icon" href="/logo.ico">
    <!-- Schema: WebSite / Organization / ItemList(4 محصول) / FAQPage -->
    <!-- کد کامل JSON-LD در فایل head.html ذخیره شده است -->
</head>
```

---

## 5. کد کامل index.html

> نسخه کامل و بهینه‌شده — فایل `SEO/index.html` (حدود ۴۸ کیلوبایت). برای آپلود مستقیم از همان فایل استفاده کنید.

**تغییرات اعمال‌شده:**
1. زبان پیش‌فرض فارسی: `<html lang="fa" dir="rtl">`
2. متن فارسی به‌صورت پیش‌فرض در HTML (قابل ایندکس شدن)
3. head جدید: عنوان بهینه، Canonical، Open Graph، Twitter Card و ۴ نوع Schema
4. لینک ایمیل خراب اصلاح شد → `info@tsgcoltd.ir`
5. فقط یک H1 در صفحه؛ «محصولات ما» به H2 تغییر کرد
6. alt تصاویر فارسی؛ محصولات به‌صورت متن ثابت در HTML
7. باگ جاوااسکریپت اصلاح شد (فوتر و سلب مسئولیت هنگام سوییچ زبان خراب نمی‌شوند)
8. بخش «بلاگ و مقالات» اضافه شد — دکمه بلاگ به `blog/` لینک شده

---

## 6. کد کامل sitemap.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">

  <url>
    <loc>https://mql5expert.ir/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/contact.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/GoldApex_WF.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/what-is-forex-robot.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/how-to-install-expert-in-metatrader5.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/supertrend-expert-advisor.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/best-forex-trading-robots-2026.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/expert-vs-indicator-mt5.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://mql5expert.ir/blog/forex-fury-review.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>

</urlset>
```

---

## 7. مقالات بلاگ

| مقاله | فایل در ریپو | دسته |
|-------|--------------|------|
| ربات فارکس چیست و چگونه کار می‌کند؟ | `blog/what-is-forex-robot.html` | آموزش |
| آموزش نصب اکسپرت در متاتریدر 5 | `blog/how-to-install-expert-in-metatrader5.html` | آموزش |
| اکسپرت سوپرترند چیست؟ | `blog/supertrend-expert-advisor.html` | محصولات |
| بهترین ربات معاملاتی فارکس 2026 | `blog/best-forex-trading-robots-2026.html` | بررسی |
| فرق اکسپرت و اندیکاتور در MT5 | `blog/expert-vs-indicator-mt5.html` | آموزش |
| بررسی ربات فارکس فیوری | `blog/forex-fury-review.html` | بررسی |
| فهرست بلاگ (لیست همه مقالات) | `blog/index.html` | — |

> **هر مقاله شامل:** عنوان و متا دیسکریپشن بهینه، Schema مقاله + Breadcrumb، لینک‌های داخلی به صفحه اصلی و فهرست بلاگ، هشدار ریسک.

---

## 8. نکات مهم

### ⚠️ هشدارهای سئو
- **هرگز از عبارت «سود تضمینی» و «پولدار شدن» استفاده نکنید** — گوگل و قوانین فارکس این ادعاها را جریمه می‌کنند.
- `lang="fa" dir="rtl"` باید در HTML ثابت باشد، نه فقط با جاوااسکریپت.
- محصولاتی که از Cloudflare Worker لود می‌شوند در HTML نیستند؛ حتماً نام و توضیح کوتاه آن‌ها به‌صورت متن ثابت در HTML باشد.
- هر صفحه فقط یک H1 داشته باشد.

### 🔧 کارهای دوره‌ای
- بعد از هر تغییر در گیت‌هاب: Cloudflare → Purge Cache
- هر مقاله جدید: اضافه کردن به sitemap.xml + یک خط به blog/index.html + درخواست ایندکس در GSC
- بررسی ماهانه: Google Search Console → Performance

### 📈 انتظار واقع‌بینانه
- ایندکس شدن: چند روز تا چند هفته
- رتبه گرفتن برای کلمات رقابتی: ۳ تا ۶ ماه با تولید محتوای منظم
- «URL is on Google, but has issues» یعنی ایندکس شده ولی Rich Results نمایش داده نمی‌شود — طبیعی و بی‌خطر است.

---

*پایان پکیج — تهیه‌شده توسط MetaTrader Assistant*
