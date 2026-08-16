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
7. [مقاله بلاگ: ربات فارکس چیست](#7-مقاله-بلاگ)
8. [نکات مهم و یادآوری‌ها](#8-نکات-مهم)

---

## 1. فهرست فایل‌ها

| فایل | محل قرارگیری در ریپو | توضیح |
|------|----------------------|--------|
| `index.html` | ریشه (جایگزین فایل فعلی) | نسخه کامل بهینه‌شده سایت |
| `sitemap.xml` | ریشه | نقشه سایت |
| `head.html` | مرجع (اختیاری) | بخش head بهینه |
| `blog/what-is-forex-robot.html` | پوشه `blog/` | مقاله اول |
| `blog-article-template.html` | مرجع (اختیاری) | قالب مقاله برای مقالات بعدی |
| `README-SEO.md` | مرجع (اختیاری) | راهنمای کوتاه |
| `SEO-PACKAGE-COMPLETE.md` | مرجع (اختیاری) | همین فایل جامع |

---

## 2. راهنمای گام‌به‌گام

### قدم ۱ — آپلود فایل‌ها در گیت‌هاب
1. `index.html` جدید را جایگزین فایل فعلی ریشه ریپو کنید (فایل قبلی را برای پشتیبان نگه دارید).
2. `sitemap.xml` را در ریشه قرار دهید.
3. پوشه `blog/` بسازید و مقاله را در آن بگذارید.
4. Commit و Push.

### قدم ۲ — Cloudflare
1. داشبورد Cloudflare → دامنه `mql5expert.ir` → **Caching → Configuration → Crawler Hints** را روشن کنید.
2. **Caching → Purge Everything** بزنید (بعد از هر تغییر سایت).

### قدم ۳ — Google Search Console
1. دامنه را وریفای کنید (DNS یا HTML file).
2. **Sitemaps** → آدرس کامل `https://mql5expert.ir/sitemap.xml` را سابمیت کنید (برای Domain property باید آدرس کامل باشد).
3. **URL Inspection** → `https://mql5expert.ir/` → **Request Indexing**.
4. پیام «URL is on Google» یعنی ایندکس شده ✅.

### قدم ۴ — تولید محتوا (مهم‌ترین قدم برای رتبه)
- ماهی ۲ تا ۴ مقاله در `blog/` با قالب آماده منتشر کنید.
- هر مقاله جدید را به `sitemap.xml` اضافه کنید.
- لینک هر مقاله به صفحه اصلی را حتماً بگذارید.

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

> بخش `<head>` بهینه‌شده — قبلاً داخل `index.html` اعمال شده است.

```html
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- عنوان و توضیحات -->
    <title>خرید اکسپرت و ربات فارکس برای متاتریدر 5 | ربات معاملاتی MT5</title>
    <meta name="description" content="خرید اکسپرت و ربات فارکس برای متاتریدر 5: ربات سوپرترند، اکسپرت فارکس فیوری، ربات گلد آپکس و اندیکاتور معاملاتی با پشتیبانی کامل و معرفی بی‌طرفانه ربات‌های معاملاتی فارکس.">

    <!-- Canonical -->
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

    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="خرید اکسپرت و ربات فارکس برای متاتریدر 5">
    <meta name="twitter:description" content="فروش اکسپرت و ربات معاملاتی فارکس برای MT5 با پشتیبانی کامل">

    <link rel="icon" type="image/x-icon" href="/logo.ico">

    <!-- Structured Data: وب‌سایت -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "WebSite",
      "name": "MQL5 Expert",
      "alternateName": "خرید اکسپرت و ربات فارکس",
      "url": "https://mql5expert.ir",
      "inLanguage": "fa-IR",
      "description": "فروش و معرفی اکسپرت و ربات معاملاتی فارکس برای پلتفرم متاتریدر 5"
    }
    </script>

    <!-- Structured Data: سازمان -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "Organization",
      "name": "MQL5 Expert",
      "url": "https://mql5expert.ir",
      "email": "info@tsgcoltd.ir",
      "contactPoint": {
        "@type": "ContactPoint",
        "email": "info@tsgcoltd.ir",
        "contactType": "customer service",
        "availableLanguage": ["fa", "en"]
      }
    }
    </script>

    <!-- Structured Data: محصولات -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "ItemList",
      "name": "محصولات اکسپرت و ربات فارکس",
      "itemListElement": [
        {
          "@type": "Product",
          "position": 1,
          "name": "EA&EM-PRO",
          "description": "ربات معاملات دستی و اتوماتیک برای متاتریدر 5",
          "url": "https://mql5expert.ir/",
          "brand": { "@type": "Brand", "name": "MQL5 Expert" },
          "offers": { "@type": "Offer", "price": "10", "priceCurrency": "USD", "availability": "https://schema.org/InStock" }
        },
        {
          "@type": "Product",
          "position": 2,
          "name": "SuperTrend EA",
          "description": "اکسپرت و ربات معاملاتی سوپرترند برای متاتریدر 5",
          "url": "https://mql5expert.ir/",
          "brand": { "@type": "Brand", "name": "MQL5 Expert" },
          "offers": { "@type": "Offer", "price": "10", "priceCurrency": "USD", "availability": "https://schema.org/InStock" }
        },
        {
          "@type": "Product",
          "position": 3,
          "name": "Forex Fury Pro",
          "description": "اکسپرت معاملات اتوماتیک فارکس فیوری پرو",
          "url": "https://mql5expert.ir/",
          "brand": { "@type": "Brand", "name": "MQL5 Expert" },
          "offers": { "@type": "Offer", "price": "10", "priceCurrency": "USD", "availability": "https://schema.org/InStock" }
        },
        {
          "@type": "Product",
          "position": 4,
          "name": "GoldApex_WF",
          "description": "اکسپرت و ربات معاملاتی طلا (گلد آپکس)",
          "url": "https://mql5expert.ir/GoldApex_WF.html",
          "brand": { "@type": "Brand", "name": "MQL5 Expert" },
          "offers": { "@type": "Offer", "price": "10", "priceCurrency": "USD", "availability": "https://schema.org/InStock" }
        }
      ]
    }
    </script>

    <!-- Structured Data: سوالات متداول -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@type": "FAQPage",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "ربات فارکس چیست؟",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "ربات فارکس یا اکسپرت (Expert Advisor) برنامه‌ای است که روی پلتفرم متاتریدر 5 نصب می‌شود و به‌صورت خودکار بر اساس استراتژی تعریف‌شده، معاملات را باز و بسته می‌کند."
          }
        },
        {
          "@type": "Question",
          "name": "اکسپرت چه فرقی با اندیکاتور دارد؟",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "اندیکاتور فقط سیگنال و اطلاعات را روی چارت نمایش می‌دهد، اما اکسپرت (ربات) می‌تواند بدون دخالت کاربر به‌صورت خودکار معامله کند."
          }
        },
        {
          "@type": "Question",
          "name": "چگونه اکسپرت را در متاتریدر 5 نصب کنیم؟",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "فایل .ex5 را در پوشه MQL5/Experts قرار دهید، سپس در متاتریدر 5 روی Navigator کلیک راست کرده و Refresh بزنید. اکسپرت در لیست Expert Advisors ظاهر می‌شود."
          }
        },
        {
          "@type": "Question",
          "name": "آیا ربات فارکس سود تضمینی دارد؟",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "خیر. هیچ ربات یا اکسپرتی سود تضمینی ندارد. مسئولیت سود و زیان ناشی از تصمیمات معاملاتی کاملاً بر عهده کاربر است."
          }
        }
      ]
    }
    </script>

    <!-- استایل سایت — بدون تغییر -->
    <style>
        /* کد CSS قبلی خودتان را اینجا نگه دارید */
    </style>
</head>
```

---

## 5. کد کامل index.html

> نسخه کامل و بهینه‌شده — این فایل همان `SEO/index.html` است و کامل‌ترین مرجع است.
> برای مشاهده کد کامل به فایل `index.html` در همین پوشه مراجعه کنید (۴۸ کیلوبایت).

**خلاصه تغییرات اعمال‌شده در index.html:**

1. زبان پیش‌فرض فارسی: `<html lang="fa" dir="rtl">`
2. متن فارسی به‌صورت پیش‌فرض در HTML (قابل ایندکس شدن)
3. head جدید: عنوان بهینه، Canonical، Open Graph، Twitter Card و ۴ نوع Schema
4. لینک ایمیل خراب اصلاح شد → `info@tsgcoltd.ir`
5. فقط یک H1 در صفحه؛ «محصولات ما» به H2 تغییر کرد
6. alt تصاویر فارسی؛ محصولات به‌صورت متن ثابت در HTML
7. باگ جاوااسکریپت اصلاح شد (فوتر و سلب مسئولیت هنگام سوییچ زبان خراب نمی‌شوند)
8. بخش «بلاگ و مقالات» با لینک به مقاله اول (ربات فارکس چیست) به صفحه اصلی اضافه شد

```html
<!--
  index.html — نسخه کامل و بهینه‌شده برای سئو
  کد کامل این فایل در: SEO/index.html (48 KB)
  نکته: به‌دلیل حجم زیاد، کد کامل در فایل جداگانه index.html ذخیره شده است.
  این بخش فقط خلاصه تغییرات است.
-->
<html lang="fa" dir="rtl">
<head>
    <!-- head بهینه: دقیقاً مطابق بخش 4 همین فایل + CSS کامل سایت -->
</head>
<body>
    <!-- بدنه: تمام بخش‌های سایت با متن فارسی پیش‌فرض + فوتر اصلاح‌شده -->
    <!-- جاوااسکریپت: زبان پیش‌فرض fa + اصلاح باگ سوییچ زبان -->
</body>
</html>
```

---

## 6. کد کامل sitemap.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">

  <!-- صفحه اصلی -->
  <url>
    <loc>https://mql5expert.ir/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>

  <!-- صفحه تماس -->
  <url>
    <loc>https://mql5expert.ir/contact.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.5</priority>
  </url>

  <!-- صفحه تحلیل GoldApex -->
  <url>
    <loc>https://mql5expert.ir/GoldApex_WF.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>

  <!-- مقاله: ربات فارکس چیست -->
  <url>
    <loc>https://mql5expert.ir/blog/what-is-forex-robot.html</loc>
    <changefreq>monthly</changefreq>
    <priority>0.7</priority>
  </url>

</urlset>
```

---

## 7. مقاله بلاگ

> فایل کامل: `SEO/blog/what-is-forex-robot.html` (16 KB)
> مسیر در ریپو: `blog/what-is-forex-robot.html`

**عنوان:** ربات فارکس چیست و چگونه کار می‌کند؟

**بخش‌های مقاله (حدود ۷۰۰ کلمه):**
- مقدمه
- ربات فارکس (اکسپرت) چیست؟
- ربات فارکس چگونه کار می‌کند؟
- تفاوت اکسپرت و اندیکاتور
- مزایای استفاده از ربات فارکس
- معایب و ریسک‌ها
- آموزش نصب در متاتریدر 5
- جدول انواع ربات‌ها (سوپرترند، فارکس فیوری، گلد آپکس، EA&EM-PRO)
- سوالات متداول
- جمع‌بندی + CTA

**امکانات سئو مقاله:** Schema مقاله + Breadcrumb + FAQ، لینک‌های داخلی، هشدار ریسک.

**ایده‌های مقالات بعدی:**
1. «آموزش نصب اکسپرت در متاتریدر 5»
2. «اکسپرت سوپرترند چیست و چگونه کار می‌کند؟»
3. «بهترین ربات معاملاتی فارکس 2026»
4. «فرق اکسپرت و اندیکاتور در MT5»
5. «بررسی ربات فارکس فیوری»

---

## 8. نکات مهم

### ⚠️ هشدارهای سئو
- **هرگز از عبارت «سود تضمینی» و «پولدار شدن» استفاده نکنید** — گوگل و قوانین فارکس این ادعاها را جریمه می‌کنند.
- `lang="fa" dir="rtl"` باید در HTML ثابت باشد، نه فقط با جاوااسکریپت.
- محصولاتی که از Cloudflare Worker لود می‌شوند در HTML نیستند؛ حتماً نام و توضیح کوتاه آن‌ها به‌صورت متن ثابت در HTML باشد.
- هر صفحه فقط یک H1 داشته باشد.

### 🔧 کارهای دوره‌ای
- بعد از هر تغییر در گیت‌هاب: Cloudflare → Purge Cache
- هر مقاله جدید: اضافه کردن به sitemap.xml + درخواست ایندکس در GSC
- بررسی ماهانه: Google Search Console → Performance

### 📈 انتظار واقع‌بینانه
- ایندکس شدن: چند روز تا چند هفته
- رتبه گرفتن برای کلمات رقابتی: ۳ تا ۶ ماه با تولید محتوای منظم
- «URL is on Google, but has issues» یعنی ایندکس شده ولی Rich Results نمایش داده نمی‌شود — طبیعی و بی‌خطر است.

---

*پایان پکیج — تهیه‌شده توسط MetaTrader Assistant*
