# 🌐 نسخه PWA — نصب مستقیم روی اندروید (بدون Play Store)

این پوشه نسخه **PWA (Progressive Web App)** اپلیکیشن فروش است.
مزیت: بدون نیاز به Android Studio و بدون APK، روی گوشی اندروید نصب می‌شود.

---

## ۱) آپلود روی سایت

پوشه `PWA` را روی هاست/گیت‌هاب آپلود کنید، مثلاً در مسیر:

```
https://mql5expert.ir/app/
```

فایل‌ها (۳ فایل):
- `index.html` — رابط فروش (همان UI اپ اندروید)
- `manifest.webmanifest` — تنظیمات نصب
- `sw.js` — سرویس‌ورکر (کش آفلاین)

> ⚠️ آدرس `start_url` و `scope` در `manifest.webmanifest` باید با مسیر آپلود هماهنگ باشد.
> اگر در مسیر دیگری آپلود کردید، `./` را تنظیم کنید.

## ۲) نصب روی گوشی اندروید

1. در گوشی (کروم)، آدرس `https://mql5expert.ir/app/` را باز کنید
2. منوی ⋮ کروم → **"Add to Home screen" / «افزودن به صفحه اصلی»**
3. آیکون اپ روی صفحه اصلی ساخته می‌شود — مثل یک اپ واقعی باز می‌شود

## ۳) تبدیل PWA به APK (آنلاین، رایگان)

اگر فایل APK واقعی می‌خواهید بدون نصب Android Studio:

1. آدرس PWA را در https://www.pwabuilder.com وارد کنید
2. `Package for stores` → `Android` → `Generate Package` / `Generate APK`
3. فایل APK دانلود می‌شود

سرویس‌های مشابه: https://appmaker.xyz / https://pwa2apk.com (با دقت استفاده کنید)

## ۴) تفاوت با پروژه AndroidApp

| | AndroidApp (Android Studio) | PWA |
|---|------------------------------|-----|
| APK واقعی | ✅ | از طریق PWABuilder |
| نصب بدون اینترنت اولیه | ✅ (UI داخل اپ است) | نیاز به باز شدن اولیه |
| سرعت توسعه | کمتر | بیشتر |
| انتشار در Google Play | ✅ | بله (TWA) |

> هر دو نسخه از یک Worker و یک UI استفاده می‌کنند؛ پیشنهاد می‌شود نسخه AndroidApp را
> برای APK اصلی و نسخه PWA را به‌عنوان راه سریع نگه دارید.

© All rights reserved K_M 2025 | info@tsgcoltd.ir
