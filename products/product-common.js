/*
  ═══════════════════════════════════════════════════════════════
  product-common.js — اسکریپت مشترک صفحات محصول (دوزبانه + قیمت‌زنده)
  سایت: https://mql5expert.ir
  هر صفحه محصول باید قبل از لود این اسکریپت این متغیرها را ست کند:
    window.PRODUCT_KEY  =  'EA_EM_PRO' | 'EA_SuperTrend' | 'EA_ForexFury' | 'GoldApex_WF'
    window.DOWNLOAD_URL = '/downloads/EA&EM-PRO.ex5'   (لینک دانلود)
    window.PRODUCT_LINKS= { fa: '/products/ea-em-pro.html', en: '/products/en/ea-em-pro.html' }
  ═══════════════════════════════════════════════════════════════
*/

(function () {
  'use strict';

  var PRODUCT_KEY = window.PRODUCT_KEY || 'EA_EM_PRO';
  var DOWNLOAD_URL = window.DOWNLOAD_URL || '/downloads/EA&EM-PRO.ex5';
  var PRODUCT_LINKS = window.PRODUCT_LINKS || { fa: '#', en: '#' };

  var WORKER_URL = 'https://supertrend-worker-fa.click4tell.workers.dev';
  var TETHER_PRICE_URL = 'https://tetercheng.click4tell.workers.dev/price';

  var currentLang = localStorage.getItem('lang') || 'fa';
  var tetherPriceInToman = 0;
  var priceTether = 0;      // قیمت محصول به تتر (از ورکر)
  var loaded = false;       // آیا قیمت واقعی لود شده؟

  // قیمت پیش‌فرض fallback (اگر ورکر در دسترس نبود) — به ترتیب محصول
  var FALLBACK_TETHER_PRICE = {
    'EA_EM_PRO': 2,
    'EA_SuperTrend': 2,
    'EA_ForexFury': 2,
    'GoldApex_WF': 10
  };

  /* ---------- یافتن المان‌های صفحه ---------- */
  function el(id) { return document.getElementById(id); }

  /* ---------- داده‌های دوزبانه هر محصول (fallback) ---------- */
  var FALLBACK_DATA = {
    'EA_EM_PRO': {
      fa: { name: 'اکسپرت EA&EM-PRO', desc: 'ربات معاملات دستی و اتوماتیک برای متاتریدر 5' },
      en: { name: 'EA&EM-PRO', desc: 'Automated & manual trading robot for MetaTrader 5' }
    },
    'EA_SuperTrend': {
      fa: { name: 'اکسپرت SuperTrend EA', desc: 'ربات معاملاتی سوپرترند برای دنبال‌کردن روند در متاتریدر 5' },
      en: { name: 'SuperTrend EA', desc: 'SuperTrend trend-following trading robot for MetaTrader 5' }
    },
    'EA_ForexFury': {
      fa: { name: 'اکسپرت Forex Fury Pro', desc: 'اکسپرت معاملات اتوماتیک فارکس فیوری پرو' },
      en: { name: 'Forex Fury Pro', desc: 'Automated Forex trading expert' }
    },
    'GoldApex_WF': {
      fa: { name: 'اکسپرت GoldApex_WF', desc: 'ربات معاملاتی طلا (XAUUSD) با استراتژی گلد آپکس' },
      en: { name: 'GoldApex_WF', desc: 'Gold (XAUUSD) trading robot with GoldApex strategy' }
    }
  };

  /* ---------- سوییچ زبان ---------- */
  function applyLanguage(lang) {
    currentLang = lang;
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
    document.body.style.direction = lang === 'fa' ? 'rtl' : 'ltr';
    document.body.style.textAlign = lang === 'fa' ? 'right' : 'left';
    localStorage.setItem('lang', lang);

    // بروزرسانی دکمه سوییچ
    var flagGb = el('flag-gb');
    var flagIr = el('flag-ir');
    var langText = el('lang-text');
    if (flagGb) flagGb.style.display = lang === 'en' ? 'block' : 'none';
    if (flagIr) flagIr.style.display = lang === 'fa' ? 'block' : 'none';
    if (langText) langText.textContent = lang === 'en' ? 'فارسی' : 'English';

    // سوییچ متن برای همه المان‌های دوزبانه منو و بدنه (data-fa/data-en)
    document.querySelectorAll('[data-fa]').forEach(function (node) {
      if (node.children.length === 0) {
        node.textContent = node.getAttribute('data-' + lang) || node.getAttribute('data-' + (lang === 'fa' ? 'en' : 'fa'));
      }
    });

    // بروزرسانی نام/توضیح محصول
    var prdName = el('prdName');
    var prdDesc = el('prdDesc');
    if (prdName) prdName.textContent = currentData().name;
    if (prdDesc) prdDesc.textContent = currentData().desc;
    if (el('buyText')) el('buyText').textContent = lang === 'fa' ? 'خرید محصول' : 'Buy Now';
    if (el('downloadText')) el('downloadText').textContent = lang === 'fa' ? 'دانلود' : 'Download';

    renderPrice();
  }

  function currentData() {
    var d = FALLBACK_DATA[PRODUCT_KEY] || FALLBACK_DATA['EA_EM_PRO'];
    return d[currentLang] || d.fa;
  }

  /* ---------- قیمت تتر ---------- */
  function fetchTetherPrice() {
    return fetch(TETHER_PRICE_URL + '?t=' + Date.now())
      .then(function (r) { return r.json(); })
      .then(function (data) {
        tetherPriceInToman = data.tether_price_toman || 0;
        return tetherPriceInToman;
      })
      .catch(function () {
        tetherPriceInToman = 0; return 0;
      });
  }

  /* ---------- قیمت محصول از ورکر ---------- */
  function fetchProductPrice() {
    return fetch(WORKER_URL + '/products?lang=' + currentLang)
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var fallback = FALLBACK_TETHER_PRICE[PRODUCT_KEY] || 0;
        if (data && data[PRODUCT_KEY]) {
          var p = data[PRODUCT_KEY];
          priceTether = Number(p.trx) || fallback;
          if (p.desc_fa && currentLang === 'fa' && el('prdDesc')) el('prdDesc').textContent = p.desc_fa;
          if (p.desc_en && currentLang === 'en' && el('prdDesc')) el('prdDesc').textContent = p.desc_en;
        } else {
          priceTether = fallback;
        }
        loaded = true;
        return priceTether;
      })
      .catch(function () {
        priceTether = FALLBACK_TETHER_PRICE[PRODUCT_KEY] || 0;
        return priceTether;
      });
  }

  /* ---------- رندر قیمت (تتر + تومان) با پیام انتظار و fallback ---------- */
  function renderPrice() {
    var priceBox = el('productPrice');
    if (!priceBox) return;

    // اگر هنوز قیمت واقعی از ورکر لود نشده → پیام «هنوز بروز نیست» (نه قیمت ثابت/اشتباه)
    if (!loaded) {
      priceBox.innerHTML =
        (currentLang === 'fa'
          ? '<span style="color:#b45309;font-weight:700;">⏳ هنوز بروز نیست...</span>'
          : '<span style="color:#b45309;font-weight:700;">⏳ Price not updated yet...</span>');
      return;
    }

    // اگر قیمت محصول واریز شده ولی قیمت تتر نیامده → فقط تتر را نشان بده
    var priceToman = Math.round(priceTether * tetherPriceInToman);

    if (currentLang === 'fa') {
      if (tetherPriceInToman > 0) {
        priceBox.innerHTML =
          'قیمت: <strong>' + priceTether + ' تتر (USDT TRC20/BEP20)</strong>' +
          ' <span style="opacity:0.75">معادل ' + priceToman.toLocaleString('fa-IR') + ' تومان</span>';
      } else {
        priceBox.innerHTML = 'قیمت: <strong>' + priceTether + ' تتر (USDT TRC20/BEP20)</strong>';
      }
    } else {
      if (tetherPriceInToman > 0) {
        priceBox.innerHTML =
          'Price: <strong>' + priceTether + ' USDT (TRC20/BEP20)</strong>' +
          ' <span style="opacity:0.75">≈ ' + priceToman.toLocaleString('en-US') + ' Toman</span>';
      } else {
        priceBox.innerHTML = 'Price: <strong>' + priceTether + ' USDT (TRC20/BEP20)</strong>';
      }
    }
  }

  /* ---------- مقداردهی اولیه ---------- */
  function init() {
    applyLanguage(currentLang);
    fetchTetherPrice()
      .then(fetchProductPrice)
      .then(function () { renderPrice(); });

    var switcher = el('lang-switcher');
    if (switcher) switcher.addEventListener('click', function () {
      applyLanguage(currentLang === 'en' ? 'fa' : 'en');
    });

    // دکمه خرید → رفتن به ناحیه خرید صفحه اصلی
    var buyBtn = el('buyBtn');
    if (buyBtn) buyBtn.addEventListener('click', function () {
      window.location.href = '/#products';
    });

    // به‌روزرسانی هر ۶۰ ثانیه قیمت
    setInterval(function () {
      fetchTetherPrice().then(function () { renderPrice(); });
    }, 60000);

    // اگر بعد از ۸ ثانیه قیمت واقعی لود نشد، همچنان «هنوز بروز نیست» نمایش داده می‌شود
    setTimeout(function () {
      if (!loaded) {
        priceTether = FALLBACK_TETHER_PRICE[PRODUCT_KEY] || 0;
        renderPrice();
      }
    }, 8000);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
