// DES implementation for Cloudflare Workers (encryption only)
// Compatible with CryptEncode(CRYPT_DES) in MT5 with ECB mode and ZeroPadding (for Telegram system compatibility)
function des(key, message, encrypt, mode, iv, padding) {
  // DES constants
  const IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
  ];
  const E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
  ];
  const SBOX = [
    [
      14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
      0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
      4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
      15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
      15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
      3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
      0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
      13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
      10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
      13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
      13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
      1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
      7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
      13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
      10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
      3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
      2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
      14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
      4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
      11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
      12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
      10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
      9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
      4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
      4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
      13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
      1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
      6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
      13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
      1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
      7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
      2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
  ];
  const PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
  ];
  const PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
  ];
  const LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
  const FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
  ];

  // String to bits array
  function stringToBits(str) {
    let bits = [];
    for (let i = 0; i < str.length; i++) {
      let char = str.charCodeAt(i);
      for (let j = 7; j >= 0; j--) {
        bits.push((char >> j) & 1);
      }
    }
    return bits;
  }

  // Bits to string
  function bitsToString(bits) {
    let str = '';
    for (let i = 0; i < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) {
        byte = (byte << 1) | (bits[i + j] || 0);
      }
      str += String.fromCharCode(byte);
    }
    return str;
  }

  // Permute bits
  function permute(bits, table) {
    let result = [];
    for (let i = 0; i < table.length; i++) {
      result.push(bits[table[i] - 1] || 0);
    }
    return result;
  }

  // Generate 16 subkeys
  function des_createKeys(key) {
    let keyBits = stringToBits(key);
    if (keyBits.length < 64) {
      keyBits = keyBits.concat(new Array(64 - keyBits.length).fill(0));
    }
    let permutedKey = permute(keyBits, PC1);
    let C = permutedKey.slice(0, 28);
    let D = permutedKey.slice(28, 56);
    let subKeys = [];
    for (let i = 0; i < 16; i++) {
      C = C.concat(C.splice(0, LEFT_SHIFTS[i]));
      D = D.concat(D.splice(0, LEFT_SHIFTS[i]));
      let CD = C.concat(D);
      subKeys.push(permute(CD, PC2));
    }
    return subKeys;
  }

  // Add ZeroPadding (modified for Telegram compatibility)
  if (padding && encrypt) {
    let padLen = (8 - (message.length % 8)) % 8;
    message += '\0'.repeat(padLen);
  }

  let keyBits = des_createKeys(key);
  let inputBits = stringToBits(message);
  let output = [];

  // Process 64-bit blocks
  for (let i = 0; i < inputBits.length; i += 64) {
    let block = inputBits.slice(i, i + 64);
    if (block.length < 64) {
      block = block.concat(new Array(64 - block.length).fill(0));
    }

    // Initial permutation
    block = permute(block, IP);

    let L = block.slice(0, 32);
    let R = block.slice(32, 64);

    // 16 rounds
    for (let round = 0; round < 16; round++) {
      let expandedR = permute(R, E);
      let key = keyBits[round];
      let xored = expandedR.map((bit, i) => bit ^ key[i]);

      // S-box substitution
      let sBoxOutput = [];
      for (let j = 0; j < 8; j++) {
        let group = xored.slice(j * 6, (j + 1) * 6);
        let row = (group[0] << 1) | group[5];
        let col = (group[1] << 3) | (group[2] << 2) | (group[3] << 1) | group[4];
        let val = SBOX[j][(row << 4) | col];
        for (let k = 3; k >= 0; k--) {
          sBoxOutput.push((val >> k) & 1);
        }
      }

      // P permutation
      const P = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
      ];
      sBoxOutput = permute(sBoxOutput, P);

      let temp = R;
      R = L.map((bit, i) => bit ^ sBoxOutput[i]);
      L = temp;
    }

    // Final permutation
    let finalBlock = permute(R.concat(L), FP);
    output = output.concat(finalBlock);
  }

  return bitsToString(output);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const TELEGRAM_TOKEN = env.TELEGRAM_TOKEN;
    const TELEGRAM_API = `https://api.telegram.org/bot${TELEGRAM_TOKEN}`;
    const ADMIN_CHAT_ID = env.ADMIN_CHAT_ID;
    const ADMIN_EMAIL = 'click4tell@gmail.com';
    const TRON_ADDRESS = 'TLBTbV3cjeR7GJU7321Q42Bjft4ZUDzVca';
    const RESEND_API_KEY = env.RESEND_API_KEY;
    const ADMIN_PASSWORD = env.ADMIN_PASSWORD || 'adminpass2025';
    const DB = env.DB;
    const KV = env.KV_ORDERS;
    const TRONSCAN_API_KEY = env.TRONSCAN_API_KEY;

    // Initialize DB schema
    async function initSchema() {
      try {
        // Create table if not exists
        await DB.prepare(`
          CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txHash TEXT UNIQUE,
            product TEXT,
            account TEXT,
            email TEXT,
            chat_id TEXT,
            status TEXT DEFAULT 'pending',
            activation_code TEXT,
            timestamp INTEGER
          )
        `).run();

        // Check if chat_id column exists
        const { results } = await DB.prepare("PRAGMA table_info(users)").all();
        const hasChatId = results.some(row => row.name === 'chat_id');
        if (!hasChatId) {
          await DB.prepare("ALTER TABLE users ADD COLUMN chat_id TEXT").run();
          console.log('Added chat_id column');
        }

        // Similarly, check for activation_code if needed
        const hasActivationCode = results.some(row => row.name === 'activation_code');
        if (!hasActivationCode) {
          await DB.prepare("ALTER TABLE users ADD COLUMN activation_code TEXT").run();
          console.log('Added activation_code column');
        }

        // Check for timestamp
        const hasTimestamp = results.some(row => row.name === 'timestamp');
        if (!hasTimestamp) {
          await DB.prepare("ALTER TABLE users ADD COLUMN timestamp INTEGER").run();
          console.log('Added timestamp column');
        }
      } catch (error) {
        console.error('Schema init error:', error);
      }
    }

    await initSchema();

    const welcomeMessage = `خوش آمدید! شما برای خرید بهترین اکسپرت‌ها و اندیکاتورهای MetaTrader 5 از ما هستید.

1. **اندیکاتور SuperTrend**:
   - قیمت: ۱۵ TRX (شبکه TRC-20)
   - توضیح: اندیکاتور SuperTrend یک ابزار محبوب دنبال‌کننده روند است که به معامله‌گران کمک می‌کند تا روندهای بازار و نقاط ورود/خروج بالقوه را شناسایی کنند. این اندیکاتور بر اساس نوسانات بازار، خطی بالای یا زیر قیمت رسم می‌کند و سیگنال‌های خرید یا فروش را نشان می‌دهد.
   - استفاده: روی MetaTrader 5 نصب کنید، تنظیمات را تنظیم کنید (مثلاً دوره، ضریب)، و سیگنال‌های روند را دنبال کنید.

2. **اکسپرت SuperTrend EA**:
   - قیمت: ۲۰۰ TRX (شبکه TRC-20)
   - توضیح: اکسپرت SuperTrend EA یک ربات معاملاتی خودکار است که از اندیکاتور SuperTrend برای اجرای خودکار معاملات بر اساس قوانین از پیش تعریف شده استفاده می‌کند. ایده‌آل برای معامله‌گرانی که به دنبال معامله بدون دخالت دستی هستند.
   - استفاده: روی MetaTrader 5 نصب کنید، تنظیمات ریسک را پیکربندی کنید، و معامله خودکار را فعال کنید.

3. **اکسپرت ForexFury EA**:
   - قیمت: ۵۰۰ TRX (شبکه TRC-20)
   - توضیح: اکسپرت ForexFury EA یک ربات معاملاتی خودکار قدرتمند برای بازارهای فارکس است که از الگوریتم‌های پیشرفته برای معاملات سودآور استفاده می‌کند.
   - استفاده: روی MetaTrader 5 نصب کنید، تنظیمات را پیکربندی کنید، و معامله خودکار را فعال کنید.

برای جزئیات بیشتر و دستورالعمل‌های راه‌اندازی، به: https://tsgcoltd.ir/ مراجعه کنید.

لطفاً یک محصول را انتخاب کنید.`; 

    // Send email function
    async function sendEmail(to, subject, html) {
      if (!RESEND_API_KEY) {
        console.error('RESEND_API_KEY not set');
        return { success: false, error: 'API key not set' };
      }
      try {
        const response = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${RESEND_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: 'info@tsgcoltd.ir',
            to: [to],
            subject,
            html,
          }),
        });
        if (!response.ok) {
          const errorText = await response.text();
          console.error('Resend API error:', errorText);
          return { success: false, error: `Resend API error: ${errorText}` };
        }
        console.log(`Email sent to ${to}`);
        return { success: true };
      } catch (error) {
        console.error('Email send error:', error.message);
        return { success: false, error: error.message };
      }
    }

    // Generate activation code
    async function generateActivationCode(account, product) {
      let masterKey;
      if (product.includes('Indicator_Supertrend') || product.includes('اندیکاتور SuperTrend')) {
        masterKey = "xAI2025"; // exactly 7 chars
      } else if (product.includes('EA_SuperTrend') || product.includes('اکسپرت SuperTrend EA')) {
        masterKey = "xAI2026"; // exactly 7 chars
      } else if (product.includes('EA_ForexFury') || product.includes('اکسپرت ForexFury')) {
        masterKey = "1404EFU"; // exactly 7 chars
      } else {
        throw new Error("Invalid product!");
      }
      if (masterKey.length !== 7) {
        throw new Error("Master key must be exactly 7 chars!");
      }
      try {
        const encrypted = des(masterKey, account, 1, 0, null, 1);
        const code = btoa(encrypted);
        console.log(`Activation code for account ${account}: ${code}`);
        return code;
      } catch (error) {
        console.error('DES encryption error:', error.message);
        throw new Error('DES encryption error: ' + error.message);
      }
    }

    // Check Tron transaction
    async function checkTronTx(txHash, expectedAmount) {
      const apiUrl = `https://apilist.tronscan.org/api/transaction_info?hash=${txHash}`;
      try {
        const response = await fetch(apiUrl, {
          headers: { 'TRON-PRO-API-KEY': TRONSCAN_API_KEY }
        });
        const data = await response.json();
        if (data.success && data.data && data.data.length > 0) {
          const tx = data.data[0];
          const toAddr = tx.raw_data?.contract?.[0]?.parameter?.value?.to_address || '';
          const valueSun = parseInt(tx.raw_data?.contract?.[0]?.parameter?.value?.amount || 0);
          const valueTrx = valueSun / 1000000;
          if (toAddr === TRON_ADDRESS && valueTrx >= expectedAmount) {
            return true;
          }
        }
      } catch (error) {
        console.error('TronScan error:', error.message);
      }
      return false;
    }

    // Send to Telegram
    async function sendToTelegram(chatId, text, replyMarkup = null) {
      const payload = {
        chat_id: chatId,
        text,
        ...(replyMarkup && { reply_markup: replyMarkup })
      };
      const response = await fetch(`${TELEGRAM_API}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      return response.json();
    }

    // Send to admin Telegram
    async function sendToAdminTelegram(state, txHash = '', code = '') {
      const text = `
درخواست جدید/تأیید شده از تلگرام:
کاربر: ${state.firstName} (@${state.username || 'N/A'})
شناسه چت: ${state.chatId}
محصول: ${state.product}
حساب: ${state.account}
ایمیل: ${state.email || 'N/A'}
TxHash: ${txHash || 'در انتظار'}
${code ? `کد: ${code}` : ''}
      `;
      await sendToTelegram(ADMIN_CHAT_ID, text);
    }

    // Get user state from KV
    async function getUserState(userId) {
      try {
        const value = await KV.get(`state_${userId}`);
        return value ? JSON.parse(value) : null;
      } catch (error) {
        console.error('KV get error:', error);
        return null;
      }
    }

    // Set user state in KV
    async function setUserState(userId, state) {
      try {
        await KV.put(`state_${userId}`, JSON.stringify(state));
      } catch (error) {
        console.error('KV put error:', error);
      }
    }

    // Clear user state
    async function clearUserState(userId) {
      try {
        await KV.delete(`state_${userId}`);
      } catch (error) {
        console.error('KV delete error:', error);
      }
    }

    // Webhook endpoint
    if (path === '/webhook' && request.method === 'POST') {
      try {
        const update = await request.json();
        console.log('Webhook update:', JSON.stringify(update));

        if (update.message) {
          const message = update.message;
          const chatId = message.chat.id.toString();
          const userId = message.from.id.toString();
          const text = message.text?.trim();

          if (text === '/start') {
            const replyMarkup = {
              inline_keyboard: [
                [{ text: 'اندیکاتور SuperTrend (۱۵ TRX)', callback_data: 'product_indicator' }],
                [{ text: 'اکسپرت SuperTrend EA (۲۰۰ TRX)', callback_data: 'product_ea' }],
                [{ text: 'اکسپرت ForexFury EA (۵۰۰ TRX)', callback_data: 'product_forexfury' }]
              ]
            };
            await sendToTelegram(chatId, welcomeMessage, replyMarkup);
            await setUserState(userId, {
              step: 'waiting_product',
              chatId,
              userId,
              username: message.from.username || '',
              firstName: message.from.first_name || ''
            });
            return new Response('OK', { status: 200 });
          }

          const state = await getUserState(userId);
          if (!state) {
            await sendToTelegram(chatId, 'لطفاً با /start شروع کنید');
            return new Response('OK', { status: 200 });
          }

          switch (state.step) {
            case 'waiting_account':
              if (/^\d{7}$/.test(text)) {
                state.account = text;
                await setUserState(userId, state);
                // Immediate email to admin about account
                const adminHtml = `
                  درخواست جدید تلگرام (حساب دریافت شد):<br>
                  کاربر: ${state.firstName} (@${state.username})<br>
                  شناسه چت: ${chatId}<br>
                  محصول: ${state.product}<br>
                  حساب: ${text}<br>
                  در انتظار ایمیل و TxHash.<br>
                  <a href="https://mq5.click4tell.workers.dev/admin">پنل ادمین</a>
                `;
                await sendEmail(ADMIN_EMAIL, 'درخواست جدید تلگرام - حساب دریافت شد', adminHtml);
                await sendToTelegram(chatId, 'حساب دریافت شد. لطفاً آدرس ایمیل خود را ارسال کنید.');
                state.step = 'waiting_email';
                await setUserState(userId, state);
              } else {
                await sendToTelegram(chatId, 'لطفاً دقیقاً شماره حساب ۷ رقمی MT5 را ارسال کنید.');
              }
              break;

            case 'waiting_email':
              if (text.includes('@') && text.includes('.')) {
                state.email = text;
                const dummyTx = `telegram_${userId}`;
                await setUserState(userId, state);
                // Insert to DB
                await DB.prepare(
                  'INSERT INTO users (txHash, product, account, email, chat_id, status, timestamp) ' +
                  'VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txHash) DO NOTHING'
                ).bind(dummyTx, state.product, state.account, text, chatId, 'pending', Date.now()).run();
                // Notify admin Telegram
                await sendToAdminTelegram(state, dummyTx);
                // Email to admin
                const adminHtml2 = `
                  درخواست جدید تلگرام (ایمیل دریافت شد):<br>
                  کاربر: ${state.firstName} (@${state.username})<br>
                  شناسه چت: ${chatId}<br>
                  محصول: ${state.product}<br>
                  حساب: ${state.account}<br>
                  ایمیل: ${text}<br>
                  TxHash: در انتظار<br>
                  <a href="https://mq5.click4tell.workers.dev/admin">پنل ادمین</a>
                `;
                await sendEmail(ADMIN_EMAIL, 'درخواست جدید تلگرام - ایمیل دریافت شد', adminHtml2);
                await sendToTelegram(chatId, `ایمیل دریافت شد. لطفاً TxHash پرداخت خود به آدرس ${TRON_ADDRESS} را ارسال کنید.`);
                state.step = 'waiting_tx';
                await setUserState(userId, state);
              } else {
                await sendToTelegram(chatId, 'ایمیل نامعتبر. لطفاً دوباره تلاش کنید.');
              }
              break;

            case 'waiting_tx':
              if (text.startsWith('0x') && text.length > 50) {
                let expectedAmount;
                if (state.product.includes('اندیکاتور SuperTrend')) {
                  expectedAmount = 15;
                } else if (state.product.includes('اکسپرت ForexFury')) {
                  expectedAmount = 500;
                } else {
                  expectedAmount = 200;
                }
                const valid = await checkTronTx(text, expectedAmount);
                if (valid) {
                  const code = await generateActivationCode(state.account, state.product);
                  const dummyTx = `telegram_${userId}`;
                  // Update DB
               
