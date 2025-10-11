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
                  await DB.prepare(
                    'UPDATE users SET txHash = ?, activation_code = ?, status = "confirmed" WHERE txHash = ?'
                  ).bind(text, code, dummyTx).run();
                  // Send to customer Telegram
                  await sendToTelegram(chatId, `کد فعال‌سازی شما: ${code}`);
                  // Send to email if available
                  if (state.email) {
                    await sendEmail(state.email, 'کد فعال‌سازی SuperTrend', `<p>کد فعال‌سازی شما: <strong>${code}</strong></p>`);
                  }
                  // Notify admin email
                  const adminHtml3 = `
                    تراکنش تأیید شد!<br>
                    کاربر: ${state.firstName} (@${state.username})<br>
                    شناسه چت: ${chatId}<br>
                    محصول: ${state.product}<br>
                    حساب: ${state.account}<br>
                    ایمیل: ${state.email || 'N/A'}<br>
                    TxHash: ${text}<br>
                    کد: ${code}<br>
                    <a href="https://mq5.click4tell.workers.dev/admin">پنل ادمین</a>
                  `;
                  await sendEmail(ADMIN_EMAIL, 'Tx تلگرام تأیید شد - کد تولید شد', adminHtml3);
                  // Notify admin Telegram
                  await sendToAdminTelegram(state, text, code);
                  await clearUserState(userId);
                } else {
                  await sendToTelegram(chatId, 'تراکنش نامعتبر (مبلغ یا آدرس اشتباه). لطفاً بررسی کنید و TxHash صحیح را ارسال کنید.');
                }
              } else {
                await sendToTelegram(chatId, 'فرمت TxHash نامعتبر. باید با 0x شروع شود و طولانی باشد.');
              }
              break;

            default:
              await sendToTelegram(chatId, 'حالت نامعتبر. لطفاً /start را دوباره بزنید.');
          }
        } else if (update.callback_query) {
          const cb = update.callback_query;
          const userId = cb.from.id.toString();
          const data = cb.data;
          const chatId = cb.message.chat.id.toString();
          
          console.log(`Callback received: userId=${userId}, data=${data}, chatId=${chatId}`);
          
          const state = await getUserState(userId);
          console.log(`State loaded:`, state);
          
          if (!state) {
            console.error(`No state for user ${userId} in callback`);
            // Answer callback to avoid hanging
            await fetch(`${TELEGRAM_API}/answerCallbackQuery`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ 
                callback_query_id: cb.id,
                text: 'خطا: لطفاً /start را دوباره بزنید.'
              })
            }).catch(err => console.error('Answer callback error:', err));
            return new Response('OK', { status: 200 });
          }

          if (data.startsWith('product_') && state.step === 'waiting_product') {
            try {
              if (data === 'product_indicator') {
                state.product = 'اندیکاتور SuperTrend - ۱۵ TRX';
              } else if (data === 'product_ea') {
                state.product = 'اکسپرت SuperTrend EA - ۲۰۰ TRX';
              } else if (data === 'product_forexfury') {
                state.product = 'اکسپرت ForexFury EA - ۵۰۰ TRX';
              } else {
                throw new Error('Invalid product data');
              }
              state.step = 'waiting_account';
              
              await setUserState(userId, state);
              console.log(`State updated for ${userId}:`, state);
              
              await sendToTelegram(chatId, 'محصول انتخاب شد. لطفاً شماره حساب ۷ رقمی MT5 خود را ارسال کنید.');
              
              // Answer callback
              const answerRes = await fetch(`${TELEGRAM_API}/answerCallbackQuery`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ callback_query_id: cb.id })
              });
              if (!answerRes.ok) {
                console.error('Answer callback failed:', await answerRes.text());
              } else {
                console.log('Callback answered successfully');
              }
              
            } catch (error) {
              console.error('Callback processing error:', error);
              // Fallback: answer و پیام خطا
              await fetch(`${TELEGRAM_API}/answerCallbackQuery`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                  callback_query_id: cb.id,
                  text: 'خطا در پردازش. لطفاً /start را دوباره بزنید.'
                })
              }).catch(err => console.error('Fallback answer error:', err));
              await sendToTelegram(chatId, 'خطا در انتخاب محصول. لطفاً /start را دوباره بزنید.');
            }
          } else {
            console.log(`Invalid callback data: ${data}, state.step: ${state.step}`);
            // Answer to clear loading
            await fetch(`${TELEGRAM_API}/answerCallbackQuery`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ callback_query_id: cb.id })
            }).catch(err => console.error('Invalid callback answer error:', err));
          }
        }

        return new Response('OK', { status: 200 });
      } catch (error) {
        console.error('Webhook error:', error);
        return new Response('Error', { status: 500 });
      }
    }

    // Check webhook status
    if (path === '/checkwebhook' && request.method === 'GET') {
      try {
        const response = await fetch(`${TELEGRAM_API}/getWebhookInfo`);
        const result = await response.json();
        if (result.ok) {
          return new Response(JSON.stringify(result.result), { 
            status: 200,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        return new Response(JSON.stringify({ error: result.description }), { status: 500 });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), { status: 500 });
      }
    }

    // Set webhook endpoint (call once to activate)
    if (path === '/setwebhook' && request.method === 'GET') {
      const webhookUrl = 'https://mq5.click4tell.workers.dev/webhook';
      try {
        const response = await fetch(`${TELEGRAM_API}/setWebhook?url=${webhookUrl}`);
        const result = await response.json();
        if (result.ok) {
          return new Response(`Webhook set successfully: ${JSON.stringify(result.result)}`, { status: 200 });
        }
        return new Response(`Error: ${JSON.stringify(result)}`, { status: 500 });
      } catch (error) {
        return new Response(`Error: ${error.message}`, { status: 500 });
      }
    }

    // Admin login and panel (integrated with DB, supports manual confirm and Telegram send)
    const cookie = request.headers.get('Cookie') || '';
    const isLoggedIn = cookie.includes('admin_logged_in=true');

    // Function to render admin panel
    async function renderAdminPanel() {
      try {
        const { results } = await DB.prepare('SELECT * FROM users ORDER BY timestamp DESC').all();
        let html = `
          <style>
            body { font-family: sans-serif; background: #f4f4f4; padding: 20px; }
            h2 { text-align: center; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            th, td { padding: 12px; border: 1px solid #ddd; text-align: center; }
            th { background: #007bff; color: white; }
            button { background: #28a745; color: white; border: none; padding: 8px 12px; border-radius: 4px; cursor: pointer; }
            button:hover { background: #218838; }
            .delete-btn { background: #dc3545; }
            .delete-btn:hover { background: #c82333; }
            form { max-width: 600px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            input, select { width: 100%; padding: 10px; margin: 10px 0; }
            a { color: #007bff; text-decoration: none; }
            .nav-container { position: absolute; top: 10px; right: 10px; }
            .nav-container a { margin-left: 10px; padding: 8px 16px; background: #007bff; color: white; border-radius: 4px; }
            .nav-container a:hover { background: #0056b3; }
            .webhook-status { margin: 10px 0; padding: 10px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; }
            .webhook-error { background: #f8d7da; border-color: #f5c6cb; }
          </style>
          <div class="nav-container">
            <a href="/admin">به‌روزرسانی</a>
            <a href="/admin?logout=true">خروج</a>
          </div>
          <h2>لیست درخواست‌ها</h2>
          <table><tr><th>شناسه</th><th>TxHash</th><th>محصول</th><th>حساب</th><th>ایمیل</th><th>شناسه چت</th><th>وضعیت</th><th>کد</th><th>عملیات</th></tr>`;
        for (const row of results) {
          html += `<tr><td>${row.id}</td><td>${row.txHash}</td><td>${row.product}</td><td>${row.account}</td><td>${row.email || 'N/A'}</td><td>${row.chat_id || 'N/A'}</td><td>${row.status}</td><td>${row.activation_code || 'N/A'}</td><td>`;
          if (row.status === 'pending') {
            html += `<form method="POST" style="display:inline;"><input type="hidden" name="action" value="confirm"><input type="hidden" name="id" value="${row.id}"><button>تأیید</button></form>`;
          }
          html += `<form method="POST" style="display:inline;"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="${row.id}"><button class="delete-btn">حذف</button></form></td></tr>`;
        }
        html += '</table>';
        html += '<h2>اضافه کردن کاربر دستی</h2><form method="POST"><input type="hidden" name="action" value="add">';
        html += '<label>محصول:</label><select name="product"><option>اندیکاتور SuperTrend - ۱۵ TRX</option><option>اکسپرت SuperTrend EA - ۲۰۰ TRX</option><option>اکسپرت ForexFury EA - ۵۰۰ TRX</option></select>';
        html += '<label>حساب MT5:</label><input type="text" name="account" required>';
        html += '<label>ایمیل:</label><input type="email" name="email" required>';
        html += '<label>شناسه چت (اختیاری):</label><input type="text" name="chat_id">';
        html += '<button type="submit">تولید و ارسال</button></form>';
        html += '<form method="POST"><input type="hidden" name="action" value="clear_db"><button class="delete-btn" style="width:100%; margin-top:20px;">پاک کردن همه DB</button></form>';
        html += `<p><a href="/setwebhook">تنظیم وب‌هوک تلگرام</a> | <a href="https://tsgcoltd.ir/admin">ادمین سایت</a></p>`;
        
        // Add webhook status check
        let webhookHtml = '';
        try {
          const webhookCheck = await fetch(`${url.origin}/checkwebhook`);
          if (webhookCheck.ok) {
            const webhookInfo = await webhookCheck.json();
            if (webhookInfo.url === 'https://mq5.click4tell.workers.dev/webhook') {
              webhookHtml = `<div class="webhook-status">وب‌هوک تلگرام: فعال ✅</div>`;
            } else {
              webhookHtml = `<div class="webhook-status webhook-error">وب‌هوک تلگرام: غیرفعال ❌ <a href="/setwebhook">حالا تنظیم کنید</a></div>`;
            }
          } else {
            webhookHtml = `<div class="webhook-status webhook-error">بررسی وب‌هوک شکست خورد: <a href="/setwebhook">حالا تنظیم کنید</a></div>`;
          }
        } catch (e) {
          webhookHtml = `<div class="webhook-status webhook-error">خطای بررسی وب‌هوک: <a href="/setwebhook">حالا تنظیم کنید</a></div>`;
        }
        html = webhookHtml + html;

        return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
      } catch (error) {
        console.error('DB query error:', error);
        return new Response(`خطا در بارگذاری لیست: ${error.message}<br><a href="/admin">بازگشت</a>`, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
      }
    }

    if (path === '/') {
      return Response.redirect(`${url.origin}/admin`, 302);
    }

    if (path === '/admin') {
      const body = await request.text();
      const params = new URLSearchParams(body || '');

      // Logout
      if (request.method === 'GET' && url.searchParams.get('logout') === 'true') {
        const headers = {
          'Set-Cookie': 'admin_logged_in=false; HttpOnly; Path=/; Max-Age=0; Secure; SameSite=None',
          'Content-Type': 'text/html; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        };
        return new Response('<p style="color: green;">خروج با موفقیت انجام شد</p><a href="/admin">دوباره ورود</a>', { headers });
      }

      // Confirm request (generate code, send to email and Telegram if available)
      if (request.method === 'POST' && params.get('action') === 'confirm' && isLoggedIn) {
        const id = params.get('id');
        try {
          const result = await DB.prepare('SELECT * FROM users WHERE id = ? AND status = ?')
            .bind(id, 'pending').first();
          if (result) {
            const code = await generateActivationCode(result.account, result.product);
            await DB.prepare('UPDATE users SET activation_code = ?, status = "confirmed" WHERE id = ?')
              .bind(code, id).run();
            // Send to email if exists
            if (result.email) {
              await sendEmail(result.email, 'کد فعال‌سازی SuperTrend', `<p>کد فعال‌سازی شما: <strong>${code}</strong></p>`);
            }
            // Send to Telegram if chat_id exists
            if (result.chat_id) {
              await sendToTelegram(result.chat_id, `کد فعال‌سازی شما: ${code}`);
            }
            // Notify admin
            const adminHtml = `
              تأیید دستی:<br>
              شناسه: ${id}<br>
              محصول: ${result.product}<br>
              حساب: ${result.account}<br>
              ایمیل: ${result.email || 'N/A'}<br>
              شناسه چت: ${result.chat_id || 'N/A'}<br>
              کد: ${code}<br>
              <a href="/admin">پنل ادمین</a>
            `;
            await sendEmail(ADMIN_EMAIL, 'تأیید دستی - کد تولید شد', adminHtml);
            await sendToAdminTelegram({ firstName: 'دستی', username: 'ادمین', product: result.product, account: result.account, email: result.email }, result.txHash, code);
            return new Response(`<p style="color: green;">کد تولید شد: <strong>${code}</strong></p><a href="/admin">بازگشت به پنل</a>`, {
              headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          } else {
            return new Response('<p style="color: red;">درخواست یافت نشد یا قبلاً تأیید شده است.</p><a href="/admin">بازگشت</a>', {
              headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
            });
          }
        } catch (error) {
          console.error('Confirm error:', error);
          return new Response(`خطا: ${error.message}<br><a href="/admin">بازگشت</a>`, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
        }
      }

      // Delete record
      if (request.method === 'POST' && params.get('action') === 'delete' && isLoggedIn) {
        const id = params.get('id');
        try {
          await DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
          return new Response('<p style="color: green;">رکورد حذف شد.</p><a href="/admin">بازگشت</a>', {
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        } catch (error) {
          console.error('Delete error:', error);
          return new Response(`خطا: ${error.message}<br><a href="/admin">بازگشت</a>`, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
        }
      }

      // Clear DB
      if (request.method === 'POST' && params.get('action') === 'clear_db' && isLoggedIn) {
        try {
          await DB.prepare('DELETE FROM users').run();
          return new Response('<p style="color: green;">DB پاک شد.</p><a href="/admin">بازگشت</a>', {
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        } catch (error) {
          console.error('Clear DB error:', error);
          return new Response(`خطا: ${error.message}<br><a href="/admin">بازگشت</a>`, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
        }
      }

      // Add manual user
      if (request.method === 'POST' && params.get('action') === 'add' && isLoggedIn) {
        const product = params.get('product');
        const account = params.get('account');
        const email = params.get('email');
        const chatId = params.get('chat_id') || null;
        if (!product || !account || !email) {
          return new Response('<p style="color: red;">داده‌های ناقص.</p><a href="/admin">بازگشت</a>', { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
        }
        try {
          const code = await generateActivationCode(account, product);
          const manualTx = 'manual_' + Date.now();
          await DB.prepare('INSERT INTO users (txHash, product, account, email, chat_id, status, activation_code, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
            .bind(manualTx, product, account, email, chatId, 'confirmed', code, Date.now()).run();
          // Send to email
          await sendEmail(email, 'کد فعال‌سازی SuperTrend', `<p>کد فعال‌سازی شما: <strong>${code}</strong></p>`);
          // Send to Telegram if chat_id
          if (chatId) {
            await sendToTelegram(chatId, `کد فعال‌سازی شما: ${code}`);
          }
          return new Response(`<p style="color: green;">کاربر اضافه شد، کد: <strong>${code}</strong></p><a href="/admin">بازگشت</a>`, {
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        } catch (error) {
          console.error('Add user error:', error);
          return new Response(`خطا: ${error.message}<br><a href="/admin">بازگشت</a>`, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
        }
      }

      // Admin login
      if (request.method === 'POST' && params.get('password') === ADMIN_PASSWORD) {
        const headers = {
          'Set-Cookie': 'admin_logged_in=true; HttpOnly; Path=/; Max-Age=3600; Secure; SameSite=None',
          'Content-Type': 'text/html; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        };
        // Render the panel immediately after login
        const panelResponse = await renderAdminPanel();
        // Clone and add cookie to panel response
        const newResponse = new Response(panelResponse.body, panelResponse);
        Object.entries(headers).forEach(([key, value]) => {
          if (key !== 'Content-Type') { // Avoid overriding content-type if already set
            newResponse.headers.set(key, value);
          }
        });
        return newResponse;
      }

      // Login form if not logged in
      if (!isLoggedIn) {
        return new Response(`
          <style>
            body { font-family: sans-serif; background: #f4f4f4; padding: 20px; text-align: center; }
            form { max-width: 400px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            input, button { width: 100%; padding: 10px; margin: 10px 0; border-radius: 4px; border: 1px solid #ccc; }
            button { background: #007bff; color: white; cursor: pointer; }
            button:hover { background: #0056b3; }
          </style>
          <form method="POST"><label>رمز عبور ادمین:</label><input type="password" name="password" required><br><button type="submit">ورود</button></form>`, {
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
        });
      }

      // Show panel if logged in
      return await renderAdminPanel();
    }

    // Process form payment (/process) - from original email worker
    if (request.method === 'POST' && path === '/process') {
      const formData = await request.formData();
      const txHash = formData.get('txHash');
      const product = formData.get('product');
      const account = formData.get('account');
      const email = formData.get('email');

      if (!txHash || !product || !account || !email) {
        console.error('Incomplete data received:', { txHash, product, account, email });
        return new Response('داده‌های ناقص', { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
      }

      try {
        // Check Tron transaction
        let expectedAmount;
        if (product.includes('Indicator_Supertrend') || product.includes('اندیکاتور SuperTrend')) {
          expectedAmount = 15;
        } else if (product.includes('EA_ForexFury') || product.includes('اکسپرت ForexFury')) {
          expectedAmount = 500;
        } else {
          expectedAmount = 200;
        }
        const valid = await checkTronTx(txHash, expectedAmount);
        if (valid) {
          const code = await generateActivationCode(account, product);
          // Insert to DB
          await DB.prepare('INSERT INTO users (txHash, product, account, email, status, activation_code, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(txHash) DO UPDATE SET activation_code = ?, status = "confirmed"')
            .bind(txHash, product, account, email, 'confirmed', code, Date.now(), code).run();
          // Send to email
          await sendEmail(email, 'کد فعال‌سازی SuperTrend', `<p>کد فعال‌سازی شما: <strong>${code}</strong></p>`);
          // Notify admin
          const adminHtml = `
            پرداخت سایت تأیید شد!<br>
            محصول: ${product}<br>
            حساب: ${account}<br>
            ایمیل: ${email}<br>
            TxHash: ${txHash}<br>
            کد: ${code}<br>
            <a href="https://mq5.click4tell.workers.dev/admin">پنل ادمین</a>
          `;
          await sendEmail(ADMIN_EMAIL, 'Tx سایت تأیید شد - کد تولید شد', adminHtml);
          await sendToAdminTelegram({ firstName: 'سایت', username: 'کاربر', product, account, email }, txHash, code);
          return new Response('<p style="color: green;">پرداخت تأیید شد! کد فعال‌سازی شما: <strong>' + code + '</strong></p>', {
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        } else {
          // Insert as pending
          await DB.prepare('INSERT INTO users (txHash, product, account, email, status, timestamp) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(txHash) DO NOTHING')
            .bind(txHash, product, account, email, 'pending', Date.now()).run();
          const adminHtml = `
            درخواست جدید سایت (در انتظار):<br>
            محصول: ${product}<br>
            حساب: ${account}<br>
            ایمیل: ${email}<br>
            TxHash: ${txHash}<br>
            <a href="https://mq5.click4tell.workers.dev/admin">پنل ادمین</a>
          `;
          await sendEmail(ADMIN_EMAIL, 'درخواست جدید سایت - در انتظار', adminHtml);
          return new Response('<p style="color: orange;">درخواست ثبت شد. در انتظار تأیید ادمین.</p>', {
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
          });
        }
      } catch (error) {
        console.error('DB insert error:', error);
        return new Response('خطا در ذخیره داده‌ها: ' + error.message, { status: 500, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
      }
    }

    // 404
    return new Response('۴۰۴ یافت نشد', { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' } });
  },
};
