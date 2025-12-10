// index.ts - No KV Version (Stateless)

// ⚠️ သင့် Bot Token ကို ဒီမှာ ပြောင်းထည့်ပါ
const BOT_TOKEN = '8581058292:AAHKD5H5PxTuGB7UaSsuhyskUYLoAXHUXz0'; 

const TIME_STEP = 30; 
const DIGITS = 6;     
const ALGORITHM = 'SHA-1'; 

// --- 1. Base32 Decoder (Robust Version) ---
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32ToBuffer(base32: string): ArrayBuffer {
    // Space တွေဖယ်၊ padding (=) တွေဖယ်၊ အကြီးစာလုံးပြောင်း
    base32 = base32.replace(/\s/g, '').replace(/=+$/, '').toUpperCase(); 
    let bits = '';
    
    for (const char of base32) {
        const val = BASE32_CHARS.indexOf(char);
        if (val === -1) {
            throw new Error(`Invalid Base32 character: ${char}`);
        }
        bits += val.toString(2).padStart(5, '0');
    }

    const bytes = [];
    for (let i = 0; i + 7 < bits.length; i += 8) {
        const byte = bits.substring(i, i + 8);
        bytes.push(parseInt(byte, 2));
    }

    return new Uint8Array(bytes).buffer;
}

// --- 2. TOTP Generator (Web Crypto API) ---
async function generateTotpCode(secret: string): Promise<string> {
    try {
        const keyBuffer = base32ToBuffer(secret); 
        const epoch = Math.floor(Date.now() / 1000);
        const counter = Math.floor(epoch / TIME_STEP);
        
        const counterBuffer = new ArrayBuffer(8);
        const view = new DataView(counterBuffer);
        view.setUint32(0, 0, false); 
        view.setUint32(4, counter, false); 

        const cryptoKey = await crypto.subtle.importKey(
            'raw', keyBuffer, { name: 'HMAC', hash: { name: ALGORITHM } }, false, ['sign']
        );

        const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
        const hash = new Uint8Array(signature);
        const offset = hash[hash.length - 1] & 0xf;
        
        const truncatedHash = new DataView(signature, offset, 4);
        let code = truncatedHash.getUint32(0, false) & 0x7fffffff; 

        code %= Math.pow(10, DIGITS);
        return String(code).padStart(DIGITS, '0');

    } catch (e) {
        console.error('TOTP Error:', e);
        return 'ERROR';
    }
}

// --- 3. Telegram Send Message ---
async function sendMessage(chatId: number, text: string): Promise<void> {
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: text, parse_mode: 'Markdown' }),
    });
}

// --- Interfaces ---
interface TelegramUpdate {
    message?: {
        chat: {
            id: number;
            type: 'private' | 'group' | 'supergroup'; // Chat Type စစ်ရန်
        };
        text: string;
    };
}

// --- 4. Main Worker Logic ---
export default {
    async fetch(request: Request): Promise<Response> {
        if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

        const update: TelegramUpdate = await request.json();
        const message = update.message;

        // Message မရှိရင် ဘာမှမလုပ်ဘူး
        if (!message || !message.text) return new Response('OK');

        const chatId = message.chat.id;
        const text = message.text.trim();
        const chatType = message.chat.type;

        // --- GROUP FILTER LOGIC ---
        // Command ဟုတ်မဟုတ် စစ်ဆေးခြင်း (/code သို့မဟုတ် /start)
        const isCommand = text.toLowerCase().startsWith('/code') || text.toLowerCase().startsWith('/start');
        const isGroup = chatType === 'group' || chatType === 'supergroup';

        // Group ထဲမှာဖြစ်ပြီး Command မဟုတ်ရင် လုံးဝ Ignore လုပ်မည်
        if (isGroup && !isCommand) {
            return new Response('OK - Group Message Ignored');
        }

        let responseText = '';

        // --- Command Handling ---

        // 1. /code <KEY>
        if (text.toLowerCase().startsWith('/code')) {
            const parts = text.split(/\s+/);
            const secretKey = parts[1]; // ဒုတိယ စာလုံးကို ယူမည် (Key)

            if (secretKey) {
                const cleanKey = secretKey.replace(/\s/g, '').toUpperCase();
                const totpCode = await generateTotpCode(cleanKey);

                if (totpCode === 'ERROR') {
                    responseText = `🚫 *Error*: Secret Key ပုံစံမမှန်ပါ။`;
                } else {
                    const timeRemaining = TIME_STEP - (Math.floor(Date.now() / 1000) % TIME_STEP);
                    responseText = `🔐 *2FA Code*: \`${totpCode}\`\n⏳ Exp: ${timeRemaining}s`;
                }
            } else {
                // Key မပါလာရင်
                responseText = '⚠️ *အသုံးပြုပုံ*: `/code <YOUR_SECRET_KEY>`\n\nဥပမာ: `/code JBSWY3DPEHPK3PXP`';
            }

        // 2. /start
        } else if (text.toLowerCase().startsWith('/start')) {
            responseText = 
                '👋 **KP 2FA Bot မှ ကြိုဆိုပါတယ်!**\n\n' +
                'အသုံးပြုရလွယ်ကူအောင် ပြင်ဆင်ထားပါတယ်\n\n' +
                'အသုံးပြုလိုပါက `/code` နောက်မှာ Key ထည့်ရိုက်ပါ။\n\n' +
                '✅ နမူနာ: `/code JBSWY3DPEHPK3PXP`';
        } 
        
        // Private Chat တွင် Command မှားနေလျှင်
        else if (!isGroup) {
            responseText = "Command မှားနေပါတယ် ဂေါင်းကြီး။ `/code <KEY>` ကိုသုံးပါ။";
        }

        // စာပြန်မည် (Response Text ရှိမှသာ)
        if (responseText) {
            await sendMessage(chatId, responseText);
        }

        return new Response('OK');
    },
};
