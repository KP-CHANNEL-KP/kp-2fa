// index.ts (Fixing the Base32 Decoding Logic)

// Replace YOUR_BOT_TOKEN with the actual token you got from BotFather
const BOT_TOKEN = '8581058292:AAHKD5H5PxTuGB7UaSsuhyskUYLoAXHUXz0'; 
const TIME_STEP = 30; // TOTP time step in seconds (standard is 30)
const DIGITS = 6;     // TOTP code length (standard is 6)
const ALGORITHM = 'SHA-1'; // HMAC algorithm (standard is SHA-1)

// --- 1. TOTP (Time-based One-Time Password) Logic ---

// --- Base32 Decoding Function (The Critical Fix) ---
// This is a robust Base32 decoding implementation required for real 2FA secrets.
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32ToBuffer(base32: string): ArrayBuffer {
    // Remove spaces, remove padding (= signs), and ensure uppercase
    base32 = base32.replace(/\s/g, '').replace(/=+$/, '').toUpperCase(); 
    let bits = '';
    
    // Convert Base32 chars to 5-bit binary strings
    for (const char of base32) {
        const val = BASE32_CHARS.indexOf(char);
        if (val === -1) {
            // Throw error for invalid characters
            throw new Error(`Invalid Base32 character: ${char}`);
        }
        bits += val.toString(2).padStart(5, '0');
    }

    // Convert binary strings to 8-bit bytes
    const bytes = [];
    for (let i = 0; i + 7 < bits.length; i += 8) {
        const byte = bits.substring(i, i + 8);
        bytes.push(parseInt(byte, 2));
    }

    // Return the binary key data
    return new Uint8Array(bytes).buffer;
}

/**
 * Generates a TOTP code using Web Crypto API.
 * @param secret Base32 encoded secret key.
 * @returns The 6-digit TOTP code as a string.
 */
async function generateTotpCode(secret: string): Promise<string> {
    try {
        // 1. Decode the secret key from Base32 to ArrayBuffer
        const keyBuffer = base32ToBuffer(secret); 

        // 2. Calculate the counter value (C) based on current time
        const epoch = Math.floor(Date.now() / 1000);
        const counter = Math.floor(epoch / TIME_STEP);
        
        // Convert counter (number) to 8-byte buffer (big-endian)
        const counterBuffer = new ArrayBuffer(8);
        const view = new DataView(counterBuffer);
        view.setUint32(0, 0, false); // High 32 bits (0 for typical TOTP epoch)
        view.setUint32(4, counter, false); // Low 32 bits, big-endian

        // 3. Import the key for HMAC operation
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'HMAC', hash: { name: ALGORITHM } },
            false, // not extractable
            ['sign']
        );

        // 4. Generate the HMAC hash
        const signature = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            counterBuffer
        );
        
        // 5. Dynamic Truncation (DT)
        const hash = new Uint8Array(signature);
        const offset = hash[hash.length - 1] & 0xf;
        
        // Extract 4 bytes from hash starting at offset (big-endian)
        const truncatedHash = new DataView(signature, offset, 4);
        let code = truncatedHash.getUint32(0, false) & 0x7fffffff; // Apply 31-bit mask

        // 6. Format to DIGITS length
        code %= Math.pow(10, DIGITS);
        return String(code).padStart(DIGITS, '0');

    } catch (e) {
        console.error('TOTP Generation Error:', e);
        return 'ERROR: Decoding/Crypto Logic Failed';
    }
}


// --- 2. Telegram Bot Communication Logic ---

/**
 * Sends a message back to the Telegram user.
 */
async function sendMessage(chatId: number, text: string): Promise<void> {
    const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
    
    await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            chat_id: chatId,
            text: text,
            parse_mode: 'Markdown',
        }),
    });
}

// Telegram Update Interface
interface TelegramUpdate {
    message?: {
        chat: {
            id: number;
        };
        text: string;
    };
}


// --- 3. Main Worker Fetch Handler ---

export default {
    async fetch(request: Request): Promise<Response> {
        // Only process Telegram Webhook (POST) requests
        if (request.method !== 'POST') {
            return new Response('Method Not Allowed', { status: 405 });
        }

        const update: TelegramUpdate = await request.json();
        const chatId = update.message?.chat.id;
        const messageText = update.message?.text?.trim();

        if (!chatId || !messageText) {
            return new Response('No valid message received', { status: 200 });
        }

        let responseText: string;

        // Command processing: /code <SECRET_KEY>
        if (messageText.toLowerCase().startsWith('/code')) {
            const parts = messageText.split(/\s+/);
            const secretKey = parts[1];

            if (secretKey) {
                // Clean the secret key (remove spaces, ensure uppercase)
                const cleanKey = secretKey.replace(/\s/g, '').toUpperCase();
                
                const totpCode = await generateTotpCode(cleanKey); 
                
                if (totpCode.startsWith('ERROR')) {
                    responseText = `🚫 *Error*: Code calculation failed. Secret Key မှန်မမှန် ပြန်စစ်ပါ။`;
                } else {
                    const timeRemaining = TIME_STEP - (Math.floor(Date.now() / 1000) % TIME_STEP);
                    
                    responseText = 
                        `✅ ဂေါင်းကြီးရဲ့ 2FA Code:\n\n` + 
                        `\`${totpCode}\`\n\n` +
                        `_Code သက်တမ်း ${timeRemaining} စက္ကန့် ကျန်ပါသည်_`;
                }

            } else {
                responseText = '❌ *အသုံးပြုပုံ*: /code ပြီးနောက် Base32 Secret Key ကို ထည့်ပေးပါ။ \n\n' +
                                'နမူနာ: `/code JBSWY3DPEHPK3PXP`';
            }
        } else if (messageText.toLowerCase().startsWith('/start')) {
             responseText = 
                '👋 KP ရဲ့ 2FA bot မှကြိုဆိုပါတယ်!\n\n' +
                'Telegram Channel => https://t.me/addlist/DaVvvOWfdg05NDJl.\n\n' +
                'ပထမဦးဆုံး အသုံးပြုသူများ /code ဖြင့်သုံးပါ **နမူနာကို အောက်တွင် ကြည့်ပါ**.\n\n' +
                'နမူနာ: `/code JBSWY3DPEHPK3PXP`';
        } else {
            responseText = "အသုံးပြုပုံ မှားနေပါတယ် ဂေါင်းကြီး `/code JBSWY3DPEHPK3PXP` command. အဆင်မပြေရင် /start ပြန်နှိပ်ပါ။.";
        }

        // Send the response back to Telegram
        await sendMessage(chatId, responseText);
        
        return new Response('OK', { status: 200 });
    },
};
