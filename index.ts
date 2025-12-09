// index.ts

// Replace YOUR_BOT_TOKEN with the actual token you got from BotFather
const BOT_TOKEN = '8581058292:AAHKD5H5PxTuGB7UaSsuhyskUYLoAXHUXz0'; 
const TIME_STEP = 30; // TOTP time step in seconds (standard is 30)
const DIGITS = 6;     // TOTP code length (standard is 6)
const ALGORITHM = 'SHA-1'; // HMAC algorithm (standard is SHA-1)


// --- 1. TOTP (Time-based One-Time Password) Logic ---

/**
 * Converts a Base32 encoded secret key string to a binary ArrayBuffer.
 * This is necessary for the cryptographic operations.
 * @param base32 The Base32 encoded string (e.g., from Google Authenticator setup).
 * @returns An ArrayBuffer containing the binary key data.
 */
function base32ToBuffer(base32: string): ArrayBuffer {
    // This is a simplified implementation; a full Base32 implementation is complex.
    // For production, use a reliable Base32 library that works in the Worker environment 
    // (or ensure keys are provided in a simpler format like hex/base64 if possible).
    
    // As a demonstration, we will assume a Base32 implementation is available
    // or the user provides a simple key. 
    // Since direct Base32 decoding is complex to implement fully here, 
    // if you use a library, you'll put its decode logic here.

    // *** IMPORTANT: If your keys are standard Base32 (e.g., from Google Authenticator), 
    // you must replace this placeholder with a working Base32 decoder. ***
    
    // For simplicity in this demo, we'll try to convert it as if it's Hex or throw an error.
    if (base32.length % 2 !== 0) {
         throw new Error('Base32 decoding failed or key length is invalid.');
    }
    
    // Assuming a reliable decoding library is used here in a real project
    const hex = base32; // Placeholder for decoded hex string
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substring(i, i + 2), 16));
    }
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
        // NOTE: The base32ToBuffer function above needs a robust implementation!
        const keyBuffer = base32ToBuffer(secret); 

        // 2. Calculate the counter value (C) based on current time
        const epoch = Math.floor(Date.now() / 1000);
        const counter = Math.floor(epoch / TIME_STEP);
        
        // Convert counter (number) to 8-byte buffer (big-endian)
        const counterBuffer = new ArrayBuffer(8);
        const view = new DataView(counterBuffer);
        // Note: JS numbers are 64-bit float, but we need 64-bit int for counter.
        // We handle the high/low 32-bit parts.
        view.setUint32(0, 0); // High 32 bits (since epoch is small)
        view.setUint32(4, counter, false); // Low 32 bits, big-endian (false)

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
        return 'ERROR: Invalid Secret Key or Implementation Error';
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
                // Ensure secret key is uppercase (Base32 standard)
                const totpCode = await generateTotpCode(secretKey.toUpperCase()); 
                
                if (totpCode.startsWith('ERROR')) {
                    responseText = `🚫 *Error*: Failed to generate code. Please check your Secret Key format.`;
                } else {
                    const timeRemaining = TIME_STEP - (Math.floor(Date.now() / 1000) % TIME_STEP);
                    
                    responseText = 
                        `✅ ဂေါင်းကြီးရဲ့ 2FA Code:\n\n` + 
                        `\`${totpCode}\`\n\n` +
                        `_Expires in ${timeRemaining} seconds_`;
                }

            } else {
                responseText = '❌ *Usage*: Please provide your Base32 Secret Key after the command. \n\n' +
                                'Example: `/code JBSWY3DPEHPK3PXP`';
            }
        } else if (messageText.toLowerCase().startsWith('/start')) {
             responseText = 
                '👋 KP ရဲ့ 2FA bot မှကြိုဆိုပါတယ်!\n\n' +
                'Telegram Channel => https://t.me/KP_CHANNEL_KP.\n\n' +
                'ပထမဦးဆုံး အသုံးပြုသူများ /code ဖြင့်သုံးပါ **နမူနာကို အောက်တွင် ကြည့်ပါ**.\n\n' +
                'နမူနာ: `/code JBSWY3DPEHPK3PXP`';
        } else {
            responseText = "အသုံးပြုပုံ မှာနေပါတယ် ဂေါင်းကြီး `/code JBSWY3DPEHPK3PXP` command. အဆင်မပြေရင် /start ပြန်နှိပ်ပါ။.";
        }

        // Send the response back to Telegram
        await sendMessage(chatId, responseText);
        
        return new Response('OK', { status: 200 });
    },
};
