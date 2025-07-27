import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import re

# Replace with your bot token from @BotFather
TELEGRAM_BOT_TOKEN = '8319446482:AAFcc_R_nYUiCnNzV0g9nhC4kMBK1-UB3K8'

# WAF fingerprint signatures
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"]
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["Sucuri/Cloudproxy"]
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"]
    },
    "akamai": {
        "headers": ["akamai-cache-status", "x-akamai-transformed"],
        "server": ["AkamaiGHost"]
    },
    "aws": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "server": []
    },
    "stackpath": {
        "headers": ["x-stackpath-rid", "x-sp-cache"],
        "server": []
    },
    "f5": {
        "headers": ["x-waf-event", "x-asm"],
        "server": ["BigIP", "F5"]
    },
    "fortinet": {
        "headers": ["server"],
        "server": ["FortiWeb"]
    },
    "barracuda": {
        "headers": ["server"],
        "server": ["Barracuda"]
    },
    "cisco": {
        "headers": ["x-cisco-ace-loginfo"],
        "server": ["ACE"]
    }
}

# Detect WAF based on response headers
def detect_waf(headers):
    found_wafs = []
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}

    for waf, sig in WAF_SIGNATURES.items():
        found = False

        for header in sig["headers"]:
            if header.lower() in lower_headers:
                found = True

        server = lower_headers.get("server", "")
        for srv_sig in sig["server"]:
            if srv_sig.lower() in server:
                found = True

        if found:
            found_wafs.append(waf.capitalize())

    return found_wafs

# /start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = (
        "👋 Welcome!\n\n"
        "🔧 *𝒯𝒽𝒾𝓈 𝓉𝑜𝑜𝓁 𝓂𝒶𝒹𝑒 𝒷𝓎 𝐻𝓊𝓈𝒷𝒶𝓃𝒹 𝑜𝒻 𝑀𝒶𝓃𝒿𝓊𝓈𝒽𝓇𝒾.*\n\n"
        "📡 To scan a website for WAF protection, use the following command:\n"
        "`/scan example.com`\n\n"
        "🛡️ The bot will check if the domain is protected by a Web Application Firewall (WAF) like:\n"
        "- Cloudflare\n- Sucuri\n- Imperva\n- Akamai\n...and more.\n\n"
        "📍 Example:\n"
        "`/scan google.com`\n\n"
        "⚠️ Please enter only the domain (without https:// or www)."
    )
    await update.message.reply_text(message, parse_mode="Markdown")

# /scan command
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: `/scan example.com`", parse_mode="Markdown")
        return

    domain = context.args[0]
    if not re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', domain):
        await update.message.reply_text("❌ Invalid domain format.")
        return

    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=10)
        headers = response.headers
        wafs = detect_waf(headers)

        if wafs:
            result = f"🔐 *WAF Detected* on `{domain}`:\n" + "\n".join([f"- {w}" for w in wafs])
        else:
            result = f"✅ No WAF detected on `{domain}`"

        await update.message.reply_text(result, parse_mode="Markdown")

    except Exception as e:
        await update.message.reply_text(f"⚠️ Error scanning `{domain}`:\n`{e}`", parse_mode="Markdown")

# Main bot runner
def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))

    print("🤖 Bot is running...")
    app.run_polling()

if __name__ == '__main__':
    main()
