"""
DMGuardBot - REBRANDED AS ANGEL X MUSIC
------------------------------------------------
Original functionality:
- Group ID auto-detect + Supabase storage
- Forward‑based DM reporting with admin Ban/Mute/Reject buttons
- Known‑member tracking (for privacy‑ON forwards)
- Groq AI scam/spam detection (content‑based, identity‑independent)

All responses are themed to look like a music bot, as requested.
"""

import json
import logging
import os
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
from dotenv import load_dotenv
from supabase import create_client, Client
from telegram import InlineKeyboardMarkup, InlineKeyboardButton, ChatPermissions, Update
from telegram.ext import Updater, CommandHandler, MessageHandler, CallbackQueryHandler, Filters, CallbackContext

# --------------------- CONFIG ---------------------
load_dotenv()

# ⚠️ Replace these with your own credentials (or keep the hardcoded ones if you trust them)
BOT_TOKEN = "8693447126:AAHwgqNjxf7ySgTkqAK5OHVdiIrKPS9elmo"
SUPABASE_URL = "https://kswscbxdvprasfdnqmxz.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtzd3NjYnhkdnByYXNmZG5xbXh6Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4Mzk1NDczNiwiZXhwIjoyMDk5NTMwNzM2fQ.TAgO9NP0LVwWMuwpLmsWW-wPgQ1IIFax11WL1SbT2LA"
GROQ_API_KEY = "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"
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN missing.")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set.")
if not GROQ_API_KEY:
    logging.warning("⚠️ GROQ_API_KEY missing – AI scam detection disabled.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Cooldown for scam alerts (5 minutes per user)
_recent_alerts = {}
ALERT_COOLDOWN_SECONDS = 300

# Quick keyword pre‑filter before calling AI
SUSPICIOUS_KEYWORDS = [
    "http://", "https://", "t.me/", "bit.ly", "wa.me", "telegram.me",
    "investment", "invest", "profit", "guaranteed return", "double your money",
    "crypto", "binance", "trading tips", "loan approved", "click here",
    "free gift", "lottery", "winner", "claim now", "paisa kamao",
    "earn money", "work from home", "job offer", "part time job",
    "whatsapp number", "call me", "dm me", "limited time",
]

# ---------- TEXT HELPERS ----------
def escape_markdown(text: str) -> str:
    if not text:
        return text
    for ch in ("_", "*", "`", "["):
        text = text.replace(ch, f"\\{ch}")
    return text

# ---------- DATABASE HELPERS ----------
def get_group_id() -> int | None:
    try:
        res = supabase.table("settings").select("value").eq("key", "group_id").execute()
        if res.data and len(res.data) > 0:
            return int(res.data[0]["value"])
    except Exception as e:
        logging.error(f"Error fetching group_id: {e}")
    return None

def set_group_id_db(chat_id: int) -> None:
    try:
        supabase.table("settings").upsert({"key": "group_id", "value": str(chat_id)}).execute()
    except Exception as e:
        logging.error(f"Error saving group_id: {e}")

def save_known_member(user_id: int, first_name: str, username: str | None) -> None:
    try:
        supabase.table("known_members").upsert({
            "user_id": user_id,
            "first_name": first_name or "Unknown",
            "username": username or "N/A",
        }).execute()
    except Exception as e:
        logging.error(f"Error saving known member: {e}")

def find_members_by_name(name: str) -> list:
    try:
        res = supabase.table("known_members").select("*").ilike("first_name", name).execute()
        return res.data or []
    except Exception as e:
        logging.error(f"Error finding members by name: {e}")
        return []

# ---------- GROQ SCAM DETECTION ----------
def looks_suspicious(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)

def analyze_scam_content(text: str) -> dict:
    default = {"is_scam": False, "confidence": "low", "reason": "N/A"}
    if not GROQ_API_KEY or not text or not text.strip():
        return default

    prompt = (
        "Tum ek Telegram group moderation assistant ho. Neeche diya gaya message padho "
        "aur judge karo ki ye scam, spam, ya phishing jaisa lagta hai ya nahi. "
        "Normal harmless conversation ko galti se scam mat bolo.\n\n"
        f"Message: \"{text[:1000]}\"\n\n"
        'SIRF is JSON format mein jawab do: {"is_scam": true/false, "confidence": "low/medium/high", "reason": "..."}'
    )

    try:
        response = requests.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 150,
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"].strip()
        content = content.replace("```json", "").replace("```", "").strip()
        result = json.loads(content)
        return {
            "is_scam": bool(result.get("is_scam", False)),
            "confidence": result.get("confidence", "low"),
            "reason": result.get("reason", "N/A"),
        }
    except Exception as e:
        logging.error(f"Groq API error: {e}")
        return default

def should_alert(user_id: int) -> bool:
    now = time.time()
    last = _recent_alerts.get(user_id, 0)
    if now - last < ALERT_COOLDOWN_SECONDS:
        return False
    _recent_alerts[user_id] = now
    return True

def is_group_admin(context: CallbackContext, group_id: int, user_id: int) -> bool:
    try:
        member = context.bot.get_chat_member(group_id, user_id)
        return member.status in ("administrator", "creator")
    except Exception:
        return False

# ---------- HANDLERS (REBRANDED) ----------

def start(update: Update, context: CallbackContext):
    """Send the promotional image text with inline buttons."""
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("🎵 Connect to Group", callback_data="connect_group")],
        [InlineKeyboardButton("💬 Support", url="https://t.me/your_support_channel")]   # Replace with your link
    ])
    message = (
        "🔥 *FEEL THE BEAT.*\n"
        "🎶 *LIVE THE MOMENT.*\n\n"
        "*ANGEL X MUSIC*\n"
        "2/6/7 ACTIVE\n\n"
        "⭐ HIGH QUALITY MUSIC\n"
        "⚡ FAST & STABLE\n"
        "🔒 100% SECURE\n"
        "🕒 24/7 ACTIVE\n"
        "📂 CUSTOM PLAYLIST\n\n"
        "🎧 *HEY, MUSIC LOVER!*\n\n"
        "You requested to join a chat where I help manage voice chat music.\n"
        "I can play songs, handle the queue, and keep your group vibe active.\n\n"
        "Want me in your group too?\n"
        "Tap below and connect me to your group.\n\n"
        "🔹 Send /start to know more about me.\n\n"
        "🎵 *Play Music 24x7*\n\n"
        "❤️ Support us by watching ads."
    )
    update.message.reply_text(message, parse_mode="Markdown", reply_markup=keyboard)

def connect_group_callback(update: Update, context: CallbackContext):
    """Handle the 'Connect to Group' button."""
    query = update.callback_query
    query.answer()
    query.edit_message_text(
        "📢 To add me to your group:\n"
        "1. Make me admin in your group.\n"
        "2. Use /setgroup in this private chat with the group ID.\n"
        "   (You can get the group ID by adding @get_id_bot to your group).\n\n"
        "Once connected, I will start managing your group's voice chat music and safety!",
        parse_mode="Markdown"
    )

def help_command(update: Update, context: CallbackContext):
    update.message.reply_text(
        "🎶 *Angel X Music – Help Menu*\n\n"
        "• /start – Show welcome message\n"
        "• /setgroup <group_id> – Manually set the group ID\n"
        "• /groupid – Show currently set group ID\n\n"
        "📩 *DM Reports:* Forward any suspicious DM to me, and I'll alert the admins.\n"
        "🤖 *AI Protection:* I automatically detect scam/spam in group messages.",
        parse_mode="Markdown"
    )

def new_chat_members(update: Update, context: CallbackContext):
    bot_id = context.bot.id
    for member in update.message.new_chat_members:
        if member.id == bot_id:
            chat_id = update.effective_chat.id
            set_group_id_db(chat_id)
            context.bot.send_message(
                chat_id,
                "🎵 *Angel X Music* is now connected!\n"
                "I'll keep your group vibe active and secure.",
                parse_mode="Markdown"
            )
        else:
            save_known_member(member.id, member.first_name, member.username)

def setgroup_command(update: Update, context: CallbackContext):
    if update.effective_chat.type == "private":
        if not context.args:
            update.message.reply_text("Usage: /setgroup <group_id> (e.g., -1001234567890)")
            return
        try:
            gid = int(context.args[0])
        except ValueError:
            update.message.reply_text("Group ID must be a number.")
            return
        set_group_id_db(gid)
        update.message.reply_text(f"✅ Group ID set to `{gid}`", parse_mode="Markdown")
    else:
        gid = update.effective_chat.id
        set_group_id_db(gid)
        update.message.reply_text(f"✅ Group ID set to `{gid}`", parse_mode="Markdown")

def groupid_command(update: Update, context: CallbackContext):
    gid = get_group_id()
    if gid:
        update.message.reply_text(f"Current group ID: `{gid}`", parse_mode="Markdown")
    else:
        update.message.reply_text("❌ Group ID not set. Add me as admin or use /setgroup.")

def track_group_message(update: Update, context: CallbackContext):
    """Track members and run AI scam detection."""
    if update.effective_chat.type not in ("group", "supergroup"):
        return

    user = update.message.from_user
    text = update.message.text or update.message.caption or ""

    if user and not user.is_bot:
        save_known_member(user.id, user.first_name, user.username)

    if text and looks_suspicious(text) and user and should_alert(user.id):
        result = analyze_scam_content(text)
        if result["is_scam"] and result["confidence"] in ("medium", "high"):
            alert_admins_scam(context, user, text, result)

def alert_admins_scam(context: CallbackContext, user, text: str, result: dict):
    group_id = get_group_id()
    if not group_id:
        return

    try:
        admins = context.bot.get_chat_administrators(group_id)
    except Exception as e:
        logging.error(f"Admins fetch error: {e}")
        return

    admin_mentions = " ".join(
        f"[{escape_markdown(a.user.first_name)}](tg://user?id={a.user.id})"
        for a in admins if not a.user.is_bot
    )

    preview = text[:200] + ("..." if len(text) > 200 else "")
    alert_text = (
        f"🚨 *AI detected a potential scam pattern*\n\n"
        f"👤 User: [{escape_markdown(user.first_name)}](tg://user?id={user.id}) "
        f"(@{user.username or 'no_username'})\n"
        f"📝 Message: _{escape_markdown(preview)}_\n"
        f"🔍 Reason: {escape_markdown(result['reason'])}\n"
        f"⚠️ Confidence: {result['confidence']}\n\n"
        f"{admin_mentions}\n"
        f"Verify and take action:"
    )

    buttons = [
        [InlineKeyboardButton("🔨 Ban", callback_data=f"scamalert_ban_{user.id}"),
         InlineKeyboardButton("🔇 Mute", callback_data=f"scamalert_mute_{user.id}")],
        [InlineKeyboardButton("✅ False Alarm", callback_data="scamalert_ignore")]
    ]
    keyboard = InlineKeyboardMarkup(buttons)

    try:
        context.bot.send_message(group_id, alert_text, reply_markup=keyboard, parse_mode="Markdown")
    except Exception as e:
        logging.error(f"Error sending scam alert: {e}")

def handle_forward_report(update: Update, context: CallbackContext):
    msg = update.message
    reporter = msg.from_user
    group_id = get_group_id()
    if not group_id:
        msg.reply_text("❌ Group ID not set. Add me as admin or use /setgroup.")
        return

    if not msg.forward_date:
        msg.reply_text("⚠️ Only forwarded original messages are accepted as proof.")
        return

    match_note = ""
    possible_matches = []

    if msg.forward_from:
        target_id = msg.forward_from.id
        target_name = msg.forward_from.first_name or "Unknown"
        target_username = msg.forward_from.username or "no_username"
        verified = True
    else:
        target_id = None
        target_name = msg.forward_sender_name or "Unknown"
        target_username = "N/A (privacy ON)"
        verified = False

        if msg.forward_sender_name:
            possible_matches = find_members_by_name(msg.forward_sender_name)
            if len(possible_matches) == 1:
                m = possible_matches[0]
                match_note = (
                    f"\n🔎 *Possible Match Found*:\n"
                    f"[{escape_markdown(m['first_name'])}](tg://user?id={m['user_id']}) "
                    f"(@{m['username']})\n"
                    f"⚠️ This is a name‑based guess – verify before action."
                )
            elif len(possible_matches) > 1:
                names_list = "\n".join(
                    f"- [{escape_markdown(m['first_name'])}](tg://user?id={m['user_id']}) (@{m['username']})"
                    for m in possible_matches
                )
                match_note = (
                    f"\n🔎 *{len(possible_matches)} possible matches:*\n"
                    f"{names_list}\n"
                    f"⚠️ Verify carefully."
                )
            else:
                match_note = "\nℹ️ No known member with this name found."

    # AI content check on forwarded message
    scam_note = ""
    forwarded_text = msg.text or msg.caption or ""
    if forwarded_text:
        scam_result = analyze_scam_content(forwarded_text)
        if scam_result["is_scam"]:
            scam_note = (
                f"\n🤖 *AI Content Check:* possible scam "
                f"(confidence: {scam_result['confidence']})\n"
                f"   Reason: {escape_markdown(scam_result['reason'])}"
            )

    try:
        admins = context.bot.get_chat_administrators(group_id)
    except Exception as e:
        msg.reply_text(f"❌ Could not fetch admins: {e}")
        return

    admin_mentions = " ".join(
        f"[{escape_markdown(a.user.first_name)}](tg://user?id={a.user.id})"
        for a in admins if not a.user.is_bot
    )

    verified_text = "✅ Identity verified" if verified else "⚠️ Identity NOT verified (privacy ON)"

    report_text = (
        f"🚨 *New DM Report*\n\n"
        f"👤 Reporter: [{escape_markdown(reporter.first_name)}](tg://user?id={reporter.id})\n"
        f"🎯 Reported: {escape_markdown(target_name)} (@{target_username})\n"
        f"🔍 {verified_text}"
        f"{match_note}"
        f"{scam_note}\n\n"
        f"{admin_mentions}\n"
        f"Review and action:"
    )

    buttons = []
    if verified:
        buttons.append([
            InlineKeyboardButton("🔨 Ban", callback_data=f"admrep_ban_{target_id}"),
            InlineKeyboardButton("🔇 Mute", callback_data=f"admrep_mute_{target_id}")
        ])
    elif len(possible_matches) == 1:
        guess_id = possible_matches[0]["user_id"]
        buttons.append([
            InlineKeyboardButton("🔨 Ban (guess)", callback_data=f"admrep_ban_{guess_id}"),
            InlineKeyboardButton("🔇 Mute (guess)", callback_data=f"admrep_mute_{guess_id}")
        ])
    buttons.append([InlineKeyboardButton("❌ Reject", callback_data="admrep_reject")])
    keyboard = InlineKeyboardMarkup(buttons)

    try:
        context.bot.forward_message(group_id, msg.chat_id, msg.message_id)
        context.bot.send_message(group_id, report_text, reply_markup=keyboard, parse_mode="Markdown")
        msg.reply_text("✅ Your report has been sent to the group admins.")
    except Exception as e:
        msg.reply_text(f"❌ Error sending report: {e}")

def handle_admin_action(update: Update, context: CallbackContext):
    query = update.callback_query
    admin = query.from_user
    data = query.data
    group_id = get_group_id()
    if not group_id:
        query.answer("❌ Group ID not set.", show_alert=True)
        return

    if not is_group_admin(context, group_id, admin.id):
        query.answer("❌ Only group admins can take this action.", show_alert=True)
        return

    if data == "admrep_reject":
        query.edit_message_text(f"❌ Report rejected by {admin.first_name}", parse_mode="Markdown")
    elif data.startswith("admrep_ban_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.ban_chat_member(group_id, target_id)
            query.edit_message_text(f"🔨 User banned by {admin.first_name}", parse_mode="Markdown")
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)
    elif data.startswith("admrep_mute_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.restrict_chat_member(
                group_id, target_id, permissions=ChatPermissions(can_send_messages=False)
            )
            query.edit_message_text(f"🔇 User muted by {admin.first_name}", parse_mode="Markdown")
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)
    query.answer()

def handle_scam_alert_action(update: Update, context: CallbackContext):
    query = update.callback_query
    admin = query.from_user
    data = query.data
    group_id = get_group_id()
    if not group_id:
        query.answer("❌ Group ID not set.", show_alert=True)
        return

    if not is_group_admin(context, group_id, admin.id):
        query.answer("❌ Only group admins can take this action.", show_alert=True)
        return

    if data == "scamalert_ignore":
        query.edit_message_text(f"✅ Ignored by {admin.first_name}", parse_mode="Markdown")
    elif data.startswith("scamalert_ban_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.ban_chat_member(group_id, target_id)
            query.edit_message_text(f"🔨 Banned by {admin.first_name}", parse_mode="Markdown")
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)
    elif data.startswith("scamalert_mute_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.restrict_chat_member(
                group_id, target_id, permissions=ChatPermissions(can_send_messages=False)
            )
            query.edit_message_text(f"🔇 Muted by {admin.first_name}", parse_mode="Markdown")
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)
    query.answer()

# ---------- HEALTH SERVER ----------
def run_health_server():
    port = int(os.getenv("PORT", 8080))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Bot is running")
        def log_message(self, format, *args):
            pass
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    httpd.serve_forever()

# ---------- MAIN ----------
def main():
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    logger = logging.getLogger(__name__)

    # Verify DB tables exist (optional)
    try:
        supabase.table("settings").select("key").limit(1).execute()
        supabase.table("known_members").select("user_id").limit(1).execute()
    except Exception:
        logger.warning("Missing 'settings' or 'known_members' table – create them in Supabase.")

    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", help_command))
    dp.add_handler(CommandHandler("setgroup", setgroup_command))
    dp.add_handler(CommandHandler("groupid", groupid_command))
    dp.add_handler(MessageHandler(Filters.status_update.new_chat_members, new_chat_members))
    dp.add_handler(MessageHandler(Filters.forwarded, handle_forward_report))
    dp.add_handler(MessageHandler(
        Filters.chat_type.groups & (~Filters.forwarded) & (~Filters.status_update),
        track_group_message
    ))
    dp.add_handler(CallbackQueryHandler(connect_group_callback, pattern="^connect_group$"))
    dp.add_handler(CallbackQueryHandler(handle_admin_action, pattern="^admrep_"))
    dp.add_handler(CallbackQueryHandler(handle_scam_alert_action, pattern="^scamalert_"))

    logger.info("🎵 Angel X Music bot is running!")
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    threading.Thread(target=run_health_server, daemon=True).start()
    main()
