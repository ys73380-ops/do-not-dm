"""
DMGuardBot - COMPLETE FINAL VERSION

Features:
1. Group ID auto-detect + Supabase storage
2. Forward-based DM harassment reporting, admins ko Ban/Mute/Reject buttons ke saath
3. Known-member tracking (jab forward privacy ON ho tab naam-match guess ke liye)
4. Groq AI se scam/spam CONTENT detection - identity se independent hai,
   isliye privacy ON/OFF kuch bhi ho, ye hamesha kaam karega (kyunki ye
   sirf MESSAGE TEXT padhta hai, kisi ki ID nikalne ki koshish nahi karta)

IMPORTANT LIMITATION (isse koi bhi code fix nahi kar sakta):
Jo member group me hai lekin kabhi bola nahi (silent lurker) aur uski
forward-privacy ON hai - uski ID kisi bhi tareeke se nahi mil sakti.
Ye Telegram Bot API ki hard, intentional privacy limitation hai.

Dependencies:
    pip install python-telegram-bot==13.15 supabase python-dotenv requests

.env file me chahiye:
    BOT_TOKEN=...
    SUPABASE_URL=...
    SUPABASE_KEY=...
    GROQ_API_KEY=...        (optional - na ho to scam-detection feature off rahega)
    GROQ_MODEL=openai/gpt-oss-20b   (optional, default already achha hai)
"""

import json
import logging
import os
import time

import requests
from dotenv import load_dotenv
from supabase import create_client, Client
from telegram import InlineKeyboardMarkup, InlineKeyboardButton, ChatPermissions, Update
from telegram.ext import Updater, CommandHandler, MessageHandler, CallbackQueryHandler, Filters, CallbackContext

# --------------------- CONFIG ---------------------
load_dotenv()

# ⚠️ WARNING: Credentials hardcoded hain (user request par). Production me
# ye .env file me rakhna chahiye, kabhi bhi is file ko publicly share/upload
# (GitHub, WhatsApp, Telegram group) mat karna - warna bot aur database dono
# hijack ho sakte hain.
BOT_TOKEN = "8693447126:AAHwgqNjxf7ySgTkqAK5OHVdiIrKPS9elmo"
SUPABASE_URL = "https://kswscbxdvprasfdnqmxz.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtzd3NjYnhkdnByYXNmZG5xbXh6Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc4Mzk1NDczNiwiZXhwIjoyMDk5NTMwNzM2fQ.TAgO9NP0LVwWMuwpLmsWW-wPgQ1IIFax11WL1SbT2LA"
GROQ_API_KEY = "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"

# Groq ne purane llama-3.3-70b-versatile / llama-3.1-8b-instant models deprecate kar diye hain.
# openai/gpt-oss-20b fast + cheap hai, is simple classification task ke liye kaafi hai.
# Behtar quality chahiye to .env me GROQ_MODEL=openai/gpt-oss-120b set kar sakte ho.
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN missing.")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
if not GROQ_API_KEY:
    logging.warning("⚠️ GROQ_API_KEY set nahi hai - AI scam-content detection feature OFF rahega.")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Same user ko baar-baar flag na kare, isliye simple in-memory cooldown
# (bot restart hone par ye reset ho jaata hai - production me DB-based bhi kar sakte ho)
_recent_alerts = {}
ALERT_COOLDOWN_SECONDS = 300  # 5 minute

SUSPICIOUS_KEYWORDS = [
    "http://", "https://", "t.me/", "bit.ly", "wa.me", "telegram.me",
    "investment", "invest", "profit", "guaranteed return", "double your money",
    "crypto", "binance", "trading tips", "loan approved", "click here",
    "free gift", "lottery", "winner", "claim now", "paisa kamao",
    "earn money", "work from home", "job offer", "part time job",
    "whatsapp number", "call me", "dm me", "limited time",
]

# --------------------- TEXT HELPERS ---------------------

def escape_markdown(text: str) -> str:
    """Telegram legacy 'Markdown' parse mode ke special chars escape karo,
    taaki user-generated text (naam/message) formatting ko break na kare."""
    if not text:
        return text
    for ch in ("_", "*", "`", "["):
        text = text.replace(ch, f"\\{ch}")
    return text

# --------------------- DB HELPERS ---------------------

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
    """Har active member ko DB me save karo (sirf tab milta hai jab wo group me msg/join kare)."""
    try:
        supabase.table("known_members").upsert({
            "user_id": user_id,
            "first_name": first_name or "Unknown",
            "username": username or "N/A",
        }).execute()
    except Exception as e:
        logging.error(f"Error saving known member: {e}")

def find_members_by_name(name: str) -> list:
    """Naam se possible matches DB me dhundo. Ye sirf ek GUESS hai, proof nahi."""
    try:
        res = supabase.table("known_members").select("*").ilike("first_name", name).execute()
        return res.data or []
    except Exception as e:
        logging.error(f"Error finding members by name: {e}")
        return []

# --------------------- GROQ: SCAM CONTENT DETECTION ---------------------

def looks_suspicious(text: str) -> bool:
    """Quick keyword pre-filter - har single message par Groq API call nahi karna
    (cost aur latency dono bachane ke liye). Sirf suspicious lagne par hi AI call hoga."""
    if not text:
        return False
    lowered = text.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)

def analyze_scam_content(text: str) -> dict:
    """
    Groq API se message CONTENT analyze karo. Ye identity se bilkul independent hai -
    isliye privacy setting ON ho ya OFF, koi fark nahi padta, ye hamesha kaam karega.
    Returns: {"is_scam": bool, "confidence": "low/medium/high", "reason": str}
    """
    default = {"is_scam": False, "confidence": "low", "reason": "N/A"}
    if not GROQ_API_KEY or not text or not text.strip():
        return default

    prompt = (
        "Tum ek Telegram group moderation assistant ho. Neeche diya gaya message padho "
        "aur judge karo ki ye scam, spam, ya phishing jaisa lagta hai ya nahi. "
        "Normal harmless conversation ko galti se scam mat bolo.\n\n"
        f"Message: \"{text[:1000]}\"\n\n"
        "SIRF is JSON format mein jawab do, koi aur text ya markdown fence mat likho:\n"
        '{"is_scam": true or false, "confidence": "low" or "medium" or "high", "reason": "ek chhoti si line"}'
    )

    try:
        response = requests.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
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
    """Cooldown check - same user ko thodi der tak dobara flag na karo."""
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

# --------------------- HANDLERS ---------------------

def start(update: Update, context: CallbackContext):
    update.message.reply_text(
        "🤖 DMGuardBot ready hai.\n"
        "Mujhe group mein admin banao, main group ID Supabase me save kar lunga.\n"
        "Phir koi bhi forwarded DM mujhe bhejo, main admins ke paas report bhej dunga.\n"
        "Main group ke scam/spam messages bhi AI se automatically detect karta rahunga."
    )

def new_chat_members(update: Update, context: CallbackContext):
    bot_id = context.bot.id
    for member in update.message.new_chat_members:
        if member.id == bot_id:
            chat_id = update.effective_chat.id
            set_group_id_db(chat_id)
            context.bot.send_message(
                chat_id,
                f"✅ Group ID `{chat_id}` save kar li. Ab members mujhe DM forward karke report kar sakte hain.",
                parse_mode="Markdown"
            )
        else:
            save_known_member(member.id, member.first_name, member.username)
    return

def setgroup_command(update: Update, context: CallbackContext):
    if update.effective_chat.type == "private":
        if not context.args:
            update.message.reply_text("Usage: /setgroup <group_id> (e.g., -1001234567890)")
            return
        try:
            gid = int(context.args[0])
        except ValueError:
            update.message.reply_text("Group ID number hona chahiye.")
            return
        set_group_id_db(gid)
        update.message.reply_text(f"✅ Group ID set to `{gid}`", parse_mode="Markdown")
    else:
        gid = update.effective_chat.id
        set_group_id_db(gid)
        update.message.reply_text(f"✅ Group ID set to `{gid}` (yehi group)", parse_mode="Markdown")

def groupid_command(update: Update, context: CallbackContext):
    gid = get_group_id()
    if gid:
        update.message.reply_text(f"Current group ID: `{gid}`", parse_mode="Markdown")
    else:
        update.message.reply_text("❌ Group ID set nahi hai. Bot ko group me admin banao ya /setgroup use karo.")

def track_group_message(update: Update, context: CallbackContext):
    """
    Har normal (non-forwarded) group message par:
    1. Sender ko silently track karo (future forward-privacy-ON name-matching ke liye)
    2. Content ko AI se scam-pattern ke liye check karo (identity ki zaroorat nahi,
       isliye privacy ON/OFF se koi fark nahi padta)

    NOTE: Silent lurkers (jo kabhi message nahi bhejte) is se bhi track nahi honge -
    ye Telegram Bot API ki hard limitation hai, iska koi workaround exist nahi karta.
    """
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
        logging.error(f"Admins fetch error in scam alert: {e}")
        return

    admin_mentions = " ".join(
        f"[{escape_markdown(a.user.first_name)}](tg://user?id={a.user.id})"
        for a in admins if not a.user.is_bot
    )

    preview = text[:200] + ("..." if len(text) > 200 else "")

    alert_text = (
        f"🚨 *AI ne Scam Pattern Detect Kiya* (khud bhi verify karo)\n\n"
        f"👤 User: [{escape_markdown(user.first_name)}](tg://user?id={user.id}) "
        f"(@{user.username or 'no_username'})\n"
        f"📝 Message: _{escape_markdown(preview)}_\n"
        f"🔍 AI Reason: {escape_markdown(result['reason'])}\n"
        f"⚠️ Confidence: {result['confidence']}\n\n"
        f"{admin_mentions}\n"
        f"Ye AI ka analysis hai, final decision khud padh kar lo:"
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
        msg.reply_text("❌ Group ID set nahi hai. Bot ko group me admin banao ya /setgroup use karo.")
        return

    if not msg.forward_date:
        msg.reply_text("⚠️ Sirf forward kiya hua original DM message hi valid proof hai.\n"
                       "Screenshot ya sirf text kaam nahi karega.")
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
                    f"\n🔎 *Possible Match Mila* (confidence: medium):\n"
                    f"[{escape_markdown(m['first_name'])}](tg://user?id={m['user_id']}) "
                    f"(@{m['username']})\n"
                    f"⚠️ Ye sirf naam-match ke aadhar par guess hai, 100% confirm nahi. "
                    f"Admin manually verify karke hi action le."
                )
            elif len(possible_matches) > 1:
                names_list = "\n".join(
                    f"- [{escape_markdown(m['first_name'])}](tg://user?id={m['user_id']}) (@{m['username']})"
                    for m in possible_matches
                )
                match_note = (
                    f"\n🔎 *{len(possible_matches)} Possible Matches Mile*:\n"
                    f"{names_list}\n"
                    f"⚠️ Confirm karke hi action lo, galat insaan ban ho sakta hai."
                )
            else:
                match_note = (
                    "\nℹ️ Is naam ka koi member DB me track nahi hua "
                    "(ya to wo silent lurker hai ya kabhi group me msg nahi kiya)."
                )

    # AI content check - forwarded message text par bhi (identity se independent, hamesha kaam karta hai)
    scam_note = ""
    forwarded_text = msg.text or msg.caption or ""
    if forwarded_text:
        scam_result = analyze_scam_content(forwarded_text)
        if scam_result["is_scam"]:
            scam_note = (
                f"\n🤖 *AI Content Check:* Scam-jaisa lagta hai "
                f"(confidence: {scam_result['confidence']})\n"
                f"   Reason: {escape_markdown(scam_result['reason'])}"
            )

    try:
        admins = context.bot.get_chat_administrators(group_id)
    except Exception as e:
        msg.reply_text(f"❌ Group admins fetch nahi ho paye: {e}")
        return

    admin_mentions = " ".join(
        f"[{escape_markdown(a.user.first_name)}](tg://user?id={a.user.id})"
        for a in admins if not a.user.is_bot
    )

    verified_text = "✅ Identity Verified (forward se)" if verified else "⚠️ Identity NOT verified (privacy ON tha)"

    report_text = (
        f"🚨 *DM Report Aayi Hai*\n\n"
        f"👤 Reporter: [{escape_markdown(reporter.first_name)}](tg://user?id={reporter.id})\n"
        f"🎯 Reported User: {escape_markdown(target_name)} (@{target_username})\n"
        f"🔍 Status: {verified_text}"
        f"{match_note}"
        f"{scam_note}\n\n"
        f"{admin_mentions}\n"
        f"⬇️ Neeche evidence hai, review karke action lo:"
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
            InlineKeyboardButton("🔨 Ban (guess-based, risky)", callback_data=f"admrep_ban_{guess_id}"),
            InlineKeyboardButton("🔇 Mute (guess-based, risky)", callback_data=f"admrep_mute_{guess_id}")
        ])
    buttons.append([InlineKeyboardButton("❌ Reject", callback_data="admrep_reject")])

    keyboard = InlineKeyboardMarkup(buttons)

    try:
        context.bot.forward_message(group_id, msg.chat_id, msg.message_id)
        context.bot.send_message(group_id, report_text, reply_markup=keyboard, parse_mode="Markdown")
        msg.reply_text("✅ Tumhari report group admins ko bhej di gayi hai review ke liye.")
    except Exception as e:
        msg.reply_text(f"❌ Report bhejte waqt error aaya: {e}")

def handle_admin_action(update: Update, context: CallbackContext):
    query = update.callback_query
    admin = query.from_user
    data = query.data

    group_id = get_group_id()
    if not group_id:
        query.answer("❌ Group ID set nahi hai.", show_alert=True)
        return

    if not is_group_admin(context, group_id, admin.id):
        query.answer("❌ Sirf group admins hi ye action le sakte hain!", show_alert=True)
        return

    if data == "admrep_reject":
        query.edit_message_text(f"❌ Report reject ki gayi by {admin.first_name}", parse_mode="Markdown")

    elif data.startswith("admrep_ban_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.ban_chat_member(group_id, target_id)
            query.edit_message_text(f"🔨 User ban kar diya gaya by {admin.first_name}", parse_mode="Markdown")
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)

    elif data.startswith("admrep_mute_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.restrict_chat_member(
                group_id, target_id, permissions=ChatPermissions(can_send_messages=False)
            )
            query.edit_message_text(f"🔇 User mute kar diya gaya by {admin.first_name}", parse_mode="Markdown")
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)

    query.answer()

def handle_scam_alert_action(update: Update, context: CallbackContext):
    query = update.callback_query
    admin = query.from_user
    data = query.data

    group_id = get_group_id()
    if not group_id:
        query.answer("❌ Group ID set nahi hai.", show_alert=True)
        return

    if not is_group_admin(context, group_id, admin.id):
        query.answer("❌ Sirf group admins hi ye action le sakte hain!", show_alert=True)
        return

    if data == "scamalert_ignore":
        query.edit_message_text(f"✅ False alarm maana gaya by {admin.first_name}", parse_mode="Markdown")

    elif data.startswith("scamalert_ban_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.ban_chat_member(group_id, target_id)
            query.edit_message_text(
                f"🔨 User ban kar diya gaya (AI-flagged) by {admin.first_name}", parse_mode="Markdown"
            )
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)

    elif data.startswith("scamalert_mute_"):
        target_id = int(data.split("_")[-1])
        try:
            context.bot.restrict_chat_member(
                group_id, target_id, permissions=ChatPermissions(can_send_messages=False)
            )
            query.edit_message_text(
                f"🔇 User mute kar diya gaya (AI-flagged) by {admin.first_name}", parse_mode="Markdown"
            )
        except Exception as e:
            query.answer(f"Error: {e}", show_alert=True)

    query.answer()

# --------------------- MAIN ---------------------
def main():
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    logger = logging.getLogger(__name__)

    try:
        supabase.table("settings").select("key").limit(1).execute()
        supabase.table("known_members").select("user_id").limit(1).execute()
    except Exception:
        logger.warning(
            "'settings' ya 'known_members' table missing ho sakti hai. "
            "Supabase dashboard me SQL Editor se manually bana lo."
        )

    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("setgroup", setgroup_command))
    dp.add_handler(CommandHandler("groupid", groupid_command))
    dp.add_handler(MessageHandler(Filters.status_update.new_chat_members, new_chat_members))

    # Forwarded messages -> DM harassment report flow
    dp.add_handler(MessageHandler(Filters.forwarded, handle_forward_report))

    # Normal group messages -> member tracking + AI scam-content detection
    dp.add_handler(MessageHandler(
        Filters.chat_type.groups & (~Filters.forwarded) & (~Filters.status_update),
        track_group_message
    ))

    dp.add_handler(CallbackQueryHandler(handle_admin_action, pattern="^admrep_"))
    dp.add_handler(CallbackQueryHandler(handle_scam_alert_action, pattern="^scamalert_"))

    logger.info("✅ DMGuardBot (Supabase + Groq AI) start ho gaya.")
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
