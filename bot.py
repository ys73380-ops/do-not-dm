"""
DM Guard Bot – Group Moderation + DM Report System
Full moderation: DM reports, AI scam detection, ban/mute, Supabase storage.

Version: 2.0
Author: DM Guard Team
License: MIT
"""

import asyncio
import csv
import io
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, List, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Event

import aiohttp
from dotenv import load_dotenv
from supabase import create_client, Client
from telegram import (
    Update,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ChatPermissions,
    InputFile,
)
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
    Defaults,
)
from telegram.error import TelegramError, BadRequest

# --------------------- CONFIGURATION ---------------------
load_dotenv()

# Required environment variables
BOT_TOKEN = os.getenv("BOT_TOKEN")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Optional environment variables with defaults
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama3-70b-8192")
GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
SUPPORT_LINK = os.getenv("SUPPORT_LINK", "https://t.me/khushimilti")
CHANNEL_LINK = os.getenv("CHANNEL_LINK", "https://t.me/your_channel_here")
PORT = int(os.getenv("PORT", "8080"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Validate required environment variables
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN missing. Set it in your .env file.")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set in your .env file.")
if not GROQ_API_KEY:
    logging.warning("⚠️ GROQ_API_KEY missing – AI scam detection disabled.")

# Initialize Supabase client
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    logging.error(f"Failed to initialize Supabase client: {e}")
    raise

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=getattr(logging, LOG_LEVEL.upper()),
)
logger = logging.getLogger(__name__)

# --------------------- DATA MODELS ---------------------
@dataclass
class ScamAnalysisResult:
    """Result of scam content analysis"""
    is_scam: bool
    confidence: str  # "low", "medium", "high"
    reason: str

@dataclass
class MemberInfo:
    """Information about a group member"""
    user_id: int
    first_name: str
    username: Optional[str] = None

# --------------------- STATE MANAGEMENT ---------------------
_recent_alerts: Dict[int, float] = {}
_alert_lock = asyncio.Lock()
_shutdown_event = Event()

# --------------------- SUSPICIOUS PATTERNS ---------------------
SUSPICIOUS_KEYWORDS = [
    "http://", "https://", "t.me/", "bit.ly", "wa.me", "telegram.me",
    "investment", "invest", "profit", "guaranteed return", "double your money",
    "crypto", "binance", "trading tips", "loan approved", "click here",
    "free gift", "lottery", "winner", "claim now", "paisa kamao",
    "earn money", "work from home", "job offer", "part time job",
    "whatsapp number", "call me", "dm me", "limited time",
    "quick money", "easy money", "get rich", "passive income",
    "binary options", "forex", "pump and dump", "airdrop",
    "giveaway", "bonus", "reward", "prize", "winning",
]

SUSPICIOUS_PATTERNS = [
    r'\b\d+\s*(?:usd|eur|inr|rupees|dollars)\b',  # Money amounts
    r'\b\d+%\s*(?:return|profit|interest)\b',  # Percentage returns
    r'\+\d{10,}',  # Phone numbers
    r'[a-zA-Z0-9]{32,}',  # Long hex strings (crypto addresses)
]

# --------------------- TEXT HELPERS ---------------------
def escape_markdown(text: str) -> str:
    """Escape special Markdown characters"""
    if not text:
        return text
    for ch in ("_", "*", "`", "[", "]", "(", ")", "~", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
        text = text.replace(ch, f"\\{ch}")
    return text

def escape_html(text: str) -> str:
    """Escape special HTML characters"""
    if not text:
        return text
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

def truncate_text(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length and add ellipsis if needed"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."

# --------------------- DATABASE HELPERS ---------------------
async def get_group_id() -> Optional[int]:
    """Fetch the configured group ID from database"""
    try:
        res = supabase.table("settings").select("value").eq("key", "group_id").execute()
        if res.data and len(res.data) > 0:
            return int(res.data[0]["value"])
    except Exception as e:
        logger.error(f"Error fetching group_id: {e}")
    return None

async def set_group_id_db(chat_id: int) -> None:
    """Save the group ID to database"""
    try:
        supabase.table("settings").upsert({"key": "group_id", "value": str(chat_id)}).execute()
        logger.info(f"Group ID set to {chat_id}")
    except Exception as e:
        logger.error(f"Error saving group_id: {e}")

async def save_known_member(user_id: int, first_name: str, username: Optional[str]) -> None:
    """Save member information to database"""
    try:
        supabase.table("known_members").upsert({
            "user_id": user_id,
            "first_name": first_name or "Unknown",
            "username": username or "N/A",
        }).execute()
    except Exception as e:
        logger.error(f"Error saving known member: {e}")

async def find_members_by_name(name: str) -> List[Dict[str, Any]]:
    """Find members by first name (case-insensitive)"""
    try:
        res = supabase.table("known_members").select("*").ilike("first_name", name).execute()
        return res.data or []
    except Exception as e:
        logger.error(f"Error finding members by name: {e}")
        return []

async def verify_database_tables() -> bool:
    """Verify that required database tables exist"""
    try:
        supabase.table("settings").select("key").limit(1).execute()
        supabase.table("known_members").select("user_id").limit(1).execute()
        return True
    except Exception as e:
        logger.warning(f"Database tables may not exist: {e}")
        return False

async def get_all_members() -> List[Dict[str, Any]]:
    """Fetch all known members from database"""
    try:
        res = supabase.table("known_members").select("*").execute()
        return res.data or []
    except Exception as e:
        logger.error(f"Error fetching all members: {e}")
        return []

# --------------------- SCAM DETECTION ---------------------
def looks_suspicious(text: str) -> bool:
    """Check if text contains suspicious keywords"""
    if not text:
        return False
    lowered = text.lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)

async def analyze_scam_content(text: str) -> ScamAnalysisResult:
    """Use AI to analyze if content is a scam"""
    default = ScamAnalysisResult(is_scam=False, confidence="low", reason="N/A")
    
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
        async with aiohttp.ClientSession() as session:
            async with session.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": GROQ_MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                    "max_tokens": 150,
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                response.raise_for_status()
                data = await response.json()
                content = data["choices"][0]["message"]["content"].strip()
                content = content.replace("```json", "").replace("```", "").strip()
                result = json.loads(content)
                
                return ScamAnalysisResult(
                    is_scam=bool(result.get("is_scam", False)),
                    confidence=result.get("confidence", "low"),
                    reason=result.get("reason", "N/A"),
                )
    except asyncio.TimeoutError:
        logger.error("Groq API timeout")
        return default
    except aiohttp.ClientError as e:
        logger.error(f"Groq API error: {e}")
        return default
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"Groq API response parsing error: {e}")
        return default
    except Exception as e:
        logger.error(f"Unexpected error in scam analysis: {e}")
        return default

async def should_alert(user_id: int) -> bool:
    """Check if we should send an alert for this user (respects cooldown)"""
    async with _alert_lock:
        now = time.time()
        last = _recent_alerts.get(user_id, 0)
        if now - last < ALERT_COOLDOWN_SECONDS:
            return False
        _recent_alerts[user_id] = now
        return True

async def is_group_admin(application, group_id: int, user_id: int) -> bool:
    """Check if a user is an admin in the group"""
    try:
        member = await application.bot.get_chat_member(group_id, user_id)
        return member.status in ("administrator", "creator")
    except Exception as e:
        logger.error(f"Error checking admin status: {e}")
        return False

# --------------------- COMMAND HANDLERS ---------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command"""
    user = update.effective_user
    if not user:
        return
    
    first_name = escape_html(user.first_name)
    add_group_url = f"https://t.me/{context.bot.username}?startgroup=true"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add me to your group", url=add_group_url)],
        [InlineKeyboardButton("❓ Help", callback_data="show_help")],
        [InlineKeyboardButton("📥 Download Data", callback_data="show_download_menu")],
        [
            InlineKeyboardButton("💬 Support", url=SUPPORT_LINK),
            InlineKeyboardButton("📢 Channel", url=CHANNEL_LINK)
        ]
    ])

    message = (
        f"👋 Hello <b>{first_name}</b>\n\n"
        f" welcomes you to <b>DM Guard Bot</b> — your group's safety shield.\n\n"
        f"<blockquote>🛡️ <b>Smart Scam &amp; Spam Detection</b>\n"
        f"AI-powered scanning catches phishing links, scam messages, and shady DMs before they hurt your group.</blockquote>\n\n"
        f"You can explore the bot using the buttons below, even before adding me to a group."
    )
    
    await update.message.reply_text(message, parse_mode="HTML", reply_markup=keyboard)

async def show_help_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle help button callback"""
    query = update.callback_query
    if not query:
        return
    
    try:
        await query.answer()
        await query.edit_message_text(
            "🤖 <b>What I do:</b>\n\n"
            "• Protect your group from spam and scams using AI\n"
            "• Alert admins when someone forwards a harassing DM\n"
            "• Track known members to help identify users with privacy ON\n"
            "• All actions (ban/mute) are controlled by admins via inline buttons\n"
            "• Download member data and reports\n\n"
            "📌 <b>Commands:</b>\n"
            "/start – Show the welcome message\n"
            "/setgroup – Set the group ID (run inside the group)\n"
            "/groupid – Show current group ID\n"
            "/download – Download data (admin only)\n"
            "/info – This help message",
            parse_mode="HTML"
        )
    except Exception as e:
        logger.error(f"show_help_callback error: {e}")

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /info command"""
    await update.message.reply_text(
        "🤖 *What I do:*\n\n"
        "• I protect your group from spam and scams using AI.\n"
        "• Admins receive reports when someone forwards a harassing DM.\n"
        "• I track known members to help identify users with privacy ON.\n"
        "• All actions (ban/mute) are controlled by admins via inline buttons.\n\n"
        "📌 *Commands:*\n"
        "/start – Show the welcome message\n"
        "/setgroup <group_id> – Manually set the group ID\n"
        "/groupid – Show current group ID\n"
        "/download – Download data (admin only)\n"
        "/info – This help message",
        parse_mode="Markdown"
    )

async def new_chat_members(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle new chat members (including bot itself)"""
    bot_id = context.bot.id
    for member in update.message.new_chat_members:
        if member.id == bot_id:
            chat_id = update.effective_chat.id
            await set_group_id_db(chat_id)
            await context.bot.send_message(
                chat_id,
                "✅ *DM Guard Bot* is now connected!\n"
                "I'll keep this group protected from scams and spam.",
                parse_mode="Markdown"
            )
        else:
            await save_known_member(member.id, member.first_name, member.username)

async def setgroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /setgroup command"""
    if update.effective_chat.type == "private":
        if not context.args:
            await update.message.reply_text("Usage: /setgroup <group_id> (e.g., -1001234567890)")
            return
        try:
            gid = int(context.args[0])
        except ValueError:
            await update.message.reply_text("Group ID must be a number.")
            return
        await set_group_id_db(gid)
        await update.message.reply_text(f"✅ Group ID set to `{gid}`", parse_mode="Markdown")
    else:
        gid = update.effective_chat.id
        await set_group_id_db(gid)
        await update.message.reply_text(f"✅ Group ID set to `{gid}`", parse_mode="Markdown")

async def groupid_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /groupid command"""
    gid = await get_group_id()
    if gid:
        await update.message.reply_text(f"Current group ID: `{gid}`", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Group ID not set. Add me as admin or use /setgroup.")

async def download_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /download command - show download menu"""
    await show_download_menu_callback(update, context)

# --------------------- MESSAGE HANDLERS ---------------------
async def track_group_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Track and analyze group messages for suspicious content"""
    if update.effective_chat.type not in ("group", "supergroup"):
        return

    user = update.message.from_user
    text = update.message.text or update.message.caption or ""

    if user and not user.is_bot:
        await save_known_member(user.id, user.first_name, user.username)

    if text and looks_suspicious(text) and user and await should_alert(user.id):
        result = await analyze_scam_content(text)
        if result.is_scam and result.confidence in ("medium", "high"):
            await alert_admins_scam(context, user, text, result)

async def alert_admins_scam(
    context: ContextTypes.DEFAULT_TYPE,
    user,
    text: str,
    result: ScamAnalysisResult
) -> None:
    """Send alert to admins about potential scam"""
    group_id = await get_group_id()
    if not group_id:
        return

    try:
        admins = await context.bot.get_chat_administrators(group_id)
    except Exception as e:
        logger.error(f"Admins fetch error: {e}")
        return

    admin_mentions = " ".join(
        f"[{escape_markdown(a.user.first_name)}](tg://user?id={a.user.id})"
        for a in admins if not a.user.is_bot
    )

    preview = truncate_text(text, 200)
    alert_text = (
        f"🚨 *AI detected a potential scam pattern*\n\n"
        f"👤 User: [{escape_markdown(user.first_name)}](tg://user?id={user.id}) "
        f"(@{user.username or 'no_username'})\n"
        f"📝 Message: _{escape_markdown(preview)}_\n"
        f"🔍 Reason: {escape_markdown(result.reason)}\n"
        f"⚠️ Confidence: {result.confidence}\n\n"
        f"{admin_mentions}\n"
        f"Verify and take action:"
    )

    buttons = [
        [
            InlineKeyboardButton("🔨 Ban", callback_data=f"scamalert_ban_{user.id}"),
            InlineKeyboardButton("🔇 Mute", callback_data=f"scamalert_mute_{user.id}")
        ],
        [InlineKeyboardButton("✅ False Alarm", callback_data="scamalert_ignore")]
    ]
    keyboard = InlineKeyboardMarkup(buttons)

    try:
        await context.bot.send_message(group_id, alert_text, reply_markup=keyboard, parse_mode="Markdown")
    except Exception as e:
        logger.error(f"Error sending scam alert: {e}")

async def handle_forward_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle forwarded messages as DM reports"""
    msg = update.message
    reporter = msg.from_user
    if not reporter:
        return
    
    group_id = await get_group_id()
    if not group_id:
        await msg.reply_text("❌ Group ID not set. Add me as admin or use /setgroup.")
        return

    if not msg.forward_date:
        await msg.reply_text("⚠️ Only forwarded original messages are accepted as proof.")
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
            possible_matches = await find_members_by_name(msg.forward_sender_name)
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

    scam_note = ""
    forwarded_text = msg.text or msg.caption or ""
    if forwarded_text:
        scam_result = await analyze_scam_content(forwarded_text)
        if scam_result.is_scam:
            scam_note = (
                f"\n🤖 *AI Content Check:* possible scam "
                f"(confidence: {scam_result.confidence})\n"
                f"   Reason: {escape_markdown(scam_result.reason)}"
            )

    try:
        admins = await context.bot.get_chat_administrators(group_id)
    except Exception as e:
        await msg.reply_text(f"❌ Could not fetch admins: {e}")
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
        await context.bot.forward_message(group_id, msg.chat_id, msg.message_id)
        await context.bot.send_message(group_id, report_text, reply_markup=keyboard, parse_mode="Markdown")
        await msg.reply_text("✅ Your report has been sent to the group admins.")
    except Exception as e:
        await msg.reply_text(f"❌ Error sending report: {e}")

# --------------------- CALLBACK HANDLERS ---------------------
async def handle_admin_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle admin action buttons for DM reports"""
    query = update.callback_query
    if not query:
        return
    
    admin = query.from_user
    data = query.data
    group_id = await get_group_id()
    
    if not group_id:
        await query.answer("❌ Group ID not set.", show_alert=True)
        return

    if not await is_group_admin(context.application, group_id, admin.id):
        await query.answer("❌ Only group admins can take this action.", show_alert=True)
        return

    try:
        if data == "admrep_reject":
            await query.edit_message_text(f"❌ Report rejected by {admin.first_name}", parse_mode="Markdown")
        elif data.startswith("admrep_ban_"):
            target_id = int(data.split("_")[-1])
            await context.bot.ban_chat_member(group_id, target_id)
            await query.edit_message_text(f"🔨 User banned by {admin.first_name}", parse_mode="Markdown")
        elif data.startswith("admrep_mute_"):
            target_id = int(data.split("_")[-1])
            await context.bot.restrict_chat_member(
                group_id, target_id, permissions=ChatPermissions(can_send_messages=False)
            )
            await query.edit_message_text(f"🔇 User muted by {admin.first_name}", parse_mode="Markdown")
        
        await query.answer()
    except BadRequest as e:
        await query.answer(f"Error: {e}", show_alert=True)
    except Exception as e:
        logger.error(f"Error in handle_admin_action: {e}")
        await query.answer(f"Error: {e}", show_alert=True)

async def handle_scam_alert_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle admin action buttons for scam alerts"""
    query = update.callback_query
    if not query:
        return
    
    admin = query.from_user
    data = query.data
    group_id = await get_group_id()
    
    if not group_id:
        await query.answer("❌ Group ID not set.", show_alert=True)
        return

    if not await is_group_admin(context.application, group_id, admin.id):
        await query.answer("❌ Only group admins can take this action.", show_alert=True)
        return

    try:
        if data == "scamalert_ignore":
            await query.edit_message_text(f"✅ Ignored by {admin.first_name}", parse_mode="Markdown")
        elif data.startswith("scamalert_ban_"):
            target_id = int(data.split("_")[-1])
            await context.bot.ban_chat_member(group_id, target_id)
            await query.edit_message_text(f"🔨 Banned by {admin.first_name}", parse_mode="Markdown")
        elif data.startswith("scamalert_mute_"):
            target_id = int(data.split("_")[-1])
            await context.bot.restrict_chat_member(
                group_id, target_id, permissions=ChatPermissions(can_send_messages=False)
            )
            await query.edit_message_text(f"🔇 Muted by {admin.first_name}", parse_mode="Markdown")
        
        await query.answer()
    except BadRequest as e:
        await query.answer(f"Error: {e}", show_alert=True)
    except Exception as e:
        logger.error(f"Error in handle_scam_alert_action: {e}")
        await query.answer(f"Error: {e}", show_alert=True)

# --------------------- DOWNLOAD HANDLERS ---------------------
async def show_download_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show download menu"""
    query = update.callback_query if update.callback_query else None
    message = query.message if query else update.message
    
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("📋 Download Members (CSV)", callback_data="download_members_csv")],
        [InlineKeyboardButton("📊 Download Members (JSON)", callback_data="download_members_json")],
        [InlineKeyboardButton("🔙 Back", callback_data="show_main_menu")]
    ])
    
    text = "📥 <b>Download Data</b>\n\nChoose what you want to download:"
    
    try:
        if query:
            await query.answer()
            await query.edit_message_text(text, parse_mode="HTML", reply_markup=keyboard)
        else:
            await message.reply_text(text, parse_mode="HTML", reply_markup=keyboard)
    except Exception as e:
        logger.error(f"Error showing download menu: {e}")

async def show_main_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show main menu"""
    query = update.callback_query
    if not query:
        return
    
    user = update.effective_user
    if not user:
        return
    
    first_name = escape_html(user.first_name)
    add_group_url = f"https://t.me/{context.bot.username}?startgroup=true"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("➕ Add me to your group", url=add_group_url)],
        [InlineKeyboardButton("❓ Help", callback_data="show_help")],
        [InlineKeyboardButton("📥 Download Data", callback_data="show_download_menu")],
        [
            InlineKeyboardButton("💬 Support", url=SUPPORT_LINK),
            InlineKeyboardButton("📢 Channel", url=CHANNEL_LINK)
        ]
    ])

    message = (
        f"👋 Hello <b>{first_name}</b>\n\n"
        f" welcomes you to <b>DM Guard Bot</b> — your group's safety shield.\n\n"
        f"<blockquote>🛡️ <b>Smart Scam &amp; Spam Detection</b>\n"
        f"AI-powered scanning catches phishing links, scam messages, and shady DMs before they hurt your group.</blockquote>\n\n"
        f"You can explore the bot using the buttons below, even before adding me to a group."
    )
    
    try:
        await query.answer()
        await query.edit_message_text(message, parse_mode="HTML", reply_markup=keyboard)
    except Exception as e:
        logger.error(f"Error showing main menu: {e}")

async def download_members_csv(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Download members as CSV file"""
    query = update.callback_query
    if not query:
        return
    
    try:
        await query.answer("⏳ Preparing CSV file...")
        
        members = await get_all_members()
        if not members:
            await query.edit_message_text("❌ No members found in database.")
            return
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(["User ID", "First Name", "Username", "Last Updated"])
        
        # Write data
        for member in members:
            writer.writerow([
                member.get("user_id", ""),
                member.get("first_name", ""),
                member.get("username", ""),
                member.get("updated_at", "")
            ])
        
        # Convert to bytes
        csv_bytes = output.getvalue().encode('utf-8')
        csv_file = io.BytesIO(csv_bytes)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"members_{timestamp}.csv"
        
        # Send file
        await query.edit_message_text("📤 Sending CSV file...")
        await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=InputFile(csv_file, filename=filename),
            caption=f"📋 Members list - {len(members)} members"
        )
        
    except Exception as e:
        logger.error(f"Error downloading members CSV: {e}")
        await query.edit_message_text(f"❌ Error: {e}")

async def download_members_json(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Download members as JSON file"""
    query = update.callback_query
    if not query:
        return
    
    try:
        await query.answer("⏳ Preparing JSON file...")
        
        members = await get_all_members()
        if not members:
            await query.edit_message_text("❌ No members found in database.")
            return
        
        # Create JSON data
        json_data = {
            "export_date": datetime.now().isoformat(),
            "total_members": len(members),
            "members": members
        }
        
        # Convert to bytes
        json_bytes = json.dumps(json_data, indent=2, ensure_ascii=False).encode('utf-8')
        json_file = io.BytesIO(json_bytes)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"members_{timestamp}.json"
        
        # Send file
        await query.edit_message_text("📤 Sending JSON file...")
        await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=InputFile(json_file, filename=filename),
            caption=f"📊 Members data - {len(members)} members"
        )
        
    except Exception as e:
        logger.error(f"Error downloading members JSON: {e}")
        await query.edit_message_text(f"❌ Error: {e}")

# --------------------- ERROR HANDLING ---------------------
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors from the bot"""
    logger.error(f"Update {update} caused error: {context.error}", exc_info=context.error)

# --------------------- HEALTH CHECK SERVER ---------------------
class HealthCheckHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for health checks"""
    
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Bot is running")
        elif self.path == "/ready":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Bot is ready")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def run_health_server(port: int, shutdown_event: Event) -> None:
    """Run the health check server in a separate thread"""
    try:
        httpd = HTTPServer(("0.0.0.0", port), HealthCheckHandler)
        logger.info(f"Health check server started on port {port}")
        
        # Run until shutdown event is set
        while not shutdown_event.is_set():
            httpd.handle_request()
    except Exception as e:
        logger.error(f"Health check server error: {e}")
    finally:
        logger.info("Health check server stopped")

# --------------------- MAIN APPLICATION ---------------------
async def post_init(application: Application) -> None:
    """Post-initialization hook"""
    logger.info("Bot initialized successfully")
    
    # Verify database tables
    if not await verify_database_tables():
        logger.warning("Database tables may not be properly configured")

async def post_shutdown(application: Application) -> None:
    """Post-shutdown hook"""
    logger.info("Bot shutting down")

def main() -> None:
    """Main entry point"""
    # Create application with default settings
    defaults = Defaults(
        block=False,
        quote=True,
    )
    
    application = (
        Application.builder()
        .token(BOT_TOKEN)
        .defaults(defaults)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # Register handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("info", info))
    application.add_handler(CommandHandler("setgroup", setgroup_command))
    application.add_handler(CommandHandler("groupid", groupid_command))
    application.add_handler(CommandHandler("download", download_command))
    
    application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, new_chat_members))
    application.add_handler(MessageHandler(filters.FORWARDED, handle_forward_report))
    application.add_handler(
        MessageHandler(
            filters.ChatType.GROUPS & ~filters.FORWARDED & ~filters.StatusUpdate,
            track_group_message
        )
    )
    
    application.add_handler(CallbackQueryHandler(show_help_callback, pattern="^show_help$"))
    application.add_handler(CallbackQueryHandler(handle_admin_action, pattern="^admrep_"))
    application.add_handler(CallbackQueryHandler(handle_scam_alert_action, pattern="^scamalert_"))
    application.add_handler(CallbackQueryHandler(show_download_menu_callback, pattern="^show_download_menu$"))
    application.add_handler(CallbackQueryHandler(show_main_menu_callback, pattern="^show_main_menu$"))
    application.add_handler(CallbackQueryHandler(download_members_csv, pattern="^download_members_csv$"))
    application.add_handler(CallbackQueryHandler(download_members_json, pattern="^download_members_json$"))
    
    application.add_error_handler(error_handler)

    # Start health check server
    health_thread = Thread(target=run_health_server, args=(PORT, _shutdown_event), daemon=True)
    health_thread.start()

    # Run the bot
    logger.info("🛡️ DM Guard Bot is running!")
    try:
        application.run_polling(drop_pending_updates=True)
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        _shutdown_event.set()
        logger.info("Bot stopped")

if __name__ == "__main__":
    main()
