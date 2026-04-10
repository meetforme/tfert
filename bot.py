import asyncio
import hashlib
import logging
import math
import os
import random
import re
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from telegram import (
    BotCommand,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    Update,
)
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

APP_NAME = "ProfShock Mega Bot"
VERSION = "2.0"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "megabot.db"
LOG_PATH = BASE_DIR / "megabot.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler()],
)
logger = logging.getLogger(APP_NAME)

MAIN_KEYBOARD = ReplyKeyboardMarkup(
    [
        [KeyboardButton("ℹ️ Инфо"), KeyboardButton("🛡 ИБ-режим")],
        [KeyboardButton("🔐 Генератор пароля"), KeyboardButton("🧮 Калькулятор")],
        [KeyboardButton("📝 Заметки"), KeyboardButton("✅ ToDo")],
        [KeyboardButton("🎲 Развлечения"), KeyboardButton("⏰ Напоминание")],
        [KeyboardButton("📊 Дашборд"), KeyboardButton("👑 Админ")],
    ],
    resize_keyboard=True,
)

ATTACK_PATTERNS = {
    "sql": r"('|--|;|drop\s+table|union\s+select)",
    "xss": r"(<script|javascript:|onerror=|onload=)",
    "path": r"(\.\./|\\\.\\|/etc/passwd|system32)",
    "cmd": r"(rm\s+-rf|del\s+/f|shutdown|powershell|cmd\.exe)",
}

JOKES = [
    "ИБ-шник не спит — он проводит ночной мониторинг.",
    "Лучший пароль — тот, который помнишь только ты и менеджер паролей.",
    "Когда преподаватель спросил про threat model, бот уже построил три.",
    "У хорошего бота две любви: логирование и минимизация привилегий.",
]

QUOTES = [
    "Безопасность — это процесс, а не продукт.",
    "Самая дорогая уязвимость — та, которую считали маловероятной.",
    "Лишние данные — лишний риск.",
    "Простая защита, внедрённая вовремя, лучше идеальной защиты, внедрённой никогда.",
]

QUIZ = [
    ("Что безопаснее хранить в открытом виде?", ["Пароль", "Токен", "Ничего из этого", "Секретный ключ"], 2),
    ("Какая атака связана с перегрузкой запросами?", ["XSS", "Flood", "Phishing", "MITM"], 1),
    ("Что делает 2FA?", ["Шифрует БД", "Добавляет второй фактор", "Сжимает трафик", "Удаляет логи"], 1),
]

@dataclass
class Config:
    bot_token: str
    admin_id: Optional[int]
    secret_code_hash: str
    admin_pin: str


def load_config() -> Config:
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)

    bot_token = os.getenv("BOT_TOKEN", "").strip()
    if not bot_token:
        raise RuntimeError(f"Не найден BOT_TOKEN. Проверь файл: {env_path}")

    admin_id_raw = os.getenv("ADMIN_ID", "").strip()
    admin_id = int(admin_id_raw) if admin_id_raw.isdigit() else None
    secret_code = os.getenv("SECRET_CODE", "safegate").strip()
    admin_pin = os.getenv("ADMIN_PIN", "123456").strip()
    return Config(
        bot_token=bot_token,
        admin_id=admin_id,
        secret_code_hash=hashlib.sha256(secret_code.encode("utf-8")).hexdigest(),
        admin_pin=admin_pin,
    )


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            full_name TEXT,
            joined_at TEXT,
            suspicious_count INTEGER DEFAULT 0,
            flood_count INTEGER DEFAULT 0,
            brute_force_count INTEGER DEFAULT 0,
            messages_count INTEGER DEFAULT 0,
            admin_verified INTEGER DEFAULT 0,
            blocked_until REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT,
            severity TEXT,
            details TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            is_done INTEGER DEFAULT 0,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            remind_at TEXT,
            content TEXT,
            created_at TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_user(user) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users(user_id, username, full_name, joined_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            username=excluded.username,
            full_name=excluded.full_name
        """,
        (user.id, user.username or "", user.full_name, now_str()),
    )
    conn.commit()
    conn.close()


def log_event(user_id: Optional[int], event_type: str, severity: str, details: str) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs(user_id, event_type, severity, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, event_type, severity, details[:1500], now_str()),
    )
    conn.commit()
    conn.close()


def incr_user_counter(user_id: int, field: str, value: int = 1) -> None:
    allowed = {"suspicious_count", "flood_count", "brute_force_count", "messages_count"}
    if field not in allowed:
        return
    conn = db()
    cur = conn.cursor()
    cur.execute(f"UPDATE users SET {field} = COALESCE({field},0) + ? WHERE user_id = ?", (value, user_id))
    conn.commit()
    conn.close()


def set_admin_verified(user_id: int, verified: bool) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET admin_verified=? WHERE user_id=?", (1 if verified else 0, user_id))
    conn.commit()
    conn.close()


def is_admin_verified(user_id: int) -> bool:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT admin_verified FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return bool(row and row[0])


def set_block(user_id: int, seconds: int) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET blocked_until=? WHERE user_id=?", (time.time() + seconds, user_id))
    conn.commit()
    conn.close()


def get_block_remaining(user_id: int) -> int:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT blocked_until FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return 0
    remaining = int((row[0] or 0) - time.time())
    return max(0, remaining)


def user_stats(user_id: int) -> Optional[sqlite3.Row]:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def overall_stats() -> sqlite3.Row:
    conn = db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
          (SELECT COUNT(*) FROM users) AS users_total,
          (SELECT COUNT(*) FROM logs) AS logs_total,
          (SELECT COUNT(*) FROM logs WHERE severity IN ('medium','high','critical')) AS incidents_total,
          (SELECT COUNT(*) FROM users WHERE blocked_until > ?) AS blocked_now,
          (SELECT COUNT(*) FROM notes) AS notes_total,
          (SELECT COUNT(*) FROM todos) AS todos_total
        """,
        (time.time(),),
    )
    row = cur.fetchone()
    conn.close()
    return row


def latest_logs(limit: int = 10, severe_only: bool = False) -> list[sqlite3.Row]:
    conn = db()
    cur = conn.cursor()
    if severe_only:
        cur.execute(
            "SELECT * FROM logs WHERE severity IN ('medium','high','critical') ORDER BY id DESC LIMIT ?",
            (limit,),
        )
    else:
        cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def latest_incident() -> Optional[sqlite3.Row]:
    rows = latest_logs(limit=1, severe_only=True)
    return rows[0] if rows else None


def compute_risk(row: sqlite3.Row) -> tuple[str, int]:
    score = (row["suspicious_count"] * 15) + (row["flood_count"] * 10) + (row["brute_force_count"] * 20)
    if score >= 90:
        return "Критический", score
    if score >= 60:
        return "Высокий", score
    if score >= 25:
        return "Повышенный", score
    return "Нормальный", score


def classify_text(text: str) -> list[str]:
    hits = []
    if len(text) > 500:
        hits.append("Слишком длинный ввод")
    for attack_type, pattern in ATTACK_PATTERNS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(f"Паттерн {attack_type.upper()}")
    if re.search(r"https?://", text, re.IGNORECASE):
        hits.append("Содержит ссылку")
    return hits


def parse_duration(spec: str) -> Optional[int]:
    m = re.fullmatch(r"(\d+)([smhd])", spec.lower().strip())
    if not m:
        return None
    value = int(m.group(1))
    unit = m.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


async def admin_notify(context: ContextTypes.DEFAULT_TYPE, text: str) -> None:
    admin_id = context.application.bot_data.get("config").admin_id
    if admin_id:
        try:
            await context.bot.send_message(admin_id, text)
        except Exception as exc:
            logger.warning("Admin notify failed: %s", exc)


async def post_init(app: Application) -> None:
    commands = [
        BotCommand("start", "Запуск и регистрация"),
        BotCommand("help", "Список возможностей"),
        BotCommand("menu", "Показать кнопочное меню"),
        BotCommand("info", "О проекте"),
        BotCommand("security", "Рекомендации по ИБ"),
        BotCommand("check", "Проверить ввод на риски"),
        BotCommand("verify", "Проверить секретный код"),
        BotCommand("password", "Сгенерировать пароль"),
        BotCommand("calc", "Безопасный калькулятор"),
        BotCommand("hash", "Получить SHA-256"),
        BotCommand("note", "Добавить заметку"),
        BotCommand("notes", "Список заметок"),
        BotCommand("todo", "Управление задачами"),
        BotCommand("remind", "Поставить напоминание"),
        BotCommand("quiz", "Мини-викторина"),
        BotCommand("fun", "Игровое меню"),
        BotCommand("risk", "Риск-профиль пользователя"),
        BotCommand("ids", "Статус IDS"),
        BotCommand("simulate", "Симуляция атаки"),
        BotCommand("dashboard", "Панель мониторинга"),
        BotCommand("admin", "Запросить админ-доступ"),
        BotCommand("admin_login", "Войти как админ по PIN"),
        BotCommand("logs", "Показать журнал событий"),
        BotCommand("incident", "Отчёт по инциденту"),
        BotCommand("report", "PDF-отчёт"),
    ]
    await app.bot.set_my_commands(commands)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    ensure_user(user)
    log_event(user.id, "start", "low", "Запуск бота")
    text = (
        f"🔥 <b>{APP_NAME}</b> v{VERSION}\n\n"
        "Это демонстрационный Telegram-бот для курсовой/практики, который совмещает ИБ-механику, утилиты, развлечения, журналирование и вау-эффекты для защиты проекта.\n\n"
        "Нажми /menu или используй кнопки ниже."
    )
    await update.message.reply_text(text, reply_markup=MAIN_KEYBOARD, parse_mode=ParseMode.HTML)


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Главные команды</b>\n"
        "/menu — клавиатура\n"
        "/info — описание проекта\n"
        "/security — ИБ-памятка\n"
        "/check текст — анализ ввода\n"
        "/verify код — проверка кода\n"
        "/password 18 — генерация пароля\n"
        "/calc 2*(5+7) — калькулятор\n"
        "/hash текст — SHA-256\n"
        "/note текст — добавить заметку\n"
        "/notes — список заметок\n"
        "/todo add текст | /todo list | /todo done 2\n"
        "/remind 10m текст — напоминание\n"
        "/quiz — мини-викторина\n"
        "/fun — развлечения\n"
        "/risk — риск-профиль\n"
        "/ids — IDS-статистика\n"
        "/simulate sql|xss|spam|bruteforce|admin — демонстрация атаки\n"
        "/dashboard — мониторинг\n"
        "/admin и /admin_login 123456 — админ-доступ\n"
        "/logs, /incident latest, /report — отчёты\n\n"
        "Honeypot-команды: /root /token /database /admin_full"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Меню активировано.", reply_markup=MAIN_KEYBOARD)


async def info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>О боте</b>\n"
        "Бот объединяет учебный стенд по информационной безопасности, интерактивную админ-панель, демонстрации атак, анализ рисков, напоминания, заметки, задачи, развлечения и генерацию PDF-отчётов.\n\n"
        "То есть это уже не просто бот, а мини-платформа для демонстрации практических механизмов ИБ."
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def security(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "🛡 <b>Памятка по ИБ</b>\n"
        "• не храни токены в открытом коде\n"
        "• используй .env и минимальные привилегии\n"
        "• валидируй пользовательский ввод\n"
        "• логируй подозрительные действия\n"
        "• ограничивай brute force и flood\n"
        "• делай резервные копии и отчёты\n"
        "• применяй 2FA для админ-функций\n"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def profile(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    row = user_stats(update.effective_user.id)
    if not row:
        await update.message.reply_text("Профиль пока не найден. Нажми /start.")
        return
    risk, score = compute_risk(row)
    text = (
        f"<b>Профиль</b>\nID: <code>{row['user_id']}</code>\n"
        f"Имя: {row['full_name']}\n"
        f"Username: @{row['username'] or 'нет'}\n"
        f"Сообщений: {row['messages_count']}\n"
        f"Подозрительных событий: {row['suspicious_count']}\n"
        f"Риск: <b>{risk}</b> ({score})"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Используй так: /check <текст>")
        return
    hits = classify_text(text)
    if hits:
        incr_user_counter(update.effective_user.id, "suspicious_count", 1)
        log_event(update.effective_user.id, "input_check", "medium", f"Подозрительный ввод: {', '.join(hits)}")
        await admin_notify(context, f"🚨 Подозрительный ввод от {update.effective_user.id}: {', '.join(hits)}")
        await update.message.reply_text("⚠️ Обнаружены риски:\n- " + "\n- ".join(hits))
    else:
        log_event(update.effective_user.id, "input_check", "low", "Ввод чистый")
        await update.message.reply_text("✅ Явных рисков не обнаружено.")


async def verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    code = " ".join(context.args).strip()
    if not code:
        await update.message.reply_text("Используй: /verify <код>")
        return
    hashed = hashlib.sha256(code.encode("utf-8")).hexdigest()
    config = context.application.bot_data["config"]
    if hashed == config.secret_code_hash:
        log_event(update.effective_user.id, "verify", "low", "Успешная проверка кода")
        await update.message.reply_text("✅ Код подтверждён.")
    else:
        incr_user_counter(update.effective_user.id, "brute_force_count", 1)
        log_event(update.effective_user.id, "verify", "high", "Неверный секретный код")
        set_block(update.effective_user.id, 30)
        await admin_notify(context, f"🚨 Попытка подбора кода: {update.effective_user.id}")
        await update.message.reply_text("❌ Код неверный. Проверка временно заблокирована на 30 секунд.")


async def password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    length = 16
    if context.args and context.args[0].isdigit():
        length = max(8, min(64, int(context.args[0])))
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    pwd = "".join(random.choice(alphabet) for _ in range(length))
    await update.message.reply_text(f"🔐 Новый пароль:\n<code>{pwd}</code>", parse_mode=ParseMode.HTML)


async def calc(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    expr = " ".join(context.args).strip()
    if not expr:
        await update.message.reply_text("Используй: /calc 2*(5+7)")
        return
    if not re.fullmatch(r"[\d\s\+\-\*\/\(\)\.,%]+", expr):
        await update.message.reply_text("Разрешены только цифры, скобки и арифметические операторы.")
        return
    try:
        expr = expr.replace(",", ".")
        result = eval(expr, {"__builtins__": {}}, {"abs": abs, "round": round, "math": math})
        await update.message.reply_text(f"🧮 Результат: <code>{result}</code>", parse_mode=ParseMode.HTML)
    except Exception:
        await update.message.reply_text("Не удалось вычислить выражение.")


async def hash_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = " ".join(context.args).strip()
    if not text:
        await update.message.reply_text("Используй: /hash <текст>")
        return
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    await update.message.reply_text(f"SHA-256:\n<code>{digest}</code>", parse_mode=ParseMode.HTML)


async def note(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    content = " ".join(context.args).strip()
    if not content:
        await update.message.reply_text("Используй: /note <текст заметки>")
        return
    conn = db()
    cur = conn.cursor()
    cur.execute("INSERT INTO notes(user_id, content, created_at) VALUES (?, ?, ?)", (update.effective_user.id, content, now_str()))
    conn.commit()
    conn.close()
    await update.message.reply_text("📝 Заметка сохранена.")


async def notes(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT id, content, created_at FROM notes WHERE user_id=? ORDER BY id DESC LIMIT 10", (update.effective_user.id,))
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await update.message.reply_text("Заметок пока нет.")
        return
    text = "<b>Последние заметки</b>\n" + "\n".join([f"{r['id']}. {r['content']} <i>({r['created_at']})</i>" for r in rows])
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def todo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Используй: /todo add <текст> | /todo list | /todo done <id>")
        return
    action = context.args[0].lower()
    conn = db()
    cur = conn.cursor()
    if action == "add":
        content = " ".join(context.args[1:]).strip()
        if not content:
            await update.message.reply_text("После add нужен текст задачи.")
        else:
            cur.execute("INSERT INTO todos(user_id, content, created_at) VALUES (?, ?, ?)", (update.effective_user.id, content, now_str()))
            conn.commit()
            await update.message.reply_text("✅ Задача добавлена.")
    elif action == "list":
        cur.execute("SELECT id, content, is_done FROM todos WHERE user_id=? ORDER BY id DESC LIMIT 15", (update.effective_user.id,))
        rows = cur.fetchall()
        if not rows:
            await update.message.reply_text("Список задач пуст.")
        else:
            text = "<b>ToDo</b>\n" + "\n".join([f"{'✅' if r['is_done'] else '▫️'} {r['id']}. {r['content']}" for r in rows])
            await update.message.reply_text(text, parse_mode=ParseMode.HTML)
    elif action == "done" and len(context.args) > 1 and context.args[1].isdigit():
        cur.execute("UPDATE todos SET is_done=1 WHERE id=? AND user_id=?", (int(context.args[1]), update.effective_user.id))
        conn.commit()
        await update.message.reply_text("Готово. Задача отмечена выполненной.")
    else:
        await update.message.reply_text("Не понял команду todo.")
    conn.close()


async def remind(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2:
        await update.message.reply_text("Используй: /remind 10m купить кофе")
        return
    seconds = parse_duration(context.args[0])
    if not seconds:
        await update.message.reply_text("Формат времени: 30s, 10m, 2h, 1d")
        return
    content = " ".join(context.args[1:]).strip()
    remind_at = datetime.now() + timedelta(seconds=seconds)
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reminders(user_id, remind_at, content, created_at) VALUES (?, ?, ?, ?)",
        (update.effective_user.id, remind_at.strftime("%Y-%m-%d %H:%M:%S"), content, now_str()),
    )
    reminder_id = cur.lastrowid
    conn.commit()
    conn.close()
    context.job_queue.run_once(reminder_job, when=seconds, data={"chat_id": update.effective_chat.id, "content": content, "user_id": update.effective_user.id, "reminder_id": reminder_id})
    await update.message.reply_text(f"⏰ Напоминание поставлено на {context.args[0]}.")


async def reminder_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    data = context.job.data
    await context.bot.send_message(data["chat_id"], f"⏰ Напоминание: {data['content']}")
    log_event(data["user_id"], "reminder", "low", f"Сработало напоминание #{data['reminder_id']}")


async def quiz(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    idx = random.randrange(len(QUIZ))
    q, options, correct = QUIZ[idx]
    context.user_data["quiz_answer"] = correct
    keyboard = [[InlineKeyboardButton(opt, callback_data=f"quiz:{i}")] for i, opt in enumerate(options)]
    await update.message.reply_text(f"❓ <b>{q}</b>", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.HTML)


async def fun(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("🎲 Бросить кубик", callback_data="fun:dice"), InlineKeyboardButton("🪙 Монетка", callback_data="fun:coin")],
            [InlineKeyboardButton("😂 Шутка", callback_data="fun:joke"), InlineKeyboardButton("💬 Цитата", callback_data="fun:quote")],
            [InlineKeyboardButton("🎯 Случайный факт", callback_data="fun:fact"), InlineKeyboardButton("🔥 Вау-режим", callback_data="fun:wow")],
        ]
    )
    await update.message.reply_text("Выбери приколюшку:", reply_markup=keyboard)


async def risk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    row = user_stats(update.effective_user.id)
    if not row:
        await update.message.reply_text("Профиль не найден.")
        return
    risk_level, score = compute_risk(row)
    reasons = []
    if row["suspicious_count"]:
        reasons.append(f"подозрительных событий: {row['suspicious_count']}")
    if row["flood_count"]:
        reasons.append(f"флуд-триггеров: {row['flood_count']}")
    if row["brute_force_count"]:
        reasons.append(f"ошибок кода: {row['brute_force_count']}")
    reason_text = "\n".join([f"- {x}" for x in reasons]) if reasons else "- серьёзных инцидентов не замечено"
    await update.message.reply_text(f"<b>Риск-профиль</b>\nУровень: <b>{risk_level}</b>\nScore: <code>{score}</code>\nПричины:\n{reason_text}", parse_mode=ParseMode.HTML)


async def ids(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    rows = latest_logs(limit=200)
    crit = sum(1 for r in rows if r["severity"] == "critical")
    high = sum(1 for r in rows if r["severity"] == "high")
    med = sum(1 for r in rows if r["severity"] == "medium")
    low = sum(1 for r in rows if r["severity"] == "low")
    text = (
        "<b>IDS-статус</b>\n"
        "Система обнаружения вторжений: активна\n"
        f"Критических: {crit}\nВысоких: {high}\nСредних: {med}\nНизких: {low}\n"
        f"Всего просмотрено последних событий: {len(rows)}"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def simulate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    attack = (context.args[0].lower() if context.args else "").strip()
    if attack not in {"sql", "xss", "spam", "bruteforce", "admin"}:
        await update.message.reply_text("Используй: /simulate sql|xss|spam|bruteforce|admin")
        return
    severity = "high" if attack in {"bruteforce", "admin"} else "medium"
    description = {
        "sql": "UNION SELECT ... DROP TABLE users;",
        "xss": "<script>alert('xss')</script>",
        "spam": "100 сообщений за 5 секунд",
        "bruteforce": "подбор секретного кода",
        "admin": "попытка эскалации привилегий",
    }[attack]
    incr_user_counter(update.effective_user.id, "suspicious_count", 1)
    if attack == "spam":
        incr_user_counter(update.effective_user.id, "flood_count", 1)
    if attack == "bruteforce":
        incr_user_counter(update.effective_user.id, "brute_force_count", 1)
        set_block(update.effective_user.id, 60)
    log_event(update.effective_user.id, f"simulate_{attack}", severity, description)
    await admin_notify(context, f"🚨 Симуляция {attack.upper()} от {update.effective_user.id}")
    await update.message.reply_text(
        f"⚠️ Симуляция атаки <b>{attack.upper()}</b>\n"
        f"Полезная нагрузка: <code>{description}</code>\n"
        "Результат: угроза распознана, событие залогировано, администратор уведомлён.",
        parse_mode=ParseMode.HTML,
    )


async def dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    stats = overall_stats()
    incident = latest_incident()
    latest = f"{incident['event_type']} / {incident['created_at']}" if incident else "нет"
    text = (
        "<b>ПАНЕЛЬ МОНИТОРИНГА</b>\n"
        f"Пользователей: {stats['users_total']}\n"
        f"Логов: {stats['logs_total']}\n"
        f"Инцидентов: {stats['incidents_total']}\n"
        f"Активных блокировок: {stats['blocked_now']}\n"
        f"Заметок: {stats['notes_total']}\n"
        f"ToDo: {stats['todos_total']}\n"
        f"Последний инцидент: {latest}"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


def require_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    config = context.application.bot_data["config"]
    uid = update.effective_user.id
    return bool(config.admin_id == uid and is_admin_verified(uid))


async def admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = context.application.bot_data["config"]
    if update.effective_user.id != config.admin_id:
        log_event(update.effective_user.id, "admin_access", "high", "Попытка доступа к панели администратора")
        await update.message.reply_text("⛔ Ты не являешься зарегистрированным администратором.")
        return
    await update.message.reply_text("👑 Для входа введи: /admin_login <PIN>")


async def admin_login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    config = context.application.bot_data["config"]
    if update.effective_user.id != config.admin_id:
        await update.message.reply_text("Нет доступа.")
        return
    pin = " ".join(context.args).strip()
    if pin == config.admin_pin:
        set_admin_verified(update.effective_user.id, True)
        log_event(update.effective_user.id, "admin_login", "medium", "Успешный вход администратора")
        await update.message.reply_text("✅ Админ-доступ активирован на текущую сессию.")
    else:
        log_event(update.effective_user.id, "admin_login", "high", "Неверный PIN администратора")
        await update.message.reply_text("❌ Неверный PIN.")


async def logs_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not require_admin(update, context):
        await update.message.reply_text("Сначала выполни /admin и /admin_login <PIN>.")
        return
    rows = latest_logs(limit=15)
    if not rows:
        await update.message.reply_text("Журнал пуст.")
        return
    text = "<b>Последние события</b>\n" + "\n\n".join([
        f"#{r['id']} [{r['severity']}] {r['event_type']}\nUID: {r['user_id']}\n{r['details']}\n{r['created_at']}" for r in rows
    ])
    await update.message.reply_text(text[:4000], parse_mode=ParseMode.HTML)


async def incident(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not require_admin(update, context):
        await update.message.reply_text("Сначала выполни /admin_login <PIN>.")
        return
    row = latest_incident()
    if not row:
        await update.message.reply_text("Инцидентов пока нет.")
        return
    text = (
        "<b>ОТЧЁТ ОБ ИНЦИДЕНТЕ</b>\n"
        f"ID события: {row['id']}\n"
        f"Пользователь: {row['user_id']}\n"
        f"Тип: {row['event_type']}\n"
        f"Критичность: {row['severity']}\n"
        f"Описание: {row['details']}\n"
        f"Дата: {row['created_at']}\n"
        "Принятые меры: логирование, уведомление администратора, ограничение доступа при необходимости."
    )
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


def build_pdf_report() -> str:
    fd, path = tempfile.mkstemp(prefix="megabot_report_", suffix=".pdf")
    os.close(fd)
    c = canvas.Canvas(path, pagesize=A4)
    w, h = A4
    y = h - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"{APP_NAME}: отчёт по безопасности")
    y -= 30
    c.setFont("Helvetica", 11)
    c.drawString(50, y, f"Дата формирования: {now_str()}")
    y -= 30
    stats = overall_stats()
    lines = [
        f"Пользователей: {stats['users_total']}",
        f"Логов: {stats['logs_total']}",
        f"Инцидентов: {stats['incidents_total']}",
        f"Активных блокировок: {stats['blocked_now']}",
        "",
        "Последние инциденты:",
    ]
    for row in latest_logs(limit=10, severe_only=True):
        lines.append(f"- [{row['severity']}] {row['event_type']} | UID {row['user_id']} | {row['created_at']}")
    for line in lines:
        if y < 60:
            c.showPage()
            y = h - 50
            c.setFont("Helvetica", 11)
        c.drawString(50, y, line[:110])
        y -= 18
    c.save()
    return path


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not require_admin(update, context):
        await update.message.reply_text("Сначала выполни /admin_login <PIN>.")
        return
    await update.message.reply_chat_action(ChatAction.UPLOAD_DOCUMENT)
    pdf_path = build_pdf_report()
    with open(pdf_path, "rb") as f:
        await update.message.reply_document(f, filename="megabot_security_report.pdf", caption="PDF-отчёт готов.")
    try:
        os.remove(pdf_path)
    except OSError:
        pass


async def honeypot(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    cmd = update.message.text.split()[0]
    incr_user_counter(update.effective_user.id, "suspicious_count", 1)
    log_event(update.effective_user.id, "honeypot", "critical", f"Использована honeypot-команда {cmd}")
    set_block(update.effective_user.id, 120)
    await admin_notify(context, f"🚨 HONEYPOT: {update.effective_user.id} вызвал {cmd}")
    await update.message.reply_text("🚨 Команда зарегистрирована системой deception security. Событие передано в IDS.")


async def text_router(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    ensure_user(user)
    incr_user_counter(user.id, "messages_count", 1)

    remaining = get_block_remaining(user.id)
    if remaining > 0:
        await update.message.reply_text(f"⛔ Временная блокировка. Осталось {remaining} сек.")
        return

    now = time.time()
    timestamps = context.user_data.setdefault("msg_times", [])
    timestamps.append(now)
    timestamps[:] = [t for t in timestamps if now - t < 5]
    if len(timestamps) > 6:
        incr_user_counter(user.id, "flood_count", 1)
        set_block(user.id, 20)
        log_event(user.id, "flood", "high", "Сработал антиспам")
        await admin_notify(context, f"🚨 Flood от {user.id}")
        await update.message.reply_text("🚫 Слишком много сообщений. Антиспам активирован на 20 секунд.")
        return

    text = (update.message.text or "").strip()
    btn = text.lower()

    mapping = {
        "ℹ️ инфо": info,
        "🛡 иб-режим": security,
        "🔐 генератор пароля": password,
        "🧮 калькулятор": calc,
        "📝 заметки": notes,
        "✅ todo": todo,
        "🎲 развлечения": fun,
        "⏰ напоминание": remind,
        "📊 дашборд": dashboard,
        "👑 админ": admin,
    }
    if btn in mapping:
        if btn in {"🔐 генератор пароля", "🧮 калькулятор", "⏰ напоминание".lower(), "✅ todo".lower()}:
            prompts = {
                "🔐 генератор пароля": "Используй: /password 18",
                "🧮 калькулятор": "Используй: /calc 2*(5+7)",
                "✅ todo": "Используй: /todo add купить кофе",
                "⏰ напоминание": "Используй: /remind 10m сделать доклад",
            }
            await update.message.reply_text(prompts[btn])
            return
        await mapping[btn](update, context)
        return

    hits = classify_text(text)
    if hits:
        incr_user_counter(user.id, "suspicious_count", 1)
        severity = "critical" if any("CMD" in h or "PATH" in h for h in hits) else "medium"
        log_event(user.id, "free_text_alert", severity, f"Текстовое сообщение вызвало IDS: {', '.join(hits)} | {text[:250]}")
        await admin_notify(context, f"🚨 IDS сработала на сообщение {user.id}: {', '.join(hits)}")
        await update.message.reply_text("⚠️ IDS заметила риск в сообщении. Событие занесено в журнал.")
        return

    if "препод" in text.lower() or "защита" in text.lower():
        await update.message.reply_text("🔥 На защите просто покажи /dashboard, /ids, /simulate sql, /incident latest и /report — эффект гарантирован.")
        return

    await update.message.reply_text(
        "Я готов к командам. Попробуй /help, /fun, /quiz, /password 20, /simulate xss или /dashboard",
        reply_markup=MAIN_KEYBOARD,
    )


async def callbacks(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    data = query.data
    if data.startswith("quiz:"):
        selected = int(data.split(":", 1)[1])
        correct = context.user_data.get("quiz_answer")
        if selected == correct:
            await query.edit_message_text("✅ Верно. Ты знаешь базу по ИБ.")
        else:
            await query.edit_message_text("❌ Неверно. Но теперь это тоже часть обучения.")
        return

    if data == "fun:dice":
        await query.edit_message_text(f"🎲 Выпало число: {random.randint(1,6)}")
    elif data == "fun:coin":
        await query.edit_message_text(f"🪙 {'Орёл' if random.choice([True, False]) else 'Решка'}")
    elif data == "fun:joke":
        await query.edit_message_text(f"😂 {random.choice(JOKES)}")
    elif data == "fun:quote":
        await query.edit_message_text(f"💬 {random.choice(QUOTES)}")
    elif data == "fun:fact":
        facts = [
            "Telegram-боты не видят сообщения до запуска их процесса.",
            "Один утёкший токен может полностью скомпрометировать бота.",
            "Журналирование без ротации и контроля доступа само становится риском.",
        ]
        await query.edit_message_text(f"🎯 {random.choice(facts)}")
    elif data == "fun:wow":
        await query.edit_message_text("🔥 Режим активирован: представь, что это уже не бот, а демонстрационный SOC в Telegram.")


async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Неизвестная команда. Открой /help")


def build_app() -> Application:
    config = load_config()
    init_db()
    app = Application.builder().token(config.bot_token).post_init(post_init).build()
    app.bot_data["config"] = config

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("menu", menu))
    app.add_handler(CommandHandler("info", info))
    app.add_handler(CommandHandler("security", security))
    app.add_handler(CommandHandler("profile", profile))
    app.add_handler(CommandHandler("check", check))
    app.add_handler(CommandHandler("verify", verify))
    app.add_handler(CommandHandler("password", password))
    app.add_handler(CommandHandler("calc", calc))
    app.add_handler(CommandHandler("hash", hash_cmd))
    app.add_handler(CommandHandler("note", note))
    app.add_handler(CommandHandler("notes", notes))
    app.add_handler(CommandHandler("todo", todo))
    app.add_handler(CommandHandler("remind", remind))
    app.add_handler(CommandHandler("quiz", quiz))
    app.add_handler(CommandHandler("fun", fun))
    app.add_handler(CommandHandler("risk", risk))
    app.add_handler(CommandHandler("ids", ids))
    app.add_handler(CommandHandler("simulate", simulate))
    app.add_handler(CommandHandler("dashboard", dashboard))
    app.add_handler(CommandHandler("admin", admin))
    app.add_handler(CommandHandler("admin_login", admin_login))
    app.add_handler(CommandHandler("logs", logs_cmd))
    app.add_handler(CommandHandler("incident", incident))
    app.add_handler(CommandHandler("report", report))

    for cmd in ["root", "token", "database", "admin_full"]:
        app.add_handler(CommandHandler(cmd, honeypot))

    app.add_handler(CallbackQueryHandler(callbacks))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_router))
    app.add_handler(MessageHandler(filters.COMMAND, unknown))
    return app


async def main() -> None:
    app = build_app()
    logger.info("%s started", APP_NAME)
    await app.initialize()
    await app.start()
    await app.updater.start_polling()
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await app.updater.stop()
        await app.stop()
        await app.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
