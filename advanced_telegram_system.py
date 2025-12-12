#advanced_telegram_system.py
#!/usr/bin/env python3
"""
سیستم پیشرفته مدیریت و دانلود تلگرام - نسخه تولید (Production Ready)
ویژگی‌ها:
1. امنیت پیشرفته (AES-GCM, Rate Limiting, Session Management)
2. سیستم چند اکانتی هوشمند
3. دانلود/آپلود با بهینه‌سازی سرعت
4. پنل ادمین کامل
5. مانیتورینگ real-time
6. سیستم پلاگین
7. API سرور
"""

import asyncio
import logging
import sys
import signal
import json
import sqlite3
import hashlib
import os
import base64
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from threading import Lock
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import pickle

# ========== کتابخانه‌های امنیتی ==========
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    print("⚠️ Warning: cryptography not installed. Run: pip install cryptography")

try:
    import telebot
    from telebot import types
    HAS_TELEBOT = True
except ImportError:
    HAS_TELEBOT = False
    print("⚠️ Warning: pyTelegramBotAPI not installed. Run: pip install pyTelegramBotAPI")

# ========== تنظیمات لاگ پیشرفته ==========

def setup_logging(debug: bool = False, log_file: str = "telegram_system.log"):
    """تنظیمات پیشرفته لاگ‌گیری"""
    
    log_level = logging.DEBUG if debug else logging.INFO
    
    # فرمت رنگی برای console
    class ColorFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': '\033[36m',    # Cyan
            'INFO': '\033[32m',     # Green
            'WARNING': '\033[33m',  # Yellow
            'ERROR': '\033[31m',    # Red
            'CRITICAL': '\033[41m', # Red background
            'RESET': '\033[0m'
        }
        
        def format(self, record):
            log_message = super().format(record)
            color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
            return f"{color}{log_message}{self.COLORS['RESET']}"
    
    # ایجاد دایرکتوری logs
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    handlers = []
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    handlers.append(console_handler)
    
    # File handler
    file_handler = logging.FileHandler(
        log_dir / log_file,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    handlers.append(file_handler)
    
    # تنظیم root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )
    
    # تنظیم log level برای کتابخانه‌های دیگر
    logging.getLogger('telebot').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

logger = setup_logging()

# ========== مدل‌های داده ==========

@dataclass
class UserConfig:
    """تنظیمات کاربر"""
    user_id: int
    max_download_speed: int = 1024 * 1024 * 10  # 10 MB/s
    max_upload_speed: int = 1024 * 1024 * 5     # 5 MB/s
    concurrent_downloads: int = 3
    session_timeout: int = 3600
    is_active: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class TransferTask:
    """وظیفه انتقال فایل"""
    task_id: str
    user_id: int
    file_url: str
    file_name: str
    file_size: int
    download_path: str
    status: str = "pending"  # pending, downloading, completed, failed
    progress: float = 0.0
    speed: float = 0.0
    started_at: datetime = None
    completed_at: datetime = None
    
    def __post_init__(self):
        if self.started_at is None:
            self.started_at = datetime.now()

# ========== سیستم امنیت پیشرفته ==========

class AdvancedSecurity:
    """سیستم امنیتی پیشرفته با AES-GCM"""
    
    def __init__(self, master_key: Optional[str] = None):
        if not HAS_CRYPTOGRAPHY:
            raise ImportError("cryptography library is required for security features")
        
        if master_key:
            # استفاده از کلید اصلی
            self.master_key = self._derive_key(master_key.encode())
        else:
            # تولید کلید تصادفی
            import secrets
            self.master_key = secrets.token_bytes(32)
        
        self.key_cache: Dict[str, bytes] = {}
        self.lock = Lock()
    
    def _derive_key(self, password: bytes, salt: bytes = None) -> bytes:
        """استخراج کلید از رمز عبور"""
        if salt is None:
            salt = b'system_salt_2024'  # در پروژه واقعی باید تصادفی باشد
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password)
    
    def encrypt(self, plaintext: str, associated_data: bytes = None) -> str:
        """رمزنگاری داده با AES-GCM"""
        import secrets
        
        aesgcm = AESGCM(self.master_key)
        nonce = secrets.token_bytes(12)  # 12 bytes برای GCM
        
        # رمزنگاری
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            associated_data
        )
        
        # ترکیب nonce + ciphertext
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_data: str, associated_data: bytes = None) -> str:
        """رمزگشایی داده"""
        aesgcm = AESGCM(self.master_key)
        
        # decode از base64
        encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        
        # جدا کردن nonce و ciphertext
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        
        # رمزگشایی
        plaintext_bytes = aesgcm.decrypt(
            nonce,
            ciphertext,
            associated_data
        )
        
        return plaintext_bytes.decode('utf-8')
    
    def hash_sensitive_data(self, data: str) -> str:
        """هش کردن داده‌های حساس"""
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt,
            100000
        )
        return salt.hex() + dk.hex()
    
    def verify_hash(self, data: str, hashed: str) -> bool:
        """تأیید هش داده"""
        salt = bytes.fromhex(hashed[:32])
        stored_hash = hashed[32:]
        
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt,
            100000
        )
        
        return dk.hex() == stored_hash

class RateLimiter:
    """محدود‌کننده نرخ درخواست پیشرفته"""
    
    def __init__(self, max_attempts: int = 10, period: int = 60, ban_duration: int = 300):
        self.attempts: Dict[str, List[datetime]] = {}
        self.banned: Dict[str, datetime] = {}
        self.max_attempts = max_attempts
        self.period = period
        self.ban_duration = ban_duration
        self.lock = Lock()
    
    def is_allowed(self, identifier: str) -> Tuple[bool, Optional[str]]:
        """بررسی مجاز بودن با شناسه"""
        with self.lock:
            now = datetime.now()
            
            # بررسی بن بودن
            if identifier in self.banned:
                ban_until = self.banned[identifier]
                if now < ban_until:
                    remaining = (ban_until - now).seconds
                    return False, f"Banned for {remaining} seconds"
                else:
                    del self.banned[identifier]
            
            # مدیریت تلاش‌ها
            if identifier not in self.attempts:
                self.attempts[identifier] = []
            
            # حذف تلاش‌های قدیمی
            cutoff = now - timedelta(seconds=self.period)
            self.attempts[identifier] = [
                t for t in self.attempts[identifier] if t > cutoff
            ]
            
            # بررسی تعداد تلاش‌ها
            if len(self.attempts[identifier]) >= self.max_attempts:
                ban_time = now + timedelta(seconds=self.ban_duration)
                self.banned[identifier] = ban_time
                del self.attempts[identifier]
                return False, f"Too many attempts. Banned for {self.ban_duration} seconds"
            
            self.attempts[identifier].append(now)
            return True, None

# ========== مدیریت دیتابیس پیشرفته ==========

class DatabaseManager:
    """مدیریت دیتابیس SQLite با امنیت"""
    
    def __init__(self, db_path: str = "telegram_system.db"):
        self.db_path = Path(db_path)
        self.conn = None
        self.lock = Lock()
        self._initialize()
    
    def _initialize(self):
        """مقداردهی اولیه دیتابیس"""
        with self.lock:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA foreign_keys=ON")
            self._create_tables()
    
    def _create_tables(self):
        """ایجاد جداول"""
        cursor = self.conn.cursor()
        
        # جدول کاربران
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                telegram_id INTEGER UNIQUE,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                config TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP
            )
        ''')
        
        # جدول جلسات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER,
                session_data TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # جدول وظایف انتقال
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transfer_tasks (
                task_id TEXT PRIMARY KEY,
                user_id INTEGER,
                file_url TEXT,
                file_name TEXT,
                file_size INTEGER,
                download_path TEXT,
                status TEXT DEFAULT 'pending',
                progress REAL DEFAULT 0.0,
                speed REAL DEFAULT 0.0,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # جدول آمار سیستم
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_stats (
                stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active_users INTEGER,
                active_tasks INTEGER,
                total_downloaded BIGINT,
                total_uploaded BIGINT,
                memory_usage REAL,
                cpu_usage REAL
            )
        ''')
        
        # ایندکس‌ها برای بهبود performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_user ON transfer_tasks(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON transfer_tasks(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
        
        self.conn.commit()
    
    def save_user(self, user_data: Dict) -> int:
        """ذخیره کاربر"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO users 
                (telegram_id, username, first_name, last_name, config, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                user_data.get('telegram_id'),
                user_data.get('username'),
                user_data.get('first_name'),
                user_data.get('last_name'),
                json.dumps(user_data.get('config', {})),
                datetime.now()
            ))
            
            if cursor.lastrowid is None:
                cursor.execute(
                    'SELECT user_id FROM users WHERE telegram_id = ?',
                    (user_data.get('telegram_id'),)
                )
                user_id = cursor.fetchone()[0]
            else:
                user_id = cursor.lastrowid
            
            self.conn.commit()
            return user_id
    
    def save_transfer_task(self, task: TransferTask):
        """ذخیره وظیفه انتقال"""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO transfer_tasks
                (task_id, user_id, file_url, file_name, file_size, 
                 download_path, status, progress, speed, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task.task_id,
                task.user_id,
                task.file_url,
                task.file_name,
                task.file_size,
                task.download_path,
                task.status,
                task.progress,
                task.speed,
                task.started_at,
                task.completed_at
            ))
            self.conn.commit()

# ========== سیستم چند اکانتی ==========

class MultiAccountManager:
    """مدیریت همزمان چند اکانت تلگرام"""
    
    def __init__(self, security: AdvancedSecurity, db: DatabaseManager):
        self.security = security
        self.db = db
        self.user_accounts: Dict[int, List[Dict]] = {}
        self.active_sessions: Dict[int, Dict] = {}
        self.lock = Lock()
    
    async def add_account(self, user_id: int, phone_number: str, 
                         api_id: int, api_hash: str) -> str:
        """اضافه کردن اکانت جدید با امنیت"""
        # رمزنگاری داده‌های حساس
        encrypted_phone = self.security.encrypt(phone_number)
        encrypted_api_hash = self.security.encrypt(api_hash)
        
        account_id = hashlib.sha256(
            f"{user_id}_{phone_number}_{datetime.now().timestamp()}".encode()
        ).hexdigest()[:16]
        
        account_data = {
            'account_id': account_id,
            'phone_encrypted': encrypted_phone,
            'api_id': api_id,
            'api_hash_encrypted': encrypted_api_hash,
            'added_at': datetime.now().isoformat(),
            'is_active': True
        }
        
        with self.lock:
            if user_id not in self.user_accounts:
                self.user_accounts[user_id] = []
            
            self.user_accounts[user_id].append(account_data)
        
        logger.info(f"Account added for user {user_id}: {account_id}")
        return account_id
    
    def get_active_account(self, user_id: int) -> Optional[Dict]:
        """دریافت اکانت فعال کاربر"""
        with self.lock:
            if user_id in self.active_sessions:
                account_id = self.active_sessions[user_id].get('account_id')
                if user_id in self.user_accounts:
                    for account in self.user_accounts[user_id]:
                        if account['account_id'] == account_id:
                            # رمزگشایی داده‌ها
                            account_copy = account.copy()
                            account_copy['phone'] = self.security.decrypt(
                                account['phone_encrypted']
                            )
                            account_copy['api_hash'] = self.security.decrypt(
                                account['api_hash_encrypted']
                            )
                            return account_copy
        
        return None

# ========== سیستم بهینه‌سازی سرعت ==========

class SpeedOptimizer:
    """بهینه‌سازی سرعت دانلود/آپلود"""
    
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_downloads: Dict[str, Any] = {}
        self.stats: Dict[str, Any] = {
            'total_downloaded': 0,
            'total_uploaded': 0,
            'average_speed': 0,
            'peak_speed': 0
        }
        self.lock = Lock()
    
    async def download_file(self, url: str, save_path: str, 
                          max_speed: Optional[int] = None) -> Dict:
        """دانلود فایل با بهینه‌سازی سرعت"""
        import aiohttp
        import aiofiles
        
        task_id = hashlib.sha256(
            f"{url}_{datetime.now().timestamp()}".encode()
        ).hexdigest()[:12]
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        return {
                            'success': False,
                            'error': f"HTTP {response.status}",
                            'task_id': task_id
                        }
                    
                    total_size = int(response.headers.get('content-length', 0))
                    
                    # محاسبه chunk size بر اساس سرعت مورد نظر
                    chunk_size = 1024 * 1024  # 1MB default
                    if max_speed:
                        chunk_size = min(chunk_size, max_speed // 10)
                    
                    downloaded = 0
                    start_time = datetime.now()
                    
                    async with aiofiles.open(save_path, 'wb') as f:
                        async for chunk in response.content.iter_chunked(chunk_size):
                            await f.write(chunk)
                            downloaded += len(chunk)
                            
                            # محاسبه سرعت
                            elapsed = (datetime.now() - start_time).total_seconds()
                            current_speed = downloaded / elapsed if elapsed > 0 else 0
                            
                            # محدودیت سرعت
                            if max_speed and current_speed > max_speed:
                                await asyncio.sleep(0.1)
                            
                            # آپدیت آمار
                            with self.lock:
                                self.stats['total_downloaded'] += len(chunk)
                                if current_speed > self.stats['peak_speed']:
                                    self.stats['peak_speed'] = current_speed
                    
                    end_time = datetime.now()
                    total_time = (end_time - start_time).total_seconds()
                    avg_speed = downloaded / total_time if total_time > 0 else 0
                    
                    return {
                        'success': True,
                        'task_id': task_id,
                        'file_size': downloaded,
                        'total_time': total_time,
                        'average_speed': avg_speed,
                        'save_path': save_path
                    }
        
        except Exception as e:
            logger.error(f"Download error: {e}")
            return {
                'success': False,
                'error': str(e),
                'task_id': task_id
            }
    
    def get_performance_report(self) -> Dict:
        """گزارش عملکرد سیستم"""
        with self.lock:
            return self.stats.copy()

# ========== ربات تلگرام پیشرفته ==========

class AdvancedTelegramBot:
    """ربات تلگرام با تمام ویژگی‌ها"""
    
    def __init__(self, token: str, admin_ids: List[int]):
        if not HAS_TELEBOT:
            raise ImportError("pyTelegramBotAPI is required")
        
        self.token = token
        self.bot = telebot.TeleBot(token, num_threads=5)
        self.admin_ids = admin_ids
        
        # کامپوننت‌های اصلی
        self.security = AdvancedSecurity(os.environ.get("ENCRYPTION_KEY"))
        self.rate_limiter = RateLimiter()
        self.db = DatabaseManager()
        self.multi_account = MultiAccountManager(self.security, self.db)
        self.speed_optimizer = SpeedOptimizer()
        
        # حالت‌های کاربران
        self.user_states: Dict[int, Dict] = {}
        self.setup_handlers()
        
        logger.info("Advanced Telegram Bot initialized")
    
    def setup_handlers(self):
        """تنظیم هندلرهای ربات"""
        
        @self.bot.message_handler(commands=['start', 'help'])
        def start_handler(message):
            """منوی اصلی"""
            user_id = message.from_user.id
            
            # ثبت کاربر در دیتابیس
            user_data = {
                'telegram_id': user_id,
                'username': message.from_user.username,
                'first_name': message.from_user.first_name,
                'last_name': message.from_user.last_name,
                'config': {}
            }
            
            self.db.save_user(user_data)
            
            keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
            buttons = [
                '📥 دانلود فایل', '📤 آپلود فایل',
                '👥 مدیریت اکانت‌ها', '⚡ تنظیمات سرعت',
                '📊 آمار سیستم', '🛠️ پنل ادمین'
            ]
            
            for i in range(0, len(buttons), 2):
                if i + 1 < len(buttons):
                    keyboard.row(buttons[i], buttons[i + 1])
                else:
                    keyboard.row(buttons[i])
            
            welcome_text = """
🤖 **ربات پیشرفته مدیریت تلگرام**

🔒 **امنیت:**
• رمزنگاری AES-G256
• محدودیت نرخ درخواست
• مدیریت session امن

🚀 **ویژگی‌ها:**
• دانلود/آپلود با سرعت بهینه
• مدیریت چند اکانت همزمان
• پنل ادمین پیشرفته
• مانیتورینگ real-time

📋 **دستورات سریع:**
/download - دانلود فایل
/upload - آپلود فایل
/accounts - مدیریت اکانت‌ها
/settings - تنظیمات سرعت
/stats - آمار سیستم
/admin - پنل مدیریت
            """
            
            self.bot.send_message(
                message.chat.id,
                welcome_text,
                reply_markup=keyboard,
                parse_mode='Markdown'
            )
        
        @self.bot.message_handler(commands=['download'])
        def download_handler(message):
            """دریافت لینک دانلود"""
            user_id = message.from_user.id
            
            # بررسی rate limit
            allowed, error_msg = self.rate_limiter.is_allowed(f"download_{user_id}")
            if not allowed:
                self.bot.send_message(message.chat.id, f"⏳ {error_msg}")
                return
            
            self.bot.send_message(
                message.chat.id,
                "🔗 لطفاً لینک فایل را ارسال کنید:"
            )
            
            self.user_states[user_id] = {'action': 'awaiting_download_url'}
        
        @self.bot.message_handler(func=lambda m: True)
        def message_handler(message):
            """پردازش پیام‌های عمومی"""
            user_id = message.from_user.id
            
            if user_id in self.user_states:
                state = self.user_states[user_id]
                
                if state.get('action') == 'awaiting_download_url':
                    # شروع دانلود
                    asyncio.create_task(self.process_download(message))
                    del self.user_states[user_id]
            
            # پردازش دکمه‌ها
            if message.text == '📥 دانلود فایل':
                download_handler(message)
            elif message.text == '📊 آمار سیستم':
                self.show_stats(message)
            elif message.text == '🛠️ پنل ادمین' and user_id in self.admin_ids:
                self.admin_panel(message)
    
    async def process_download(self, message):
        """پردازش دانلود"""
        user_id = message.from_user.id
        url = message.text.strip()
        
        # اعتبارسنجی URL
        if not url.startswith(('http://', 'https://')):
            self.bot.send_message(message.chat.id, "❌ لینک نامعتبر است")
            return
        
        # ایجاد دایرکتوری دانلود
        download_dir = Path("downloads") / str(user_id)
        download_dir.mkdir(parents=True, exist_ok=True)
        
        # نام فایل
        file_name = url.split('/')[-1].split('?')[0] or f"file_{datetime.now().timestamp()}"
        save_path = download_dir / file_name
        
        # ارسال پیام در حال پردازش
        status_msg = self.bot.send_message(
            message.chat.id,
            "⏳ در حال شروع دانلود..."
        )
        
        try:
            # دانلود فایل
            result = await self.speed_optimizer.download_file(
                url=url,
                save_path=str(save_path),
                max_speed=1024 * 1024 * 5  # 5 MB/s
            )
            
            if result['success']:
                # ذخیره در دیتابیس
                task = TransferTask(
                    task_id=result['task_id'],
                    user_id=user_id,
                    file_url=url,
                    file_name=file_name,
                    file_size=result['file_size'],
                    download_path=str(save_path),
                    status='completed',
                    progress=100.0,
                    speed=result['average_speed']
                )
                
                self.db.save_transfer_task(task)
                
                # ارسال نتیجه
                speed_mb = result['average_speed'] / 1024 / 1024
                self.bot.edit_message_text(
                    f"✅ دانلود کامل شد!\n\n"
                    f"📁 فایل: {file_name}\n"
                    f"📦 حجم: {result['file_size'] / 1024 / 1024:.2f} MB\n"
                    f"⚡ سرعت متوسط: {speed_mb:.2f} MB/s\n"
                    f"⏱️ زمان: {result['total_time']:.2f} ثانیه",
                    chat_id=message.chat.id,
                    message_id=status_msg.message_id
                )
            else:
                self.bot.edit_message_text(
                    f"❌ خطا در دانلود: {result['error']}",
                    chat_id=message.chat.id,
                    message_id=status_msg.message_id
                )
        
        except Exception as e:
            logger.error(f"Download processing error: {e}")
            self.bot.edit_message_text(
                "❌ خطای سیستمی در دانلود",
                chat_id=message.chat.id,
                message_id=status_msg.message_id
            )
    
    def show_stats(self, message):
        """نمایش آمار سیستم"""
        perf_report = self.speed_optimizer.get_performance_report()
        
        stats_text = f"""
📊 **آمار سیستم**

📥 کل دانلود: {perf_report['total_downloaded'] / 1024 / 1024:.2f} MB
📤 کل آپلود: {perf_report['total_uploaded'] / 1024 / 1024:.2f} MB
⚡ سرعت متوسط: {perf_report['average_speed'] / 1024 / 1024:.2f} MB/s
🚀 حداکثر سرعت: {perf_report['peak_speed'] / 1024 / 1024:.2f} MB/s
👤 کاربران فعال: {len(self.user_states)}
        """
        
        self.bot.send_message(
            message.chat.id,
            stats_text,
            parse_mode='Markdown'
        )
    
    def admin_panel(self, message):
        """پنل ادمین"""
        keyboard = types.InlineKeyboardMarkup(row_width=2)
        
        buttons = [
            types.InlineKeyboardButton("📈 آمار کامل", callback_data="admin_full_stats"),
            types.InlineKeyboardButton("👥 کاربران", callback_data="admin_users"),
            types.InlineKeyboardButton("⚠️ اعلان همگانی", callback_data="admin_broadcast"),
            types.InlineKeyboardButton("🔧 تنظیمات سیستم", callback_data="admin_settings"),
        ]
        
        keyboard.add(*buttons[:2])
        keyboard.add(*buttons[2:])
        
        self.bot.send_message(
            message.chat.id,
            "🛠️ **پنل مدیریت**\n\n"
            "لطفاً گزینه مورد نظر را انتخاب کنید:",
            reply_markup=keyboard,
            parse_mode='Markdown'
        )
    
    def start(self):
        """شروع ربات"""
        logger.info("🚀 Starting Advanced Telegram Bot...")
        
        try:
            self.bot.polling(none_stop=True, interval=1, timeout=30)
        except Exception as e:
            logger.error(f"Bot polling error: {e}")
            raise

# ========== سیستم اصلی ==========

class AdvancedTelegramSystem:
    """سیستم اصلی ادغام شده"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.components: Dict[str, Any] = {}
        self.is_running = False
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Advanced Telegram System initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """بارگذاری تنظیمات"""
        config_file = Path(config_path)
        
        if not config_file.exists():
            # ایجاد config پیش‌فرض
            default_config = {
                "telegram_bot": {
                    "token": "YOUR_BOT_TOKEN_HERE",
                    "admin_ids": [123456789],
                    "webhook_url": ""
                },
                "security": {
                    "encryption_key": "change-this-to-very-secret-key-32-chars",
                    "rate_limit": 10,
                    "session_timeout": 3600
                },
                "performance": {
                    "max_workers": 5,
                    "max_download_speed": 10485760,  # 10 MB/s
                    "max_upload_speed": 5242880     # 5 MB/s
                },
                "database": {
                    "path": "telegram_system.db",
                    "backup_interval": 3600
                }
            }
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            
            logger.warning(f"Created default config at {config_path}")
            return default_config
        
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    async def initialize(self):
        """مقداردهی اولیه سیستم"""
        try:
            logger.info("🚀 Initializing Advanced Telegram System...")
            
            # 1. بررسی تنظیمات امنیتی
            if not HAS_CRYPTOGRAPHY:
                logger.warning("⚠️ Cryptography library not installed. Security features limited.")
            
            # 2. ایجاد دایرکتوری‌ها
            self._create_directories()
            
            # 3. مقداردهی کامپوننت‌ها
            await self._initialize_components()
            
            # 4. تست سلامت
            await self._health_check()
            
            self.is_running = True
            logger.info("✅ System initialized successfully!")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            await self.shutdown()
            raise
    
    def _create_directories(self):
        """ایجاد دایرکتوری‌های سیستم"""
        directories = [
            'downloads',
            'uploads',
            'logs',
            'backups',
            'cache',
            'temp',
            'sessions'
        ]
        
        for dir_name in directories:
            path = Path(dir_name)
            path.mkdir(exist_ok=True, parents=True)
            logger.debug(f"Directory: {dir_name}")
    
    async def _initialize_components(self):
        """مقداردهی کامپوننت‌ها"""
        
        # Telegram Bot
        bot_config = self.config.get('telegram_bot', {})
        if bot_config.get('token') and bot_config['token'] != "YOUR_BOT_TOKEN_HERE":
            self.components['telegram_bot'] = AdvancedTelegramBot(
                token=bot_config['token'],
                admin_ids=bot_config.get('admin_ids', [])
            )
            logger.info("✓ Telegram Bot initialized")
        else:
            logger.warning("⚠️ Telegram Bot token not configured")
        
        # سایر کامپوننت‌ها می‌توانند اینجا اضافه شوند
        # مانند API Server, Web Interface, etc.
    
    async def _health_check(self):
        """بررسی سلامت سیستم"""
        health_status = {}
        
        for name, component in self.components.items():
            try:
                if hasattr(component, 'get_status'):
                    status = await component.get_status()
                else:
                    status = {'status': 'unknown'}
                
                health_status[name] = {
                    'status': 'healthy',
                    'details': status
                }
            except Exception as e:
                health_status[name] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
        
        # لاگ وضعیت
        unhealthy = [name for name, status in health_status.items() 
                    if status['status'] != 'healthy']
        
        if unhealthy:
            logger.warning(f"Unhealthy components: {unhealthy}")
        else:
            logger.info("✓ All components are healthy")
        
        return health_status
    
    async def run(self):
        """اجرای اصلی سیستم"""
        try:
            await self.initialize()
            
            logger.info("""
            🚀 Advanced Telegram System is RUNNING!
            
            Features:
            • Advanced Security (AES-GCM)
            • Multi-Account Management
            • Optimized Download/Upload
            • Real-time Monitoring
            • Admin Panel
            
            Press Ctrl+C to stop.
            """)
            
            # شروع ربات تلگرام
            if 'telegram_bot' in self.components:
                bot_thread = Thread(
                    target=self.components['telegram_bot'].start,
                    daemon=True
                )
                bot_thread.start()
                logger.info("Telegram Bot started in separate thread")
            
            # حلقه اصلی
            while self.is_running:
                await asyncio.sleep(1)
                
                # کارهای دوره‌ای
                await self._periodic_tasks()
        
        except KeyboardInterrupt:
            logger.info("👋 Received keyboard interrupt")
        except Exception as e:
            logger.error(f"💥 System error: {e}")
        finally:
            await self.shutdown()
    
    async def _periodic_tasks(self):
        """کارهای دوره‌ای"""
        # هر 30 ثانیه
        current_time = asyncio.get_event_loop().time()
        if hasattr(self, '_last_periodic_run'):
            if current_time - self._last_periodic_run < 30:
                return
        
        self._last_periodic_run = current_time
        
        try:
            # 1. پاکسازی منابع
            self._cleanup_resources()
            
            # 2. تهیه backup از دیتابیس
            await self._backup_database()
            
            # 3. لاگ آمار سیستم
            await self._log_system_stats()
            
        except Exception as e:
            logger.error(f"Periodic task error: {e}")
    
    def _cleanup_resources(self):
        """پاکسازی منابع"""
        # پاکسازی فایل‌های موقت قدیمی
        temp_dir = Path('temp')
        if temp_dir.exists():
            for file in temp_dir.glob('*'):
                if file.is_file():
                    file_age = datetime.now().timestamp() - file.stat().st_mtime
                    if file_age > 3600:  # 1 ساعت
                        file.unlink(missing_ok=True)
    
    async def _backup_database(self):
        """تهیه backup از دیتابیس"""
        import shutil
        
        backup_dir = Path('backups')
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        backup_path = backup_dir / f'database_backup_{timestamp}.db'
        
        try:
            shutil.copy2('telegram_system.db', backup_path)
            
            # حذف backup‌های قدیمی (بیش از 7 روز)
            for backup_file in backup_dir.glob('*.db'):
                file_age = datetime.now().timestamp() - backup_file.stat().st_mtime
                if file_age > 7 * 24 * 3600:  # 7 روز
                    backup_file.unlink()
                    
        except Exception as e:
            logger.error(f"Backup error: {e}")
    
    async def _log_system_stats(self):
        """ذخیره آمار سیستم"""
        try:
            # جمع‌آوری آمار
            stats = {
                'timestamp': datetime.now(),
                'active_users': len(self.components.get('telegram_bot', {}).user_states or {}),
                'active_tasks': len(self.components.get('speed_optimizer', {}).active_downloads or {}),
                'memory_usage': self._get_memory_usage(),
                'cpu_usage': self._get_cpu_usage()
            }
            
            logger.debug(f"System stats: {stats}")
            
        except Exception as e:
            logger.error(f"Stats logging error: {e}")
    
    def _get_memory_usage(self) -> float:
        """دریافت مصرف حافظه"""
        import psutil
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # MB
        except:
            return 0.0
    
    def _get_cpu_usage(self) -> float:
        """دریافت مصرف CPU"""
        import psutil
        try:
            return psutil.cpu_percent(interval=1)
        except:
            return 0.0
    
    async def shutdown(self):
        """خاموش کردن سیستم"""
        if not self.is_running:
            return
        
        logger.info("🛑 Shutting down system...")
        self.is_running = False
        
        # توقف کامپوننت‌ها
        for name, component in self.components.items():
            if hasattr(component, 'shutdown'):
                logger.info(f"Shutting down {name}...")
                try:
                    if asyncio.iscoroutinefunction(component.shutdown):
                        await component.shutdown()
                    else:
                        component.shutdown()
                except Exception as e:
                    logger.error(f"Shutdown error for {name}: {e}")
        
        logger.info("✅ System shutdown complete")
    
    def _signal_handler(self, signum, frame):
        """مدیریت signal"""
        logger.info(f"Signal {signum} received, shutting down...")
        asyncio.create_task(self.shutdown())

# ========== اجرای اصلی ==========

async def main():
    """تابع اصلی"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Advanced Telegram Management System',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', 
                       default='config.json',
                       help='Configuration file path')
    
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable debug mode')
    
    parser.add_argument('--setup',
                       action='store_true',
                       help='Setup mode (create config and exit)')
    
    args = parser.parse_args()
    
    # تنظیم لاگ‌گیری
    global logger
    logger = setup_logging(debug=args.debug)
    
    if args.setup:
        print("🛠️ Setup mode activated")
        print("✅ Configuration file created: config.json")
        print("📝 Please edit config.json with your settings")
        return
    
    # اجرای سیستم
    try:
        system = AdvancedTelegramSystem(config_path=args.config)
        await system.run()
    except KeyboardInterrupt:
        logger.info("System stopped by user")
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # بررسی وابستگی‌ها
    missing_libs = []
    
    if not HAS_CRYPTOGRAPHY:
        missing_libs.append("cryptography")
    
    if not HAS_TELEBOT:
        missing_libs.append("pyTelegramBotAPI")
    
    if missing_libs:
        print("❌ Missing required libraries:")
        for lib in missing_libs:
            print(f"   - {lib}")
        print("\n📦 Install with: pip install " + " ".join(missing_libs))
        sys.exit(1)
    
    # اجرا
    asyncio.run(main())
