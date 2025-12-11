#!/usr/bin/env python3
# telegram_bot.py - ربات توزیع فایل برای کاربران

import telebot
from telebot import types
import json
import os
import threading
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Optional, List, Dict, Any
import hashlib

# تنظیمات لاگ
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('telegram_bot.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FileDistributionBot:
    def __init__(self, token: str):
        """
        Initialize File Distribution Bot
        
        Args:
            token: Telegram Bot Token from @BotFather
        """
        self.bot = telebot.TeleBot(token, parse_mode='HTML')
        self.token = token
        
        # پوشه‌های پروژه
        self.base_dir = Path(__file__).parent
        self.downloads_dir = self.base_dir / "downloads"
        self.data_dir = self.base_dir / "data"
        self.uploads_dir = self.base_dir / "uploads"
        
        # ایجاد پوشه‌های لازم
        for directory in [self.downloads_dir, self.data_dir, self.uploads_dir]:
            directory.mkdir(exist_ok=True)
        
        # دیتابیس SQLite
        self.db_path = self.data_dir / "bot_database.db"
        self.init_database()
        
        # فایل‌های JSON (برای سازگاری)
        self.files_json = self.data_dir / "files_database.json"
        self.broadcast_queue_json = self.data_dir / "broadcast_queue.json"
        
        # تنظیمات
        self.settings = self.load_settings()
        self.admins = self.settings.get('admins', [])
        
        # کانال‌های اجباری
        self.required_channels = self.settings.get('required_channels', [])
        
        # وضعیت
        self.is_broadcasting = False
        self.broadcast_lock = threading.Lock()
        
        logger.info("FileDistributionBot initialized")
    
    def init_database(self):
        """ایجاد جداول دیتابیس"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # جدول کاربران
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            join_date TIMESTAMP,
            last_activity TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            language TEXT DEFAULT 'fa'
        )
        ''')
        
        # جدول فایل‌ها
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE,
            file_name TEXT,
            file_path TEXT,
            file_size INTEGER,
            file_type TEXT,
            category TEXT,
            description TEXT,
            upload_date TIMESTAMP,
            uploader_id INTEGER,
            download_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        )
        ''')
        
        # جدول دسته‌بندی‌ها
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT,
            icon TEXT
        )
        ''')
        
        # جدول صف ارسال
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS broadcast_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            scheduled_time TIMESTAMP,
            sent_time TIMESTAMP,
            status TEXT DEFAULT 'pending',
            sent_count INTEGER DEFAULT 0,
            failed_count INTEGER DEFAULT 0,
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
        ''')
        
        # جدول فعالیت‌ها
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
        ''')
        
        # درج دسته‌بندی‌های پیش‌فرض
        default_categories = [
            ('📚 کتاب', 'کتاب‌های الکترونیکی', '📚'),
            ('🎬 ویدیو', 'فیلم و ویدیو آموزشی', '🎬'),
            ('🎵 صدا', 'پادکست و فایل صوتی', '🎵'),
            ('📄 سند', 'اسناد و مقالات', '📄'),
            ('📁 فشرده', 'فایل‌های فشرده', '📁'),
            ('🖼 تصویر', 'عکس و تصویر', '🖼'),
        ]
        
        cursor.executemany(
            'INSERT OR IGNORE INTO categories (name, description, icon) VALUES (?, ?, ?)',
            default_categories
        )
        
        conn.commit()
        conn.close()
        
        logger.info("Database initialized")
    
    def load_settings(self) -> dict:
        """بارگذاری تنظیمات از فایل"""
        settings_file = self.base_dir / "bot_settings.json"
        
        if settings_file.exists():
            try:
                with open(settings_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading settings: {e}")
        
        # تنظیمات پیش‌فرض
        default_settings = {
            'admins': [123456789],  # آیدی ادمین
            'required_channels': ['@your_channel'],  # کانال‌های اجباری
            'welcome_message': 'به ربات ما خوش آمدید!',
            'max_file_size': 2000,  # مگابایت
            'daily_download_limit': 10,
            'broadcast_delay': 1,  # ثانیه بین ارسال‌ها
        }
        
        # ذخیره تنظیمات پیش‌فرض
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(default_settings, f, ensure_ascii=False, indent=2)
        
        logger.info("Created default settings file")
        return default_settings
    
    def save_settings(self):
        """ذخیره تنظیمات"""
        settings_file = self.base_dir / "bot_settings.json"
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(self.settings, f, ensure_ascii=False, indent=2)
    
    def register_user(self, user_id: int, username: str, first_name: str, last_name: str = ""):
        """ثبت کاربر جدید"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        cursor.execute('''
        INSERT OR REPLACE INTO users 
        (user_id, username, first_name, last_name, join_date, last_activity)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, first_name, last_name, now, now))
        
        conn.commit()
        conn.close()
        
        logger.info(f"New user registered: {user_id} (@{username})")
        
        # ثبت فعالیت
        self.log_activity(user_id, 'register')
    
    def log_activity(self, user_id: int, action: str, details: str = ""):
        """ثبت فعالیت کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        INSERT INTO activities (user_id, action, details, timestamp)
        VALUES (?, ?, ?, ?)
        ''', (user_id, action, details, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def is_admin(self, user_id: int) -> bool:
        """بررسی ادمین بودن"""
        return user_id in self.admins
    
    def check_channel_membership(self, user_id: int) -> bool:
        """بررسی عضویت کاربر در کانال‌های اجباری"""
        if not self.required_channels:
            return True
        
        # در اینجا باید API تلگرام را برای بررسی عضویت فراخوانی کنید
        # این یک پیاده‌سازی ساده است
        try:
            for channel in self.required_channels:
                # با استفاده از getChatMember می‌توانید بررسی کنید
                # این قسمت نیاز به پیاده‌سازی دارد
                pass
            return True  # موقتاً true برمی‌گرداند
        except:
            return False
    
    def scan_files_directory(self):
        """اسکن پوشه دانلود و اضافه کردن فایل‌های جدید به دیتابیس"""
        logger.info("Scanning downloads directory for new files...")
        
        files_added = 0
        for file_path in self.downloads_dir.rglob('*'):
            if file_path.is_file() and not file_path.name.startswith('.'):
                # محاسبه hash فایل
                try:
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                except:
                    continue
                
                # بررسی وجود در دیتابیس
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('SELECT id FROM files WHERE file_hash = ?', (file_hash,))
                exists = cursor.fetchone()
                
                if not exists:
                    # اضافه کردن به دیتابیس
                    file_size = file_path.stat().st_size
                    file_ext = file_path.suffix.lower()
                    
                    # تعیین نوع فایل
                    if file_ext in ['.pdf', '.doc', '.docx', '.txt']:
                        file_type = 'document'
                        category = '📚 کتاب'
                    elif file_ext in ['.mp4', '.avi', '.mkv', '.mov']:
                        file_type = 'video'
                        category = '🎬 ویدیو'
                    elif file_ext in ['.mp3', '.wav', '.ogg']:
                        file_type = 'audio'
                        category = '🎵 صدا'
                    elif file_ext in ['.jpg', '.jpeg', '.png', '.gif']:
                        file_type = 'photo'
                        category = '🖼 تصویر'
                    elif file_ext in ['.zip', '.rar', '.7z']:
                        file_type = 'archive'
                        category = '📁 فشرده'
                    else:
                        file_type = 'other'
                        category = '📄 سند'
                    
                    cursor.execute('''
                    INSERT INTO files 
                    (file_hash, file_name, file_path, file_size, file_type, category, upload_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        file_hash,
                        file_path.name,
                        str(file_path),
                        file_size,
                        file_type,
                        category,
                        datetime.now().isoformat()
                    ))
                    
                    files_added += 1
                    logger.info(f"Added new file: {file_path.name}")
                
                conn.commit()
                conn.close()
        
        logger.info(f"Scan complete. Added {files_added} new files.")
        return files_added
    
    def get_file_categories(self) -> List[tuple]:
        """دریافت لیست دسته‌بندی‌ها"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, name, icon FROM categories ORDER BY name')
        categories = cursor.fetchall()
        
        conn.close()
        return categories
    
    def get_files_by_category(self, category_id: int, limit: int = 20) -> List[dict]:
        """دریافت فایل‌های یک دسته‌بندی"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT f.*, c.name as category_name 
        FROM files f
        LEFT JOIN categories c ON f.category = c.name
        WHERE c.id = ? AND f.is_active = 1
        ORDER BY f.upload_date DESC
        LIMIT ?
        ''', (category_id, limit))
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return files
    
    def search_files(self, query: str) -> List[dict]:
        """جستجوی فایل‌ها"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        search_term = f"%{query}%"
        cursor.execute('''
        SELECT * FROM files 
        WHERE (file_name LIKE ? OR description LIKE ?) 
        AND is_active = 1
        ORDER BY download_count DESC
        LIMIT 20
        ''', (search_term, search_term))
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return files
    
    def send_file_to_user(self, user_id: int, file_id: int):
        """ارسال فایل به کاربر"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # دریافت اطلاعات فایل
        cursor.execute('SELECT * FROM files WHERE id = ?', (file_id,))
        file_info = cursor.fetchone()
        
        if not file_info:
            conn.close()
            return False, "فایل یافت نشد"
        
        # بررسی وجود فایل
        file_path = Path(file_info[3])  # ستون file_path
        if not file_path.exists():
            conn.close()
            return False, "فایل در سرور وجود ندارد"
        
        # بررسی محدودیت دانلود
        cursor.execute('SELECT download_count FROM users WHERE user_id = ?', (user_id,))
        user_downloads = cursor.fetchone()
        
        if user_downloads and user_downloads[0] >= self.settings.get('daily_download_limit', 10):
            conn.close()
            return False, "محدودیت دانلود روزانه شما تکمیل شده است"
        
        try:
            # ارسال فایل بر اساس نوع
            with open(file_path, 'rb') as f:
                if file_info[5] == 'video':  # ستون file_type
                    self.bot.send_video(user_id, f, timeout=60)
                elif file_info[5] == 'audio':
                    self.bot.send_audio(user_id, f, timeout=60)
                elif file_info[5] == 'photo':
                    self.bot.send_photo(user_id, f, timeout=60)
                else:
                    self.bot.send_document(user_id, f, timeout=60)
            
            # به‌روزرسانی آمار
            cursor.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_id,))
            cursor.execute('UPDATE users SET download_count = download_count + 1 WHERE user_id = ?', (user_id,))
            
            # ثبت فعالیت
            self.log_activity(user_id, 'download', f"File: {file_info[2]}")
            
            conn.commit()
            conn.close()
            
            logger.info(f"File sent: {file_info[2]} to user {user_id}")
            return True, "فایل با موفقیت ارسال شد"
            
        except Exception as e:
            conn.close()
            logger.error(f"Error sending file: {e}")
            return False, f"خطا در ارسال فایل: {str(e)}"
    
    def start_broadcast_scheduler(self):
        """شروع زمان‌بند ارسال همگانی"""
        def scheduler():
            while True:
                self.process_broadcast_queue()
                time.sleep(60)  # هر دقیقه بررسی
        
        thread = threading.Thread(target=scheduler, daemon=True)
        thread.start()
        logger.info("Broadcast scheduler started")
    
    def process_broadcast_queue(self):
        """پردازش صف ارسال همگانی"""
        with self.broadcast_lock:
            if self.is_broadcasting:
                return
            
            self.is_broadcasting = True
            
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # دریافت ارسال‌های در انتظار
                cursor.execute('''
                SELECT bq.*, f.file_path, f.file_name 
                FROM broadcast_queue bq
                JOIN files f ON bq.file_id = f.id
                WHERE bq.status = 'pending' 
                AND (bq.scheduled_time IS NULL OR bq.scheduled_time <= ?)
                ORDER BY bq.id ASC
                LIMIT 1
                ''', (datetime.now().isoformat(),))
                
                broadcast = cursor.fetchone()
                
                if broadcast:
                    broadcast_id, file_id, scheduled_time, sent_time, status, sent_count, failed_count, file_path, file_name = broadcast
                    
                    logger.info(f"Processing broadcast {broadcast_id} for file: {file_name}")
                    
                    # دریافت همه کاربران غیرمسدود
                    cursor.execute('SELECT user_id FROM users WHERE is_banned = 0')
                    users = cursor.fetchall()
                    
                    total_users = len(users)
                    success_count = 0
                    fail_count = 0
                    
                    # ارسال به کاربران
                    for user_row in users:
                        user_id = user_row[0]
                        
                        try:
                            success, message = self.send_file_to_user(user_id, file_id)
                            if success:
                                success_count += 1
                            else:
                                fail_count += 1
                            
                            # تاخیر بین ارسال‌ها
                            time.sleep(self.settings.get('broadcast_delay', 1))
                            
                        except Exception as e:
                            logger.error(f"Error in broadcast to {user_id}: {e}")
                            fail_count += 1
                    
                    # به‌روزرسانی وضعیت
                    cursor.execute('''
                    UPDATE broadcast_queue 
                    SET status = 'completed', 
                        sent_time = ?,
                        sent_count = ?,
                        failed_count = ?
                    WHERE id = ?
                    ''', (
                        datetime.now().isoformat(),
                        success_count,
                        fail_count,
                        broadcast_id
                    ))
                    
                    conn.commit()
                    
                    logger.info(f"Broadcast {broadcast_id} completed: {success_count}/{total_users} successful")
                
                conn.close()
                
            except Exception as e:
                logger.error(f"Error in broadcast scheduler: {e}")
            finally:
                self.is_broadcasting = False
    
    def setup_handlers(self):
        """تنظیم هندلرهای ربات"""
        
        @self.bot.message_handler(commands=['start'])
        def start_handler(message):
            """هندلر دستور /start"""
            user_id = message.from_user.id
            username = message.from_user.username
            first_name = message.from_user.first_name
            last_name = message.from_user.last_name or ""
            
            # ثبت کاربر
            self.register_user(user_id, username, first_name, last_name)
            
            # بررسی عضویت در کانال
            if not self.check_channel_membership(user_id):
                keyboard = types.InlineKeyboardMarkup()
                for channel in self.required_channels:
                    keyboard.add(types.InlineKeyboardButton(
                        f"عضویت در کانال 📢",
                        url=f"https://t.me/{channel.replace('@', '')}"
                    ))
                
                self.bot.send_message(
                    user_id,
                    "⛔ برای استفاده از ربات ابتدا باید در کانل‌های زیر عضو شوید:",
                    reply_markup=keyboard
                )
                return
            
            # نمایش منوی اصلی
            self.show_main_menu(user_id)
            
            self.log_activity(user_id, 'start')
        
        @self.bot.message_handler(func=lambda m: m.text == '📁 فایل‌ها')
        def files_handler(message):
            """نمایش دسته‌بندی‌های فایل"""
            user_id = message.from_user.id
            
            categories = self.get_file_categories()
            
            keyboard = types.InlineKeyboardMarkup(row_width=2)
            for cat_id, cat_name, cat_icon in categories:
                keyboard.add(types.InlineKeyboardButton(
                    f"{cat_icon} {cat_name}",
                    callback_data=f"cat_{cat_id}"
                ))
            
            keyboard.add(types.InlineKeyboardButton("🔍 جستجوی فایل", callback_data="search_files"))
            
            self.bot.send_message(
                user_id,
                "📚 <b>دسته‌بندی فایل‌ها</b>\n\nلطفاً یک دسته را انتخاب کنید:",
                reply_markup=keyboard,
                parse_mode='HTML'
            )
            
            self.log_activity(user_id, 'view_categories')
        
        @self.bot.callback_query_handler(func=lambda call: call.data.startswith('cat_'))
        def category_handler(call):
            """هندلر انتخاب دسته‌بندی"""
            user_id = call.from_user.id
            
            try:
                cat_id = int(call.data.replace('cat_', ''))
                files = self.get_files_by_category(cat_id)
                
                if not files:
                    self.bot.answer_callback_query(call.id, "هیچ فایلی در این دسته وجود ندارد.")
                    return
                
                keyboard = types.InlineKeyboardMarkup()
                
                for file in files:
                    file_name = file['file_name']
                    file_id = file['id']
                    
                    # کوتاه کردن نام فایل اگر طولانی باشد
                    if len(file_name) > 30:
                        display_name = file_name[:27] + "..."
                    else:
                        display_name = file_name
                    
                    keyboard.add(types.InlineKeyboardButton(
                        f"📄 {display_name} ({file['file_size'] // 1024}KB)",
                        callback_data=f"dl_{file_id}"
                    ))
                
                # صفحه‌بندی
                keyboard.row(
                    types.InlineKeyboardButton("◀️ قبلی", callback_data=f"page_{cat_id}_0"),
                    types.InlineKeyboardButton("▶️ بعدی", callback_data=f"page_{cat_id}_2")
                )
                
                self.bot.edit_message_text(
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    text=f"📁 فایل‌های این دسته:\n\nبرای دانلود روی فایل کلیک کنید:",
                    reply_markup=keyboard
                )
                
                self.log_activity(user_id, 'view_category', f"Category: {cat_id}")
                
            except Exception as e:
                self.bot.answer_callback_query(call.id, "خطا در دریافت فایل‌ها")
                logger.error(f"Error in category handler: {e}")
        
        @self.bot.callback_query_handler(func=lambda call: call.data.startswith('dl_'))
        def download_handler(call):
            """هندلر دانلود فایل"""
            user_id = call.from_user.id
            
            try:
                file_id = int(call.data.replace('dl_', ''))
                
                # ارسال فایل
                success, message = self.send_file_to_user(user_id, file_id)
                
                if success:
                    self.bot.answer_callback_query(call.id, "✅ فایل ارسال شد!")
                    self.log_activity(user_id, 'download_success', f"File: {file_id}")
                else:
                    self.bot.answer_callback_query(call.id, f"❌ {message}")
                    self.log_activity(user_id, 'download_failed', f"File: {file_id} - {message}")
                
            except Exception as e:
                self.bot.answer_callback_query(call.id, "خطا در ارسال فایل")
                logger.error(f"Error in download handler: {e}")
        
        @self.bot.message_handler(commands=['admin'])
        def admin_handler(message):
            """پنل مدیریت"""
            user_id = message.from_user.id
            
            if not self.is_admin(user_id):
                self.bot.reply_to(message, "⛔ دسترسی denied!")
                return
            
            keyboard = types.InlineKeyboardMarkup(row_width=2)
            keyboard.add(
                types.InlineKeyboardButton("📊 آمار", callback_data="admin_stats"),
                types.InlineKeyboardButton("📤 ارسال همگانی", callback_data="admin_broadcast")
            )
            keyboard.add(
                types.InlineKeyboardButton("📁 مدیریت فایل‌ها", callback_data="admin_files"),
                types.InlineKeyboardButton("👥 مدیریت کاربران", callback_data="admin_users")
            )
            keyboard.add(
                types.InlineKeyboardButton("🔄 اسکن فایل‌ها", callback_data="admin_scan"),
                types.InlineKeyboardButton("⚙️ تنظیمات", callback_data="admin_settings")
            )
            
            self.bot.send_message(
                user_id,
                "👨‍💼 <b>پنل مدیریت</b>\n\nلطفاً گزینه مورد نظر را انتخاب کنید:",
                reply_markup=keyboard,
                parse_mode='HTML'
            )
            
            self.log_activity(user_id, 'admin_panel')
        
        @self.bot.callback_query_handler(func=lambda call: call.data == 'admin_scan')
        def admin_scan_handler(call):
            """اسکن فایل‌های جدید"""
            user_id = call.from_user.id
            
            if not self.is_admin(user_id):
                self.bot.answer_callback_query(call.id, "⛔ دسترسی denied!")
                return
            
            self.bot.answer_callback_query(call.id, "در حال اسکن...")
            
            # اسکن فایل‌ها در پس‌زمینه
            def scan_background():
                files_added = self.scan_files_directory()
                
                self.bot.send_message(
                    user_id,
                    f"✅ اسکن کامل شد.\n{files_added} فایل جدید اضافه شد."
                )
            
            thread = threading.Thread(target=scan_background, daemon=True)
            thread.start()
            
            self.log_activity(user_id, 'admin_scan')
        
        @self.bot.message_handler(content_types=['document', 'video', 'audio', 'photo'])
        def upload_handler(message):
            """آپلود فایل توسط ادمین"""
            user_id = message.from_user.id
            
            if not self.is_admin(user_id):
                return
            
            try:
                if message.document:
                    file_info = self.bot.get_file(message.document.file_id)
                    file_name = message.document.file_name
                elif message.video:
                    file_info = self.bot.get_file(message.video.file_id)
                    file_name = f"video_{message.message_id}.mp4"
                elif message.audio:
                    file_info = self.bot.get_file(message.audio.file_id)
                    file_name = f"audio_{message.message_id}.mp3"
                elif message.photo:
                    # گرفتن بزرگترین عکس
                    file_info = self.bot.get_file(message.photo[-1].file_id)
                    file_name = f"photo_{message.message_id}.jpg"
                else:
                    return
                
                # دانلود فایل
                downloaded_file = self.bot.download_file(file_info.file_path)
                
                # ذخیره در پوشه آپلود
                upload_path = self.uploads_dir / file_name
                with open(upload_path, 'wb') as f:
                    f.write(downloaded_file)
                
                # محاسبه hash
                file_hash = hashlib.md5(downloaded_file).hexdigest()
                
                # ذخیره در دیتابیس
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                INSERT OR IGNORE INTO files 
                (file_hash, file_name, file_path, file_size, file_type, upload_date, uploader_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_hash,
                    file_name,
                    str(upload_path),
                    len(downloaded_file),
                    message.content_type,
                    datetime.now().isoformat(),
                    user_id
                ))
                
                conn.commit()
                conn.close()
                
                self.bot.reply_to(
                    message,
                    f"✅ فایل '{file_name}' با موفقیت آپلود شد."
                )
                
                self.log_activity(user_id, 'upload_file', f"File: {file_name}")
                
            except Exception as e:
                self.bot.reply_to(message, f"❌ خطا در آپلود: {str(e)}")
                logger.error(f"Upload error: {e}")
        
        @self.bot.message_handler(func=lambda m: True)
        def text_handler(message):
            """هندلر پیام‌های متنی"""
            user_id = message.from_user.id
            
            if message.text == '📞 پشتیبانی':
                self.bot.send_message(
                    user_id,
                    "📞 <b>پشتیبانی</b>\n\n"
                    "برای ارتباط با پشتیبانی:\n"
                    "👨‍💼 ادمین: @admin_username\n"
                    "📧 ایمل: support@example.com\n\n"
                    "ساعات پاسخگویی: 9 صبح تا 5 بعدازظهر",
                    parse_mode='HTML'
                )
            
            elif message.text == 'ℹ️ راهنما':
                self.bot.send_message(
                    user_id,
                    "📖 <b>راهنمای استفاده</b>\n\n"
                    "1. برای مشاهده فایل‌ها روی '📁 فایل‌ها' کلیک کنید\n"
                    "2. دسته مورد نظر را انتخاب کنید\n"
                    "3. روی فایل دلخواه کلیک کنید تا دانلود شود\n"
                    "4. برای جستجو از دکمه '🔍 جستجو' استفاده کنید\n\n"
                    "⚠️ <b>توجه:</b> حداکثر 10 دانلود در روز مجاز است.",
                    parse_mode='HTML'
                )
            
            elif message.text == '📊 آمار من':
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                SELECT download_count, join_date 
                FROM users WHERE user_id = ?
                ''', (user_id,))
                
                user_stats = cursor.fetchone()
                conn.close()
                
                if user_stats:
                    download_count, join_date = user_stats
                    
                    self.bot.send_message(
                        user_id,
                        f"📊 <b>آمار شما</b>\n\n"
                        f"📥 تعداد دانلود: {download_count}\n"
                        f"📅 تاریخ عضویت: {join_date[:10]}\n"
                        f"🎯 محدودیت روزانه: {self.settings.get('daily_download_limit', 10)}",
                        parse_mode='HTML'
                    )
            
            self.log_activity(user_id, 'text_message', f"Text: {message.text[:50]}")
    
    def show_main_menu(self, chat_id):
        """نمایش منوی اصلی"""
        keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
        keyboard.row('📁 فایل‌ها', '🔍 جستجو')
        keyboard.row('📊 آمار من', '📞 پشتیبانی')
        keyboard.row('ℹ️ راهنما')
        
        if self.is_admin(chat_id):
            keyboard.row('👨‍💼 پنل مدیریت')
        
        welcome_text = (
            f"🎉 <b>به ربات توزیع فایل خوش آمدید!</b>\n\n"
            f"در این ربات می‌توانید فایل‌های مختلف را دانلود کنید.\n\n"
            f"📁 <b>تعداد فایل‌های موجود:</b> {self.get_total_files_count()}\n"
            f"👥 <b>کاربران فعال:</b> {self.get_active_users_count()}\n\n"
            f"برای شروع روی '📁 فایل‌ها' کلیک کنید."
        )
        
        self.bot.send_message(
            chat_id,
            welcome_text,
            reply_markup=keyboard,
            parse_mode='HTML'
        )
    
    def get_total_files_count(self) -> int:
        """دریافت تعداد کل فایل‌ها"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM files WHERE is_active = 1')
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
    
    def get_active_users_count(self) -> int:
        """دریافت تعداد کاربران فعال"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE is_banned = 0')
        count = cursor.fetchone()[0]
        
        conn.close()
        return count
    
    def start_polling(self):
        """شروع ربات"""
        logger.info("Starting File Distribution Bot...")
        
        # اسکن اولیه فایل‌ها
        self.scan_files_directory()
        
        # شروع زمان‌بند ارسال همگانی
        self.start_broadcast_scheduler()
        
        # تنظیم هندلرها
        self.setup_handlers()
        
        logger.info("✅ Bot is running. Press Ctrl+C to stop.")
        
        # شروع polling
        self.bot.polling(none_stop=True, interval=1)

# تابع اصلی
def main():
    """تابع اصلی اجرای ربات"""
    
    # خواندن توکن از فایل config
    config_file = Path(__file__).parent / "bot_config.json"
    
    if not config_file.exists():
        # ایجاد فایل config پیش‌فرض
        default_config = {
            "bot_token": "YOUR_BOT_TOKEN_HERE",
            "admins": [123456789],
            "required_channels": ["@your_channel"]
        }
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, ensure_ascii=False, indent=2)
        
        print(f"⚠️  فایل bot_config.json ایجاد شد. لطفاً توکن ربات را وارد کنید.")
        print(f"   فایل: {config_file}")
        return
    
    # بارگذاری تنظیمات
    with open(config_file, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    bot_token = config.get("bot_token")
    
    if not bot_token or bot_token == "YOUR_BOT_TOKEN_HERE":
        print("❌ لطفاً bot_token را در فایل bot_config.json تنظیم کنید.")
        print("   از @BotFather دریافت کنید.")
        return
    
    # ایجاد و اجرای ربات
    bot = FileDistributionBot(bot_token)
    
    try:
        bot.start_polling()
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()
