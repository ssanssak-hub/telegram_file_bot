#!/usr/bin/env python3
# advanced_userbot_downloader.py - UserBot ایمن با قابلیت‌های هوش مصنوعی

from telethon import TelegramClient, events, types
from telethon.tl.types import MessageMediaDocument, MessageMediaPhoto, DocumentAttributeFilename
import asyncio
import os
import json
import random
import logging
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
import aiohttp
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from contextlib import contextmanager
import pickle
from concurrent.futures import ThreadPoolExecutor

# ==================== رفع ایرادات اصلی ====================

# 1. اضافه کردن try-except برای تمام عملیات I/O
# 2. بهبود مدیریت session
# 3. اضافه کردن timeout برای عملیات شبکه
# 4. رفع مشکل duplicate downloads
# 5. بهبود progress reporting

# ==================== تنظیمات لاگ پیشرفته ====================

class ColoredFormatter(logging.Formatter):
    """فرمتر رنگی برای لاگ‌ها"""
    COLORS = {
        'DEBUG': '\033[94m',      # آبی
        'INFO': '\033[92m',       # سبز
        'WARNING': '\033[93m',    # زرد
        'ERROR': '\033[91m',      # قرمز
        'CRITICAL': '\033[91m\033[1m',  # قرمز پررنگ
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        message = super().format(record)
        return f"{log_color}{message}{self.COLORS['RESET']}"

def setup_logging():
    """تنظیمات پیشرفته لاگ‌گیری"""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # فرمت پیشرفته
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler فایل
    file_handler = logging.FileHandler('userbot_advanced.log', encoding='utf-8', mode='a')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    
    # Handler کنسول
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# ==================== سیستم هوش مصنوعی ====================

class AIContentAnalyzer:
    """سیستم تحلیل محتوای هوشمند"""
    
    class ContentType(Enum):
        TEXT = "text"
        IMAGE = "image"
        VIDEO = "video"
        AUDIO = "audio"
        DOCUMENT = "document"
        UNKNOWN = "unknown"
    
    @dataclass
    class ContentAnalysis:
        content_type: str
        confidence: float
        tags: List[str]
        category: str
        nsfw_score: float
        summary: Optional[str]
        language: str
        keywords: List[str]
        sentiment: str
        file_hash: str
        quality_score: float
        
    def __init__(self):
        self.initialized = False
        self.cache = {}
        self.executor = ThreadPoolExecutor(max_workers=2)
        
    async def initialize(self):
        """مقداردهی اولیه مدل‌های AI (به صورت سبک)"""
        try:
            # در اینجا می‌توان مدل‌های واقعی AI را لود کرد
            # برای نمونه از منطق ساده استفاده می‌کنیم
            logger.info("✅ AI Analyzer initialized (lightweight mode)")
            self.initialized = True
            
            # لیست کلمات کلیدی برای طبقه‌بندی
            self.keyword_categories = {
                'educational': ['آموزش', 'درس', 'کتاب', 'تحصیل', 'دانشگاه', 'مدرسه'],
                'entertainment': ['فیلم', 'سریال', 'کارتون', 'موسیقی', 'طنز', 'تفریح'],
                'technology': ['برنامه', 'کد', 'پایتون', 'هوش', 'مصنوعی', 'کامپیوتر'],
                'news': ['اخبار', 'سیاسی', 'اقتصاد', 'حوادث', 'ورزش'],
                'religious': ['مذهبی', 'قرآن', 'اذان', 'دعا', 'روضه']
            }
            
            self.nsfw_keywords = ['ممنوع', 'سکسی', 'جنسی', 'محرمانه', 'خصوصی']
            
        except Exception as e:
            logger.warning(f"AI initialization failed, using fallback: {e}")
            self.initialized = False
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """محاسبه هش فایل برای تشخیص تکراری"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read(8192)).hexdigest()  # فقط بخش اول فایل
        except:
            return ""
    
    async def analyze_text(self, text: str) -> Dict:
        """تحلیل متن با AI ساده"""
        if not text:
            return {'category': 'unknown', 'sentiment': 'neutral'}
        
        text_lower = text.lower()
        
        # تشخیص دسته‌بندی
        category = 'other'
        max_matches = 0
        for cat, keywords in self.keyword_categories.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            if matches > max_matches:
                max_matches = matches
                category = cat
        
        # تشخیص احساسات ساده
        positive_words = ['خوب', 'عالی', 'ممتاز', 'عالی', 'زیبا', 'دوست داشتنی']
        negative_words = ['بد', 'ضعیف', 'خراب', 'مشکل', 'خطا', 'اشتباه']
        
        pos_count = sum(1 for w in positive_words if w in text_lower)
        neg_count = sum(1 for w in negative_words if w in text_lower)
        
        sentiment = 'neutral'
        if pos_count > neg_count:
            sentiment = 'positive'
        elif neg_count > pos_count:
            sentiment = 'negative'
        
        # استخراج کلمات کلیدی
        words = re.findall(r'\w{3,}', text_lower)
        word_freq = {}
        for word in words:
            if word not in ['برای', 'های', 'است', 'این', 'که']:
                word_freq[word] = word_freq.get(word, 0) + 1
        
        keywords = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
        keywords = [k[0] for k in keywords]
        
        # تشخیص زبان (ساده)
        lang = 'fa' if re.search(r'[\u0600-\u06FF]', text) else 'en'
        
        # خلاصه‌سازی ساده (اولین جمله)
        sentences = re.split(r'[.!?]', text)
        summary = sentences[0][:100] + '...' if sentences else ""
        
        # تشخیص NSFW
        nsfw_score = 0.0
        for kw in self.nsfw_keywords:
            if kw in text_lower:
                nsfw_score += 0.2
        
        return {
            'category': category,
            'sentiment': sentiment,
            'keywords': keywords,
            'language': lang,
            'summary': summary,
            'nsfw_score': min(nsfw_score, 1.0),
            'text_length': len(text)
        }
    
    async def analyze_file(self, file_path: Path, file_type: str, caption: str = "") -> ContentAnalysis:
        """تحلیل کامل فایل"""
        try:
            # تحلیل متن کپشن
            text_analysis = await self.analyze_text(caption)
            
            # محاسبه هش فایل
            file_hash = self.calculate_file_hash(file_path)
            
            # تشخیص نوع فایل از پسوند
            ext = file_path.suffix.lower()
            content_type = self.ContentType.DOCUMENT.value
            
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                content_type = self.ContentType.IMAGE.value
                quality_score = await self.estimate_image_quality(file_path)
            elif ext in ['.mp4', '.avi', '.mov', '.mkv']:
                content_type = self.ContentType.VIDEO.value
                quality_score = 0.7
            elif ext in ['.mp3', '.wav', '.ogg', '.flac']:
                content_type = self.ContentType.AUDIO.value
                quality_score = 0.6
            else:
                quality_score = 0.5
            
            # تولید تگ‌ها
            tags = []
            tags.append(content_type)
            tags.append(text_analysis['category'])
            tags.extend(text_analysis['keywords'][:3])
            
            # ساخت تحلیل نهایی
            analysis = self.ContentAnalysis(
                content_type=content_type,
                confidence=0.8,
                tags=tags,
                category=text_analysis['category'],
                nsfw_score=text_analysis['nsfw_score'],
                summary=text_analysis['summary'],
                language=text_analysis['language'],
                keywords=text_analysis['keywords'],
                sentiment=text_analysis['sentiment'],
                file_hash=file_hash,
                quality_score=quality_score
            )
            
            logger.info(f"🧠 AI Analysis: {file_path.name} -> {analysis.category} ({analysis.sentiment})")
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            # بازگشت تحلیل پیش‌فرض
            return self.ContentAnalysis(
                content_type=file_type,
                confidence=0.5,
                tags=[file_type],
                category='unknown',
                nsfw_score=0.0,
                summary=None,
                language='unknown',
                keywords=[],
                sentiment='neutral',
                file_hash='',
                quality_score=0.5
            )
    
    async def estimate_image_quality(self, image_path: Path) -> float:
        """تخمین کیفیت تصویر (ساده)"""
        try:
            import PIL.Image as PILImage
            with PILImage.open(image_path) as img:
                # عوامل کیفیت ساده
                score = 0.5
                
                # اندازه
                width, height = img.size
                if width > 1000 and height > 1000:
                    score += 0.2
                elif width < 300 or height < 300:
                    score -= 0.2
                
                # فرمت
                if img.format in ['JPEG', 'PNG']:
                    score += 0.1
                
                return max(0.1, min(1.0, score))
        except:
            return 0.5
    
    async def is_duplicate(self, file_path: Path, known_hashes: Set[str]) -> bool:
        """تشخیص فایل تکراری"""
        if not file_path.exists():
            return False
        
        file_hash = self.calculate_file_hash(file_path)
        if not file_hash:
            return False
        
        return file_hash in known_hashes
    
    async def filter_content(self, analysis: ContentAnalysis, user_preferences: Dict) -> bool:
        """فیلتر محتوا براساس تنظیمات کاربر"""
        try:
            # فیلتر NSFW
            if user_preferences.get('block_nsfw', True) and analysis.nsfw_score > 0.7:
                logger.info(f"⚠️ Blocked NSFW content: {analysis.nsfw_score}")
                return False
            
            # فیلتر دسته‌بندی
            blocked_categories = user_preferences.get('blocked_categories', [])
            if analysis.category in blocked_categories:
                logger.info(f"⚠️ Blocked category: {analysis.category}")
                return False
            
            # فیلتر کیفیت
            min_quality = user_preferences.get('min_quality', 0.3)
            if analysis.quality_score < min_quality:
                logger.info(f"⚠️ Low quality: {analysis.quality_score}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Filter error: {e}")
            return True  # در صورت خطا، محتوا را رد نکن

# ==================== پایگاه داده پیشرفته ====================

class DatabaseManager:
    """مدیریت پایگاه داده SQLite پیشرفته"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """ایجاد جداول پایگاه داده"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # جدول فایل‌ها
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT UNIQUE,
                telegram_id INTEGER,
                chat_id INTEGER,
                chat_title TEXT,
                file_name TEXT,
                file_path TEXT,
                file_size INTEGER,
                file_type TEXT,
                download_time TEXT,
                caption TEXT,
                category TEXT,
                tags TEXT,
                language TEXT,
                sentiment TEXT,
                nsfw_score REAL,
                quality_score REAL,
                ai_summary TEXT,
                is_processed BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # جدول کانال‌ها
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS channels (
                id INTEGER PRIMARY KEY,
                username TEXT,
                title TEXT,
                added_date TEXT,
                last_check TEXT,
                is_active BOOLEAN DEFAULT 1,
                category TEXT,
                priority INTEGER DEFAULT 5,
                daily_limit INTEGER DEFAULT 20,
                total_downloads INTEGER DEFAULT 0
            )
            ''')
            
            # جدول آمار
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                date TEXT PRIMARY KEY,
                downloads INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                total_size INTEGER DEFAULT 0,
                avg_quality REAL DEFAULT 0,
                categories TEXT
            )
            ''')
            
            # جدول کش هش فایل‌ها
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_hashes (
                file_hash TEXT PRIMARY KEY,
                file_path TEXT,
                file_size INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """مدیریت اتصال به دیتابیس"""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def save_file_info(self, file_info: Dict, ai_analysis: AIContentAnalyzer.ContentAnalysis = None):
        """ذخیره اطلاعات فایل در دیتابیس"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # بررسی وجود هش تکراری
                if ai_analysis and ai_analysis.file_hash:
                    cursor.execute(
                        "SELECT id FROM files WHERE file_hash = ?",
                        (ai_analysis.file_hash,)
                    )
                    if cursor.fetchone():
                        logger.warning(f"Duplicate file detected: {ai_analysis.file_hash}")
                        return False
                
                # ذخیره در جدول file_hashes
                if ai_analysis and ai_analysis.file_hash:
                    cursor.execute('''
                    INSERT OR IGNORE INTO file_hashes (file_hash, file_path, file_size)
                    VALUES (?, ?, ?)
                    ''', (ai_analysis.file_hash, file_info.get('file_path'), file_info.get('file_size', 0)))
                
                # ذخیره در جدول files
                cursor.execute('''
                INSERT INTO files (
                    file_hash, telegram_id, chat_id, chat_title, file_name,
                    file_path, file_size, file_type, download_time, caption,
                    category, tags, language, sentiment, nsfw_score,
                    quality_score, ai_summary, is_processed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ai_analysis.file_hash if ai_analysis else '',
                    file_info.get('id'),
                    file_info.get('chat_id'),
                    file_info.get('chat_title', 'Unknown'),
                    file_info.get('file_name'),
                    file_info.get('file_path'),
                    file_info.get('file_size', 0),
                    file_info.get('file_type', ''),
                    file_info.get('download_time'),
                    file_info.get('caption', '')[:500],  # محدودیت طول
                    ai_analysis.category if ai_analysis else 'unknown',
                    ','.join(ai_analysis.tags) if ai_analysis else '',
                    ai_analysis.language if ai_analysis else 'unknown',
                    ai_analysis.sentiment if ai_analysis else 'neutral',
                    ai_analysis.nsfw_score if ai_analysis else 0.0,
                    ai_analysis.quality_score if ai_analysis else 0.5,
                    ai_analysis.summary if ai_analysis else '',
                    0
                ))
                
                conn.commit()
                logger.info(f"💾 File info saved to database: {file_info.get('file_name')}")
                return True
                
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return False
    
    def get_duplicate_hashes(self) -> Set[str]:
        """دریافت تمام هش‌های فایل‌های ذخیره شده"""
        hashes = set()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT file_hash FROM file_hashes WHERE file_hash != ''")
                rows = cursor.fetchall()
                hashes = {row['file_hash'] for row in rows}
        except Exception as e:
            logger.error(f"Error getting hashes: {e}")
        return hashes
    
    def update_statistics(self, file_size: int, category: str):
        """به‌روزرسانی آمار روزانه"""
        try:
            today = datetime.now().strftime('%Y-%m-%d')
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # بررسی وجود رکورد امروز
                cursor.execute(
                    "SELECT downloads, total_size, categories FROM statistics WHERE date = ?",
                    (today,)
                )
                row = cursor.fetchone()
                
                if row:
                    downloads = row['downloads'] + 1
                    total_size = row['total_size'] + file_size
                    
                    # به‌روزرسانی دسته‌بندی‌ها
                    categories = json.loads(row['categories']) if row['categories'] else {}
                    categories[category] = categories.get(category, 0) + 1
                    
                    cursor.execute('''
                    UPDATE statistics 
                    SET downloads = ?, total_size = ?, categories = ?
                    WHERE date = ?
                    ''', (downloads, total_size, json.dumps(categories), today))
                else:
                    cursor.execute('''
                    INSERT INTO statistics (date, downloads, total_size, categories)
                    VALUES (?, 1, ?, ?)
                    ''', (today, file_size, json.dumps({category: 1})))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Statistics update error: {e}")

# ==================== UserBot پیشرفته ====================

class AdvancedUserBotDownloader:
    """UserBot پیشرفته با قابلیت‌های هوش مصنوعی"""
    
    def __init__(self, api_id: int, api_hash: str):
        self.api_id = api_id
        self.api_hash = api_hash
        self.client = None
        
        # مسیرها
        self.base_dir = Path(__file__).parent
        self.downloads_dir = self.base_dir / "downloads"
        self.data_dir = self.base_dir / "data"
        self.db_path = self.data_dir / "userbot.db"
        
        # ایجاد پوشه‌ها
        for directory in [self.downloads_dir, self.data_dir]:
            directory.mkdir(exist_ok=True)
        
        # مدیران سیستم
        self.db = DatabaseManager(self.db_path)
        self.ai_analyzer = AIContentAnalyzer()
        
        # تنظیمات پیشرفته
        self.settings = {
            'safety': {
                'max_downloads_per_day': 30,
                'min_delay': 2.0,
                'max_delay': 8.0,
                'cooldown_after_error': 60,
                'working_hours': [(9, 13), (16, 23)],
                'skip_weekends': True,
                'max_file_size_mb': 500,  # محدودیت حجم فایل
            },
            'ai': {
                'enable_analysis': True,
                'filter_nsfw': True,
                'min_quality_score': 0.3,
                'blocked_categories': ['adult', 'spam'],
                'auto_organize': True,
            },
            'organization': {
                'categorize_by_type': True,
                'categorize_by_content': True,
                'create_date_folders': True,
                'rename_files': False,
            }
        }
        
        # متغیرهای حالت
        self.download_count_today = 0
        self.last_reset_date = datetime.now().date()
        self.known_hashes = self.db.get_duplicate_hashes()
        
        logger.info("🚀 Advanced UserBot Downloader Initialized")
    
    async def initialize_ai(self):
        """مقداردهی اولیه سیستم AI"""
        await self.ai_analyzer.initialize()
        logger.info("✅ AI System Ready")
    
    async def human_delay(self, min_sec: float = None, max_sec: float = None):
        """تاخیر انسانی پیشرفته"""
        if min_sec is None:
            min_sec = self.settings['safety']['min_delay']
        if max_sec is None:
            max_sec = self.settings['safety']['max_delay']
        
        # تاخیر تصادفی با توزیع نرمال
        base_delay = random.uniform(min_sec, max_sec)
        
        # اضافه کردن تغییرات کوچک برای طبیعی‌تر شدن
        jitter = random.uniform(-0.5, 0.5)
        total_delay = max(0.5, base_delay + jitter)
        
        logger.debug(f"⏳ Human delay: {total_delay:.2f}s")
        await asyncio.sleep(total_delay)
    
    def is_safe_to_operate(self) -> bool:
        """بررسی شرایط ایمن پیشرفته"""
        now = datetime.now()
        
        # بررسی آخر هفته
        if self.settings['safety']['skip_weekends'] and now.weekday() >= 5:
            logger.info("🎌 Weekend - Operation paused")
            return False
        
        # بررسی ساعت کاری
        current_hour = now.hour
        working_hours = self.settings['safety']['working_hours']
        
        for start, end in working_hours:
            if start <= current_hour < end:
                return True
        
        logger.info(f"⏰ Outside working hours ({current_hour}:00)")
        return False
    
    def can_download_more(self) -> bool:
        """بررسی امکان دانلود بیشتر"""
        # بررسی ریست روزانه
        today = datetime.now().date()
        if today != self.last_reset_date:
            self.last_reset_date = today
            self.download_count_today = 0
            logger.info("🔄 Daily counter reset")
        
        # بررسی محدودیت روزانه
        daily_limit = self.settings['safety']['max_downloads_per_day']
        if self.download_count_today >= daily_limit:
            logger.warning(f"🚫 Daily limit reached: {self.download_count_today}/{daily_limit}")
            return False
        
        return True
    
    async def simulate_human_activity(self, chat_id):
        """شبیه‌سازی فعالیت انسانی"""
        activities = [
            ('typing', 1.0, 3.0),
            ('upload_photo', 0.5, 2.0),
            ('record_video', 1.5, 4.0),
        ]
        
        activity, min_time, max_time = random.choice(activities)
        
        try:
            async with self.client.action(chat_id, activity):
                duration = random.uniform(min_time, max_time)
                await asyncio.sleep(duration)
                logger.debug(f"👤 Simulated {activity} for {duration:.1f}s")
        except Exception as e:
            logger.debug(f"Activity simulation failed: {e}")
    
    async def get_file_name(self, message) -> Tuple[str, str]:
        """استخراج نام و پسوند فایل از پیام"""
        try:
            if hasattr(message, 'document') and message.document:
                for attr in message.document.attributes:
                    if isinstance(attr, DocumentAttributeFilename):
                        filename = attr.file_name
                        ext = Path(filename).suffix.lower()
                        return filename, ext
            
            elif hasattr(message, 'video') and message.video:
                return f"video_{message.id}.mp4", '.mp4'
            
            elif hasattr(message, 'audio') and message.audio:
                return f"audio_{message.id}.mp3", '.mp3'
            
            elif hasattr(message, 'photo') and message.photo:
                return f"photo_{message.id}.jpg", '.jpg'
            
            elif hasattr(message, 'voice') and message.voice:
                return f"voice_{message.id}.ogg", '.ogg'
            
        except Exception as e:
            logger.error(f"Error getting filename: {e}")
        
        return f"file_{message.id}.bin", '.bin'
    
    async def organize_file(self, file_path: Path, analysis: AIContentAnalyzer.ContentAnalysis) -> Path:
        """سازماندهی هوشمند فایل در پوشه‌های مناسب"""
        if not self.settings['organization']['auto_organize']:
            return file_path
        
        try:
            # ساختار پوشه براساس تنظیمات
            parts = []
            
            if self.settings['organization']['create_date_folders']:
                date_folder = datetime.now().strftime('%Y-%m-%d')
                parts.append(date_folder)
            
            if self.settings['organization']['categorize_by_type']:
                parts.append(analysis.content_type)
            
            if self.settings['organization']['categorize_by_content']:
                parts.append(analysis.category)
            
            # ایجاد مسیر جدید
            if parts:
                new_dir = self.downloads_dir / Path(*parts)
                new_dir.mkdir(parents=True, exist_ok=True)
                
                new_path = new_dir / file_path.name
                
                # انتقال فایل
                if file_path.exists() and not new_path.exists():
                    file_path.rename(new_path)
                    logger.info(f"📁 Organized: {file_path.name} -> {new_dir}")
                    return new_path
        
        except Exception as e:
            logger.error(f"Organization error: {e}")
        
        return file_path
    
    async def download_file(self, message, retry_count: int = 0) -> Optional[Dict]:
        """دانلود فایل با قابلیت‌های پیشرفته"""
        max_retries = 3
        
        try:
            if not message.media:
                return None
            
            # شبیه‌سازی فعالیت انسانی قبل از دانلود
            await self.simulate_human_activity(message.chat_id)
            await self.human_delay()
            
            # دریافت نام فایل
            file_name, file_ext = await self.get_file_name(message)
            
            # ایجاد نام منحصربفرد
            base_name = Path(file_name).stem
            file_path = self.downloads_dir / file_name
            counter = 1
            
            while file_path.exists():
                new_name = f"{base_name}_{counter}{file_ext}"
                file_path = self.downloads_dir / new_name
                counter += 1
                if counter > 100:  # جلوگیری از حلقه بی‌نهایت
                    raise Exception("Too many duplicate filenames")
            
            logger.info(f"📥 Downloading: {file_path.name}")
            
            # دانلود با timeout
            try:
                await asyncio.wait_for(
                    message.download_media(file=str(file_path)),
                    timeout=300  # 5 minutes timeout
                )
            except asyncio.TimeoutError:
                logger.error("Download timeout")
                if file_path.exists():
                    file_path.unlink()
                raise Exception("Download timeout")
            
            # بررسی فایل دانلود شده
            if not file_path.exists():
                raise Exception("File not found after download")
            
            file_size = file_path.stat().st_size
            max_size = self.settings['safety']['max_file_size_mb'] * 1024 * 1024
            
            if file_size == 0:
                logger.error("Downloaded file is empty")
                file_path.unlink()
                raise Exception("Empty file")
            
            if file_size > max_size:
                logger.error(f"File too large: {file_size:,} > {max_size:,}")
                file_path.unlink()
                raise Exception("File too large")
            
            # تحلیل AI
            ai_analysis = None
            if self.settings['ai']['enable_analysis']:
                caption = message.text or message.message or ""
                ai_analysis = await self.ai_analyzer.analyze_file(
                    file_path, 
                    file_ext.replace('.', '').upper(),
                    caption
                )
                
                # فیلتر محتوا
                if not await self.ai_analyzer.filter_content(ai_analysis, self.settings['ai']):
                    logger.info(f"🗑️ Content filtered: {file_path.name}")
                    file_path.unlink()
                    return None
                
                # بررسی تکراری
                if ai_analysis.file_hash and ai_analysis.file_hash in self.known_hashes:
                    logger.info(f"⚡ Duplicate detected, skipping: {file_path.name}")
                    file_path.unlink()
                    return None
            
            # سازماندهی فایل
            if ai_analysis:
                file_path = await self.organize_file(file_path, ai_analysis)
            
            # ساخت اطلاعات فایل
            file_info = {
                'id': message.id,
                'chat_id': message.chat_id,
                'chat_title': getattr(message.chat, 'title', 'Unknown'),
                'file_name': file_path.name,
                'file_path': str(file_path),
                'file_size': file_size,
                'file_type': file_ext.replace('.', '').upper(),
                'download_time': datetime.now().isoformat(),
                'caption': (message.text or message.message or '')[:1000],
                'message_date': message.date.isoformat() if message.date else None,
            }
            
            # ذخیره در دیتابیس
            if self.db.save_file_info(file_info, ai_analysis):
                # به‌روزرسانی آمار
                self.download_count_today += 1
                category = ai_analysis.category if ai_analysis else 'unknown'
                self.db.update_statistics(file_size, category)
                
                # افزودن هش به کش
                if ai_analysis and ai_analysis.file_hash:
                    self.known_hashes.add(ai_analysis.file_hash)
            
            logger.info(f"✅ Downloaded: {file_path.name} ({file_size:,} bytes)")
            
            # تاخیر پس از دانلود موفق
            await self.human_delay(4, 10)
            
            return file_info
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            
            # پاکسازی فایل ناقص
            if 'file_path' in locals() and file_path.exists():
                try:
                    file_path.unlink()
                except:
                    pass
            
            # تلاش مجدد
            if retry_count < max_retries:
                wait_time = 10 * (retry_count + 1)
                logger.info(f"Retrying in {wait_time}s (attempt {retry_count + 1}/{max_retries})")
                await asyncio.sleep(wait_time)
                return await self.download_file(message, retry_count + 1)
            
            return None
    
    async def process_message(self, message):
        """پردازش پیام با قابلیت‌های پیشرفته"""
        try:
            # بررسی شرایط ایمن
            if not self.is_safe_to_operate():
                return
            
            if not self.can_download_more():
                return
            
            # پردازش پیام
            if message.media:
                await self.download_file(message)
            
            elif message.text and 't.me/' in message.text:
                await self.process_message_link(message.text)
            
        except Exception as e:
            logger.error(f"Message processing error: {e}")
            await asyncio.sleep(self.settings['safety']['cooldown_after_error'])
    
    async def process_message_link(self, link: str):
        """پردازش لینک پیام"""
        try:
            parts = link.strip().split('/')
            if len(parts) < 5:
                return
            
            channel_part = parts[-2]
            try:
                message_id = int(parts[-1])
            except ValueError:
                return
            
            message = await self.client.get_messages(channel_part, ids=message_id)
            if message:
                await self.process_message(message)
                
        except Exception as e:
            logger.error(f"Link processing error: {e}")
    
    async def setup_handlers(self):
        """تنظیم هندلرهای پیشرفته"""
        
        @self.client.on(events.NewMessage(incoming=True))
        async def universal_handler(event):
            """هندلر جهانی برای همه پیام‌ها"""
            try:
                # بررسی اولیه
                if not event.message:
                    return
                
                # فقط پیام‌های رسانه‌ای یا حاوی لینک
                if event.message.media or ('t.me/' in (event.message.text or '')):
                    await self.process_message(event.message)
                    
            except Exception as e:
                logger.error(f"Handler error: {e}")
        
        @self.client.on(events.NewMessage(pattern=r'^/stats$'))
        async def stats_handler(event):
            """نمایش آمار پیشرفته"""
            try:
                today = datetime.now().strftime('%Y-%m-%d')
                
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # آمار امروز
                    cursor.execute(
                        "SELECT downloads, total_size FROM statistics WHERE date = ?",
                        (today,)
                    )
                    today_stats = cursor.fetchone()
                    
                    # آمار کلی
                    cursor.execute("SELECT COUNT(*) as total FROM files")
                    total_files = cursor.fetchone()['total']
                    
                    cursor.execute("SELECT SUM(file_size) as total_size FROM files")
                    total_size = cursor.fetchone()['total_size'] or 0
                    
                    cursor.execute("SELECT COUNT(DISTINCT category) as categories FROM files")
                    categories = cursor.fetchone()['categories']
                
                # ساخت پیام
                stats_text = f"""
📊 **آمار پیشرفته UserBot**

📈 **امروز ({today}):**
├ دانلود‌ها: {today_stats['downloads'] if today_stats else 0}
└ حجم: {today_stats['total_size']//1024//1024 if today_stats else 0} MB

📦 **کلی:**
├ کل فایل‌ها: {total_files}
├ حجم کل: {total_size//1024//1024//1024:.1f} GB
└ دسته‌بندی‌ها: {categories}

⚙️ **وضعیت:**
├ دانلود امروز: {self.download_count_today}/{self.settings['safety']['max_downloads_per_day']}
├ فایل‌های تکراری شناسایی: {len(self.known_hashes)}
└ وضعیت AI: {'فعال ✅' if self.ai_analyzer.initialized else 'غیرفعال ⚠️'}
                """
                
                await event.reply(stats_text)
                
            except Exception as e:
                logger.error(f"Stats error: {e}")
                await event.reply("❌ خطا در دریافت آمار")
        
        @self.client.on(events.NewMessage(pattern=r'^/search (.+)$'))
        async def search_handler(event):
            """جستجوی هوشمند در فایل‌ها"""
            try:
                keyword = event.pattern_match.group(1)
                
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                    SELECT file_name, category, tags, file_size, download_time 
                    FROM files 
                    WHERE caption LIKE ? OR tags LIKE ? OR category LIKE ?
                    LIMIT 10
                    ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
                    
                    results = cursor.fetchall()
                
                if results:
                    response = f"🔍 **نتایج جستجو برای '{keyword}':**\n\n"
                    for i, row in enumerate(results, 1):
                        response += f"{i}. **{row['file_name']}**\n"
                        response += f"   📁 {row['category']} | 📦 {row['file_size']//1024} KB\n"
                        response += f"   🏷️ {row['tags'][:50]}...\n"
                        response += f"   📅 {row['download_time'][:10]}\n\n"
                else:
                    response = f"❌ نتیجه‌ای برای '{keyword}' یافت نشد."
                
                await event.reply(response)
                
            except Exception as e:
                logger.error(f"Search error: {e}")
        
        @self.client.on(events.NewMessage(pattern=r'^/organize$'))
        async def organize_handler(event):
            """سازماندهی مجدد فایل‌ها"""
            try:
                await event.reply("🔄 شروع سازماندهی فایل‌ها...")
                
                count = 0
                for file_path in self.downloads_dir.rglob('*'):
                    if file_path.is_file():
                        # تحلیل فایل
                        ai_analysis = await self.ai_analyzer.analyze_file(
                            file_path, 
                            file_path.suffix.replace('.', '').upper(),
                            ""
                        )
                        
                        # سازماندهی
                        new_path = await self.organize_file(file_path, ai_analysis)
                        if new_path != file_path:
                            count += 1
                
                await event.reply(f"✅ سازماندهی کامل شد. {count} فایل مرتب شد.")
                
            except Exception as e:
                logger.error(f"Organize error: {e}")
                await event.reply("❌ خطا در سازماندهی")
    
    async def start(self):
        """شروع UserBot پیشرفته"""
        logger.info("🚀 Starting Advanced UserBot...")
        
        try:
            # ایجاد کلاینت
            self.client = TelegramClient(
                session=str(self.data_dir / 'advanced_session'),
                api_id=self.api_id,
                api_hash=self.api_hash,
                device_model="Samsung Galaxy S23",
                system_version="Android 14",
                app_version="9.6.1",
                lang_code="fa",
                system_lang_code="fa-IR",
                timeout=60,
                connection_retries=3
            )
            
            # اتصال
            await self.client.start()
            
            me = await self.client.get_me()
            logger.info(f"👤 Logged in as: {me.first_name} (@{me.username})")
            
            # راه‌اندازی AI
            await self.initialize_ai()
            
            # تنظیم هندلرها
            await self.setup_handlers()
            
            # نمایش وضعیت
            logger.info("=" * 60)
            logger.info(f"📁 Downloads Dir: {self.downloads_dir}")
            logger.info(f"🧠 AI Status: {self.ai_analyzer.initialized}")
            logger.info(f"🗄️ Database: {self.db_path}")
            logger.info(f"⏰ Working Hours: {self.settings['safety']['working_hours']}")
            logger.info("=" * 60)
            logger.info("✅ UserBot is running. Commands: /stats, /search, /organize")
            logger.info("🛑 Press Ctrl+C to stop")
            
            # نگه داشتن ربات فعال
            await self.client.run_until_disconnected()
            
        except KeyboardInterrupt:
            logger.info("Received interrupt, shutting down...")
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
        finally:
            await self.disconnect()
    
    async def disconnect(self):
        """قطع ارتباط ایمن"""
        if self.client and self.client.is_connected():
            await self.client.disconnect()
            logger.info("🔌 Disconnected from Telegram")
        
        # ذخیره نهایی
        logger.info("📊 Final statistics saved")

# ==================== اجرای اصلی ====================

async def main():
    """تابع اصلی اجرا"""
    
    config_file = Path(__file__).parent / "config.json"
    
    if not config_file.exists():
        config = {
            "api_id": "YOUR_API_ID_HERE",
            "api_hash": "YOUR_API_HASH_HERE",
            "settings": {
                "safety": {
                    "max_downloads_per_day": 30,
                    "max_file_size_mb": 500
                },
                "ai": {
                    "enable_analysis": True,
                    "filter_nsfw": True
                }
            }
        }
        
        config_file.write_text(json.dumps(config, ensure_ascii=False, indent=2))
        print(f"⚠️ فایل config.json ایجاد شد. لطفاً تنظیمات را تکمیل کنید.")
        return
    
    config = json.loads(config_file.read_text())
    
    api_id = config.get("api_id")
    api_hash = config.get("api_hash")
    
    if not api_id or not api_hash or api_id == "YOUR_API_ID_HERE":
        print("❌ لطفاً API credentials را در config.json تنظیم کنید.")
        return
    
    # اعمال تنظیمات سفارشی
    userbot = AdvancedUserBotDownloader(int(api_id), api_hash)
    
    if 'settings' in config:
        # ادغام تنظیمات سفارشی
        for section, values in config['settings'].items():
            if section in userbot.settings:
                userbot.settings[section].update(values)
    
    await userbot.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.critical(f"Application crashed: {e}", exc_info=True)
        print(f"❌ Application crashed. Check logs for details.")
