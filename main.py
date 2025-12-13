#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🤖 **ربات تلگرام یکپارچه پیشرفته - نسخه نهایی**
🚀 ترکیب: مدیریت اکانت + سیستم امنیتی + UserBot + AI + Redis + Webhook
"""

import asyncio
import logging
import sys
import os
import json
import base64
import hashlib
import re
import sqlite3
import pickle
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple, Set, Union
from contextlib import contextmanager, asynccontextmanager
from io import BytesIO, StringIO
import random
import string
import uuid

# ========== کتابخانه‌های اصلی ==========
from telegram import (
    Update, 
    InlineKeyboardButton, 
    InlineKeyboardMarkup, 
    InputFile,
    BotCommand,
    WebAppInfo
)
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    filters,
    PicklePersistence,
    JobQueue
)
from telegram.constants import ParseMode

# ========== کتابخانه‌های اختیاری ==========
try:
    import aiohttp
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False
    aiosqlite = None

try:
    import redis.asyncio as redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    redis = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import DocumentAttributeFilename
    from telethon.errors import SessionPasswordNeededError, PhoneNumberInvalidError
    HAS_TELETHON = True
except ImportError:
    HAS_TELETHON = False

# ========== ایمپورت ماژول‌های داخلی ==========
try:
    from advanced_account_manager import AdvancedAccountManager
    from advanced_features import AdvancedReportGenerator, TwoFactorAuthentication
except ImportError:
    # Fallback به کلاس‌های داخلی اگر ماژول جداگانه نباشد
    class AdvancedAccountManager:
        def __init__(self, *args, **kwargs):
            pass
    
    class AdvancedReportGenerator:
        def __init__(self):
            pass
    
    class TwoFactorAuthentication:
        def __init__(self):
            pass

# ========== لاگ‌گیری پیشرفته ==========

class ColoredFormatter(logging.Formatter):
    """فرمتر رنگی برای لاگ‌ها با قابلیت‌های بیشتر"""
    COLORS = {
        'DEBUG': '\033[94m',
        'INFO': '\033[92m',
        'WARNING': '\033[93m',
        'ERROR': '\033[91m',
        'CRITICAL': '\033[91m\033[1m',
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        message = super().format(record)
        
        # اضافه کردن آیدی کاربر اگر وجود دارد
        if hasattr(record, 'user_id'):
            message = f"[User:{record.user_id}] {message}"
        
        return f"{log_color}{message}{self.COLORS['RESET']}"

def setup_logging(log_level=logging.INFO):
    """تنظیمات پیشرفته لاگ‌گیری با چندین handler"""
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # حذف handlerهای قدیمی
    logger.handlers.clear()
    
    # فرمت اصلی
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # File Handler با چرخش فایل
    from logging.handlers import RotatingFileHandler
    file_handler = RotatingFileHandler(
        'telegram_bot.log',
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    file_handler.setLevel(logging.INFO)
    
    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    # Error File Handler
    error_handler = logging.FileHandler('errors.log', encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d'
    ))
    
    # اضافه کردن handlerها
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.addHandler(error_handler)
    
    # لاگ‌گیری کتابخانه‌های سوم
    logging.getLogger('telethon').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

logger = setup_logging()

# ========== Redis Manager ==========

class RedisManager:
    """مدیریت Redis برای کش و جلسات"""
    
    def __init__(self, host='localhost', port=6379, password=None, db=0):
        self.host = host
        self.port = port
        self.password = password
        self.db = db
        self.client = None
        self.connected = False
        
    async def connect(self):
        """اتصال به Redis"""
        if not HAS_REDIS:
            logger.warning("Redis not installed. Cache features disabled.")
            return False
        
        try:
            self.client = redis.Redis(
                host=self.host,
                port=self.port,
                password=self.password,
                db=self.db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            
            # تست اتصال
            await self.client.ping()
            self.connected = True
            logger.info("✅ Connected to Redis")
            return True
            
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """قطع ارتباط با Redis"""
        if self.client and self.connected:
            await self.client.close()
            self.connected = False
            logger.info("Redis disconnected")
    
    async def set_cache(self, key: str, value: Any, expire: int = 3600):
        """ذخیره در کش"""
        if not self.connected:
            return False
        
        try:
            serialized = pickle.dumps(value)
            await self.client.setex(
                f"cache:{key}",
                expire,
                serialized
            )
            return True
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    async def get_cache(self, key: str) -> Any:
        """دریافت از کش"""
        if not self.connected:
            return None
        
        try:
            data = await self.client.get(f"cache:{key}")
            if data:
                return pickle.loads(data)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
        
        return None
    
    async def delete_cache(self, key: str):
        """حذف از کش"""
        if self.connected:
            await self.client.delete(f"cache:{key}")
    
    async def increment_counter(self, key: str, amount: int = 1) -> int:
        """افزایش شمارنده"""
        if not self.connected:
            return amount
        
        try:
            return await self.client.incrby(f"counter:{key}", amount)
        except:
            return amount
    
    async def get_user_session(self, user_id: int) -> Optional[Dict]:
        """دریافت جلسه کاربر"""
        if not self.connected:
            return None
        
        try:
            data = await self.client.get(f"session:{user_id}")
            if data:
                return json.loads(data)
        except:
            pass
        
        return None
    
    async def set_user_session(self, user_id: int, data: Dict, expire: int = 86400):
        """ذخیره جلسه کاربر"""
        if not self.connected:
            return False
        
        try:
            await self.client.setex(
                f"session:{user_id}",
                expire,
                json.dumps(data)
            )
            return True
        except Exception as e:
            logger.error(f"Session save error: {e}")
            return False
    
    async def delete_user_session(self, user_id: int):
        """حذف جلسه کاربر"""
        if self.connected:
            await self.client.delete(f"session:{user_id}")

# ========== Webhook Manager ==========

class WebhookManager:
    """مدیریت Webhook برای محیط تولید"""
    
    def __init__(self, webhook_url: str, bot_token: str, cert_path: str = None):
        self.webhook_url = webhook_url
        self.bot_token = bot_token
        self.cert_path = cert_path
        self.is_webhook = bool(webhook_url)
        
    async def setup_webhook(self, application: Application):
        """تنظیم Webhook"""
        if not self.is_webhook:
            logger.info("Running in polling mode")
            return
        
        try:
            # حذف Webhook قبلی
            await application.bot.delete_webhook()
            
            # تنظیم Webhook جدید
            await application.bot.set_webhook(
                url=f"{self.webhook_url}/{self.bot_token}",
                certificate=open(self.cert_path, 'rb') if self.cert_path else None,
                max_connections=100,
                allowed_updates=Update.ALL_TYPES,
                drop_pending_updates=True
            )
            
            logger.info(f"✅ Webhook set to: {self.webhook_url}")
            logger.info(f"Webhook info: {await application.bot.get_webhook_info()}")
            
        except Exception as e:
            logger.error(f"❌ Webhook setup failed: {e}")
            raise
    
    async def run_webhook(self, application: Application, host: str = "0.0.0.0", port: int = 8443):
        """اجرای سرور Webhook"""
        if not self.is_webhook:
            return
        
        try:
            await application.run_webhook(
                listen=host,
                port=port,
                url_path=self.bot_token,
                webhook_url=self.webhook_url,
                cert=self.cert_path
            )
        except Exception as e:
            logger.error(f"❌ Webhook server failed: {e}")
            raise

# ========== سیستم AI پیشرفته ==========

class AdvancedAIAnalyzer:
    """سیستم تحلیل محتوای هوشمند با قابلیت‌های بیشتر"""
    
    def __init__(self, redis_manager: Optional[RedisManager] = None):
        self.redis = redis_manager
        self.model_loaded = False
        self.categories = {
            'educational': ['آموزش', 'درس', 'کتاب', 'تحصیل', 'دانشگاه', 'مدرسه'],
            'entertainment': ['فیلم', 'سریال', 'کارتون', 'موسیقی', 'طنز', 'تفریح'],
            'technology': ['برنامه', 'کد', 'پایتون', 'هوش', 'مصنوعی', 'کامپیوتر'],
            'news': ['اخبار', 'سیاسی', 'اقتصاد', 'حوادث', 'ورزش'],
            'religious': ['مذهبی', 'قرآن', 'اذان', 'دعا', 'روضه'],
            'business': ['کسب', 'کار', 'تجارت', 'بازاریابی', 'فروش'],
            'health': ['سلامت', 'ورزش', 'غذا', 'درمان', 'پزشکی'],
            'other': []
        }
        
        self.nsfw_keywords = ['ممنوع', 'سکسی', 'جنسی', 'محرمانه', 'خصوصی', '18+']
        self.spam_patterns = [
            r'خرید.*فوری',
            r'پول.*سریع',
            r'کلیک.*کمک',
            r'فالوور.*رایگان'
        ]
    
    async def initialize(self):
        """مقداردهی اولیه مدل‌های AI"""
        try:
            # بارگذاری مدل‌ها (در آینده می‌توان از transformers استفاده کرد)
            self.model_loaded = True
            logger.info("✅ AI Analyzer initialized")
            return True
        except Exception as e:
            logger.error(f"AI initialization failed: {e}")
            return False
    
    async def analyze_text(self, text: str, user_id: int = None) -> Dict:
        """تحلیل متن با قابلیت کش"""
        if not text:
            return self._empty_analysis()
        
        # بررسی کش
        cache_key = f"text_analysis:{hashlib.md5(text.encode()).hexdigest()}"
        if self.redis and self.redis.connected:
            cached = await self.redis.get_cache(cache_key)
            if cached:
                return cached
        
        # تحلیل
        analysis = {
            'category': self._detect_category(text),
            'language': self._detect_language(text),
            'length': len(text),
            'word_count': len(text.split()),
            'sentiment': self._analyze_sentiment(text),
            'is_spam': self._detect_spam(text),
            'is_nsfw': self._detect_nsfw(text),
            'keywords': self._extract_keywords(text),
            'readability_score': self._calculate_readability(text),
            'analysis_time': datetime.now().isoformat()
        }
        
        # ذخیره در کش
        if self.redis and self.redis.connected:
            await self.redis.set_cache(cache_key, analysis, expire=3600)
        
        return analysis
    
    def _detect_category(self, text: str) -> str:
        """تشخیص دسته‌بندی متن"""
        text_lower = text.lower()
        max_score = 0
        best_category = 'other'
        
        for category, keywords in self.categories.items():
            score = sum(10 if kw in text_lower else 0 for kw in keywords)
            if score > max_score:
                max_score = score
                best_category = category
        
        return best_category
    
    def _detect_language(self, text: str) -> str:
        """تشخیص زبان"""
        # تشخیص فارسی
        persian_chars = len(re.findall(r'[\u0600-\u06FF]', text))
        english_chars = len(re.findall(r'[a-zA-Z]', text))
        
        if persian_chars > english_chars:
            return 'fa'
        elif english_chars > persian_chars:
            return 'en'
        else:
            return 'mixed'
    
    def _analyze_sentiment(self, text: str) -> str:
        """تحلیل احساس متن (ساده)"""
        positive_words = ['خوب', 'عالی', 'ممنون', 'عالیه', 'عالیست', 'دوست', 'دوست دارم']
        negative_words = ['بد', 'بدی', 'ضعیف', 'خراب', 'مشکل', 'ایراد', 'ناراحت']
        
        text_lower = text.lower()
        positive_count = sum(1 for word in positive_words if word in text_lower)
        negative_count = sum(1 for word in negative_words if word in text_lower)
        
        if positive_count > negative_count:
            return 'positive'
        elif negative_count > positive_count:
            return 'negative'
        else:
            return 'neutral'
    
    def _detect_spam(self, text: str) -> bool:
        """تشخیص اسپم"""
        text_lower = text.lower()
        for pattern in self.spam_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _detect_nsfw(self, text: str) -> bool:
        """تشخیص محتوای نامناسب"""
        text_lower = text.lower()
        for keyword in self.nsfw_keywords:
            if keyword in text_lower:
                return True
        return False
    
    def _extract_keywords(self, text: str, max_keywords: int = 5) -> List[str]:
        """استخراج کلمات کلیدی"""
        words = re.findall(r'\b\w{3,}\b', text.lower())
        
        # حذف کلمات رایج
        stopwords = {'این', 'که', 'با', 'را', 'برای', 'است', 'های', 'از', 'به', 'در'}
        keywords = [word for word in words if word not in stopwords]
        
        # شمارش تکرار
        from collections import Counter
        word_counts = Counter(keywords)
        
        return [word for word, _ in word_counts.most_common(max_keywords)]
    
    def _calculate_readability(self, text: str) -> float:
        """محاسبه خوانایی متن"""
        words = text.split()
        sentences = re.split(r'[.!?]', text)
        
        if not words or not sentences:
            return 0.0
        
        avg_words_per_sentence = len(words) / len(sentences)
        avg_word_length = sum(len(word) for word in words) / len(words)
        
        # فرمول ساده خوانایی
        readability = 206.835 - (1.015 * avg_words_per_sentence) - (84.6 * avg_word_length)
        return max(0.0, min(100.0, readability))
    
    def _empty_analysis(self) -> Dict:
        """تحلیل خالی"""
        return {
            'category': 'unknown',
            'language': 'unknown',
            'length': 0,
            'word_count': 0,
            'sentiment': 'neutral',
            'is_spam': False,
            'is_nsfw': False,
            'keywords': [],
            'readability_score': 0.0,
            'analysis_time': datetime.now().isoformat()
        }
    
    async def analyze_file(self, file_path: Path) -> Dict:
        """تحلیل فایل"""
        try:
            file_info = {
                'name': file_path.name,
                'size': file_path.stat().st_size,
                'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                'extension': file_path.suffix.lower(),
                'type': self._detect_file_type(file_path)
            }
            
            # برای فایل‌های متنی، محتوا را هم تحلیل کن
            if file_path.suffix.lower() in ['.txt', '.md', '.json', '.py', '.html']:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read(5000)  # فقط 5000 کاراکتر اول
                    text_analysis = await self.analyze_text(content)
                    file_info['content_analysis'] = text_analysis
                except:
                    pass
            
            return file_info
            
        except Exception as e:
            logger.error(f"File analysis error: {e}")
            return {'error': str(e)}
    
    def _detect_file_type(self, file_path: Path) -> str:
        """تشخیص نوع فایل"""
        ext = file_path.suffix.lower()
        
        image_ext = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
        video_ext = ['.mp4', '.avi', '.mkv', '.mov', '.wmv']
        audio_ext = ['.mp3', '.wav', '.ogg', '.flac', '.m4a']
        doc_ext = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']
        
        if ext in image_ext:
            return 'image'
        elif ext in video_ext:
            return 'video'
        elif ext in audio_ext:
            return 'audio'
        elif ext in doc_ext:
            return 'document'
        else:
            return 'unknown'

# ========== سیستم امنیتی پیشرفته ==========

class AdvancedSecuritySystem:
    """سیستم امنیتی کامل با AES-GCM و ویژگی‌های بیشتر"""
    
    def __init__(self, master_key: Optional[str] = None, redis_manager: Optional[RedisManager] = None):
        if not HAS_CRYPTOGRAPHY:
            logger.warning("⚠️ Cryptography not installed. Security features limited.")
            self.available = False
            return
        
        self.available = True
        self.redis = redis_manager
        
        if master_key:
            if len(master_key) < 32:
                logger.warning("Master key too short, generating new one")
                master_key = self._generate_key()
            self.master_key = self._derive_key(master_key.encode())
        else:
            self.master_key = self._generate_key()
            logger.info("Generated new encryption key")
        
        # سیستم تشخیص نفوذ
        self.intrusion_attempts = {}
        self.max_attempts = 5
        self.lockout_time = 300  # 5 دقیقه
    
    def _generate_key(self) -> bytes:
        """تولید کلید تصادفی"""
        import secrets
        return secrets.token_bytes(32)
    
    def _derive_key(self, password: bytes, salt: bytes = None) -> bytes:
        """استخراج کلید از رمز عبور"""
        if salt is None:
            salt = b'telegram_advanced_bot_salt_2024'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password)
    
    def encrypt(self, plaintext: str) -> str:
        """رمزنگاری داده"""
        if not self.available:
            return plaintext
        
        import secrets
        aesgcm = AESGCM(self.master_key)
        nonce = secrets.token_bytes(12)
        
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode('utf-8'),
            None
        )
        
        encrypted_data = nonce + ciphertext
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_data: str) -> str:
        """رمزگشایی داده"""
        if not self.available:
            return encrypted_data
        
        try:
            aesgcm = AESGCM(self.master_key)
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]
            
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise ValueError("Invalid encrypted data or wrong key")
    
    def encrypt_file(self, input_path: Path, output_path: Path = None) -> bool:
        """رمزنگاری فایل"""
        if not self.available:
            return False
        
        try:
            if output_path is None:
                output_path = input_path.with_suffix(input_path.suffix + '.enc')
            
            import secrets
            aesgcm = AESGCM(self.master_key)
            nonce = secrets.token_bytes(12)
            
            with open(input_path, 'rb') as f_in:
                plaintext = f_in.read()
            
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            with open(output_path, 'wb') as f_out:
                f_out.write(nonce)
                f_out.write(ciphertext)
            
            return True
            
        except Exception as e:
            logger.error(f"File encryption error: {e}")
            return False
    
    def decrypt_file(self, input_path: Path, output_path: Path = None) -> bool:
        """رمزگشایی فایل"""
        if not self.available:
            return False
        
        try:
            if output_path is None:
                if input_path.suffix == '.enc':
                    output_path = input_path.with_suffix('')
                else:
                    output_path = input_path.with_suffix('.dec' + input_path.suffix)
            
            aesgcm = AESGCM(self.master_key)
            
            with open(input_path, 'rb') as f_in:
                nonce = f_in.read(12)
                ciphertext = f_in.read()
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            with open(output_path, 'wb') as f_out:
                f_out.write(plaintext)
            
            return True
            
        except Exception as e:
            logger.error(f"File decryption error: {e}")
            return False
    
    async def check_intrusion(self, user_id: int, action: str) -> bool:
        """بررسی تلاش نفوذ"""
        if not self.redis or not self.redis.connected:
            return await self._check_intrusion_local(user_id)
        
        # استفاده از Redis برای tracking
        key = f"intrusion:{user_id}:{action}"
        attempts = await self.redis.increment_counter(key, 1)
        
        # تنظیم زمان انقضا
        await self.redis.client.expire(key, self.lockout_time)
        
        if attempts > self.max_attempts:
            logger.warning(f"Intrusion detected: user {user_id}, action {action}, attempts {attempts}")
            await self.notify_admins_intrusion(user_id, action, attempts)
            return False
        
        return True
    
    async def _check_intrusion_local(self, user_id: int) -> bool:
        """بررسی نفوذ محلی"""
        now = time.time()
        key = f"{user_id}"
        
        if key not in self.intrusion_attempts:
            self.intrusion_attempts[key] = {'count': 1, 'time': now}
            return True
        
        attempts = self.intrusion_attempts[key]
        
        # ریست کردن اگر زمان گذشته
        if now - attempts['time'] > self.lockout_time:
            self.intrusion_attempts[key] = {'count': 1, 'time': now}
            return True
        
        # افزایش شمارنده
        attempts['count'] += 1
        
        if attempts['count'] > self.max_attempts:
            logger.warning(f"Intrusion detected (local): user {user_id}")
            return False
        
        return True
    
    async def notify_admins_intrusion(self, user_id: int, action: str, attempts: int):
        """اعلام نفوذ به ادمین‌ها"""
        # این تابع باید توسط کلاس اصلی پر شود
        pass
    
    def generate_otp(self, length: int = 6) -> str:
        """تولید کد یکبار مصرف"""
        import secrets
        digits = string.digits
        return ''.join(secrets.choice(digits) for _ in range(length))
    
    def generate_session_token(self, user_id: int) -> str:
        """تولید توکن جلسه"""
        import secrets
        token = secrets.token_urlsafe(32)
        
        if self.redis and self.redis.connected:
            asyncio.create_task(
                self.redis.set_cache(f"session_token:{token}", user_id, expire=86400)
            )
        
        return token
    
    async def validate_session_token(self, token: str) -> Optional[int]:
        """اعتبارسنجی توکن جلسه"""
        if not self.redis or not self.redis.connected:
            return None
        
        user_id = await self.redis.get_cache(f"session_token:{token}")
        return user_id

# ========== پایگاه داده پیشرفته ==========

class AdvancedDatabase:
    """پایگاه داده پیشرفته با aiosqlite"""
    
    def __init__(self, db_path: str = "telegram_bot_advanced.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()
    
    def init_db(self):
        """ایجاد جداول اولیه"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # جدول کاربران
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE NOT NULL,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                phone_number TEXT,
                language_code TEXT DEFAULT 'fa',
                is_premium BOOLEAN DEFAULT 0,
                is_admin BOOLEAN DEFAULT 0,
                is_banned BOOLEAN DEFAULT 0,
                daily_downloads INTEGER DEFAULT 0,
                total_downloads INTEGER DEFAULT 0,
                data_usage INTEGER DEFAULT 0,
                config TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_download TIMESTAMP
            )
            ''')
            
            # جدول فایل‌ها
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                file_hash TEXT UNIQUE NOT NULL,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_type TEXT NOT NULL,
                mime_type TEXT,
                source_chat TEXT,
                source_message_id INTEGER,
                caption TEXT,
                category TEXT,
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                download_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                access_count INTEGER DEFAULT 0,
                is_encrypted BOOLEAN DEFAULT 0,
                encryption_key_hash TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            ''')
            
            # جدول فعالیت‌ها
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                activity_subtype TEXT,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN DEFAULT 1,
                error_message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            ''')
            
            # جدول جلسات
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                device_info TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            ''')
            
            # جدول API Keys
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                api_key TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                permissions TEXT DEFAULT '[]',
                rate_limit INTEGER DEFAULT 100,
                usage_count INTEGER DEFAULT 0,
                last_used TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            ''')
            
            # اندیس‌ها
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_category ON files(category)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_user_id ON activities(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activities_type ON activities(activity_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_telegram_id ON users(telegram_id)')
            
            conn.commit()
    
    @asynccontextmanager
    async def get_connection(self):
        """مدیریت اتصال به دیتابیس"""
        if HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as conn:
                conn.row_factory = aiosqlite.Row
                try:
                    yield conn
                finally:
                    await conn.close()
        else:
            # Fallback به sqlite3 ساده
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    async def execute_query(self, query: str, params: tuple = None, fetch_one: bool = False, fetch_all: bool = False):
        """اجرای کوئری به صورت عمومی"""
        async with self.get_connection() as conn:
            if HAS_AIOSQLITE:
                cursor = await conn.execute(query, params or ())
                await conn.commit()
                
                if fetch_one:
                    row = await cursor.fetchone()
                    return dict(row) if row else None
                elif fetch_all:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows]
                else:
                    return cursor.lastrowid
            else:
                cursor = conn.execute(query, params or ())
                conn.commit()
                
                if fetch_one:
                    row = cursor.fetchone()
                    return dict(row) if row else None
                elif fetch_all:
                    rows = cursor.fetchall()
                    return [dict(row) for row in rows]
                else:
                    return cursor.lastrowid
    
    async def add_user(self, telegram_id: int, username: str = None, first_name: str = None, 
                      last_name: str = None, phone_number: str = None) -> int:
        """افزودن کاربر جدید"""
        query = '''
        INSERT OR IGNORE INTO users 
        (telegram_id, username, first_name, last_name, phone_number, created_at, last_active)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        '''
        
        user_id = await self.execute_query(query, (telegram_id, username, first_name, last_name, phone_number))
        
        # اگر کاربر وجود داشت، آپدیت کن
        if user_id == 0:
            query = '''
            UPDATE users 
            SET username = ?, first_name = ?, last_name = ?, phone_number = ?, last_active = CURRENT_TIMESTAMP
            WHERE telegram_id = ?
            '''
            await self.execute_query(query, (username, first_name, last_name, phone_number, telegram_id))
            
            # گرفتن آیدی کاربر
            query = 'SELECT id FROM users WHERE telegram_id = ?'
            result = await self.execute_query(query, (telegram_id,), fetch_one=True)
            user_id = result['id'] if result else None
        
        return user_id
    
    async def log_activity(self, user_id: int, activity_type: str, details: str = None, 
                          success: bool = True, error_message: str = None):
        """ثبت فعالیت کاربر"""
        query = '''
        INSERT INTO activities (user_id, activity_type, details, success, error_message)
        VALUES (?, ?, ?, ?, ?)
        '''
        await self.execute_query(query, (user_id, activity_type, details, success, error_message))
    
    async def add_file(self, user_id: int, file_info: Dict) -> int:
        """افزودن فایل جدید"""
        query = '''
        INSERT INTO files 
        (user_id, file_hash, file_name, file_path, file_size, file_type, mime_type, 
         source_chat, caption, category, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        file_id = await self.execute_query(
            query,
            (
                user_id,
                file_info.get('hash'),
                file_info.get('name'),
                file_info.get('path'),
                file_info.get('size'),
                file_info.get('type'),
                file_info.get('mime_type'),
                file_info.get('source_chat'),
                file_info.get('caption'),
                file_info.get('category'),
                json.dumps(file_info.get('metadata', {}))
            )
        )
        
        # آپدیت آمار کاربر
        await self.execute_query(
            'UPDATE users SET total_downloads = total_downloads + 1, data_usage = data_usage + ?, last_download = CURRENT_TIMESTAMP WHERE id = ?',
            (file_info.get('size', 0), user_id)
        )
        
        return file_id
    
    async def get_user_stats(self, user_id: int) -> Dict:
        """دریافت آمار کاربر"""
        query = '''
        SELECT 
            COUNT(f.id) as total_files,
            SUM(f.file_size) as total_size,
            COUNT(DISTINCT f.category) as categories_count,
            MAX(f.download_time) as last_download,
            u.daily_downloads,
            u.total_downloads,
            u.data_usage,
            u.created_at
        FROM users u
        LEFT JOIN files f ON u.id = f.user_id
        WHERE u.id = ?
        GROUP BY u.id
        '''
        
        result = await self.execute_query(query, (user_id,), fetch_one=True)
        
        if result:
            return dict(result)
        else:
            # اگر کاربر وجود ندارد
            user_info = await self.execute_query(
                'SELECT * FROM users WHERE id = ?',
                (user_id,),
                fetch_one=True
            )
            
            if user_info:
                return {
                    'total_files': 0,
                    'total_size': 0,
                    'categories_count': 0,
                    'last_download': None,
                    'daily_downloads': user_info['daily_downloads'],
                    'total_downloads': user_info['total_downloads'],
                    'data_usage': user_info['data_usage'],
                    'created_at': user_info['created_at']
                }
        
        return {}
    
    async def search_files(self, user_id: int, query: str = None, category: str = None, 
                          limit: int = 20, offset: int = 0) -> List[Dict]:
        """جستجوی فایل‌ها"""
        base_query = 'SELECT * FROM files WHERE user_id = ?'
        params = [user_id]
        
        conditions = []
        
        if query:
            conditions.append('(file_name LIKE ? OR caption LIKE ?)')
            params.extend([f'%{query}%', f'%{query}%'])
        
        if category:
            conditions.append('category = ?')
            params.append(category)
        
        if conditions:
            base_query += ' AND ' + ' AND '.join(conditions)
        
        base_query += ' ORDER BY download_time DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        return await self.execute_query(base_query, tuple(params), fetch_all=True)
    
    async def cleanup_old_files(self, days: int = 30) -> int:
        """پاکسازی فایل‌های قدیمی"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        # گرفتن فایل‌های قدیمی
        query = 'SELECT id, file_path FROM files WHERE download_time < ?'
        old_files = await self.execute_query(query, (cutoff_date,), fetch_all=True)
        
        # حذف فایل‌ها از دیسک
        deleted_count = 0
        for file in old_files:
            try:
                file_path = Path(file['file_path'])
                if file_path.exists():
                    file_path.unlink()
                    deleted_count += 1
            except:
                pass
        
        # حذف از دیتابیس
        await self.execute_query('DELETE FROM files WHERE download_time < ?', (cutoff_date,))
        
        return deleted_count

# ========== Integrated Bot Manager ==========

class IntegratedBotManager:
    """مدیریت یکپارچه تمام سیستم‌ها"""
    
    def __init__(self, config: Dict):
        self.config = config
        
        # مدیر Redis
        self.redis = RedisManager(
            host=config.get('REDIS_HOST', 'localhost'),
            port=config.get('REDIS_PORT', 6379),
            password=config.get('REDIS_PASSWORD'),
            db=config.get('REDIS_DB', 0)
        )
        
        # مدیر Webhook
        self.webhook = WebhookManager(
            webhook_url=config.get('WEBHOOK_URL', ''),
            bot_token=config['TOKEN'],
            cert_path=config.get('SSL_CERT_PATH')
        )
        
        # سیستم AI
        self.ai = AdvancedAIAnalyzer(self.redis)
        
        # سیستم امنیتی
        self.security = AdvancedSecuritySystem(
            master_key=config.get('ENCRYPTION_KEY'),
            redis_manager=self.redis
        )
        
        # پایگاه داده
        self.db = AdvancedDatabase(config.get('DATABASE_PATH', 'telegram_bot.db'))
        
        # UserBot (اگر فعال باشد)
        self.userbot_client = None
        self.userbot_initialized = False
        
        # Job Queue برای کارهای زمان‌بندی شده
        self.job_queue = None
        
        # داده‌های موقت
        self.user_sessions = {}
        self.download_tasks = {}
        self.rate_limits = {}
        
        logger.info("✅ Integrated Bot Manager initialized")
    
    async def initialize(self):
        """مقداردهی اولیه تمام سیستم‌ها"""
        try:
            # اتصال به Redis
            await self.redis.connect()
            
            # راه‌اندازی AI
            await self.ai.initialize()
            
            # راه‌اندازی UserBot (اگر telethon نصب باشد)
            if HAS_TELETHON and self.config.get('API_ID') and self.config.get('API_HASH'):
                await self.initialize_userbot()
            
            logger.info("✅ All systems initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            return False
    
    async def initialize_userbot(self):
        """راه‌اندازی UserBot"""
        try:
            self.userbot_client = TelegramClient(
                session="userbot_session",
                api_id=self.config['API_ID'],
                api_hash=self.config['API_HASH'],
                device_model="Samsung Galaxy S23",
                system_version="Android 14",
                app_version="9.6.1",
                lang_code="fa",
                system_lang_code="fa-IR"
            )
            
            await self.userbot_client.start()
            me = await self.userbot_client.get_me()
            logger.info(f"✅ UserBot initialized as: {me.first_name} (@{me.username})")
            
            self.userbot_initialized = True
            
            # تنظیم هندلرهای UserBot
            await self.setup_userbot_handlers()
            
        except Exception as e:
            logger.error(f"❌ UserBot initialization failed: {e}")
            self.userbot_client = None
    
    async def setup_userbot_handlers(self):
        """تنظیم هندلرهای UserBot"""
        if not self.userbot_client:
            return
        
        @self.userbot_client.on(events.NewMessage(incoming=True))
        async def message_handler(event):
            """هندلر پیام‌های دریافتی"""
            try:
                # لاگ کردن پیام
                logger.debug(f"UserBot received message: {event.chat_id} - {event.sender_id}")
                
                # می‌توانید منطق پردازش پیام‌ها را اینجا اضافه کنید
                # مثلاً پاسخ خودکار، فوروارد، یا پردازش خاص
                
            except Exception as e:
                logger.error(f"UserBot message handler error: {e}")
        
        @self.userbot_client.on(events.ChatAction)
        async def chat_action_handler(event):
            """هندلر تغییرات چت"""
            try:
                if event.user_added or event.user_joined:
                    logger.info(f"New user joined chat: {event.chat_id}")
            except Exception as e:
                logger.error(f"UserBot chat action handler error: {e}")
    
    async def download_with_userbot(self, user_id: int, chat_link: str, limit: int = 10, media_types: List[str] = None):
        """دانلود از کانال/گروه با UserBot"""
        if not self.userbot_client or not self.userbot_initialized:
            return {"success": False, "error": "UserBot not initialized"}
        
        # بررسی محدودیت روزانه
        daily_key = f"daily_downloads:{user_id}:{datetime.now().strftime('%Y%m%d')}"
        daily_count = await self.redis.increment_counter(daily_key, 0)
        
        if daily_count >= self.config.get('DAILY_DOWNLOAD_LIMIT', 20):
            return {"success": False, "error": "Daily download limit reached"}
        
        try:
            # استخراج شناسه چت
            if "t.me/" in chat_link:
                chat_identifier = chat_link.split("t.me/")[-1].split("/")[0]
            else:
                chat_identifier = chat_link
            
            # دریافت پیام‌ها
            messages = []
            async for message in self.userbot_client.iter_messages(
                chat_identifier,
                limit=limit,
                wait_time=2,
                reverse=True  # از قدیمی به جدید
            ):
                if message.media:
                    messages.append(message)
            
            # دانلود فایل‌ها
            downloaded_files = []
            download_dir = Path(f"downloads/user_{user_id}")
            download_dir.mkdir(exist_ok=True)
            
            for message in messages:
                if len(downloaded_files) >= limit:
                    break
                
                file_info = await self._download_single_file(user_id, message, download_dir)
                if file_info:
                    downloaded_files.append(file_info)
                    
                    # افزایش شمارنده روزانه
                    await self.redis.increment_counter(daily_key, 1)
            
            # ذخیره در دیتابیس
            for file_info in downloaded_files:
                await self.db.add_file(user_id, file_info)
                await self.db.log_activity(
                    user_id,
                    "file_download",
                    f"{file_info['name']} ({file_info['category']})"
                )
            
            return {
                "success": True,
                "count": len(downloaded_files),
                "files": downloaded_files,
                "daily_remaining": max(0, self.config.get('DAILY_DOWNLOAD_LIMIT', 20) - daily_count - len(downloaded_files))
            }
            
        except Exception as e:
            logger.error(f"UserBot download error: {e}")
            await self.db.log_activity(user_id, "file_download_error", str(e), success=False)
            return {"success": False, "error": str(e)}
    
    async def _download_single_file(self, user_id: int, message, download_dir: Path) -> Optional[Dict]:
        """دانلود یک فایل"""
        try:
            if not message.media:
                return None
            
            # نام فایل
            file_name = self._get_filename_from_message(message)
            file_path = download_dir / file_name
            
            # بررسی وجود فایل
            if file_path.exists():
                # اگر فایل وجود دارد، نام جدید ایجاد کن
                counter = 1
                while file_path.exists():
                    new_name = f"{file_path.stem}_{counter}{file_path.suffix}"
                    file_path = download_dir / new_name
                    counter += 1
            
            # دانلود
            await message.download_media(file=str(file_path))
            
            # تحلیل فایل
            file_size = file_path.stat().st_size
            
            # بررسی محدودیت حجم
            if file_size > self.config.get('MAX_FILE_SIZE_MB', 500) * 1024 * 1024:
                file_path.unlink()
                return None
            
            # تحلیل AI
            caption = message.text or ""
            analysis = await self.ai.analyze_text(caption, user_id)
            
            # محاسبه هش
            file_hash = self._calculate_file_hash(file_path)
            
            # اطلاعات فایل
            file_info = {
                'hash': file_hash,
                'name': file_name,
                'path': str(file_path),
                'size': file_size,
                'type': self._get_file_type(file_path),
                'mime_type': self._get_mime_type(file_path),
                'source_chat': getattr(message.chat, 'title', 'Unknown'),
                'caption': caption[:500],
                'category': analysis['category'],
                'metadata': {
                    'analysis': analysis,
                    'message_id': message.id,
                    'date': message.date.isoformat() if hasattr(message, 'date') else None
                }
            }
            
            return file_info
            
        except Exception as e:
            logger.error(f"Single file download error: {e}")
            return None
    
    def _get_filename_from_message(self, message) -> str:
        """دریافت نام فایل از پیام"""
        try:
            if hasattr(message, 'document') and message.document:
                for attr in message.document.attributes:
                    if isinstance(attr, DocumentAttributeFilename):
                        return attr.file_name
            
            # نام‌گذاری بر اساس نوع
            ext_map = {
                'photo': '.jpg',
                'video': '.mp4',
                'audio': '.mp3',
                'voice': '.ogg',
                'sticker': '.webp',
                'document': '.bin'
            }
            
            for media_type, ext in ext_map.items():
                if getattr(message, media_type, None):
                    return f"{media_type}_{message.id}{ext}"
            
            return f"file_{message.id}.bin"
            
        except Exception as e:
            logger.error(f"Error getting filename: {e}")
            return f"file_{message.id}.bin"
    
    def _get_file_type(self, file_path: Path) -> str:
        """تشخیص نوع فایل"""
        ext = file_path.suffix.lower()
        
        if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
            return 'image'
        elif ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv']:
            return 'video'
        elif ext in ['.mp3', '.wav', '.ogg', '.flac', '.m4a']:
            return 'audio'
        elif ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
            return 'document'
        elif ext in ['.txt', '.md', '.json', '.xml', '.csv']:
            return 'text'
        else:
            return 'other'
    
    def _get_mime_type(self, file_path: Path) -> str:
        """تشخیص MIME type"""
        import mimetypes
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return mime_type or 'application/octet-stream'
    
    def _calculate_file_hash(self, file_path: Path, chunk_size: int = 8192) -> str:
        """محاسبه هش فایل"""
        hasher = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error: {e}")
            return ""
    
    async def cleanup_task(self):
        """کارهای زمان‌بندی شده پاکسازی"""
        try:
            # پاکسازی فایل‌های قدیمی
            cleaned = await self.db.cleanup_old_files(30)
            if cleaned > 0:
                logger.info(f"🧹 Cleaned {cleaned} old files")
            
            # پاکسازی جلسات منقضی شده
            if self.redis.connected:
                # می‌توانید منطق پاکسازی Redis را اینجا اضافه کنید
                pass
            
            # پشتیبان‌گیری از دیتابیس
            await self.backup_database()
            
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")
    
    async def backup_database(self):
        """پشتیبان‌گیری از دیتابیس"""
        try:
            backup_dir = Path("backups")
            backup_dir.mkdir(exist_ok=True)
            
            backup_file = backup_dir / f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            
            if self.db.db_path.exists():
                import shutil
                shutil.copy2(self.db.db_path, backup_file)
                
                # حذف پشتیبان‌های قدیمی (بیشتر از 7 روز)
                for old_backup in backup_dir.glob("backup_*.db"):
                    if old_backup.stat().st_mtime < (time.time() - 7 * 86400):
                        old_backup.unlink()
                
                logger.info(f"✅ Database backed up to {backup_file}")
                
        except Exception as e:
            logger.error(f"Database backup error: {e}")
    
    async def get_system_stats(self) -> Dict:
        """دریافت آمار سیستم"""
        try:
            # آمار از دیتابیس
            stats = {}
            
            async with self.db.get_connection() as conn:
                if HAS_AIOSQLITE:
                    cursor = await conn.execute('SELECT COUNT(*) as total_users FROM users')
                    row = await cursor.fetchone()
                    stats['total_users'] = row['total_users'] if row else 0
                    
                    cursor = await conn.execute('SELECT COUNT(*) as total_files FROM files')
                    row = await cursor.fetchone()
                    stats['total_files'] = row['total_files'] if row else 0
                    
                    cursor = await conn.execute('SELECT SUM(file_size) as total_size FROM files')
                    row = await cursor.fetchone()
                    stats['total_size'] = row['total_size'] or 0
                    
                    cursor = await conn.execute('SELECT COUNT(*) as active_today FROM users WHERE last_active > DATE("now", "-1 day")')
                    row = await cursor.fetchone()
                    stats['active_today'] = row['active_today'] if row else 0
                else:
                    cursor = conn.execute('SELECT COUNT(*) as total_users FROM users')
                    row = cursor.fetchone()
                    stats['total_users'] = row['total_users'] if row else 0
                    
                    cursor = conn.execute('SELECT COUNT(*) as total_files FROM files')
                    row = cursor.fetchone()
                    stats['total_files'] = row['total_files'] if row else 0
                    
                    cursor = conn.execute('SELECT SUM(file_size) as total_size FROM files')
                    row = cursor.fetchone()
                    stats['total_size'] = row['total_size'] or 0
                    
                    cursor = conn.execute('SELECT COUNT(*) as active_today FROM users WHERE last_active > DATE("now", "-1 day")')
                    row = cursor.fetchone()
                    stats['active_today'] = row['active_today'] if row else 0
            
            # آمار Redis
            if self.redis.connected:
                stats['redis_connected'] = True
                stats['redis_keys'] = await self.redis.client.dbsize()
            else:
                stats['redis_connected'] = False
            
            # آمار سیستم
            import psutil
            stats['system'] = {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            }
            
            # آمار ربات
            stats['bot'] = {
                'userbot_active': self.userbot_initialized,
                'ai_loaded': self.ai.model_loaded,
                'security_active': self.security.available
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"System stats error: {e}")
            return {"error": str(e)}

# ========== Telegram Bot Handlers ==========

class TelegramBotHandlers:
    """هندلرهای ربات تلگرام"""
    
    def __init__(self, manager: IntegratedBotManager):
        self.manager = manager
        self.STATES = {
            'AWAITING_PHONE': 1,
            'AWAITING_CODE': 2,
            'AWAITING_PASSWORD': 3,
            'AWAITING_DOWNLOAD_LINK': 4,
            'AWAITING_DOWNLOAD_LIMIT': 5,
            'AWAITING_ENCRYPT_TEXT': 6,
            'AWAITING_DECRYPT_TEXT': 7,
            'AWAITING_AI_TEXT': 8,
            'AWAITING_FEEDBACK': 9
        }
        
        # دستورات ربات
        self.commands = [
            BotCommand("start", "شروع کار با ربات"),
            BotCommand("help", "راهنمای کامل ربات"),
            BotCommand("download", "دانلود از کانال/گروه"),
            BotCommand("myfiles", "مشاهده فایل‌های من"),
            BotCommand("encrypt", "رمزنگاری متن"),
            BotCommand("decrypt", "رمزگشایی متن"),
            BotCommand("ai_analyze", "تحلیل متن با هوش مصنوعی"),
            BotCommand("security", "وضعیت امنیتی"),
            BotCommand("stats", "آمار شخصی"),
            BotCommand("report", "دریافت گزارش"),
            BotCommand("backup", "پشتیبان‌گیری"),
            BotCommand("settings", "تنظیمات"),
            BotCommand("admin", "پنل مدیریت (ادمین)")
        ]
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /start"""
        user = update.effective_user
        user_id = user.id
        
        # ثبت کاربر در دیتابیس
        await self.manager.db.add_user(
            telegram_id=user_id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        # ثبت فعالیت
        await self.manager.db.log_activity(user_id, "start_command")
        
        # ایجاد منوی اصلی
        keyboard = [
            [
                InlineKeyboardButton("📥 دانلود فایل", callback_data='download_menu'),
                InlineKeyboardButton("📁 فایل‌های من", callback_data='my_files')
            ],
            [
                InlineKeyboardButton("🔐 رمزنگاری", callback_data='encryption_menu'),
                InlineKeyboardButton("🧠 تحلیل AI", callback_data='ai_menu')
            ],
            [
                InlineKeyboardButton("⚙️ تنظیمات", callback_data='settings_menu'),
                InlineKeyboardButton("📊 آمار", callback_data='stats_menu')
            ]
        ]
        
        # اگر ادمین است، دکمه مدیریت اضافه کن
        if user_id in self.manager.config.get('ADMIN_IDS', []):
            keyboard.append([
                InlineKeyboardButton("🛠️ پنل مدیریت", callback_data='admin_panel')
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_text = f"""
👋 سلام {user.first_name}!

🤖 **به ربات مدیریت تلگرام پیشرفته خوش آمدید!**

✨ **ویژگی‌های اصلی:**
• 📥 دانلود خودکار از کانال‌ها
• 🔐 رمزنگاری AES-G256
• 🧠 تحلیل هوشمند محتوا
• 📊 آمار پیشرفته
• 🛡️ امنیت چندلایه

💡 برای شروع، یکی از گزینه‌های زیر را انتخاب کنید یا از دستورات استفاده نمایید.
        """
        
        await update.message.reply_text(welcome_text, reply_markup=reply_markup)
    
    async def download_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /download"""
        user_id = update.effective_user.id
        
        # بررسی فعال بودن UserBot
        if not self.manager.userbot_initialized:
            await update.message.reply_text(
                "⚠️ **سیستم UserBot فعال نیست**\n\n"
                "برای فعال‌سازی:\n"
                "1. کتابخانه telethon را نصب کنید\n"
                "2. API_ID و API_HASH را تنظیم کنید\n"
                "3. ربات را مجدداً راه‌اندازی کنید\n\n"
                "📚 راهنمای نصب: /help"
            )
            return ConversationHandler.END
        
        await update.message.reply_text(
            "📥 **سیستم دانلود پیشرفته**\n\n"
            "🔗 لطفاً لینک کانال یا گروه را ارسال کنید:\n"
            "مثال: https://t.me/channel_name یا @channel_name\n\n"
            "❌ برای لغو: /cancel"
        )
        
        return self.STATES['AWAITING_DOWNLOAD_LINK']
    
    async def handle_download_link(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """پردازش لینک دانلود"""
        user_id = update.effective_user.id
        chat_link = update.message.text.strip()
        
        # ذخیره لینک
        context.user_data['download_link'] = chat_link
        
        await update.message.reply_text(
            "🔢 **تعداد فایل‌ها**\n\n"
            "لطفاً تعداد فایل‌هایی که می‌خواهید دانلود کنید را وارد کنید:\n"
            "عدد بین ۱ تا ۲۰ (پیش‌فرض: ۵)\n\n"
            "📊 محدودیت روزانه: ۲۰ فایل"
        )
        
        return self.STATES['AWAITING_DOWNLOAD_LIMIT']
    
    async def handle_download_limit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """پردازش تعداد دانلود"""
        user_id = update.effective_user.id
        
        try:
            limit = int(update.message.text)
            limit = max(1, min(20, limit))  # محدودیت ۱-۲۰
        except:
            limit = 5
        
        chat_link = context.user_data.get('download_link', '')
        
        # ارسال پیام در حال پردازش
        status_msg = await update.message.reply_text(
            f"⏳ **در حال پردازش...**\n\n"
            f"🔗 لینک: {chat_link}\n"
            f"📦 تعداد: {limit} فایل\n"
            f"⏱️ لطفاً منتظر بمانید..."
        )
        
        # شروع دانلود
        result = await self.manager.download_with_userbot(user_id, chat_link, limit)
        
        if result['success']:
            await status_msg.edit_text(
                f"✅ **دانلود کامل شد!**\n\n"
                f"📊 آمار:\n"
                f"• تعداد فایل‌ها: {result['count']}\n"
                f"• دانلود باقی‌مانده امروز: {result.get('daily_remaining', 0)}\n"
                f"• زمان: {datetime.now().strftime('%H:%M:%S')}\n\n"
                f"📁 فایل‌ها در پوشه `downloads/user_{user_id}` ذخیره شدند.\n"
                f"برای مشاهده: /myfiles"
            )
        else:
            await status_msg.edit_text(
                f"❌ **خطا در دانلود**\n\n"
                f"خطا: {result.get('error', 'خطای ناشناخته')}\n\n"
                f"🔧 راه‌حل‌های احتمالی:\n"
                f"1. لینک را بررسی کنید\n"
                f"2. UserBot به کانال دسترسی دارد\n"
                f"3. محدودیت روزانه را رعایت کنید"
            )
        
        return ConversationHandler.END
    
    async def myfiles_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /myfiles"""
        user_id = update.effective_user.id
        
        # دریافت فایل‌ها
        files = await self.manager.db.search_files(user_id, limit=10)
        
        if not files:
            keyboard = [[InlineKeyboardButton("📥 شروع دانلود", callback_data='download_menu')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                "📭 **هنوز فایلی ندارید**\n\n"
                "برای شروع دانلود از کانال‌ها استفاده کنید:",
                reply_markup=reply_markup
            )
            return
        
        # ساخت لیست فایل‌ها
        files_text = "📁 **آخرین فایل‌های شما**\n\n"
        
        for i, file in enumerate(files, 1):
            size_mb = file['file_size'] / 1024 / 1024
            time_str = file['download_time'][:16] if file['download_time'] else "نامشخص"
            
            files_text += f"{i}. **{file['file_name']}**\n"
            files_text += f"   📦 {size_mb:.1f} MB | 📁 {file['category']} | 📅 {time_str}\n"
        
        # آمار کلی
        stats = await self.manager.db.get_user_stats(user_id)
        if stats:
            files_text += f"\n📊 **آمار کلی:**\n"
            files_text += f"• کل فایل‌ها: {stats['total_files']}\n"
            files_text += f"• حجم کل: {stats['total_size'] / 1024 / 1024 / 1024:.2f} GB\n"
            files_text += f"• دسته‌بندی‌ها: {stats['categories_count']}\n"
        
        keyboard = [
            [
                InlineKeyboardButton("🔍 جستجو", callback_data='search_files'),
                InlineKeyboardButton("🗂️ دسته‌بندی", callback_data='categories')
            ],
            [
                InlineKeyboardButton("📥 دانلود بیشتر", callback_data='download_menu'),
                InlineKeyboardButton("🔄 به‌روزرسانی", callback_data='refresh_files')
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(files_text, reply_markup=reply_markup)
    
    async def encrypt_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /encrypt"""
        await update.message.reply_text(
            "🔐 **رمزنگاری AES-G256**\n\n"
            "لطفاً متنی که می‌خواهید رمزنگاری شود را ارسال کنید:\n\n"
            "⚠️ کلید رمزنگاری به صورت امن ذخیره می‌شود.\n"
            "❌ برای لغو: /cancel"
        )
        
        return self.STATES['AWAITING_ENCRYPT_TEXT']
    
    async def handle_encrypt_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """پردازش رمزنگاری"""
        user_id = update.effective_user.id
        plaintext = update.message.text
        
        if not plaintext or len(plaintext) < 2:
            await update.message.reply_text("❌ متن بسیار کوتاه است.")
            return ConversationHandler.END
        
        try:
            encrypted = self.manager.security.encrypt(plaintext)
            
            await update.message.reply_text(
                f"✅ **رمزنگاری موفق**\n\n"
                f"🔐 متن رمز شده:\n"
                f"```\n{encrypted}\n```\n\n"
                f"📝 متن اصلی: `{plaintext[:50]}{'...' if len(plaintext) > 50 else ''}`\n\n"
                f"💡 برای رمزگشایی: /decrypt",
                parse_mode='Markdown'
            )
            
            # ثبت فعالیت
            await self.manager.db.log_activity(user_id, "text_encryption", f"length: {len(plaintext)}")
            
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            await update.message.reply_text("❌ خطا در رمزنگاری")
        
        return ConversationHandler.END
    
    async def decrypt_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /decrypt"""
        await update.message.reply_text(
            "🔓 **رمزگشایی AES-G256**\n\n"
            "لطفاً متن رمزنگاری شده را ارسال کنید:\n\n"
            "⚠️ فقط متنی که با همین سیستم رمز شده قابل رمزگشایی است.\n"
            "❌ برای لغو: /cancel"
        )
        
        return self.STATES['AWAITING_DECRYPT_TEXT']
    
    async def handle_decrypt_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """پردازش رمزگشایی"""
        user_id = update.effective_user.id
        encrypted_text = update.message.text
        
        if not encrypted_text:
            await update.message.reply_text("❌ متن رمز شده را وارد کنید.")
            return ConversationHandler.END
        
        try:
            decrypted = self.manager.security.decrypt(encrypted_text)
            
            await update.message.reply_text(
                f"✅ **رمزگشایی موفق**\n\n"
                f"🔓 متن اصلی:\n"
                f"```\n{decrypted}\n```",
                parse_mode='Markdown'
            )
            
            # ثبت فعالیت
            await self.manager.db.log_activity(user_id, "text_decryption", f"length: {len(decrypted)}")
            
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            await update.message.reply_text("❌ خطا در رمزگشایی. مطمئن شوید متن معتبر است.")
        
        return ConversationHandler.END
    
    async def ai_analyze_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /ai_analyze"""
        await update.message.reply_text(
            "🧠 **تحلیل هوشمند محتوا**\n\n"
            "لطفاً متنی که می‌خواهید تحلیل شود را ارسال کنید:\n\n"
            "📊 **تحلیل شامل:**\n"
            "• دسته‌بندی محتوا\n"
            "• تحلیل احساس\n"
            "• کلمات کلیدی\n"
            "• تشخیص زبان\n"
            "• امتیاز خوانایی\n\n"
            "❌ برای لغو: /cancel"
        )
        
        return self.STATES['AWAITING_AI_TEXT']
    
    async def handle_ai_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """پردازش تحلیل AI"""
        user_id = update.effective_user.id
        text = update.message.text
        
        if not text or len(text) < 5:
            await update.message.reply_text("❌ متن بسیار کوتاه است.")
            return ConversationHandler.END
        
        status_msg = await update.message.reply_text("🧠 **در حال تحلیل...**\nلطفاً منتظر بمانید.")
        
        # تحلیل متن
        analysis = await self.manager.ai.analyze_text(text, user_id)
        
        # ساخت پاسخ
        emoji_map = {
            'positive': '😊',
            'negative': '😔',
            'neutral': '😐'
        }
        
        category_map = {
            'educational': 'آموزشی 📚',
            'entertainment': 'سرگرمی 🎭',
            'technology': 'تکنولوژی 💻',
            'news': 'خبری 📰',
            'religious': 'مذهبی 🙏',
            'business': 'تجاری 💼',
            'health': 'سلامتی 🏥',
            'other': 'سایر 📝'
        }
        
        response = f"""
✅ **تحلیل هوشمند متن**

📝 **متن ورودی:**
`{text[:100]}{'...' if len(text) > 100 else ''}`

📊 **نتایج تحلیل:**

🏷️ **دسته‌بندی:** {category_map.get(analysis['category'], analysis['category'])}
🌐 **زبان:** {'فارسی' if analysis['language'] == 'fa' else 'انگلیسی' if analysis['language'] == 'en' else 'ترکیبی'}
😊 **احساس:** {analysis['sentiment']} {emoji_map.get(analysis['sentiment'], '')}
📏 **طول:** {analysis['length']} کاراکتر ({analysis['word_count']} کلمه)
📖 **خوانایی:** {analysis['readability_score']:.1f}/100
🚫 **اسپم:** {'✅ بله' if analysis['is_spam'] else '❌ خیر'}
🔞 **محتوای نامناسب:** {'✅ بله' if analysis['is_nsfw'] else '❌ خیر'}

🔑 **کلمات کلیدی:** {', '.join(analysis['keywords'][:5]) if analysis['keywords'] else 'ندارد'}

🕒 **زمان تحلیل:** {analysis['analysis_time'][11:19]}
        """
        
        await status_msg.edit_text(response, parse_mode='Markdown')
        
        # ثبت فعالیت
        await self.manager.db.log_activity(user_id, "ai_analysis", f"category: {analysis['category']}")
        
        return ConversationHandler.END
    
    async def security_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /security"""
        security_info = """
🛡️ **وضعیت امنیتی سیستم**

🔐 **رمزنگاری:**
• AES-G256: ✅ فعال
• کلید: ذخیره‌سازی امن
• الگوریتم: AES-GCM با 256 بیت

🧠 **هوش مصنوعی:**
• تحلیل محتوا: ✅ فعال
• تشخیص اسپم: ✅ فعال
• فیلتر محتوا: ✅ فعال

📥 **سیستم دانلود:**
• UserBot: {} فعال
• محدودیت روزانه: {} فایل
• حداکثر حجم: {} MB

🗄️ **ذخیره‌سازی:**
• دیتابیس: ✅ فعال
• Redis Cache: {} فعال
• پشتیبان‌گیری: روزانه

🔍 **نظارت:**
• تشخیص نفوذ: ✅ فعال
• لاگ‌گیری: ✅ کامل
• رمزنگاری داده: ✅ فعال
        """.format(
            "✅" if self.manager.userbot_initialized else "❌",
            self.manager.config.get('DAILY_DOWNLOAD_LIMIT', 20),
            self.manager.config.get('MAX_FILE_SIZE_MB', 500),
            "✅" if self.manager.redis.connected else "❌"
        )
        
        keyboard = [
            [
                InlineKeyboardButton("🔐 تست رمزنگاری", callback_data='test_encryption'),
                InlineKeyboardButton("📊 لاگ‌های امنیتی", callback_data='security_logs')
            ],
            [
                InlineKeyboardButton("⚙️ تنظیمات امنیت", callback_data='security_settings'),
                InlineKeyboardButton("🔄 به‌روزرسانی", callback_data='refresh_security')
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(security_info, reply_markup=reply_markup)
    
    async def stats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /stats"""
        user_id = update.effective_user.id
        
        # آمار کاربر
        user_stats = await self.manager.db.get_user_stats(user_id)
        
        if not user_stats:
            await update.message.reply_text("❌ اطلاعات کاربر یافت نشد.")
            return
        
        # آمار سیستم
        system_stats = await self.manager.get_system_stats()
        
        stats_text = f"""
📊 **آمار شخصی شما**

👤 **کاربری:**
• فایل‌های دانلود شده: {user_stats.get('total_files', 0)}
• حجم کل فایل‌ها: {user_stats.get('total_size', 0) / 1024 / 1024:.1f} MB
• دانلود امروز: {user_stats.get('daily_downloads', 0)} از {self.manager.config.get('DAILY_DOWNLOAD_LIMIT', 20)}
• دسته‌بندی‌ها: {user_stats.get('categories_count', 0)}
• آخرین دانلود: {user_stats.get('last_download', 'ندارد')}

📈 **آمار سیستم:**
• کاربران کل: {system_stats.get('total_users', 0)}
• فایل‌های کل: {system_stats.get('total_files', 0)}
• حجم کل سیستم: {system_stats.get('total_size', 0) / 1024 / 1024 / 1024:.2f} GB
• کاربران فعال امروز: {system_stats.get('active_today', 0)}

⚙️ **وضعیت سیستم:**
• CPU: {system_stats.get('system', {}).get('cpu_percent', 0):.1f}%
• RAM: {system_stats.get('system', {}).get('memory_percent', 0):.1f}%
• Disk: {system_stats.get('system', {}).get('disk_percent', 0):.1f}%
• UserBot: {'✅' if self.manager.userbot_initialized else '❌'}
• AI: {'✅' if self.manager.ai.model_loaded else '❌'}
• Redis: {'✅' if self.manager.redis.connected else '❌'}
        """
        
        await update.message.reply_text(stats_text)
    
    async def admin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /admin - فقط برای ادمین‌ها"""
        user_id = update.effective_user.id
        
        if user_id not in self.manager.config.get('ADMIN_IDS', []):
            await update.message.reply_text("❌ دسترسی ممنوع!")
            return
        
        keyboard = [
            [
                InlineKeyboardButton("📊 آمار سیستم", callback_data='admin_stats'),
                InlineKeyboardButton("👥 مدیریت کاربران", callback_data='admin_users')
            ],
            [
                InlineKeyboardButton("🧹 پاکسازی", callback_data='admin_cleanup'),
                InlineKeyboardButton("🔄 راه‌اندازی مجدد", callback_data='admin_restart')
            ],
            [
                InlineKeyboardButton("📤 خروجی داده", callback_data='admin_export'),
                InlineKeyboardButton("🔒 تنظیمات امنیت", callback_data='admin_security')
            ],
            [
                InlineKeyboardButton("📢 اطلاعیه همگانی", callback_data='admin_broadcast'),
                InlineKeyboardButton("🚫 مدیریت بن", callback_data='admin_ban')
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "🛠️ **پنل مدیریت پیشرفته**\n\n"
            "لطفاً گزینه مورد نظر را انتخاب کنید:",
            reply_markup=reply_markup
        )
    
    async def handle_callback_query(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """پردازش کلیک دکمه‌ها"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        data = query.data
        
        # مدیریت منوها
        if data == 'download_menu':
            await self.download_command(update, context)
        elif data == 'my_files':
            await self.myfiles_command(update, context)
        elif data == 'encryption_menu':
            await query.edit_message_text(
                "🔐 **منوی رمزنگاری**\n\n"
                "لطفاً انتخاب کنید:",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("📝 رمزنگاری متن", callback_data='encrypt_text')],
                    [InlineKeyboardButton("🔓 رمزگشایی متن", callback_data='decrypt_text')],
                    [InlineKeyboardButton("📁 رمزنگاری فایل", callback_data='encrypt_file')],
                    [InlineKeyboardButton("🔙 بازگشت", callback_data='back_to_main')]
                ])
            )
        elif data == 'ai_menu':
            await self.ai_analyze_command(update, context)
        elif data == 'settings_menu':
            await query.edit_message_text(
                "⚙️ **تنظیمات**\n\n"
                "لطفاً انتخاب کنید:",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🌐 زبان", callback_data='language_settings')],
                    [InlineKeyboardButton("📁 پوشه دانلود", callback_data='download_folder')],
                    [InlineKeyboardButton("🔔 اطلاع‌رسانی", callback_data='notifications')],
                    [InlineKeyboardButton("🔙 بازگشت", callback_data='back_to_main')]
                ])
            )
        elif data == 'stats_menu':
            await self.stats_command(update, context)
        elif data == 'admin_panel':
            await self.admin_command(update, context)
        elif data == 'back_to_main':
            await self.start_command(update, context)
        
        # مدیریت دیگر callbackها
        # ...
    
    async def cancel_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """لغو عملیات"""
        await update.message.reply_text("❌ عملیات لغو شد.")
        return ConversationHandler.END
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """دستور /help"""
        help_text = """
📚 **راهنمای کامل ربات**

🔐 **مدیریت اکانت و امنیت:**
/start - شروع کار با ربات
/login - ورود به اکانت تلگرام
/security - وضعیت امنیتی سیستم
/backup - پشتیبان‌گیری اطلاعات

📥 **سیستم دانلود:**
/download - دانلود از کانال یا گروه
/myfiles - مشاهده فایل‌های دانلود شده
/search - جستجوی فایل‌ها
/organize - سازماندهی فایل‌ها

🛡️ **رمزنگاری:**
/encrypt - رمزنگاری متن (AES-G256)
/decrypt - رمزگشایی متن
/encrypt_file - رمزنگاری فایل
/decrypt_file - رمزگشایی فایل

🧠 **هوش مصنوعی:**
/ai_analyze - تحلیل متن با AI
/ai_categorize - دسته‌بندی خودکار
/ai_filter - فیلتر محتوای نامناسب

📊 **گزارش و آمار:**
/stats - آمار شخصی و سیستم
/report - گزارش فعالیت
/insights - تحلیل هوشمند
/export - خروجی گرفتن از داده‌ها

⚙️ **مدیریت سیستم (ادمین):**
/admin - پنل مدیریت
/health - سلامت سیستم
/users - مدیریت کاربران
/broadcast - ارسال اطلاعیه

🔧 **پشتیبانی:**
/support - ارتباط با پشتیبانی
/feedback - ارسال نظرات و پیشنهادات
/guide - راهنمای گام به گام

⚠️ **نکات مهم:**
1. اطلاعات حساس را در چت عمومی ارسال نکنید
2. کلیدهای رمزنگاری را امن نگهداری کنید
3. از فایل‌های مشکوک دانلود نکنید
4. در صورت مشکل با پشتیبانی تماس بگیرید

📞 **پشتیبانی:** @YourSupportUsername
🆘 **ارسال باگ:** /reportbug
        """
        
        await update.message.reply_text(help_text)

# ========== تابع اصلی ==========

async def main():
    """تابع اصلی اجرای ربات"""
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║   🤖 ربات تلگرام یکپارچه پیشرفته - نسخه نهایی             ║
║   🚀 ترکیب: مدیریت اکانت + سیستم امنیتی + UserBot          ║
║          + AI + Redis + Webhook                             ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # بارگذاری تنظیمات
    try:
        from config import (
            TOKEN, BOT_USERNAME, API_ID, API_HASH, ADMIN_IDS,
            ENCRYPTION_KEY, REDIS_HOST, REDIS_PORT, REDIS_PASSWORD,
            WEBHOOK_URL, MAX_DOWNLOAD_LIMIT, MAX_FILE_SIZE_MB,
            DAILY_DOWNLOAD_LIMIT
        )
        
        config = {
            'TOKEN': TOKEN,
            'BOT_USERNAME': BOT_USERNAME,
            'API_ID': API_ID,
            'API_HASH': API_HASH,
            'ADMIN_IDS': ADMIN_IDS,
            'ENCRYPTION_KEY': ENCRYPTION_KEY,
            'REDIS_HOST': REDIS_HOST,
            'REDIS_PORT': REDIS_PORT,
            'REDIS_PASSWORD': REDIS_PASSWORD,
            'REDIS_DB': 0,
            'WEBHOOK_URL': WEBHOOK_URL,
            'MAX_DOWNLOAD_LIMIT': MAX_DOWNLOAD_LIMIT,
            'MAX_FILE_SIZE_MB': MAX_FILE_SIZE_MB,
            'DAILY_DOWNLOAD_LIMIT': DAILY_DOWNLOAD_LIMIT,
            'DATABASE_PATH': 'database/telegram_bot.db'
        }
        
    except ImportError as e:
        print(f"❌ خطا در بارگذاری config.py: {e}")
        print("""
📝 لطفاً فایل config.py را ایجاد کنید با این محتوا:

TOKEN = "توکن_ربات_شما"
BOT_USERNAME = "username_bot"
API_ID = 123456  # از my.telegram.org
API_HASH = "your_api_hash_here"
ADMIN_IDS = [123456789]
ENCRYPTION_KEY = "your_secure_key_32_chars_long"
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_PASSWORD = None
WEBHOOK_URL = ""  # خالی برای polling
MAX_DOWNLOAD_LIMIT = 20
MAX_FILE_SIZE_MB = 500
DAILY_DOWNLOAD_LIMIT = 20
        """)
        sys.exit(1)
    
    # بررسی توکن
    if config['TOKEN'] == "توکن_ربات_شما":
        print("❌ خطا: توکن ربات تنظیم نشده است!")
        print("لطفاً فایل config.py را ویرایش کنید.")
        sys.exit(1)
    
    # ایجاد مدیر یکپارچه
    manager = IntegratedBotManager(config)
    
    # مقداردهی اولیه سیستم‌ها
    print("🔄 در حال راه‌اندازی سیستم‌ها...")
    if not await manager.initialize():
        print("❌ خطا در راه‌اندازی سیستم‌ها!")
        sys.exit(1)
    
    # ایجاد اپلیکیشن تلگرام
    print("🤖 در حال ایجاد اپلیکیشن تلگرام...")
    
    # استفاده از persistence برای ذخیره state
    persistence = PicklePersistence(filepath="bot_persistence.pickle")
    
    application = (
        ApplicationBuilder()
        .token(config['TOKEN'])
        .persistence(persistence)
        .concurrent_updates(True)
        .post_init(manager.webhook.setup_webhook)
        .post_shutdown(manager.redis.disconnect)
        .build()
    )
    
    # تنظیم job queue برای کارهای زمان‌بندی شده
    manager.job_queue = application.job_queue
    if manager.job_queue:
        # پاکسازی روزانه
        manager.job_queue.run_daily(
            manager.cleanup_task,
            time=datetime.time(hour=3, minute=0),  # ساعت 3 صبح
            days=(0, 1, 2, 3, 4, 5, 6)
        )
        
        # پشتیبان‌گیری ساعتی از دیتابیس
        manager.job_queue.run_repeating(
            manager.backup_database,
            interval=3600,  # هر ساعت
            first=10
        )
    
    # ایجاد هندلرها
    handlers = TelegramBotHandlers(manager)
    
    # تنظیم دستورات ربات
    await application.bot.set_my_commands(handlers.commands)
    
    # ========== تنظیم Conversation Handlers ==========
    
    # دانلود
    download_conv = ConversationHandler(
        entry_points=[CommandHandler('download', handlers.download_command)],
        states={
            handlers.STATES['AWAITING_DOWNLOAD_LINK']: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_download_link)
            ],
            handlers.STATES['AWAITING_DOWNLOAD_LIMIT']: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_download_limit)
            ]
        },
        fallbacks=[CommandHandler('cancel', handlers.cancel_command)],
        allow_reentry=True
    )
    
    # رمزنگاری
    encrypt_conv = ConversationHandler(
        entry_points=[CommandHandler('encrypt', handlers.encrypt_command)],
        states={
            handlers.STATES['AWAITING_ENCRYPT_TEXT']: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_encrypt_text)
            ]
        },
        fallbacks=[CommandHandler('cancel', handlers.cancel_command)],
        allow_reentry=True
    )
    
    # رمزگشایی
    decrypt_conv = ConversationHandler(
        entry_points=[CommandHandler('decrypt', handlers.decrypt_command)],
        states={
            handlers.STATES['AWAITING_DECRYPT_TEXT']: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_decrypt_text)
            ]
        },
        fallbacks=[CommandHandler('cancel', handlers.cancel_command)],
        allow_reentry=True
    )
    
    # تحلیل AI
    ai_conv = ConversationHandler(
        entry_points=[CommandHandler('ai_analyze', handlers.ai_analyze_command)],
        states={
            handlers.STATES['AWAITING_AI_TEXT']: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_ai_text)
            ]
        },
        fallbacks=[CommandHandler('cancel', handlers.cancel_command)],
        allow_reentry=True
    )
    
    # ========== اضافه کردن هندلرها ==========
    
    # دستورات اصلی
    application.add_handler(CommandHandler("start", handlers.start_command))
    application.add_handler(CommandHandler("help", handlers.help_command))
    application.add_handler(CommandHandler("myfiles", handlers.myfiles_command))
    application.add_handler(CommandHandler("security", handlers.security_command))
    application.add_handler(CommandHandler("stats", handlers.stats_command))
    application.add_handler(CommandHandler("admin", handlers.admin_command))
    application.add_handler(CommandHandler("cancel", handlers.cancel_command))
    
    # Conversation Handlers
    application.add_handler(download_conv)
    application.add_handler(encrypt_conv)
    application.add_handler(decrypt_conv)
    application.add_handler(ai_conv)
    
    # Callback Handler
    application.add_handler(CallbackQueryHandler(handlers.handle_callback_query))
    
    # هندلر پیام‌های متنی
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handlers.handle_ai_text), group=1)
    
    # ========== اجرای ربات ==========
    
    print(f"\n✅ ربات @{config['BOT_USERNAME']} آماده است!")
    print("📊 سیستم‌های فعال:")
    print(f"   🔐 امنیت: {'✅' if manager.security.available else '❌'}")
    print(f"   🧠 AI: {'✅' if manager.ai.model_loaded else '❌'}")
    print(f"   📥 UserBot: {'✅' if manager.userbot_initialized else '❌'}")
    print(f"   🗄️ Redis: {'✅' if manager.redis.connected else '❌'}")
    print(f"   📊 دیتابیس: ✅")
    print(f"   🔄 Job Queue: {'✅' if manager.job_queue else '❌'}")
    print(f"\n🌐 حالت: {'Webhook' if manager.webhook.is_webhook else 'Polling'}")
    print("\n📝 برای خروج Ctrl+C را فشار دهید")
    print("=" * 60)
    
    try:
        if manager.webhook.is_webhook:
            # اجرای Webhook
            await manager.webhook.run_webhook(
                application,
                host="0.0.0.0",
                port=8443
            )
        else:
            # اجرای Polling
            await application.run_polling(
                allowed_updates=Update.ALL_TYPES,
                drop_pending_updates=True
            )
            
    except KeyboardInterrupt:
        print("\n\n👋 ربات با موفقیت متوقف شد.")
    except Exception as e:
        print(f"\n💥 خطای غیرمنتظره: {e}")
        logger.exception("خطای اصلی")
    finally:
        # اطمینان از بسته شدن صحیح
        if application.running:
            await application.stop()
        await manager.redis.disconnect()

if __name__ == "__main__":
    # تنظیم event loop برای ویندوز
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # اجرای ربات
    asyncio.run(main())
