#!/usr/bin/env python3
# telegram_bot.py - ربات توزیع فایل پیشرفته با هوش مصنوعی

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
from typing import Optional, List, Dict, Any, Tuple
import hashlib
import re
import secrets
from collections import defaultdict
import asyncio
import aiohttp
from functools import wraps, lru_cache
import redis
import pickle
import schedule
import requests
from werkzeug.security import generate_password_hash, check_password_hash

# ==================== هوش مصنوعی و پردازش زبان طبیعی ====================
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("⚠️  کتابخانه transformers نصب نیست. ویژگی‌های هوش مصنوعی غیرفعال.")
    print("   نصب: pip install transformers torch")

try:
    from sentence_transformers import SentenceTransformer
    SEMANTIC_SEARCH_AVAILABLE = True
except ImportError:
    SEMANTIC_SEARCH_AVAILABLE = False

# ==================== تنظیمات لاگ ====================
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
        Initialize Advanced File Distribution Bot
        
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
        self.backup_dir = self.base_dir / "backups"
        self.cache_dir = self.base_dir / "cache"
        
        # ایجاد پوشه‌های لازم
        for directory in [self.downloads_dir, self.data_dir, self.uploads_dir, 
                         self.backup_dir, self.cache_dir]:
            directory.mkdir(exist_ok=True)
        
        # دیتابیس SQLite
        self.db_path = self.data_dir / "bot_database.db"
        self.init_database()
        
        # سیستم کش (Redis)
        self.redis_client = self.init_redis()
        
        # تنظیمات
        self.settings = self.load_settings()
        self.admins = self.settings.get('admins', [])
        self.required_channels = self.settings.get('required_channels', [])
        
        # سیستم هوش مصنوعی
        self.ai_models = self.init_ai_models()
        
        # سیستم امنیتی
        self.security = SecuritySystem(self)
        
        # سیستم پرداخت
        self.payment_system = PaymentSystem(self)
        
        # سیستم کش
        self.cache_system = CacheSystem(self)
        
        # سیستم گزارش‌گیری
        self.analytics = AnalyticsSystem(self)
        
        # سیستم پیشنهاد
        self.recommendation = RecommendationSystem(self)
        
        # سیستم بک‌آپ
        self.backup_system = BackupSystem(self)
        
        # سیستم جستجوی پیشرفته
        self.search_system = SearchSystem(self)
        
        # سیستم گیمیفیکیشن
        self.gamification = GamificationSystem(self)
        
        # سیستم وب‌داشبورد
        self.web_dashboard = WebDashboard(self)
        
        # وضعیت
        self.is_broadcasting = False
        self.broadcast_lock = threading.Lock()
        self.user_sessions = {}
        
        logger.info("✅ FileDistributionBot initialized with advanced features")
    
    def init_database(self):
        """ایجاد جداول دیتابیس پیشرفته"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # جدول کاربران (بهبود یافته)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            last_name TEXT,
            phone TEXT,
            email TEXT,
            join_date TIMESTAMP,
            last_activity TIMESTAMP,
            download_count INTEGER DEFAULT 0,
            upload_count INTEGER DEFAULT 0,
            total_points INTEGER DEFAULT 0,
            level INTEGER DEFAULT 1,
            subscription_type TEXT DEFAULT 'free',
            subscription_expiry TIMESTAMP,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            language TEXT DEFAULT 'fa',
            theme TEXT DEFAULT 'default',
            api_key TEXT UNIQUE,
            last_login_ip TEXT
        )
        ''')
        
        # جدول فایل‌ها (بهبود یافته)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE,
            file_name TEXT,
            file_path TEXT,
            file_size INTEGER,
            file_type TEXT,
            category_id INTEGER,
            tags TEXT,
            description TEXT,
            upload_date TIMESTAMP,
            uploader_id INTEGER,
            download_count INTEGER DEFAULT 0,
            view_count INTEGER DEFAULT 0,
            rating_avg REAL DEFAULT 0,
            rating_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            is_premium INTEGER DEFAULT 0,
            is_featured INTEGER DEFAULT 0,
            metadata TEXT,
            FOREIGN KEY (category_id) REFERENCES categories (id),
            FOREIGN KEY (uploader_id) REFERENCES users (user_id)
        )
        ''')
        
        # جدول دسته‌بندی‌ها
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            description TEXT,
            icon TEXT,
            parent_id INTEGER DEFAULT NULL,
            is_premium INTEGER DEFAULT 0,
            sort_order INTEGER DEFAULT 0,
            FOREIGN KEY (parent_id) REFERENCES categories (id)
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
            target_users TEXT DEFAULT 'all',
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
        ''')
        
        # جدول فعالیت‌ها (بهبود یافته)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
        ''')
        
        # جدول امتیازات و رتبه‌بندی
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_id INTEGER,
            rating INTEGER CHECK(rating >= 1 AND rating <= 5),
            review TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id),
            FOREIGN KEY (file_id) REFERENCES files (id),
            UNIQUE(user_id, file_id)
        )
        ''')
        
        # جدول تراکنش‌های پرداخت
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount INTEGER,
            currency TEXT DEFAULT 'IRT',
            gateway TEXT,
            transaction_id TEXT UNIQUE,
            status TEXT,
            description TEXT,
            created_at TIMESTAMP,
            completed_at TIMESTAMP,
            metadata TEXT,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
        ''')
        
        # جدول دستاوردها
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            achievement_id TEXT,
            achievement_name TEXT,
            unlocked_at TIMESTAMP,
            points_awarded INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (user_id),
            UNIQUE(user_id, achievement_id)
        )
        ''')
        
        # جدول کش جستجو
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS search_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_hash TEXT UNIQUE,
            query_text TEXT,
            results TEXT,
            created_at TIMESTAMP,
            expires_at TIMESTAMP
        )
        ''')
        
        # درج دسته‌بندی‌های پیش‌فرض
        default_categories = [
            ('📚 کتاب‌های الکترونیکی', 'کتاب‌های الکترونیکی در فرمت‌های مختلف', '📚', None, 0, 1),
            ('🎬 فیلم و ویدیو', 'فیلم‌های آموزشی و سرگرمی', '🎬', None, 0, 2),
            ('🎵 موسیقی و صدا', 'آهنگ، پادکست و فایل صوتی', '🎵', None, 0, 3),
            ('📄 اسناد و مقالات', 'مقاله، تحقیق و پایان‌نامه', '📄', None, 0, 4),
            ('📁 فایل‌های فشرده', 'زیپ، رار و فایل‌های آرشیو', '📁', None, 0, 5),
            ('🖼 تصاویر و عکس', 'عکس، طرح و تصویر', '🖼', None, 0, 6),
            ('💻 نرم‌افزار', 'برنامه و اپلیکیشن', '💻', None, 1, 7),
            ('🎮 بازی', 'بازی کامپیوتری و موبایل', '🎮', None, 1, 8),
            ('📊 داده و تحلیل', 'دیتاست و اطلاعات آماری', '📊', None, 1, 9),
        ]
        
        cursor.executemany(
            'INSERT OR IGNORE INTO categories (name, description, icon, parent_id, is_premium, sort_order) VALUES (?, ?, ?, ?, ?, ?)',
            default_categories
        )
        
        # درج دستاوردهای پیش‌فرض
        default_achievements = [
            ('first_download', 'نخستین دانلود', 'دانلود اولین فایل', 10),
            ('power_user', 'کاربر پرتوان', '۱۰۰ دانلود انجام شده', 100),
            ('uploader', 'آپلودکننده', 'آپلود ۱۰ فایل', 50),
            ('reviewer', 'نقدگر', 'ثبت ۲۰ نظر', 75),
            ('vip', 'کاربر ویژه', 'عضویت یک ماهه VIP', 200),
            ('inviter', 'دعوت‌کننده', 'دعوت ۵ کاربر', 150),
        ]
        
        cursor.executemany(
            'INSERT OR IGNORE INTO achievement_templates (achievement_id, name, description, points) VALUES (?, ?, ?, ?)',
            default_achievements
        )
        
        conn.commit()
        conn.close()
        
        logger.info("✅ Database initialized with advanced tables")
    
    def init_redis(self):
        """راه‌اندازی Redis برای کش"""
        try:
            redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True,
                socket_connect_timeout=2
            )
            redis_client.ping()
            logger.info("✅ Redis connected successfully")
            return redis_client
        except redis.ConnectionError:
            logger.warning("❌ Redis not available, using in-memory cache")
            return None
    
    def init_ai_models(self):
        """راه‌اندازی مدل‌های هوش مصنوعی"""
        models = {}
        
        if AI_AVAILABLE:
            try:
                # مدل طبقه‌بندی زبان فارسی
                models['fa_classifier'] = pipeline(
                    "text-classification",
                    model="HooshvareLab/bert-fa-base-uncased",
                    tokenizer="HooshvareLab/bert-fa-base-uncased"
                )
                
                # مدل خلاصه‌سازی متن
                models['summarizer'] = pipeline(
                    "summarization",
                    model="m3hrdadfi/bert2bert-fa-news-headline"
                )
                
                logger.info("✅ AI models loaded successfully")
            except Exception as e:
                logger.error(f"❌ Failed to load AI models: {e}")
        
        if SEMANTIC_SEARCH_AVAILABLE:
            try:
                # مدل جستجوی معنایی
                models['sentence_encoder'] = SentenceTransformer(
                    'parsbert/parsbert-base-uncased'
                )
                logger.info("✅ Sentence transformer loaded successfully")
            except Exception as e:
                logger.error(f"❌ Failed to load sentence transformer: {e}")
        
        return models
    
    def load_settings(self) -> dict:
        """بارگذاری تنظیمات از فایل"""
        settings_file = self.base_dir / "bot_settings.json"
        
        if settings_file.exists():
            try:
                with open(settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    
                    # تنظیمات پیشرفته پیش‌فرض
                    default_advanced = {
                        'rate_limits': {
                            'download': {'limit': 10, 'period': 3600},
                            'search': {'limit': 30, 'period': 3600},
                            'upload': {'limit': 5, 'period': 86400}
                        },
                        'premium_features': {
                            'max_file_size': 500,  # MB
                            'daily_download_limit': 100,
                            'priority_download': True
                        },
                        'security': {
                            'max_login_attempts': 5,
                            'session_timeout': 3600,
                            'require_2fa_for_admin': False
                        },
                        'cache': {
                            'enabled': True,
                            'ttl': 300,
                            'max_size': 1000
                        }
                    }
                    
                    # ادغام تنظیمات
                    for key, value in default_advanced.items():
                        if key not in settings:
                            settings[key] = value
                    
                    return settings
            except Exception as e:
                logger.error(f"Error loading settings: {e}")
        
        # تنظیمات پیش‌فرض کامل
        default_settings = {
            'admins': [123456789],
            'required_channels': ['@your_channel'],
            'welcome_message': 'به ربات پیشرفته توزیع فایل خوش آمدید! 🚀',
            'max_file_size': 2000,
            'daily_download_limit': 10,
            'broadcast_delay': 1,
            'backup_enabled': True,
            'backup_schedule': 'daily',
            'payment_gateway': 'zarinpal',
            'currency': 'IRT',
            'premium_price_monthly': 29000,
            'premium_price_yearly': 290000,
            'rate_limits': {
                'download': {'limit': 10, 'period': 3600},
                'search': {'limit': 30, 'period': 3600},
                'upload': {'limit': 5, 'period': 86400}
            },
            'premium_features': {
                'max_file_size': 500,
                'daily_download_limit': 100,
                'priority_download': True
            },
            'security': {
                'max_login_attempts': 5,
                'session_timeout': 3600,
                'require_2fa_for_admin': False
            },
            'cache': {
                'enabled': True,
                'ttl': 300,
                'max_size': 1000
            }
        }
        
        # ذخیره تنظیمات پیش‌فرض
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(default_settings, f, ensure_ascii=False, indent=2)
        
        logger.info("✅ Created advanced settings file")
        return default_settings
    
    # ==================== ویژگی 1: سیستم امنیتی چندلایه ====================
    
    def check_rate_limit(self, user_id: int, action: str) -> bool:
        """بررسی محدودیت نرخ درخواست"""
        if not self.redis_client:
            return True
            
        key = f"rate_limit:{user_id}:{action}"
        limit_info = self.settings['rate_limits'].get(action, {'limit': 10, 'period': 3600})
        
        current = self.redis_client.incr(key)
        if current == 1:
            self.redis_client.expire(key, limit_info['period'])
        
        if current > limit_info['limit']:
            logger.warning(f"Rate limit exceeded for user {user_id}, action: {action}")
            return False
        
        return True
    
    def verify_user_session(self, user_id: int, session_token: str) -> bool:
        """تأیید اعتبار سشن کاربر"""
        session_key = f"session:{user_id}"
        stored_token = self.redis_client.get(session_key) if self.redis_client else None
        
        if stored_token == session_token:
            # تمدید سشن
            if self.redis_client:
                self.redis_client.expire(session_key, self.settings['security']['session_timeout'])
            return True
        
        return False
    
    # ==================== ویژگی 2: سیستم پرداخت و اشتراک ====================
    
    def check_subscription(self, user_id: int) -> Dict[str, Any]:
        """بررسی وضعیت اشتراک کاربر"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT subscription_type, subscription_expiry 
        FROM users WHERE user_id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return {'type': 'free', 'is_active': False}
        
        subscription_type = user['subscription_type']
        expiry = user['subscription_expiry']
        
        is_active = False
        if expiry:
            expiry_date = datetime.fromisoformat(expiry)
            is_active = expiry_date > datetime.now()
        
        return {
            'type': subscription_type,
            'is_active': is_active,
            'expiry_date': expiry,
            'features': self.get_subscription_features(subscription_type)
        }
    
    def get_subscription_features(self, plan_type: str) -> Dict[str, Any]:
        """ویژگی‌های هر طرح اشتراک"""
        plans = {
            'free': {
                'daily_downloads': 10,
                'max_file_size': 100,  # MB
                'ads_enabled': True,
                'priority_support': False,
                'advanced_search': False
            },
            'premium': {
                'daily_downloads': 100,
                'max_file_size': 500,
                'ads_enabled': False,
                'priority_support': True,
                'advanced_search': True
            },
            'vip': {
                'daily_downloads': 9999,
                'max_file_size': 2000,
                'ads_enabled': False,
                'priority_support': True,
                'advanced_search': True,
                'personal_assistant': True
            }
        }
        
        return plans.get(plan_type, plans['free'])
    
    # ==================== ویژگی 3: سیستم کش هوشمند ====================
    
    def cache_get(self, key: str, ttl: int = 300):
        """دریافت از کش"""
        if not self.redis_client:
            return None
        
        try:
            data = self.redis_client.get(key)
            if data:
                return pickle.loads(data)
        except:
            pass
        return None
    
    def cache_set(self, key: str, data: Any, ttl: int = 300):
        """ذخیره در کش"""
        if not self.redis_client:
            return
        
        try:
            serialized = pickle.dumps(data)
            self.redis_client.setex(key, 
