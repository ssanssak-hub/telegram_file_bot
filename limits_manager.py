#!/usr/bin/env python3
# limits_manager.py - سیستم مدیریت محدودیت‌های ربات

import json
import time
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class LimitType(Enum):
    """انواع محدودیت‌ها"""
    DAILY_DOWNLOADS = "daily_downloads"
    TOTAL_DOWNLOADS = "total_downloads"
    DOWNLOAD_SIZE = "download_size"
    CONCURRENT_DOWNLOADS = "concurrent_downloads"
    USER_COUNT = "user_count"
    FILE_COUNT = "file_count"
    BANDWIDTH = "bandwidth"
    API_REQUESTS = "api_requests"
    STORAGE_SPACE = "storage_space"

@dataclass
class LimitConfig:
    """تنظیمات هر محدودیت"""
    limit_type: LimitType
    max_value: int
    period_seconds: int  # 0 = کل مدت
    reset_automatically: bool = True
    penalty_action: str = "block"  # block, throttle, notify
    grace_percent: float = 0.1  # 10% grace قبل از هشدار

class LimitsManager:
    """مدیریت کامل محدودیت‌ها"""
    
    def __init__(self, db_path: Path = Path("data/limits.db")):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
        # ایجاد دیتابیس
        self.init_database()
        
        # بارگذاری تنظیمات پیش‌فرض
        self.limits_config = self.load_limits_config()
        
        # کش برای کارایی بهتر
        self.user_cache = {}
        self.global_cache = {}
        self.cache_timeout = 60  # ثانیه
        
        logger.info("LimitsManager initialized")
    
    def init_database(self):
        """ایجاد جداول دیتابیس"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # جدول محدودیت‌های کاربران
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_limits (
            user_id INTEGER,
            limit_type TEXT,
            used_value INTEGER DEFAULT 0,
            period_start TIMESTAMP,
            period_end TIMESTAMP,
            last_updated TIMESTAMP,
            PRIMARY KEY (user_id, limit_type, period_start)
        )
        ''')
        
        # جدول محدودیت‌های سراسری
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS global_limits (
            limit_type TEXT PRIMARY KEY,
            used_value INTEGER DEFAULT 0,
            period_start TIMESTAMP,
            period_end TIMESTAMP,
            last_updated TIMESTAMP
        )
        ''')
        
        # جدول تاریخچه محدودیت‌ها
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS limits_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            limit_type TEXT,
            action TEXT,
            value INTEGER,
            timestamp TIMESTAMP,
            ip_address TEXT,
            user_agent TEXT
        )
        ''')
        
        # جدول تخلفات کاربران
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS violations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            limit_type TEXT,
            exceeded_by INTEGER,
            timestamp TIMESTAMP,
            action_taken TEXT,
            resolved BOOLEAN DEFAULT 0
        )
        ''')
        
        self.conn.commit()
    
    def load_limits_config(self) -> Dict[str, LimitConfig]:
        """بارگذاری تنظیمات محدودیت‌ها"""
        config_file = Path("config/limits_config.json")
        
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
        else:
            # تنظیمات پیش‌فرض
            config_data = self.get_default_limits()
            
            # ذخیره تنظیمات پیش‌فرض
            config_file.parent.mkdir(exist_ok=True, parents=True)
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
        
        # تبدیل به LimitConfig
        limits_config = {}
        for limit_type_str, config in config_data.items():
            limit_type = LimitType(limit_type_str)
            limits_config[limit_type_str] = LimitConfig(
                limit_type=limit_type,
                max_value=config['max_value'],
                period_seconds=config['period_seconds'],
                reset_automatically=config.get('reset_automatically', True),
                penalty_action=config.get('penalty_action', 'block'),
                grace_percent=config.get('grace_percent', 0.1)
            )
        
        return limits_config
    
    def get_default_limits(self) -> Dict:
        """تنظیمات محدودیت پیش‌فرض"""
        return {
            "daily_downloads": {
                "description": "تعداد دانلود روزانه هر کاربر",
                "max_value": 10,
                "period_seconds": 24 * 3600,  # 24 ساعت
                "reset_automatically": True,
                "penalty_action": "block",
                "grace_percent": 0.1,
                "tiered_limits": {
                    "free": 10,
                    "premium": 50,
                    "vip": 200
                }
            },
            "total_downloads": {
                "description": "تعداد کل دانلودهای هر کاربر",
                "max_value": 100,
                "period_seconds": 0,  # کل مدت
                "reset_automatically": False,
                "penalty_action": "notify",
                "grace_percent": 0.2
            },
            "download_size": {
                "description": "حداکثر حجم فایل قابل دانلود (مگابایت)",
                "max_value": 500,  # 500 مگابایت
                "period_seconds": 0,
                "reset_automatically": True,
                "penalty_action": "block",
                "grace_percent": 0.0
            },
            "concurrent_downloads": {
                "description": "تعداد دانلود همزمان",
                "max_value": 3,
                "period_seconds": 0,
                "reset_automatically": True,
                "penalty_action": "throttle",
                "grace_percent": 0.0
            },
            "user_count": {
                "description": "حداکثر تعداد کاربران",
                "max_value": 1000,
                "period_seconds": 0,
                "reset_automatically": False,
                "penalty_action": "block",
                "grace_percent": 0.05
            },
            "file_count": {
                "description": "حداکثر تعداد فایل‌ها در سیستم",
                "max_value": 10000,
                "period_seconds": 0,
                "reset_automatically": False,
                "penalty_action": "block",
                "grace_percent": 0.05
            },
            "bandwidth": {
                "description": "پهنای باند ماهانه (گیگابایت)",
                "max_value": 100,  # 100 گیگابایت
                "period_seconds": 30 * 24 * 3600,  # 30 روز
                "reset_automatically": True,
                "penalty_action": "throttle",
                "grace_percent": 0.1
            },
            "api_requests": {
                "description": "تعداد درخواست‌های API در دقیقه",
                "max_value": 60,
                "period_seconds": 60,  # 1 دقیقه
                "reset_automatically": True,
                "penalty_action": "throttle",
                "grace_percent": 0.0
            },
            "storage_space": {
                "description": "فضای ذخیره‌سازی (گیگابایت)",
                "max_value": 50,  # 50 گیگابایت
                "period_seconds": 0,
                "reset_automatically": False,
                "penalty_action": "block",
                "grace_percent": 0.05
            }
        }
    
    def check_user_limit(self, user_id: int, limit_type: LimitType, 
                        value: int = 1) -> Dict:
        """
        بررسی محدودیت کاربر
        Returns: {
            'allowed': bool,
            'remaining': int,
            'used': int,
            'limit': int,
            'next_reset': str or None,
            'warning': bool
        }
        """
        limit_key = limit_type.value
        config = self.limits_config.get(limit_key)
        
        if not config:
            return {
                'allowed': True,
                'remaining': float('inf'),
                'used': 0,
                'limit': float('inf'),
                'next_reset': None,
                'warning': False
            }
        
        # دریافت مقدار استفاده شده
        used = self.get_user_usage(user_id, limit_type)
        
        # بررسی محدودیت tiered
        user_tier = self.get_user_tier(user_id)
        tiered_limit = self.get_tiered_limit(limit_type, user_tier)
        actual_limit = tiered_limit if tiered_limit else config.max_value
        
        # محاسبه باقیمانده
        remaining = max(0, actual_limit - used)
        
        # بررسی امکان انجام عمل
        allowed = value <= remaining
        
        # بررسی هشدار (grace period)
        warning = False
        if used >= actual_limit * (1 - config.grace_percent):
            warning = True
        
        # زمان reset بعدی
        next_reset = None
        if config.period_seconds > 0 and config.reset_automatically:
            next_reset = self.get_next_reset_time(user_id, limit_type)
        
        result = {
            'allowed': allowed,
            'remaining': remaining,
            'used': used,
            'limit': actual_limit,
            'next_reset': next_reset,
            'warning': warning,
            'tier': user_tier
        }
        
        # ثبت در تاریخچه اگر محدودیت رد شود
        if not allowed:
            self.record_violation(user_id, limit_type, value, used, actual_limit)
        
        return result
    
    def check_global_limit(self, limit_type: LimitType, value: int = 1) -> Dict:
        """بررسی محدودیت سراسری"""
        limit_key = limit_type.value
        config = self.limits_config.get(limit_key)
        
        if not config:
            return {'allowed': True, 'remaining': float('inf')}
        
        used = self.get_global_usage(limit_type)
        remaining = max(0, config.max_value - used)
        allowed = value <= remaining
        
        # بررسی هشدار
        warning = False
        if used >= config.max_value * (1 - config.grace_percent):
            warning = True
        
        result = {
            'allowed': allowed,
            'remaining': remaining,
            'used': used,
            'limit': config.max_value,
            'warning': warning
        }
        
        if not allowed:
            logger.warning(f"Global limit exceeded: {limit_type.value}")
        
        return result
    
    def get_user_usage(self, user_id: int, limit_type: LimitType) -> int:
        """دریافت میزان استفاده کاربر"""
        cache_key = f"{user_id}_{limit_type.value}"
        
        # بررسی کش
        if cache_key in self.user_cache:
            cached_time, cached_value = self.user_cache[cache_key]
            if time.time() - cached_time < self.cache_timeout:
                return cached_value
        
        config = self.limits_config.get(limit_type.value)
        now = datetime.now()
        
        if config.period_seconds > 0:
            # محدودیت دوره‌ای
            period_start = now - timedelta(seconds=config.period_seconds)
            
            self.cursor.execute('''
            SELECT COALESCE(SUM(used_value), 0)
            FROM user_limits
            WHERE user_id = ? AND limit_type = ? 
            AND period_start >= ? AND period_end <= ?
            ''', (user_id, limit_type.value, period_start.isoformat(), now.isoformat()))
        else:
            # محدودیت کل
            self.cursor.execute('''
            SELECT COALESCE(SUM(used_value), 0)
            FROM user_limits
            WHERE user_id = ? AND limit_type = ?
            ''', (user_id, limit_type.value))
        
        result = self.cursor.fetchone()
        used = result[0] if result else 0
        
        # ذخیره در کش
        self.user_cache[cache_key] = (time.time(), used)
        
        return used
    
    def get_global_usage(self, limit_type: LimitType) -> int:
        """دریافت میزان استفاده سراسری"""
        cache_key = f"global_{limit_type.value}"
        
        # بررسی کش
        if cache_key in self.global_cache:
            cached_time, cached_value = self.global_cache[cache_key]
            if time.time() - cached_time < self.cache_timeout:
                return cached_value
        
        config = self.limits_config.get(limit_type.value)
        now = datetime.now()
        
        if config.period_seconds > 0:
            # محدودیت دوره‌ای
            period_start = now - timedelta(seconds=config.period_seconds)
            
            self.cursor.execute('''
            SELECT COALESCE(SUM(used_value), 0)
            FROM global_limits
            WHERE limit_type = ? 
            AND period_start >= ? AND period_end <= ?
            ''', (limit_type.value, period_start.isoformat(), now.isoformat()))
        else:
            # محدودیت کل
            self.cursor.execute('''
            SELECT COALESCE(SUM(used_value), 0)
            FROM global_limits
            WHERE limit_type = ?
            ''', (limit_type.value,))
        
        result = self.cursor.fetchone()
        used = result[0] if result else 0
        
        # ذخیره در کش
        self.global_cache[cache_key] = (time.time(), used)
        
        return used
    
    def increment_user_usage(self, user_id: int, limit_type: LimitType, 
                           value: int = 1, **kwargs):
        """افزایش میزان استفاده کاربر"""
        config = self.limits_config.get(limit_type.value)
        now = datetime.now()
        
        if config.period_seconds > 0:
            # محدودیت دوره‌ای
            period_start = now
            period_end = now + timedelta(seconds=config.period_seconds)
        else:
            # محدودیت کل
            period_start = now
            period_end = None
        
        # ثبت در دیتابیس
        self.cursor.execute('''
        INSERT INTO user_limits 
        (user_id, limit_type, used_value, period_start, period_end, last_updated)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, limit_type, period_start) 
        DO UPDATE SET 
            used_value = used_value + ?,
            last_updated = ?
        ''', (
            user_id, limit_type.value, value, 
            period_start.isoformat(), 
            period_end.isoformat() if period_end else None,
            now.isoformat(),
            value, now.isoformat()
        ))
        
        # ثبت در تاریخچه
        self.cursor.execute('''
        INSERT INTO limits_history 
        (user_id, limit_type, action, value, timestamp, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id, limit_type.value, 'increment', value,
            now.isoformat(),
            kwargs.get('ip_address', ''),
            kwargs.get('user_agent', '')
        ))
        
        self.conn.commit()
        
        # پاکسازی کش
        cache_key = f"{user_id}_{limit_type.value}"
        if cache_key in self.user_cache:
            del self.user_cache[cache_key]
    
    def increment_global_usage(self, limit_type: LimitType, value: int = 1):
        """افزایش میزان استفاده سراسری"""
        config = self.limits_config.get(limit_type.value)
        now = datetime.now()
        
        if config.period_seconds > 0:
            # محدودیت دوره‌ای
            period_start = now
            period_end = now + timedelta(seconds=config.period_seconds)
        else:
            # محدودیت کل
            period_start = now
            period_end = None
        
        # ثبت در دیتابیس
        self.cursor.execute('''
        INSERT INTO global_limits 
        (limit_type, used_value, period_start, period_end, last_updated)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(limit_type) 
        DO UPDATE SET 
            used_value = used_value + ?,
            last_updated = ?,
            period_start = ?,
            period_end = ?
        ''', (
            limit_type.value, value, 
            period_start.isoformat(), 
            period_end.isoformat() if period_end else None,
            now.isoformat(),
            value, now.isoformat(),
            period_start.isoformat(),
            period_end.isoformat() if period_end else None
        ))
        
        self.conn.commit()
        
        # پاکسازی کش
        cache_key = f"global_{limit_type.value}"
        if cache_key in self.global_cache:
            del self.global_cache[cache_key]
    
    def get_user_tier(self, user_id: int) -> str:
        """دریافت tier کاربر"""
        # در اینجا می‌توانید از دیتابیس کاربران خوانده شود
        # به صورت پیش‌فرض free در نظر می‌گیریم
        return "free"
    
    def get_tiered_limit(self, limit_type: LimitType, tier: str) -> Optional[int]:
        """دریافت محدودیت بر اساس tier"""
        config = self.limits_config.get(limit_type.value)
        if not config:
            return None
        
        # خواندن tiered limits از config
        tiered_limits = self.get_tiered_limits_from_config()
        
        limit_key = limit_type.value
        if limit_key in tiered_limits and tier in tiered_limits[limit_key]:
            return tiered_limits[limit_key][tier]
        
        return None
    
    def get_tiered_limits_from_config(self) -> Dict:
        """دریافت محدودیت‌های tiered از config"""
        tiered_limits = {}
        
        for limit_key, config in self.limits_config.items():
            # بارگذاری config کامل
            config_file = Path("config/limits_config.json")
            with open(config_file, 'r', encoding='utf-8') as f:
                full_config = json.load(f)
            
            if limit_key in full_config and 'tiered_limits' in full_config[limit_key]:
                tiered_limits[limit_key] = full_config[limit_key]['tiered_limits']
        
        return tiered_limits
    
    def get_next_reset_time(self, user_id: int, limit_type: LimitType) -> str:
        """زمان reset بعدی"""
        config = self.limits_config.get(limit_type.value)
        
        if not config or config.period_seconds <= 0:
            return None
        
        # آخرین period_start را پیدا کن
        self.cursor.execute('''
        SELECT MAX(period_start)
        FROM user_limits
        WHERE user_id = ? AND limit_type = ?
        ''', (user_id, limit_type.value))
        
        result = self.cursor.fetchone()
        if result and result[0]:
            last_start = datetime.fromisoformat(result[0])
            next_reset = last_start + timedelta(seconds=config.period_seconds)
            return next_reset.isoformat()
        
        return None
    
    def record_violation(self, user_id: int, limit_type: LimitType, 
                        attempted_value: int, current_usage: int, limit: int):
        """ثبت تخلف"""
        exceeded_by = attempted_value - (limit - current_usage)
        
        self.cursor.execute('''
        INSERT INTO violations 
        (user_id, limit_type, exceeded_by, timestamp, action_taken)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            user_id, limit_type.value, exceeded_by,
            datetime.now().isoformat(),
            'recorded'
        ))
        
        self.conn.commit()
        
        logger.warning(
            f"User {user_id} violated {limit_type.value} limit: "
            f"attempted {attempted_value}, used {current_usage}, limit {limit}"
        )
    
    def reset_user_limits(self, user_id: int, limit_type: LimitType = None):
        """ریست محدودیت‌های کاربر"""
        if limit_type:
            self.cursor.execute('''
            DELETE FROM user_limits
            WHERE user_id = ? AND limit_type = ?
            ''', (user_id, limit_type.value))
        else:
            self.cursor.execute('''
            DELETE FROM user_limits
            WHERE user_id = ?
            ''', (user_id,))
        
        self.conn.commit()
        
        # پاکسازی کش
        if limit_type:
            cache_key = f"{user_id}_{limit_type.value}"
            if cache_key in self.user_cache:
                del self.user_cache[cache_key]
        else:
            # پاکسازی همه کش‌های این کاربر
            keys_to_remove = [
                k for k in self.user_cache.keys() 
                if k.startswith(f"{user_id}_")
            ]
            for key in keys_to_remove:
                del self.user_cache[key]
    
    def get_user_stats(self, user_id: int) -> Dict:
        """آمار کامل کاربر"""
        stats = {
            'user_id': user_id,
            'tier': self.get_user_tier(user_id),
            'limits': {},
            'violations': []
        }
        
        for limit_type in LimitType:
            limit_key = limit_type.value
            config = self.limits_config.get(limit_key)
            
            if config:
                used = self.get_user_usage(user_id, limit_type)
                limit = self.get_tiered_limit(limit_type, stats['tier']) or config.max_value
                
                stats['limits'][limit_key] = {
                    'used': used,
                    'limit': limit,
                    'remaining': max(0, limit - used),
                    'percent_used': (used / limit * 100) if limit > 0 else 0,
                    'next_reset': self.get_next_reset_time(user_id, limit_type)
                }
        
        # دریافت تخلفات
        self.cursor.execute('''
        SELECT limit_type, exceeded_by, timestamp, action_taken
        FROM violations
        WHERE user_id = ? AND resolved = 0
        ORDER BY timestamp DESC
        LIMIT 10
        ''', (user_id,))
        
        for row in self.cursor.fetchall():
            stats['violations'].append({
                'limit_type': row[0],
                'exceeded_by': row[1],
                'timestamp': row[2],
                'action_taken': row[3]
            })
        
        return stats
    
    def close(self):
        """بستن اتصالات"""
        if self.conn:
            self.conn.close()

# تابع کمکی برای استفاده آسان
def create_limits_manager() -> LimitsManager:
    """ایجاد instance از Limits Manager"""
    return LimitsManager()
