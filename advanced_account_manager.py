#advanced_account_manager.py
#!/usr/bin/env python3
"""
🔐 سیستم مدیریت پیشرفته اکانت تلگرام
ویژگی‌ها:
1. رمزنگاری AES-256 برای sessions و داده‌های حساس
2. سیستم چند اکانتی با load balancing
3. تشخیص ناهنجاری و امنیت پیشرفته
4. API REST برای مدیریت اکانت‌ها
5. مانیتورینگ real-time و alerting
6. Backup خودکار و recovery
7. پشتیبانی از proxy و TOR
8. Webhook برای رویدادها
"""

import asyncio
import json
import logging
import sys
import signal
import secrets
import hashlib
import base64
import re
import getpass
import sqlite3
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple, Union, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
import pickle
import zlib
import jwt
import bcrypt
import string
import hmac
from ipaddress import ip_address, ip_network
import os
from ipaddress import ip_address, ip_network
from collections import defaultdict


# کتابخانه‌های امنیتی
try:
    import jwt
    import bcrypt
    import argon2
    HAS_SECURITY_LIBS = True
except ImportError:
    HAS_SECURITY_LIBS = False
    print("❌ برای احراز هویت پیشرفته نصب کنید: pip install pyjwt bcrypt argon2-cffi")
    sys.exit(1)

# بارگذاری متغیرهای محیطی
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)
# ========== کتابخانه‌های ضروری ==========
try:
    
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    print("⚠️ برای رمزنگاری پیشرفته: pip install cryptography")

try:
    from telethon import TelegramClient, functions, types
    from telethon.sessions import SQLiteSession, StringSession
    from telethon.errors import (
        SessionPasswordNeededError,
        PhoneCodeInvalidError,
        PhoneNumberInvalidError,
        FloodWaitError,
        AuthKeyDuplicatedError,
        PhoneCodeExpiredError,
        ApiIdInvalidError
    )
    HAS_TELETHON = True
except ImportError:
    HAS_TELETHON = False
    print("❌ Telethon ضروری است: pip install telethon")

try:
    import aiohttp
    from aiohttp import web
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    print("⚠️ برای API سرور: pip install aiohttp")
    
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("⚠️ برای مانیتورینگ: pip install psutil")

# ========== تنظیمات لاگ پیشرفته ==========

class ColorFormatter(logging.Formatter):
    """فرمت رنگی برای لاگ‌ها"""
    COLORS = {
        'DEBUG': '\033[36m',
        'INFO': '\033[32m',
        'WARNING': '\033[33m',
        'ERROR': '\033[31m',
        'CRITICAL': '\033[41m',
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_message = super().format(record)
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        return f"{color}{log_message}{self.COLORS['RESET']}"

def setup_logging(debug: bool = False):
    """تنظیم سیستم لاگ‌گیری"""
    log_level = logging.DEBUG if debug else logging.INFO
    
    # ایجاد دایرکتوری logs
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # فرمت لاگ
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    color_formatter = ColorFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    handlers = []
    
    # Console handler با رنگ
    console = logging.StreamHandler()
    console.setFormatter(color_formatter)
    handlers.append(console)
    
    # File handler
    file_handler = logging.FileHandler(
        log_dir / f"account_manager_{datetime.now().strftime('%Y%m%d')}.log",
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    handlers.append(file_handler)
    
    # Error file handler
    error_handler = logging.FileHandler(
        log_dir / "errors.log",
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    handlers.append(error_handler)
    
    # تنظیم root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )
    
    # تنظیم سطح لاگ برای کتابخانه‌های دیگر
    logging.getLogger('telethon').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    return logging.getLogger(__name__)

logger = setup_logging()

# ========== مدل‌های داده ==========

class AccountStatus(Enum):
    """وضعیت اکانت"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    BANNED = "banned"
    FLOOD_WAIT = "flood_wait"
    NEED_VERIFICATION = "need_verification"
    EXPIRED = "expired"

class LoginMethod(Enum):
    """روش ورود"""
    PHONE_CODE = "phone_code"
    PASSWORD = "password"
    QR_CODE = "qr_code"
    BOT_TOKEN = "bot_token"

@dataclass
class AccountInfo:
    """اطلاعات کامل اکانت"""
    account_id: str
    session_name: str
    user_id: int
    username: Optional[str]
    first_name: str
    last_name: Optional[str]
    phone: str
    phone_hash: str
    is_bot: bool = False
    is_premium: bool = False
    status: AccountStatus = AccountStatus.ACTIVE
    login_method: LoginMethod = LoginMethod.PHONE_CODE
    created_at: datetime = field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    total_messages: int = 0
    total_downloads: int = 0
    security_score: int = 100  # امتیاز امنیتی 0-100
    
    def to_dict(self) -> Dict:
        """تبدیل به دیکشنری"""
        data = asdict(self)
        data['status'] = self.status.value
        data['login_method'] = self.login_method.value
        data['created_at'] = self.created_at.isoformat()
        data['last_login'] = self.last_login.isoformat() if self.last_login else None
        data['last_activity'] = self.last_activity.isoformat() if self.last_activity else None
        return data

@dataclass
class LoginAttempt:
    """لاگ تلاش ورود"""
    attempt_id: str
    phone: str
    timestamp: datetime
    success: bool
    method: LoginMethod
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    error_message: Optional[str] = None
    response_time: Optional[float] = None

# ========== سیستم رمزنگاری پیشرفته ==========

class AdvancedEncryption:
    """سیستم رمزنگاری پیشرفته با چند لایه امنیتی"""
    
    def __init__(self, master_key: Optional[str] = None):
        if not HAS_CRYPTOGRAPHY:
            raise ImportError("کتابخانه cryptography ضروری است")
        
        if master_key:
            # استفاده از کلید اصلی
            self.master_key = self._derive_key(master_key.encode(), b'telegram_master_salt')
        else:
            # تولید کلید تصادفی
            self.master_key = secrets.token_bytes(32)
        
        # کلیدهای مختلف برای اهداف مختلف
        self.session_key = self._derive_key(self.master_key, b'session_encryption')
        self.data_key = self._derive_key(self.master_key, b'data_encryption')
        self.auth_key = self._derive_key(self.master_key, b'auth_hmac')
        
        # ایجاد cipherها
        self.session_cipher = AESGCM(self.session_key)
        self.data_cipher = AESGCM(self.data_key)
        
        logger.info("سیستم رمزنگاری پیشرفته راه‌اندازی شد")
    
    def _derive_key(self, password: bytes, salt: bytes, iterations: int = 100000) -> bytes:
        """استخراج کلید با PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations
        )
        return kdf.derive(password)
    
    def encrypt_session(self, session_data: bytes) -> Dict[str, str]:
        """رمزنگاری session با احراز هویت"""
        nonce = secrets.token_bytes(12)
        
        # رمزنگاری
        ciphertext = self.session_cipher.encrypt(
            nonce,
            session_data,
            associated_data=b'session_encryption'
        )
        
        # HMAC برای احراز هویت
        h = hmac.HMAC(self.auth_key, hashes.SHA256())
        h.update(nonce + ciphertext)
        tag = h.finalize()
        
        return {
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'version': '2.0',
            'timestamp': datetime.now().isoformat()
        }
    
    def decrypt_session(self, encrypted_data: Dict[str, str]) -> Optional[bytes]:
        """رمزگشایی و احراز هویت session"""
        try:
            nonce = base64.b64decode(encrypted_data['nonce'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            # بررسی HMAC
            h = hmac.HMAC(self.auth_key, hashes.SHA256())
            h.update(nonce + ciphertext)
            h.verify(tag)
            
            # رمزگشایی
            plaintext = self.session_cipher.decrypt(
                nonce,
                ciphertext,
                associated_data=b'session_encryption'
            )
            
            return plaintext
            
        except Exception as e:
            logger.error(f"خطا در رمزگشایی session: {e}")
            return None
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """رمزنگاری داده‌های حساس"""
        nonce = secrets.token_bytes(12)
        ciphertext = self.data_cipher.encrypt(
            nonce,
            data.encode('utf-8'),
            associated_data=None
        )
        
        # ترکیب nonce + ciphertext
        encrypted = nonce + ciphertext
        return base64.b64encode(encrypted).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> Optional[str]:
        """رمزگشایی داده‌های حساس"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]
            
            plaintext = self.data_cipher.decrypt(
                nonce,
                ciphertext,
                associated_data=None
            )
            
            return plaintext.decode('utf-8')
        except Exception as e:
            logger.error(f"خطا در رمزگشایی داده: {e}")
            return None

# ========== سیستم تشخیص ناهنجاری ==========

class AnomalyDetector:
    """تشخیص رفتارهای غیرعادی و حملات"""
    
    def __init__(self):
        self.login_patterns: Dict[str, List[datetime]] = {}
        self.failed_attempts: Dict[str, int] = {}
        self.geo_locations: Dict[str, List[str]] = {}
        self.device_fingerprints: Dict[str, List[str]] = {}
        self.lock = Lock()
        
        # الگوهای حمله شناخته شده
        self.malicious_patterns = {
            'rapid_logins': 5,  # بیش از 5 لاگین در دقیقه
            'multiple_failures': 3,  # بیش از 3 شکست متوالی
            'geo_hopping': 2,  # تغییر مکان جغرافیایی سریع
            'device_changes': 3  # تغییر دستگاه مکرر
        }
    
    def analyze_login_attempt(self, attempt: LoginAttempt) -> Dict[str, Any]:
        """تحلیل تلاش ورود برای تشخیص ناهنجاری"""
        anomalies = []
        risk_score = 0
        
        with self.lock:
            phone = attempt.phone
            
            # 1. بررسی rate limiting
            if phone not in self.login_patterns:
                self.login_patterns[phone] = []
            
            # حذف لاگین‌های قدیمی
            cutoff = datetime.now() - timedelta(minutes=1)
            self.login_patterns[phone] = [
                t for t in self.login_patterns[phone] if t > cutoff
            ]
            
            # اضافه کردن لاگین فعلی
            self.login_patterns[phone].append(attempt.timestamp)
            
            # بررسی تعداد لاگین‌های سریع
            if len(self.login_patterns[phone]) > self.malicious_patterns['rapid_logins']:
                anomalies.append("rapid_login_attempts")
                risk_score += 30
            
            # 2. بررسی شکست‌های متوالی
            if not attempt.success:
                self.failed_attempts[phone] = self.failed_attempts.get(phone, 0) + 1
                
                if self.failed_attempts[phone] > self.malicious_patterns['multiple_failures']:
                    anomalies.append("multiple_failed_attempts")
                    risk_score += 40
            else:
                self.failed_attempts[phone] = 0
            
            # 3. بررسی جغرافیا (اگر IP موجود باشد)
            if attempt.ip_address:
                if phone not in self.geo_locations:
                    self.geo_locations[phone] = []
                
                # استخراج کشور از IP (شبیه‌سازی)
                country = self._ip_to_country(attempt.ip_address)
                self.geo_locations[phone].append(country)
                
                # بررسی تغییرات سریع جغرافیایی
                if len(self.geo_locations[phone]) > 1:
                    unique_countries = len(set(self.geo_locations[phone][-3:]))
                    if unique_countries > self.malicious_patterns['geo_hopping']:
                        anomalies.append("suspicious_geo_hopping")
                        risk_score += 30
        
        return {
            'has_anomalies': len(anomalies) > 0,
            'anomalies': anomalies,
            'risk_score': min(risk_score, 100),
            'recommendation': self._get_recommendation(anomalies, risk_score)
        }
    
    def _ip_to_country(self, ip: str) -> str:
        """تبدیل IP به کشور (شبیه‌سازی)"""
        # در پروژه واقعی از GeoIP database استفاده کنید
        return "IR"  # شبیه‌سازی
    
    def _get_recommendation(self, anomalies: List[str], risk_score: int) -> str:
        """پیشنهادات امنیتی براساس ریسک"""
        if risk_score >= 70:
            return "BLOCK_IMMEDIATE"
        elif risk_score >= 50:
            return "REQUIRE_2FA"
        elif risk_score >= 30:
            return "REQUIRE_CAPTCHA"
        else:
            return "ALLOW"

# ========== سیستم مانیتورینگ real-time ==========

class AccountMonitor:
    """مانیتورینگ real-time اکانت‌ها"""
    
    def __init__(self):
        self.account_metrics: Dict[str, Dict] = {}
        self.alerts: List[Dict] = []
        self.metrics_history: Dict[str, List] = {}
        self.last_check = datetime.now()
        self.lock = Lock()
        
        # آستانه‌های هشدار
        self.alert_thresholds = {
            'inactive_hours': 24,
            'flood_wait_count': 3,
            'login_failures': 5,
            'memory_usage_mb': 500,
            'api_errors': 10
        }
    
    async def monitor_account(self, account_id: str, client: TelegramClient) -> Dict:
        """مانیتورینگ وضعیت اکانت"""
        metrics = {
            'timestamp': datetime.now(),
            'is_connected': client.is_connected(),
            'last_seen': None,
            'unread_count': 0,
            'memory_usage': self._get_memory_usage(),
            'api_latency': await self._check_api_latency(client),
            'is_online': await self._check_online_status(client)
        }
        
        with self.lock:
            self.account_metrics[account_id] = metrics
            
            # ذخیره تاریخچه
            if account_id not in self.metrics_history:
                self.metrics_history[account_id] = []
            
            self.metrics_history[account_id].append(metrics)
            
            # حفظ فقط 100 رکورد آخر
            if len(self.metrics_history[account_id]) > 100:
                self.metrics_history[account_id] = self.metrics_history[account_id][-100:]
            
            # بررسی هشدارها
            await self._check_alerts(account_id, metrics)
        
        return metrics
    
    async def _check_api_latency(self, client: TelegramClient) -> float:
        """بررسی تأخیر API"""
        import time
        
        try:
            start = time.time()
            await client.get_me()
            end = time.time()
            return end - start
        except:
            return -1
    
    async def _check_online_status(self, client: TelegramClient) -> bool:
        """بررسی وضعیت آنلاین"""
        try:
            me = await client.get_me()
            return me.status is not None
        except:
            return False
    
    def _get_memory_usage(self) -> float:
        """مصرف حافظه"""
        import psutil
        try:
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # MB
        except:
            return 0
    
    async def _check_alerts(self, account_id: str, metrics: Dict):
        """بررسی و ایجاد هشدار"""
        alerts = []
        
        # بررسی اتصال
        if not metrics['is_connected']:
            alerts.append({
                'type': 'DISCONNECTED',
                'account_id': account_id,
                'message': 'اکانت قطع شده است',
                'severity': 'HIGH'
            })
        
        # بررسی تأخیر API
        if metrics['api_latency'] > 5.0:  # بیش از 5 ثانیه
            alerts.append({
                'type': 'HIGH_LATENCY',
                'account_id': account_id,
                'message': f'تأخیر API بالا: {metrics["api_latency"]:.2f}s',
                'severity': 'MEDIUM'
            })
        
        # بررسی مصرف حافظه
        if metrics['memory_usage'] > self.alert_thresholds['memory_usage_mb']:
            alerts.append({
                'type': 'HIGH_MEMORY',
                'account_id': account_id,
                'message': f'مصرف حافظه بالا: {metrics["memory_usage"]:.2f}MB',
                'severity': 'MEDIUM'
            })
        
        # ذخیره هشدارها
        if alerts:
            self.alerts.extend(alerts)
            logger.warning(f"هشدار برای اکانت {account_id}: {alerts}")

# ========== سیستم مدیریت اکانت پیشرفته ==========

class AdvancedAccountManager:
    """مدیریت پیشرفته اکانت‌های تلگرام"""
    
    def __init__(self, base_dir: Path = Path("accounts"), 
                 encryption_key: Optional[str] = None,
                 api_id: Optional[int] = None,
                 api_hash: Optional[str] = None):
        
        self.base_dir = base_dir
        self.api_id = api_id
        self.api_hash = api_hash
        
        # ایجاد دایرکتوری‌ها
        self.directories = {
            'sessions': base_dir / "sessions",
            'encrypted': base_dir / "encrypted",
            'backups': base_dir / "backups",
            'logs': base_dir / "logs",
            'temp': base_dir / "temp",
            'exports': base_dir / "exports"
        }
                     
        # سیستم احراز هویت پیشرفته
        self.auth_system = AdvancedAuthMiddleware(
            jwt_secret=config.get('jwt_secret', secrets.token_urlsafe(64)),
            token_expiry_hours=config.get('token_expiry_hours', 24),
            rate_limit_per_minute=config.get('rate_limit', 100),
            allowed_ips=config.get('allowed_ips'),
            blocked_ips=config.get('blocked_ips', [])
        )

        for name, path in self.directories.items():
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # سیستم‌های اصلی
        self.encryption = AdvancedEncryption(encryption_key) if HAS_CRYPTOGRAPHY else None
        self.anomaly_detector = AnomalyDetector()
        self.monitor = AccountMonitor()
        self.database = AccountDatabase(base_dir / "accounts.db")
        
        # کش اکانت‌های فعال
        self.active_accounts: Dict[str, Dict] = {}
        self.account_pool = ThreadPoolExecutor(max_workers=10)
        self.locks: Dict[str, Lock] = {}
        
        # Webhook برای رویدادها
        self.webhook_url = None
        self.webhook_secret = secrets.token_urlsafe(32)
        
        # تنظیمات proxy
        self.proxy_settings = None
        
        logger.info("مدیریت اکانت پیشرفته راه‌اندازی شد")
    
    # ========== سیستم ورود پیشرفته ==========
    
    async def login_with_phone_advanced(
        self,
        phone: str,
        session_name: Optional[str] = None,  # ✅ باید Optional باشد
        use_proxy: bool = False,
        enable_2fa: bool = True,
        device_info: Optional[Dict] = None
    ) -> Tuple[bool, Optional[TelegramClient], Optional[str]]:
        """ورود پیشرفته با شماره تلفن"""
        
        # اعتبارسنجی شماره
        if not self._validate_phone_number(phone):
            return False, None, "شماره تلفن نامعتبر"
        
        # بررسی امنیتی اولیه
        security_check = await self._pre_login_security_check(phone)
        if not security_check['allowed']:
            return False, None, security_check['reason']
        
        # ایجاد نام session
        if not session_name:
            session_name = self._generate_session_name(phone)
        
        session_path = self.directories['sessions'] / f"{session_name}.session"
        
        # تنظیمات دستگاه
        if not device_info:
            device_info = self._get_default_device_info()
        
        try:
            # ایجاد کلاینت با تنظیمات پیشرفته
            client = await self._create_advanced_client(
                session_path=session_path,
                device_info=device_info,
                use_proxy=use_proxy
            )
            
            # لاگ تلاش ورود
            attempt = LoginAttempt(
                attempt_id=secrets.token_hex(8),
                phone=phone,
                timestamp=datetime.now(),
                success=False,
                method=LoginMethod.PHONE_CODE,
                ip_address=self._get_client_ip(),
                user_agent="AdvancedAccountManager/2.0"
            )
            
            # بررسی session موجود
            if await client.is_user_authorized():
                logger.info(f"Session موجود برای {phone}")
                attempt.success = True
                await self._log_login_attempt(attempt)
                
                # بارگذاری اطلاعات اکانت
                account_info = await self._load_or_create_account(client, phone, session_name)
                return True, client, account_info.account_id
            
            # درخواست کد تأیید
            logger.info(f"درخواست کد برای {phone}")
            
            try:
                sent = await client.send_code_request(phone)
                phone_code_hash = sent.phone_code_hash
                
                # ارسال webhook برای درخواست کد
                await self._send_webhook('code_requested', {
                    'phone': phone,
                    'session_name': session_name,
                    'timestamp': datetime.now().isoformat()
                })
                
            except FloodWaitError as e:
                logger.warning(f"Flood wait: {e.seconds} seconds")
                attempt.error_message = f"Flood wait {e.seconds}s"
                await self._log_login_attempt(attempt)
                
                # ذخیره flood wait در دیتابیس
                await self.database.update_account_status(
                    session_name, AccountStatus.FLOOD_WAIT, e.seconds
                )
                
                return False, None, f"لطفاً {e.seconds} ثانیه صبر کنید"
            
            # دریافت کد از کاربر (چند روش)
            code = await self._get_verification_code_interactive(phone)
            if code.lower() == 'resend':
                return await self.login_with_phone_advanced(
                    phone, session_name, use_proxy, enable_2fa, device_info
                )
            
            # تلاش برای ورود با کد
            try:
                await client.sign_in(
                    phone=phone,
                    code=code,
                    phone_code_hash=phone_code_hash
                )
                
                logger.info(f"ورود موفق با کد برای {phone}")
                attempt.success = True
                
            except SessionPasswordNeededError:
                # نیاز به رمز دو مرحله‌ای
                if enable_2fa:
                    password = await self._get_2fa_password_secure()
                    
                    try:
                        await client.sign_in(password=password)
                        attempt.method = LoginMethod.PASSWORD
                        attempt.success = True
                        logger.info(f"ورود موفق با 2FA برای {phone}")
                    except Exception as e:
                        attempt.error_message = str(e)
                        await self._log_login_attempt(attempt)
                        return False, None, f"رمز دو مرحله‌ای نامعتبر: {e}"
                else:
                    return False, None, "اکانت نیاز به رمز دو مرحله‌ای دارد"
            
            except PhoneCodeInvalidError:
                attempt.error_message = "کد تأیید نامعتبر"
                await self._log_login_attempt(attempt)
                return False, None, "کد تأیید نامعتبر"
            
            except PhoneCodeExpiredError:
                attempt.error_message = "کد تأیید منقضی شده"
                await self._log_login_attempt(attempt)
                return False, None, "کد تأیید منقضی شده. لطفاً دوباره تلاش کنید"
            
            # تأیید نهایی ورود
            if await client.is_user_authorized():
                attempt.response_time = (datetime.now() - attempt.timestamp).total_seconds()
                await self._log_login_attempt(attempt)
                
                # تحلیل ناهنجاری
                anomaly_result = self.anomaly_detector.analyze_login_attempt(attempt)
                
                if anomaly_result['has_anomalies']:
                    logger.warning(f"ناهنجاری تشخیص داده شد: {anomaly_result}")
                    
                    # اقدامات امنیتی براساس سطح ریسک
                    if anomaly_result['risk_score'] >= 70:
                        await client.disconnect()
                        return False, None, "ورود مسدود شد (ریسک امنیتی بالا)"
                
                # ایجاد/بارگذاری اطلاعات اکانت
                account_info = await self._load_or_create_account(client, phone, session_name)
                
                # ذخیره session رمزنگاری شده
                if self.encryption:
                    await self._encrypt_and_save_session(session_path, session_name)
                
                # شروع مانیتورینگ
                asyncio.create_task(
                    self.monitor.monitor_account(account_info.account_id, client)
                )
                
                # ارسال webhook برای ورود موفق
                await self._send_webhook('login_successful', {
                    'account_id': account_info.account_id,
                    'phone': phone,
                    'session_name': session_name,
                    'timestamp': datetime.now().isoformat(),
                    'risk_score': anomaly_result.get('risk_score', 0)
                })
                
                return True, client, account_info.account_id
            
            return False, None, "ورود ناموفق"
            
        except ApiIdInvalidError:
            return False, None, "API ID یا Hash نامعتبر"
        except Exception as e:
            logger.error(f"خطای ناشناخته در ورود: {e}")
            return False, None, f"خطای سیستمی: {str(e)}"
    
    async def login_with_qr(self) -> Tuple[bool, Optional[TelegramClient], Optional[str]]:
        """ورود با QR Code - متد اصلی"""
        try:
            session_name = self._generate_session_name("qr_login")
            session_path = self.directories['sessions'] / f"{session_name}.session"
            
            client = TelegramClient(
                session=str(session_path),
                api_id=self.api_id,
                api_hash=self.api_hash
            )
            
            await client.connect()
            
            # ایجاد QR Code
            qr_login = await client.qr_login()
            
            print("\n" + "="*50)
            print("📱 لطفاً QR Code زیر را با تلگرام اسکن کنید:")
            print("="*50)
            print(qr_login.url)
            print("\n⏳ منتظر تأیید... (30 ثانیه)")
            
            # انتظار برای تأیید
            try:
                await asyncio.wait_for(qr_login.wait(), timeout=30)
                
                if await client.is_user_authorized():
                    me = await client.get_me()
                    
                    # ایجاد اطلاعات اکانت
                    account_info = await self._create_account_info(
                        client, me.phone, session_name, LoginMethod.QR_CODE
                    )
                    
                    logger.info(f"ورود QR موفق برای {me.phone}")
                    return True, client, account_info.account_id
                
            except asyncio.TimeoutError:
                return False, None, "زمان اسکن QR Code به پایان رسید"
            
            return False, None, "ورود با QR ناموفق"
            
        except Exception as e:
            logger.error(f"خطا در ورود QR: {e}")
            return False, None, f"خطا در ورود QR: {str(e)}"
    
    async def login_with_qr_code(self) -> Tuple[bool, Optional[TelegramClient], Optional[str]]:
        """ورود با QR Code - سازگار با main.py"""
        return await self.login_with_qr()

    # اضافه کردن این متدها به کلاس AdvancedAccountManager
    
    async def handle_login(self, request):
        """Handler برای ورود"""
        try:
            data = await request.json()
            phone = data.get('phone')
            
            if not phone:
                return web.json_response({
                    'success': False,
                    'error': 'شماره تلفن الزامی است'
                }, status=400)
            
            success, client, account_id = await self.login_with_phone_advanced(phone=phone)
            
            return web.json_response({
                'success': success,
                'account_id': account_id,
                'message': 'ورود موفق' if success else 'ورود ناموفق'
            })
        except Exception as e:
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)
    
    async def handle_logout(self, request):
        """Handler برای خروج"""
        try:
            account_id = request.match_info.get('account_id')
            
            if account_id in self.active_accounts:
                client = self.active_accounts[account_id].get('client')
                if client:
                    await client.disconnect()
                del self.active_accounts[account_id]
            
            return web.json_response({
                'success': True,
                'message': 'اکانت خارج شد'
            })
        except Exception as e:
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)
    
    async def handle_status(self, request):
        """Handler برای وضعیت"""
        account_id = request.match_info.get('account_id')
        
        if account_id in self.active_accounts:
            return web.json_response({
                'success': True,
                'account_id': account_id,
                'status': 'active',
                'data': self.active_accounts[account_id]
            })
        else:
            return web.json_response({
                'success': False,
                'error': 'اکانت یافت نشد'
            }, status=404)
    
    async def handle_backup(self, request):
        """Handler برای backup"""
        try:
            account_id = request.match_info.get('account_id')
            data = await request.json()
            backup_type = data.get('type', 'full')
            
            backup_path = await self.backup_account(account_id, backup_type)
            
            if backup_path:
                return web.json_response({
                    'success': True,
                    'backup_path': str(backup_path),
                    'message': 'Backup ایجاد شد'
                })
            else:
                return web.json_response({
                    'success': False,
                    'error': 'خطا در ایجاد backup'
                }, status=500)
        except Exception as e:
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)
    
    async def handle_webhook(self, request):
        """Handler برای webhook"""
        try:
            data = await request.json()
            logger.info(f"Webhook دریافت شد: {data}")
            
            return web.json_response({
                'success': True,
                'message': 'Webhook دریافت شد'
            })
        except Exception as e:
            return web.json_response({
                'success': False,
                'error': str(e)
            }, status=500)
        
        # ادامه پردازش
        return await handler(request)
    
    # ========== سیستم چند اکانتی ==========
    
    async def create_account_pool(self, accounts: List[Dict]) -> Dict[str, TelegramClient]:
        """ایجاد استخر اکانت برای load balancing"""
        account_pool = {}
        
        for account_config in accounts:
            phone = account_config.get('phone')
            session_name = account_config.get('session_name')
            
            if phone and session_name:
                success, client, account_id = await self.login_with_phone_advanced(
                    phone=phone,
                    session_name=session_name,
                    use_proxy=account_config.get('use_proxy', False)
                )
                
                if success and client:
                    account_pool[account_id] = client
        
        logger.info(f"استخر اکانت با {len(account_pool)} اکانت ایجاد شد")
        return account_pool
    
    async def get_account_for_task(self, task_type: str) -> Optional[TelegramClient]:
        """دریافت اکانت مناسب برای task خاص"""
        # الگوریتم load balancing هوشمند
        available_accounts = []
        
        for account_id, account_data in self.active_accounts.items():
            client = account_data.get('client')
            metrics = account_data.get('metrics', {})
            
            if client and client.is_connected():
                # بررسی workload اکانت
                workload = metrics.get('workload', 0)
                api_latency = metrics.get('api_latency', 0)
                
                if workload < 5 and api_latency < 3.0:  # آستانه‌ها
                    available_accounts.append((account_id, client, workload))
        
        if not available_accounts:
            return None
        
        # انتخاب اکانت با کمترین workload
        available_accounts.sort(key=lambda x: x[2])
        selected_account = available_accounts[0]
        
        # به‌روزرسانی workload
        account_id, client, _ = selected_account
        if account_id in self.active_accounts:
            self.active_accounts[account_id]['workload'] = \
                self.active_accounts[account_id].get('workload', 0) + 1
        
        return client
    
    # ========== مدیریت session ==========
    
    async def backup_account(self, account_id: str, 
                           backup_type: str = "full") -> Optional[Path]:
        """تهیه backup از اکانت"""
        try:
            if account_id not in self.active_accounts:
                return None
            
            account_data = self.active_accounts[account_id]
            session_name = account_data.get('session_name')
            
            if not session_name:
                return None
            
            # مسیر فایل‌های session
            session_file = self.directories['sessions'] / f"{session_name}.session"
            encrypted_file = self.directories['encrypted'] / f"{session_name}.enc"
            
            # ایجاد فایل backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = self.directories['backups'] / f"{session_name}_{timestamp}.backup"
            
            backup_data = {
                'account_id': account_id,
                'session_name': session_name,
                'backup_type': backup_type,
                'timestamp': timestamp,
                'files': {}
            }
            
            # backup از فایل session
            if session_file.exists():
                with open(session_file, 'rb') as f:
                    session_data = f.read()
                
                backup_data['files']['session'] = base64.b64encode(session_data).decode()
            
            # backup از فایل رمزنگاری شده
            if encrypted_file.exists():
                with open(encrypted_file, 'rb') as f:
                    encrypted_data = f.read()
                
                backup_data['files']['encrypted'] = base64.b64encode(encrypted_data).decode()
            
            # ذخیره backup
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, ensure_ascii=False, indent=2)
            
            # فشرده‌سازی
            compressed_file = await self._compress_backup(backup_file)
            
            logger.info(f"Backup ایجاد شد: {compressed_file}")
            return compressed_file
            
        except Exception as e:
            logger.error(f"خطا در backup: {e}")
            return None
    
    async def restore_account(self, backup_file: Path) -> bool:
        """بازیابی اکانت از backup"""
        try:
            # decompress فایل
            decompressed_file = await self._decompress_backup(backup_file)
            
            with open(decompressed_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            session_name = backup_data.get('session_name')
            
            # بازیابی session
            if 'session' in backup_data['files']:
                session_data = base64.b64decode(backup_data['files']['session'])
                session_file = self.directories['sessions'] / f"{session_name}.session"
                
                with open(session_file, 'wb') as f:
                    f.write(session_data)
            
            # بازیابی فایل رمزنگاری شده
            if 'encrypted' in backup_data['files']:
                encrypted_data = base64.b64decode(backup_data['files']['encrypted'])
                encrypted_file = self.directories['encrypted'] / f"{session_name}.enc"
                
                with open(encrypted_file, 'wb') as f:
                    f.write(encrypted_data)
            
            logger.info(f"اکانت {session_name} بازیابی شد")
            return True
            
        except Exception as e:
            logger.error(f"خطا در بازیابی: {e}")
            return False
    
    async def export_account(self, account_id: str, 
                           password: str) -> Optional[Path]:
        """خروجی گرفتن از اکانت با رمز"""
        try:
            if account_id not in self.active_accounts:
                return None
            
            account_data = self.active_accounts[account_id]
            client = account_data.get('client')
            
            if not client:
                return None
            
            # ایجاد session string
            session_string = await client.session.save()
            
            # رمزنگاری با رمز کاربر
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            cipher = Fernet(key)
            encrypted_session = cipher.encrypt(session_string.encode())
            
            # ایجاد فایل export
            export_data = {
                'version': '1.0',
                'export_date': datetime.now().isoformat(),
                'salt': base64.b64encode(salt).decode(),
                'encrypted_session': base64.b64encode(encrypted_session).decode(),
                'account_info': account_data.get('info', {})
            }
            
            export_file = self.directories['exports'] / f"{account_id}_{datetime.now().strftime('%Y%m%d')}.export"
            
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            return export_file
            
        except Exception as e:
            logger.error(f"خطا در export: {e}")
            return None
    
    # ========== امنیت و مانیتورینگ ==========
    
    async def security_audit(self, account_id: str) -> Dict[str, Any]:
        """بررسی امنیتی اکانت"""
        if account_id not in self.active_accounts:
            return {'status': 'error', 'message': 'اکانت یافت نشد'}
        
        account_data = self.active_accounts[account_id]
        security_report = {
            'account_id': account_id,
            'timestamp': datetime.now().isoformat(),
            'checks': [],
            'score': 0,
            'recommendations': []
        }
        
        # 1. بررسی session
        session_check = await self._check_session_security(account_data)
        security_report['checks'].append(session_check)
        
        # 2. بررسی فعالیت‌های مشکوک
        activity_check = await self._check_suspicious_activity(account_id)
        security_report['checks'].append(activity_check)
        
        # 3. بررسی تنظیمات امنیتی
        settings_check = await self._check_security_settings(account_data)
        security_report['checks'].append(settings_check)
        
        # محاسبه امتیاز
        total_score = sum(check.get('score', 0) for check in security_report['checks'])
        security_report['score'] = total_score // len(security_report['checks'])
        
        # تولید پیشنهادات
        if security_report['score'] < 50:
            security_report['recommendations'].append("فعال‌سازی 2FA فوری")
        if security_report['score'] < 70:
            security_report['recommendations'].append("تغییر رمز session")
        
        return security_report
    
    async def rotate_session_key(self, account_id: str) -> bool:
        """تغییر کلید session برای امنیت بیشتر"""
        try:
            if account_id not in self.active_accounts:
                return False
            
            account_data = self.active_accounts[account_id]
            session_name = account_data.get('session_name')
            
            if not session_name:
                return False
            
            session_file = self.directories['sessions'] / f"{session_name}.session"
            
            if session_file.exists():
                # پشتیبان‌گیری
                backup = await self.backup_account(account_id, "pre_rotation")
                
                # حذف session قدیمی
                session_file.unlink()
                
                # ایجاد session جدید
                client = account_data.get('client')
                if client:
                    await client.disconnect()
                    
                    # اتصال مجدد برای ایجاد session جدید
                    await client.connect()
                    
                    # ذخیره session جدید
                    if self.encryption:
                        await self._encrypt_and_save_session(session_file, session_name)
                    
                    logger.info(f"کلید session برای {account_id} تغییر کرد")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"خطا در تغییر کلید: {e}")
            return False

    async def _check_session_security(self, account_data: Dict) -> Dict[str, Any]:
        """بررسی امنیت session"""
        try:
            client = account_data.get('client')
            if not client:
                return {'check': 'session', 'score': 0, 'message': 'کلاینت وجود ندارد'}
            
            session_file = self.directories['sessions'] / f"{account_data.get('session_name')}.session"
            encrypted_file = self.directories['encrypted'] / f"{account_data.get('session_name')}.enc"
            
            score = 50  # امتیاز پایه
            
            # بررسی وجود session رمزنگاری شده
            if encrypted_file.exists():
                score += 30
            
            # بررسی تاریخ‌چه session
            if session_file.exists():
                import os
                file_age = datetime.now().timestamp() - os.path.getmtime(session_file)
                if file_age < 86400:  # کمتر از 24 ساعت
                    score += 20
            
            return {
                'check': 'session_security',
                'score': min(score, 100),
                'message': f'امتیاز امنیت session: {score}/100'
            }
        except Exception as e:
            return {'check': 'session', 'score': 0, 'message': f'خطا: {str(e)}'}
    
    async def _check_suspicious_activity(self, account_id: str) -> Dict[str, Any]:
        """بررسی فعالیت‌های مشکوک"""
        try:
            # اینجا می‌توانید لاگ‌ها را از دیتابیس بررسی کنید
            score = 80  # امتیاز اولیه
            
            # شبیه‌سازی: اگر account_id شامل 'test' باشد، امتیاز کم کنید
            if 'test' in account_id.lower():
                score -= 30
            
            return {
                'check': 'suspicious_activity',
                'score': max(score, 0),
                'message': f'امتیاز فعالیت: {score}/100'
            }
        except Exception as e:
            return {'check': 'activity', 'score': 0, 'message': f'خطا: {str(e)}'}
    
    async def _check_security_settings(self, account_data: Dict) -> Dict[str, Any]:
        """بررسی تنظیمات امنیتی"""
        try:
            score = 70  # امتیاز اولیه
            info = account_data.get('info', {})
            
            # بررسی 2FA
            if info.get('login_method') == LoginMethod.PASSWORD.value:
                score += 20
            
            # بررسی اکانت پریمیوم
            if info.get('is_premium'):
                score += 10
            
            return {
                'check': 'security_settings',
                'score': min(score, 100),
                'message': f'امتیاز تنظیمات: {score}/100'
            }
        except Exception as e:
            return {'check': 'settings', 'score': 0, 'message': f'خطا: {str(e)}'}    
    
    # ========== API و Webhook ==========
    
    async def start_api_server(self, host: str = "127.0.0.1", 
                             port: int = 8080):
        """شروع API سرور"""
        if not HAS_AIOHTTP:
            logger.error("aiohttp برای API سرور نیاز است")
            return
        
        app = web.Application()
        
        # تعریف routes
        # ========== اضافه کردن Middleware‌ها ==========
        app.middlewares.append(self.auth_middleware)  # Middleware احراز هویت
        app.middlewares.append(self.logging_middleware)  # Middleware لاگ‌گیری
        app.middlewares.append(self.cors_middleware)  # Middleware CORS
        app.middlewares.append(self.error_handling_middleware)  # Middleware مدیریت خطا
        # ========== تعریف Routes ==========
        # Routes عمومی (بدون احراز هویت)
        app.router.add_post('/api/auth/login', self.handle_auth_login)
        app.router.add_post('/api/auth/register', self.handle_auth_register)
        app.router.add_get('/api/auth/verify', self.handle_auth_verify)
        # Routes خصوصی (نیاز به احراز هویت)
        private_routes = web.RouteTableDef()

        # middleware برای احراز هویت
        app.middlewares.append(self.auth_middleware)

        @private_routes.get('/api/accounts')
        async def handle_list_accounts(request):
            return await self.handle_list_accounts(request)

        @private_routes.post('/api/accounts/login')
        async def handle_login(request):
            return await self.handle_login(request)
    
        @private_routes.delete('/api/accounts/{account_id}')
        async def handle_logout(request):
            return await self.handle_logout(request)
    
        @private_routes.get('/api/accounts/{account_id}/status')
        async def handle_status(request):
            return await self.handle_status(request)
    
        @private_routes.post('/api/accounts/{account_id}/backup')
        async def handle_backup(request):
            return await self.handle_backup(request)
    
        @private_routes.post('/api/webhook')
        async def handle_webhook(request):
            return await self.handle_webhook(request)

        # اضافه کردن routes خصوصی به app
        app.add_routes(private_routes)

        # ========== Routes مدیریت کاربران ==========
        app.router.add_post('/api/users/create', self.handle_create_user)
        app.router.post('/api/users/{user_id}/apikey', self.handle_generate_apikey)
        app.router.get('/api/users/{user_id}/logs', self.handle_get_user_logs)
    
        # ========== Routes مدیریت سیستم ==========
        app.router.get('/api/system/status', self.handle_system_status)
        app.router.get('/api/system/metrics', self.handle_system_metrics)
        app.router.get('/api/system/audit', self.handle_system_audit)
    
        # ========== تنظیمات CORS ==========
        self._setup_cors(app)
    
        # ========== تنظیمات Static Files ==========
        self._setup_static_files(app)

        # ========== شروع سرور ==========
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        
        await site.start()

        logger.info(f"✅ API سرور پیشرفته شروع شد: http://{host}:{port}")
        logger.info("📋 Routes فعال:")
        logger.info("  - POST   /api/auth/login")
        logger.info("  - POST   /api/auth/register")
        logger.info("  - GET    /api/accounts (نیاز به token)")
        logger.info("  - POST   /api/accounts/login (نیاز به token)")
        logger.info("  - DELETE /api/accounts/{id} (نیاز به token)")
        logger.info("  - POST   /api/users/create (نیاز به token admin)")
        
        return runner
    
    async def handle_list_accounts(self, request):
        """لیست اکانت‌ها"""
        accounts = []
        for account_id, data in self.active_accounts.items():
            accounts.append({
                'account_id': account_id,
                'session_name': data.get('session_name'),
                'phone': data.get('phone'),
                'status': data.get('status'),
                'metrics': data.get('metrics', {})
            })
        
        return web.json_response({
            'success': True,
            'count': len(accounts),
            'accounts': accounts
        })
    
    # ========== توابع کمکی ==========
    
    def _validate_phone_number(self, phone: str) -> bool:
        """اعتبارسنجی شماره تلفن"""
        patterns = [
            r'^\+[1-9]\d{1,14}$',  # E.164
            r'^\+98[1-9]\d{9}$',    # ایران
            r'^09[0-9]{9}$',        # ایران بدون +
        ]
        
        for pattern in patterns:
            if re.match(pattern, phone):
                return True
        
        return False
    
    async def _pre_login_security_check(self, phone: str) -> Dict[str, Any]:
        """بررسی امنیتی قبل از ورود"""
        # بررسی flood wait
        flood_status = await self.database.get_flood_wait_status(phone)
        if flood_status['in_flood']:
            return {
                'allowed': False,
                'reason': f"Flood wait: {flood_status['remaining']} ثانیه"
            }
        
        # بررسی تعداد تلاش‌های اخیر
        recent_attempts = await self.database.get_recent_login_attempts(phone, minutes=5)
        if len(recent_attempts) >= 3:
            return {
                'allowed': False,
                'reason': "تعداد تلاش‌ها بیش از حد مجاز"
            }
        
        return {'allowed': True, 'reason': None}
    
    def _generate_session_name(self, phone: str) -> str:
        """تولید نام session منحصر به فرد"""
        phone_hash = hashlib.sha256(phone.encode()).hexdigest()[:8]
        timestamp = int(datetime.now().timestamp())
        random_part = secrets.token_hex(4)
        
        return f"acc_{phone_hash}_{timestamp}_{random_part}"
    
    async def _create_advanced_client(self, session_path: Path, 
                                    device_info: Dict,
                                    use_proxy: bool = False) -> TelegramClient:
        """ایجاد کلاینت پیشرفته"""
        proxy = None
        if use_proxy and self.proxy_settings:
            from telethon.network import connection
            proxy = (self.proxy_settings['type'],
                    self.proxy_settings['host'],
                    self.proxy_settings['port'])
        
        client = TelegramClient(
            session=str(session_path),
            api_id=self.api_id,
            api_hash=self.api_hash,
            device_model=device_info.get('device_model', 'Desktop'),
            system_version=device_info.get('system_version', '10.0'),
            app_version=device_info.get('app_version', '4.0'),
            lang_code='fa',
            system_lang_code='fa-IR',
            proxy=proxy,
            connection_retries=3,
            retry_delay=2,
            timeout=30,
            flood_sleep_threshold=60
        )
        
        return client
    
    async def _get_verification_code_interactive(self, phone: str) -> str:
        """دریافت کد تأیید به صورت تعاملی"""
        print(f"\n📨 کد تأیید به {phone} ارسال شد")
        print("🔢 کد ۵ رقمی را وارد کنید")
        print("🔄 برای ارسال مجدد: resend")
        print("❌ برای لغو: cancel")
        
        while True:
            code = input("\nکد تأیید: ").strip()
            
            if code.lower() == 'cancel':
                raise KeyboardInterrupt("ورود لغو شد")
            elif code.lower() == 'resend':
                return 'resend'
            elif re.match(r'^\d{5}$', code):
                return code
            else:
                print("❌ کد باید ۵ رقم باشد")
    
    async def _get_2fa_password_secure(self) -> str:
        """دریافت رمز دو مرحله‌ای به صورت امن"""
        print("\n🔐 این اکانت رمز دو مرحله‌ای دارد")
        
        while True:
            password = getpass.getpass("رمز دو مرحله‌ای: ").strip()
            
            if len(password) >= 6:
                return password
            else:
                print("❌ رمز باید حداقل ۶ کاراکتر باشد")
    
    async def _load_or_create_account(self, client: TelegramClient, 
                                    phone: str, session_name: str) -> AccountInfo:
        """بارگذاری یا ایجاد اطلاعات اکانت"""
        # بررسی وجود در دیتابیس
        existing = await self.database.get_account_by_session(session_name)
        
        if existing:
            account_info = AccountInfo(**existing)
        else:
            # ایجاد جدید
            me = await client.get_me()
            account_info = await self._create_account_info(
                client, phone, session_name, LoginMethod.PHONE_CODE
            )
            
            # ذخیره در دیتابیس
            await self.database.save_account(account_info)
        
        # به‌روزرسانی در حافظه
        self.active_accounts[account_info.account_id] = {
            'client': client,
            'info': account_info,
            'session_name': session_name,
            'phone': phone,
            'last_used': datetime.now(),
            'metrics': {},
            'workload': 0
        }
        
        return account_info
    
    async def _create_account_info(self, client: TelegramClient, phone: str,
                                 session_name: str, method: LoginMethod) -> AccountInfo:
        """ایجاد اطلاعات اکانت"""
        me = await client.get_me()
        
        return AccountInfo(
            account_id=secrets.token_hex(8),
            session_name=session_name,
            user_id=me.id,
            username=me.username,
            first_name=me.first_name,
            last_name=me.last_name,
            phone=phone,
            phone_hash=hashlib.sha256(phone.encode()).hexdigest(),
            is_bot=me.bot,
            is_premium=me.premium,
            status=AccountStatus.ACTIVE,
            login_method=method,
            last_login=datetime.now(),
            security_score=85  # امتیاز اولیه
        )
    
    async def _encrypt_and_save_session(self, session_path: Path, session_name: str):
        """رمزنگاری و ذخیره session"""
        if not self.encryption or not session_path.exists():
            return
        
        try:
            # خواندن session
            with open(session_path, 'rb') as f:
                session_data = f.read()
            
            # رمزنگاری
            encrypted_data = self.encryption.encrypt_session(session_data)
            
            # ذخیره
            encrypted_file = self.directories['encrypted'] / f"{session_name}.enc"
            with open(encrypted_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_data, f, indent=2)
            
            # حذف فایل اصلی
            session_path.unlink()
            
            logger.debug(f"Session رمزنگاری شد: {session_name}")
            
        except Exception as e:
            logger.error(f"خطا در رمزنگاری session: {e}")
    
    async def _send_webhook(self, event_type: str, data: Dict):
        """ارسال webhook"""
        if not self.webhook_url:
            return
        
        try:
            payload = {
                'event': event_type,
                'timestamp': datetime.now().isoformat(),
                'data': data,
                'signature': self._create_webhook_signature(data)
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    if resp.status != 200:
                        logger.warning(f"Webhook ارسال نشد: {resp.status}")
        
        except Exception as e:
            logger.error(f"خطا در ارسال webhook: {e}")
    
    def _create_webhook_signature(self, data: Dict) -> str:
        """ایجاد امضا برای webhook"""
        import hmac
        
        message = json.dumps(data, sort_keys=True).encode()
        signature = hmac.new(
            self.webhook_secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _get_client_ip(self) -> str:
        """دریافت IP کلاینت (شبیه‌سازی)"""
        # در پروژه واقعی از request IP استفاده کنید
        return "127.0.0.1"
    
    def _get_default_device_info(self) -> Dict:
        """اطلاعات پیش‌فرض دستگاه"""
        import platform
        
        return {
            'device_model': 'Desktop',
            'system_version': platform.version(),
            'app_version': '4.0.0',
            'platform': platform.platform(),
            'python_version': platform.python_version()
        }
    
    async def _compress_backup(self, backup_file: Path) -> Path:
        """فشرده‌سازی backup"""
        compressed_file = backup_file.with_suffix('.backup.gz')
        
        import gzip
        with open(backup_file, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb') as f_out:
                f_out.write(f_in.read())
        
        backup_file.unlink()  # حذف فایل اصلی
        return compressed_file
    
    async def _decompress_backup(self, backup_file: Path) -> Path:
        """از حالت فشرده خارج کردن"""
        decompressed_file = backup_file.with_suffix('').with_suffix('.backup')
        
        import gzip
        with gzip.open(backup_file, 'rb') as f_in:
            with open(decompressed_file, 'wb') as f_out:
                f_out.write(f_in.read())
        
        return decompressed_file
    
    async def _log_login_attempt(self, attempt: LoginAttempt):
        """ذخیره لاگ تلاش ورود"""
        await self.database.log_login_attempt(attempt)

# ========== دیتابیس پیشرفته ==========

class AccountDatabase:
    """دیتابیس پیشرفته برای مدیریت اکانت‌ها"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = None
        self._initialize()
    
    def _initialize(self):
        """مقداردهی اولیه دیتابیس"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()
    
    def _create_tables(self):
        """ایجاد جداول دیتابیس"""
        cursor = self.conn.cursor()
        
        # جدول اکانت‌ها
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                session_name TEXT UNIQUE,
                user_id INTEGER,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                phone TEXT,
                phone_hash TEXT,
                is_bot BOOLEAN,
                is_premium BOOLEAN,
                status TEXT,
                login_method TEXT,
                created_at TIMESTAMP,
                last_login TIMESTAMP,
                last_activity TIMESTAMP,
                total_messages INTEGER DEFAULT 0,
                total_downloads INTEGER DEFAULT 0,
                security_score INTEGER DEFAULT 100,
                metadata TEXT
            )
        ''')
        
        # جدول تلاش‌های ورود
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                attempt_id TEXT PRIMARY KEY,
                phone TEXT,
                timestamp TIMESTAMP,
                success BOOLEAN,
                method TEXT,
                ip_address TEXT,
                user_agent TEXT,
                error_message TEXT,
                response_time REAL
            )
        ''')
        
        # جدول flood wait
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flood_waits (
                phone TEXT PRIMARY KEY,
                wait_until TIMESTAMP,
                wait_seconds INTEGER,
                reason TEXT
            )
        ''')
        
        # جدول آمار
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS account_stats (
                stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id TEXT,
                timestamp TIMESTAMP,
                is_connected BOOLEAN,
                api_latency REAL,
                memory_usage REAL,
                unread_count INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts (account_id)
            )
        ''')
        
        # ایندکس‌ها
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_accounts_phone ON accounts(phone)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_phone ON login_attempts(phone)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(timestamp)')
        
        self.conn.commit()
        
    async def update_account_status(self, session_name: str, status: AccountStatus, wait_seconds: int = 0):
        """به‌روزرسانی وضعیت اکانت"""
        try:
            cursor = self.conn.cursor()
            if status == AccountStatus.FLOOD_WAIT:
                # ذخیره flood wait
                wait_until = datetime.now() + timedelta(seconds=wait_seconds)
                cursor.execute('''
                    INSERT OR REPLACE INTO flood_waits (phone, wait_until, wait_seconds, reason)
                    VALUES (?, ?, ?, ?)
                ''', (session_name, wait_until, wait_seconds, 'flood_wait'))
            else:
                # به‌روزرسانی وضعیت اکانت
                cursor.execute('''
                    UPDATE accounts SET status = ? WHERE session_name = ?
                ''', (status.value, session_name))
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"خطا در به‌روزرسانی وضعیت: {e}")
    
    async def get_flood_wait_status(self, phone: str) -> Dict[str, Any]:
        """بررسی وضعیت flood wait"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT wait_until FROM flood_waits WHERE phone = ?', (phone,))
            result = cursor.fetchone()
            
            if result:
                wait_until = datetime.fromisoformat(result[0])
                remaining = (wait_until - datetime.now()).seconds
                return {
                    'in_flood': remaining > 0,
                    'remaining': max(0, remaining)
                }
        except Exception as e:
            logger.error(f"خطا در بررسی flood wait: {e}")
        
        return {'in_flood': False, 'remaining': 0}
    
    async def get_recent_login_attempts(self, phone: str, minutes: int = 5) -> List[Dict]:
        """دریافت تلاش‌های ورود اخیر"""
        try:
            cursor = self.conn.cursor()
            cutoff = datetime.now() - timedelta(minutes=minutes)
            cursor.execute('''
                SELECT * FROM login_attempts 
                WHERE phone = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (phone, cutoff))
            
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"خطا در دریافت تلاش‌های ورود: {e}")
            return []
    
    async def get_account_by_session(self, session_name: str) -> Optional[Dict]:
        """دریافت اکانت براساس session name"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM accounts WHERE session_name = ?', (session_name,))
            result = cursor.fetchone()
            
            if result:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, result))
        except Exception as e:
            logger.error(f"خطا در دریافت اکانت: {e}")
        
        return None
    
    async def save_account(self, account_info: AccountInfo):
        """ذخیره اکانت در دیتابیس"""
        try:
            cursor = self.conn.cursor()
            account_dict = account_info.to_dict()
            
            # تبدیل به tuple برای SQL
            values = tuple(account_dict.values())
            
            cursor.execute('''
                INSERT OR REPLACE INTO accounts 
                (account_id, session_name, user_id, username, first_name, last_name, 
                 phone, phone_hash, is_bot, is_premium, status, login_method, 
                 created_at, last_login, last_activity, total_messages, 
                 total_downloads, security_score, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', values)
            
            self.conn.commit()
            logger.debug(f"اکانت {account_info.account_id} ذخیره شد")
        except Exception as e:
            logger.error(f"خطا در ذخیره اکانت: {e}")
    
    async def log_login_attempt(self, attempt: LoginAttempt):
        """ذخیره لاگ تلاش ورود"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO login_attempts 
                (attempt_id, phone, timestamp, success, method, ip_address, 
                 user_agent, error_message, response_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attempt.attempt_id, attempt.phone, attempt.timestamp,
                attempt.success, attempt.method.value, attempt.ip_address,
                attempt.user_agent, attempt.error_message, attempt.response_time
            ))
            
            self.conn.commit()
        except Exception as e:
            logger.error(f"خطا در ذخیره لاگ ورود: {e}")

# ========== رابط خط فرمان ==========

class AdvancedCLI:
    """رابط خط فرمان پیشرفته"""
    
    def __init__(self, manager: AdvancedAccountManager):
        self.manager = manager
        self.running = True
    
    async def run(self):
        """اجرای رابط"""
        self._print_banner()
        
        while self.running:
            try:
                await self._show_main_menu()
            except KeyboardInterrupt:
                print("\n\n⚠️ عملیات لغو شد")
                continue
            except Exception as e:
                print(f"\n❌ خطا: {e}")
                logger.exception("CLI error")
    
    def _print_banner(self):
        """چاپ بنر"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║   🔐 سیستم مدیریت پیشرفته اکانت تلگرام - نسخه حرفه‌ای   ║
║                   با ۱۵+ ویژگی امنیتی                     ║
╚══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    async def _show_main_menu(self):
        """نمایش منوی اصلی"""
        menu = """
┌──────────────────────────────────────────────────────┐
│                    منوی اصلی                          │
├──────────────────────────────────────────────────────┤
│ 1. 📱 ورود با شماره تلفن (پیشرفته)                  │
│ 2. 📷 ورود با QR Code                               │
│ 3. 📋 لیست اکانت‌های فعال                          │
│ 4. 🔍 بررسی وضعیت اکانت                            │
│ 5. 🛡️  بررسی امنیتی اکانت                          │
│ 6. 💾 Backup از اکانت                              │
│ 7. 🔄 بازیابی اکانت                                │
│ 8. 📤 Export اکانت                                 │
│ 9. 🚪 خروج از اکانت                                │
│ 10. 📊 آمار سیستم                                  │
│ 11. ⚙️  تنظیمات                                    │
│ 12. ❌ خروج از برنامه                              │
└──────────────────────────────────────────────────────┘
        """
        
        print(menu)
        choice = input("\n📝 انتخاب شما: ").strip()
        
        if choice == '1':
            await self.login_with_phone()
        elif choice == '2':
            await self.login_with_qr()
        elif choice == '3':
            await self.list_accounts()
        elif choice == '4':
            await self.check_account_status()
        elif choice == '5':
            await self.security_audit()
        elif choice == '6':
            await self.backup_account()
        elif choice == '7':
            await self.restore_account()
        elif choice == '8':
            await self.export_account()
        elif choice == '9':
            await self.logout_account()
        elif choice == '10':
            await self.system_stats()
        elif choice == '11':
            await self.settings()
        elif choice == '12':
            self.running = False
            print("\n👋 خروج از برنامه...")
        else:
            print("\n❌ انتخاب نامعتبر")
    
    async def login_with_phone(self):
        """ورود با شماره تلفن"""
        print("\n" + "═"*50)
        print("📱 ورود پیشرفته با شماره تلفن")
        print("═"*50)
        
        phone = input("شماره تلفن (با +98): ").strip()
        
        if not phone:
            print("❌ شماره تلفن الزامی است")
            return
        
        use_proxy = input("استفاده از proxy؟ (y/n): ").strip().lower() == 'y'
        enable_2fa = input("فعال‌سازی 2FA؟ (y/n): ").strip().lower() == 'y'
        
        print("\n⏳ در حال ورود...")
        
        success, client, account_id = await self.manager.login_with_phone_advanced(
            phone=phone,
            use_proxy=use_proxy,
            enable_2fa=enable_2fa
        )
        
        if success and client:
            print(f"\n✅ ورود موفق!")
            print(f"🆔 Account ID: {account_id}")
            
            # نمایش اطلاعات کاربر
            me = await client.get_me()
            print(f"\n👤 اطلاعات کاربر:")
            print(f"   نام: {me.first_name} {me.last_name or ''}")
            print(f"   یوزرنیم: @{me.username or 'ندارد'}")
            print(f"   شماره: {me.phone}")
            
            # پرسش برای عملیات بیشتر
            await self.post_login_menu(account_id, client)
        else:
            print(f"\n❌ ورود ناموفق: {account_id}")

class AdvancedAuthMiddleware:
    """سیستم احراز هویت Enterprise-Grade با 10 لایه امنیتی"""
    
    def __init__(self, 
                 config: Optional[Dict[str, Any]] = None,
                 environment: str = "production",
                 use_database: bool = True):
        """
        Args:
            config: دیکشنری تنظیمات
            environment: محیط اجرا (production/development/testing)
            use_database: استفاده از دیتابیس برای ذخیره‌سازی
        """
        
        self.environment = environment
        self.use_database = use_database
        self.config = config or {}
        
        # 🛡️ لایه 1: مدیریت کلیدهای رمزنگاری
        self._setup_encryption_keys()
        
        # 🛡️ لایه 2: سیستم Rate Limiting پیشرفته
        self._setup_rate_limiting()
        
        # 🛡️ لایه 3: سیستم IP Management
        self._setup_ip_management()
        
        # 🛡️ لایه 4: سیستم احراز هویت چند عاملی
        self._setup_mfa_system()
        
        # 🛡️ لایه 5: سیستم نقش‌ها و دسترسی‌ها
        self._setup_rbac_system()
        
        # 🛡️ لایه 6: سیستم Audit و لاگ‌گیری
        self._setup_audit_system()
        
        # 🛡️ لایه 7: سیستم کش‌گذاری امن
        self._setup_cache_system()
        
        # 🛡️ لایه 8: سیستم Detection و Prevention
        self._setup_threat_detection()
        
        # 🛡️ لایه 9: سیستم Session Management
        self._setup_session_management()
        
        # 🛡️ لایه 10: سیستم Health Check
        self._setup_health_monitoring()
        
        logger.info(f"✅ سیستم احراز هویت Enterprise راه‌اندازی شد (محیط: {environment})")
    
    # ========== لایه 1: مدیریت کلیدهای رمزنگاری ==========
    
    def _setup_encryption_keys(self):
        """راه‌اندازی سیستم مدیریت کلیدهای امنیتی"""
        
        # اولویت‌بندی برای دریافت کلیدها
        self.jwt_secret = self._get_secure_secret('JWT_SECRET', min_length=64)
        self.encryption_key = self._get_secure_secret('ENCRYPTION_KEY', min_length=32)
        self.hmac_key = self._get_secure_secret('HMAC_KEY', min_length=32)
        
        # تنظیمات JWT
        self.jwt_algorithm = self.config.get('jwt_algorithm', 'HS256')
        self.jwt_expiry_hours = self.config.get('jwt_expiry_hours', 24)
        self.refresh_token_expiry_days = self.config.get('refresh_token_expiry_days', 30)
        
        # تنظیمات Argon2 برای hash کردن رمزهای عبور
        self.argon2_params = {
            'time_cost': self.config.get('argon2_time_cost', 3),
            'memory_cost': self.config.get('argon2_memory_cost', 65536),
            'parallelism': self.config.get('argon2_parallelism', 4),
            'hash_len': self.config.get('argon2_hash_len', 32),
            'salt_len': self.config.get('argon2_salt_len', 16)
        }
        
        # Hash‌های غیرفعال شده
        self.revoked_hashes: Set[str] = set()
        
        # کلیدهای API
        self.api_keys: Dict[str, Dict] = {}
        self.api_key_versions: Dict[str, List] = defaultdict(list)
    
    def _get_secure_secret(self, env_name: str, min_length: int = 32) -> str:
        """دریافت کلید امن از منابع مختلف"""
        
        sources = [
            self.config.get(env_name.lower()),
            os.getenv(env_name),
            os.getenv(env_name.upper()),
            os.getenv(env_name.lower())
        ]
        
        for secret in sources:
            if secret and len(secret) >= min_length:
                return secret
        
        # در محیط production حتما باید کلید تنظیم شده باشد
        if self.environment == "production":
            raise ValueError(
                f"{env_name} در محیط production باید تنظیم شود. "
                f"حداقل طول: {min_length} کاراکتر"
            )
        else:
            # تولید کلید تصادفی برای محیط توسعه
            generated = secrets.token_urlsafe(max(48, min_length))
            logger.warning(
                f"⚠️  {env_name} تنظیم نشده. "
                f"کلید تصادفی تولید شد (فقط برای محیط {self.environment})"
            )
            return generated
    
    # ========== لایه 2: سیستم Rate Limiting پیشرفته ==========
    
    def _setup_rate_limiting(self):
        """راه‌اندازی سیستم Rate Limiting چند سطحی"""
        
        self.rate_limits = {
            'global': self.config.get('rate_limit_global', 1000),  # درخواست در دقیقه
            'per_ip': self.config.get('rate_limit_per_ip', 100),
            'per_user': self.config.get('rate_limit_per_user', 50),
            'login': self.config.get('rate_limit_login', 5),  # لاگین در دقیقه
            'api_key': self.config.get('rate_limit_api_key', 200)
        }
        
        # ذخیره‌سازی درخواست‌ها
        self.request_counts: Dict[str, Dict[str, List]] = {
            'ip': defaultdict(list),
            'user': defaultdict(list),
            'endpoint': defaultdict(list),
            'api_key': defaultdict(list)
        }
        
        # تنظیمات burst protection
        self.burst_limits = {
            'max_burst': self.config.get('max_burst_requests', 20),
            'burst_window': self.config.get('burst_window_seconds', 10)
        }
        
        # Lock برای thread safety
        self.rate_lock = asyncio.Lock()
        
        # الگوهای حمله شناخته شده
        self.attack_patterns = [
            (100, 1),   # 100 درخواست در 1 ثانیه
            (50, 2),    # 50 درخواست در 2 ثانیه
            (200, 10)   # 200 درخواست در 10 ثانیه
        ]
    
    async def check_rate_limit(self, 
                              identifier: str, 
                              limit_type: str = 'ip',
                              endpoint: str = None) -> Dict[str, Any]:
        """بررسی Rate Limiting پیشرفته"""
        
        async with self.rate_lock:
            now = datetime.now()
            key = f"{limit_type}:{identifier}"
            
            if endpoint:
                endpoint_key = f"endpoint:{endpoint}:{identifier}"
            
            # بررسی burst
            burst_check = await self._check_burst_attack(identifier, now)
            if burst_check['is_attack']:
                return {
                    'allowed': False,
                    'retry_after': burst_check['retry_after'],
                    'reason': 'burst_attack_detected',
                    'is_attack': True
                }
            
            # پاک‌سازی درخواست‌های قدیمی
            window_start = now - timedelta(minutes=1)
            
            if key in self.request_counts[limit_type]:
                self.request_counts[limit_type][key] = [
                    t for t in self.request_counts[limit_type][key] 
                    if t > window_start
                ]
            
            if endpoint and endpoint_key in self.request_counts['endpoint']:
                self.request_counts['endpoint'][endpoint_key] = [
                    t for t in self.request_counts['endpoint'][endpoint_key]
                    if t > window_start
                ]
            
            # بررسی محدودیت
            limit = self.rate_limits.get(limit_type, 100)
            current_count = len(self.request_counts[limit_type].get(key, []))
            
            if current_count >= limit:
                retry_time = self._calculate_retry_time(
                    self.request_counts[limit_type][key][0]
                )
                return {
                    'allowed': False,
                    'retry_after': retry_time,
                    'reason': 'rate_limit_exceeded',
                    'current': current_count,
                    'limit': limit
                }
            
            # اضافه کردن درخواست جدید
            self.request_counts[limit_type][key].append(now)
            
            if endpoint:
                self.request_counts['endpoint'][endpoint_key].append(now)
            
            return {
                'allowed': True,
                'current': current_count + 1,
                'limit': limit,
                'remaining': limit - (current_count + 1)
            }
    
    async def _check_burst_attack(self, identifier: str, timestamp: datetime) -> Dict[str, Any]:
        """تشخیص حملات burst"""
        
        burst_key = f"burst:{identifier}"
        window_start = timestamp - timedelta(seconds=self.burst_limits['burst_window'])
        
        if burst_key not in self.request_counts['ip']:
            self.request_counts['ip'][burst_key] = []
        
        # پاک‌سازی قدیمی‌ها
        self.request_counts['ip'][burst_key] = [
            t for t in self.request_counts['ip'][burst_key]
            if t > window_start
        ]
        
        # اضافه کردن درخواست جدید
        self.request_counts['ip'][burst_key].append(timestamp)
        
        current_count = len(self.request_counts['ip'][burst_key])
        
        if current_count > self.burst_limits['max_burst']:
            return {
                'is_attack': True,
                'retry_after': self.burst_limits['burst_window'],
                'burst_count': current_count,
                'threshold': self.burst_limits['max_burst']
            }
        
        return {'is_attack': False, 'burst_count': current_count}
    
    def _calculate_retry_time(self, first_request: datetime) -> int:
        """محاسبه زمان مجدد تلاش"""
        now = datetime.now()
        window_end = first_request + timedelta(minutes=1)
        return max(0, int((window_end - now).total_seconds()))
    
    # ========== لایه 3: سیستم IP Management ==========
    
    def _setup_ip_management(self):
        """راه‌اندازی سیستم مدیریت IP"""
        
        self.ip_whitelist = self._parse_ip_list(
            self.config.get('ip_whitelist', [])
        )
        self.ip_blacklist = self._parse_ip_list(
            self.config.get('ip_blacklist', [])
        )
        
        # IPهای مشکوک با امتیاز ریسک
        self.suspicious_ips: Dict[str, Dict] = {}
        
        # GeoIP restrictions
        self.allowed_countries = set(
            self.config.get('allowed_countries', [])
        )
        self.blocked_countries = set(
            self.config.get('blocked_countries', [])
        )
        
        # شبکه‌های معتبر
        self.trusted_networks = self._parse_ip_list(
            self.config.get('trusted_networks', [])
        )
        
        # تور و VPN detection
        self.block_tor = self.config.get('block_tor', True)
        self.block_vpn = self.config.get('block_vpn', False)
    
    def _parse_ip_list(self, ip_list: List[str]) -> Set[str]:
        """تبدیل لیست IP به مجموعه"""
        parsed = set()
        
        for item in ip_list:
            try:
                if '/' in item:
                    # CIDR notation
                    network = ip_network(item, strict=False)
                    parsed.add(str(network))
                else:
                    # Single IP
                    ip_obj = ip_address(item)
                    parsed.add(str(ip_obj))
            except ValueError as e:
                logger.warning(f"IP نامعتبر: {item} - {e}")
        
        return parsed
    
    def check_ip_security(self, ip: str, user_agent: str = None) -> Dict[str, Any]:
        """بررسی کامل امنیت IP"""
        
        risk_score = 0
        warnings = []
        blocked = False
        reason = ""
        
        # 1. بررسی لیست سیاه
        if self._is_ip_in_list(ip, self.ip_blacklist):
            blocked = True
            reason = "ip_blacklisted"
            risk_score = 100
        
        # 2. بررسی لیست سفید (اگر وجود دارد)
        elif self.ip_whitelist and not self._is_ip_in_list(ip, self.ip_whitelist):
            blocked = True
            reason = "ip_not_whitelisted"
            risk_score = 90
        
        # 3. بررسی کشور
        country = self._get_country_from_ip(ip)
        if country:
            if country in self.blocked_countries:
                blocked = True
                reason = f"country_blocked_{country}"
                risk_score = 85
            elif self.allowed_countries and country not in self.allowed_countries:
                blocked = True
                reason = f"country_not_allowed_{country}"
                risk_score = 80
        
        # 4. بررسی شبکه‌های معتبر
        if not blocked and self._is_ip_in_list(ip, self.trusted_networks):
            risk_score -= 20  # کاهش ریسک
        
        # 5. بررسی IP مشکوک
        if ip in self.suspicious_ips:
            ip_data = self.suspicious_ips[ip]
            risk_score += ip_data.get('risk_score', 0)
            warnings.append(f"IP مشکوک: {ip_data.get('reason', 'unknown')}")
        
        # 6. بررسی تور و VPN (شبیه‌سازی)
        if self.block_tor and self._is_tor_exit_node(ip):
            risk_score += 30
            warnings.append("تور exit node تشخیص داده شد")
        
        if self.block_vpn and self._is_vpn_ip(ip):
            risk_score += 25
            warnings.append("VPN IP تشخیص داده شد")
        
        # 7. بررسی User-Agent مشکوک
        if user_agent and self._is_suspicious_user_agent(user_agent):
            risk_score += 20
            warnings.append("User-Agent مشکوک")
        
        # تصمیم نهایی
        action = "allow"
        if blocked or risk_score >= 80:
            action = "block"
        elif risk_score >= 60:
            action = "challenge"  # نیاز به CAPTCHA
        elif risk_score >= 40:
            action = "monitor"  # مانیتورینگ دقیق‌تر
        
        return {
            'ip': ip,
            'country': country,
            'risk_score': min(risk_score, 100),
            'action': action,
            'blocked': blocked,
            'reason': reason,
            'warnings': warnings,
            'requires_challenge': action == "challenge",
            'requires_monitoring': action == "monitor"
        }
    
    def _is_ip_in_list(self, ip: str, ip_list: Set[str]) -> bool:
        """بررسی وجود IP در لیست"""
        try:
            ip_obj = ip_address(ip)
            
            for item in ip_list:
                if '/' in item:
                    if ip_obj in ip_network(item):
                        return True
                elif str(ip_obj) == item:
                    return True
            
            return False
        except ValueError:
            return False
    
    def _get_country_from_ip(self, ip: str) -> Optional[str]:
        """دریافت کشور از IP (شبیه‌سازی)"""
        # در پروژه واقعی از GeoIP database استفاده کنید
        # مانند geoip2 یا ip2location
        return "IR"  # شبیه‌سازی
    
    def _is_tor_exit_node(self, ip: str) -> bool:
        """بررسی تور exit node (شبیه‌سازی)"""
        # در پروژه واقعی از لیست تور exit nodes استفاده کنید
        return False
    
    def _is_vpn_ip(self, ip: str) -> bool:
        """بررسی VPN IP (شبیه‌سازی)"""
        # در پروژه واقعی از سرویس‌های تشخیص VPN استفاده کنید
        return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """بررسی User-Agent مشکوک"""
        
        if not user_agent or user_agent == "Unknown":
            return False
        
        ua_lower = user_agent.lower()
        
        # لیست سفید مرورگرهای معتبر
        valid_browsers = [
            'mozilla', 'chrome', 'safari', 'firefox', 'edge',
            'opera', 'webkit', 'gecko', 'applewebkit'
        ]
        
        # اگر مرورگر معتبر باشد
        if any(browser in ua_lower for browser in valid_browsers):
            return False
        
        # لیست مشکوک
        suspicious_patterns = [
            'curl', 'wget', 'python', 'requests', 'scrapy',
            'go-http-client', 'java', 'httpclient', 'okhttp',
            'node-fetch', 'postman', 'insomnia', 'thunder client',
            'nmap', 'sqlmap', 'nikto', 'metasploit',
            'bot', 'crawler', 'spider', 'scanner'
        ]
        
        return any(pattern in ua_lower for pattern in suspicious_patterns)
    
    # ========== لایه 4: سیستم احراز هویت چند عاملی ==========
    
    def _setup_mfa_system(self):
        """راه‌اندازی سیستم MFA"""
        
        self.mfa_methods = {
            'totp': self.config.get('enable_totp', True),
            'sms': self.config.get('enable_sms_mfa', False),
            'email': self.config.get('enable_email_mfa', True),
            'biometric': self.config.get('enable_biometric', False),
            'hardware_token': self.config.get('enable_hardware_token', False)
        }
        
        # کدهای MFA موقت
        self.mfa_codes: Dict[str, Dict] = {}
        
        # دستگاه‌های معتبر
        self.trusted_devices: Dict[str, List] = {}
        
        # تنظیمات TOTP
        self.totp_settings = {
            'digits': 6,
            'interval': 30,
            'window': 1  # قبول کردن کدهای قبلی و بعدی
        }
    
    async def generate_mfa_code(self, 
                               user_id: str, 
                               method: str = 'totp',
                               device_info: Dict = None) -> Dict[str, Any]:
        """تولید کد MFA"""
        
        if method not in self.mfa_methods or not self.mfa_methods[method]:
            raise ValueError(f"روش {method} فعال نیست")
        
        code_data = {
            'code': self._generate_secure_code(method),
            'method': method,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(minutes=5),
            'attempts': 0,
            'max_attempts': 3,
            'device_info': device_info,
            'ip_address': None,
            'user_agent': None
        }
        
        # ذخیره در حافظه
        self.mfa_codes[user_id] = code_data
        
        # ارسال کد (شبیه‌سازی)
        if method == 'sms':
            logger.info(f"📱 کد SMS برای کاربر {user_id}: {code_data['code']}")
        elif method == 'email':
            logger.info(f"📧 کد ایمیل برای کاربر {user_id}: {code_data['code']}")
        
        return {
            'code_length': len(code_data['code']),
            'expires_in': 300,  # 5 دقیقه
            'method': method
        }
    
    def _generate_secure_code(self, method: str) -> str:
        """تولید کد امن"""
        
        if method == 'totp':
            # برای TOTP واقعی باید secret داشته باشیم
            import pyotp  # نیاز به نصب: pip install pyotp
            totp = pyotp.TOTP(secrets.token_hex(16))
            return totp.now()
        else:
            # کد عددی ۶ رقمی
            return ''.join(secrets.choice(string.digits) for _ in range(6))
    
    async def verify_mfa_code(self, 
                             user_id: str, 
                             code: str,
                             ip: str = None,
                             user_agent: str = None) -> Dict[str, Any]:
        """تأیید کد MFA"""
        
        if user_id not in self.mfa_codes:
            return {
                'verified': False,
                'reason': 'code_not_found',
                'remaining_attempts': 0
            }
        
        code_data = self.mfa_codes[user_id]
        
        # بررسی انقضا
        if datetime.now() > code_data['expires_at']:
            del self.mfa_codes[user_id]
            return {
                'verified': False,
                'reason': 'code_expired',
                'remaining_attempts': 0
            }
        
        # بررسی تعداد تلاش‌ها
        if code_data['attempts'] >= code_data['max_attempts']:
            del self.mfa_codes[user_id]
            return {
                'verified': False,
                'reason': 'max_attempts_exceeded',
                'remaining_attempts': 0
            }
        
        # افزایش شمارنده تلاش‌ها
        code_data['attempts'] += 1
        
        # بررسی کد
        if code_data['method'] == 'totp':
            import pyotp
            # در پروژه واقعی باید TOTP secret را از دیتابیس بخوانیم
            verified = False  # شبیه‌سازی
        else:
            verified = code_data['code'] == code
        
        if verified:
            # ثبت اطلاعات دستگاه
            if ip and user_agent:
                if user_id not in self.trusted_devices:
                    self.trusted_devices[user_id] = []
                
                device_hash = hashlib.sha256(
                    f"{ip}:{user_agent}".encode()
                ).hexdigest()[:16]
                
                self.trusted_devices[user_id].append({
                    'device_hash': device_hash,
                    'ip': ip,
                    'user_agent': user_agent,
                    'last_used': datetime.now(),
                    'trust_level': 'high'
                })
            
            # حذف کد استفاده شده
            del self.mfa_codes[user_id]
            
            return {
                'verified': True,
                'device_trusted': True,
                'method': code_data['method']
            }
        else:
            remaining = code_data['max_attempts'] - code_data['attempts']
            return {
                'verified': False,
                'reason': 'invalid_code',
                'remaining_attempts': remaining
            }
    
    # ========== لایه 5: سیستم نقش‌ها و دسترسی‌ها ==========
    
    def _setup_rbac_system(self):
        """راه‌اندازی سیستم Role-Based Access Control"""
        
        self.roles = {
            'super_admin': {
                'description': 'دسترسی کامل به همه چیز',
                'permissions': ['*'],
                'inherits': []
            },
            'admin': {
                'description': 'مدیر سیستم',
                'permissions': [
                    'users:*',
                    'accounts:*',
                    'system:*',
                    'logs:read',
                    'backup:*'
                ],
                'inherits': ['manager']
            },
            'manager': {
                'description': 'مدیر محتوا',
                'permissions': [
                    'accounts:read',
                    'accounts:write',
                    'messages:send',
                    'backup:create',
                    'logs:read:self'
                ],
                'inherits': ['user']
            },
            'user': {
                'description': 'کاربر عادی',
                'permissions': [
                    'accounts:read',
                    'accounts:self:write',
                    'profile:*'
                ],
                'inherits': []
            },
            'api_client': {
                'description': 'دسترسی API',
                'permissions': [
                    'accounts:read',
                    'messages:send',
                    'data:export'
                ],
                'inherits': []
            },
            'viewer': {
                'description': 'فقط مشاهده',
                'permissions': ['accounts:read'],
                'inherits': []
            }
        }
        
        # لیست permissions
        self.available_permissions = [
            # Accounts
            'accounts:read',
            'accounts:write',
            'accounts:delete',
            'accounts:create',
            'accounts:self:read',
            'accounts:self:write',
            
            # Users
            'users:read',
            'users:write',
            'users:delete',
            'users:create',
            
            # System
            'system:status',
            'system:config',
            'system:restart',
            
            # Logs
            'logs:read',
            'logs:read:self',
            'logs:export',
            
            # Backup
            'backup:create',
            'backup:restore',
            'backup:delete',
            
            # Messages
            'messages:send',
            'messages:read',
            'messages:delete',
            
            # Profile
            'profile:read',
            'profile:write',
            'profile:delete'
        ]
    
    def check_permission(self, 
                        role: str, 
                        permission: str,
                        context: Dict = None) -> Dict[str, Any]:
        """بررسی دسترسی کاربر"""
        
        if role not in self.roles:
            return {
                'allowed': False,
                'reason': 'invalid_role',
                'role': role
            }
        
        # بررسی دسترسی مستقیم
        role_data = self.roles[role]
        
        # دسترسی کامل
        if '*' in role_data['permissions']:
            return {
                'allowed': True,
                'reason': 'full_access',
                'role': role
            }
        
        # بررسی permission مستقیم
        if permission in role_data['permissions']:
            return {
                'allowed': True,
                'reason': 'direct_permission',
                'role': role
            }
        
        # بررسی inheritance
        for inherited_role in role_data['inherits']:
            if inherited_role in self.roles:
                inherited_permissions = self.roles[inherited_role]['permissions']
                if '*' in inherited_permissions or permission in inherited_permissions:
                    return {
                        'allowed': True,
                        'reason': 'inherited_permission',
                        'from_role': inherited_role,
                        'role': role
                    }
        
        # بررسی context-based permissions
        if context and self._check_context_permission(role, permission, context):
            return {
                'allowed': True,
                'reason': 'context_permission',
                'role': role
            }
        
        return {
            'allowed': False,
            'reason': 'permission_denied',
            'role': role,
            'required_permission': permission
        }
    
    def _check_context_permission(self, 
                                 role: str, 
                                 permission: str,
                                 context: Dict) -> bool:
        """بررسی دسترسی‌های مبتنی بر context"""
        
        # مثال: بررسی ownership
        if ':self:' in permission:
            # اگر کاربر مالک resource باشد
            user_id = context.get('user_id')
            resource_owner = context.get('resource_owner')
            
            if user_id and resource_owner and user_id == resource_owner:
                return True
        
        # بررسی محدوده زمانی
        if 'time_restricted' in context:
            allowed_hours = context.get('allowed_hours', range(0, 24))
            current_hour = datetime.now().hour
            
            if current_hour not in allowed_hours:
                return False
        
        # بررسی محدوده جغرافیایی
        if 'geo_restricted' in context:
            allowed_countries = context.get('allowed_countries', [])
            user_country = context.get('user_country')
            
            if user_country and user_country not in allowed_countries:
                return False
        
        return False
    
    # ========== لایه 6: سیستم Audit و لاگ‌گیری ==========
    
    def _setup_audit_system(self):
        """راه‌اندازی سیستم Audit"""
        
        self.audit_logs: List[Dict] = []
        self.max_audit_logs = self.config.get('max_audit_logs', 10000)
        
        # فیلترهای audit
        self.audit_filters = {
            'security': ['LOGIN', 'LOGOUT', 'PERMISSION', 'ACCESS'],
            'system': ['CONFIG', 'BACKUP', 'RESTART'],
            'user': ['CREATE', 'UPDATE', 'DELETE'],
            'api': ['API_CALL', 'RATE_LIMIT', 'BLOCKED']
        }
    
    async def log_audit_event(self, 
                             event_type: str,
                             user_id: str = None,
                             ip: str = None,
                             user_agent: str = None,
                             resource: str = None,
                             action: str = None,
                             status: str = 'SUCCESS',
                             details: Dict = None):
        """ثبت رویداد Audit"""
        
        audit_entry = {
            'id': secrets.token_hex(8),
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': user_agent,
            'resource': resource,
            'action': action,
            'status': status,
            'details': details or {},
            'environment': self.environment
        }
        
        self.audit_logs.append(audit_entry)
        
        # محدود کردن حجم لاگ‌ها
        if len(self.audit_logs) > self.max_audit_logs:
            self.audit_logs = self.audit_logs[-self.max_audit_logs:]
        
        # لاگ کردن در فایل
        log_message = (
            f"AUDIT [{status}] {event_type} - "
            f"User: {user_id or 'SYSTEM'} - "
            f"IP: {ip} - "
            f"Resource: {resource}"
        )
        
        if status == 'FAILURE':
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    async def get_audit_logs(self,
                           start_date: datetime = None,
                           end_date: datetime = None,
                           event_type: str = None,
                           user_id: str = None,
                           status: str = None,
                           limit: int = 100) -> List[Dict]:
        """دریافت لاگ‌های Audit"""
        
        filtered = self.audit_logs
        
        if start_date:
            filtered = [log for log in filtered 
                       if datetime.fromisoformat(log['timestamp']) >= start_date]
        
        if end_date:
            filtered = [log for log in filtered 
                       if datetime.fromisoformat(log['timestamp']) <= end_date]
        
        if event_type:
            filtered = [log for log in filtered 
                       if log['event_type'] == event_type]
        
        if user_id:
            filtered = [log for log in filtered 
                       if log['user_id'] == user_id]
        
        if status:
            filtered = [log for log in filtered 
                       if log['status'] == status]
        
        return filtered[-limit:]
    
    # ========== لایه 7: سیستم کش‌گذاری امن ==========
    
    def _setup_cache_system(self):
        """راه‌اندازی سیستم کش"""
        
        self.cache: Dict[str, Dict] = {}
        self.cache_ttl = self.config.get('cache_ttl', 300)  # 5 دقیقه
        
        # انواع کش
        self.cache_types = {
            'token': 300,      # 5 دقیقه
            'user': 600,       # 10 دقیقه
            'permission': 900, # 15 دقیقه
            'rate_limit': 60,  # 1 دقیقه
            'ip_check': 300    # 5 دقیقه
        }
    
    async def cache_get(self, key: str, cache_type: str = 'general') -> Optional[Any]:
        """دریافت از کش"""
        
        cache_key = f"{cache_type}:{key}"
        
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            
            # بررسی انقضا
            if datetime.now().timestamp() < entry['expires_at']:
                return entry['data']
            else:
                # حذف entry منقضی شده
                del self.cache[cache_key]
        
        return None
    
    async def cache_set(self, 
                       key: str, 
                       data: Any, 
                       cache_type: str = 'general',
                       ttl: int = None):
        """ذخیره در کش"""
        
        if ttl is None:
            ttl = self.cache_types.get(cache_type, self.cache_ttl)
        
        cache_key = f"{cache_type}:{key}"
        
        self.cache[cache_key] = {
            'data': data,
            'created_at': datetime.now().timestamp(),
            'expires_at': datetime.now().timestamp() + ttl,
            'type': cache_type
        }
        
        # محدود کردن حجم کش
        max_cache_size = self.config.get('max_cache_size', 1000)
        if len(self.cache) > max_cache_size:
            # حذف قدیمی‌ترین entries
            sorted_keys = sorted(
                self.cache.keys(),
                key=lambda k: self.cache[k]['created_at']
            )
            
            for k in sorted_keys[:len(self.cache) - max_cache_size]:
                del self.cache[k]
    
    # ========== لایه 8: سیستم Detection و Prevention ==========
    
    def _setup_threat_detection(self):
        """راه‌اندازی سیستم تشخیص تهدید"""
        
        self.threat_patterns = {
            'sql_injection': [
                r"('(''|[^'])*')",
                r"\b(union|select|insert|update|delete|drop|create|alter)\b",
                r"\b(OR|AND)\b\s*1\s*=\s*1",
                r"(--|#|\/\*)"
            ],
            'xss': [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"alert\("
            ],
            'path_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"\/etc\/",
                r"\/proc\/"
            ],
            'command_injection': [
                r"[;&|`]",
                r"\$\(.*?\)",
                r"\b(rm|mkdir|wget|curl|nc|netcat)\b"
            ]
        }
        
        # امتیازهای ریسک
        self.threat_scores = {
            'sql_injection': 80,
            'xss': 70,
            'path_traversal': 75,
            'command_injection': 85,
            'brute_force': 60,
            'credential_stuffing': 65
        }
        
        # سیستم یادگیری الگوهای حمله
        self.attack_patterns_learned: List[Dict] = []
    
    def detect_threats(self, data: Union[str, Dict]) -> Dict[str, Any]:
        """تشخیص تهدیدات امنیتی"""
        
        threats = []
        total_risk_score = 0
        
        # تبدیل داده به string برای بررسی
        if isinstance(data, dict):
            data_str = json.dumps(data)
        else:
            data_str = str(data)
        
        # بررسی الگوهای مختلف حمله
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                import re
                if re.search(pattern, data_str, re.IGNORECASE):
                    threat = {
                        'type': threat_type,
                        'pattern': pattern,
                        'score': self.threat_scores.get(threat_type, 50)
                    }
                    threats.append(threat)
                    total_risk_score += threat['score']
                    break  # یک تهدید از هر نوع کافی است
        
        # بررسی brute force
        if self._is_brute_force_pattern(data_str):
            threats.append({
                'type': 'brute_force',
                'score': self.threat_scores.get('brute_force', 60)
            })
            total_risk_score += self.threat_scores.get('brute_force', 60)
        
        # تصمیم‌گیری
        max_risk_score = 100
        risk_percentage = min(total_risk_score, max_risk_score)
        
        action = "allow"
        if risk_percentage >= 80:
            action = "block"
        elif risk_percentage >= 60:
            action = "challenge"
        elif risk_percentage >= 40:
            action = "monitor"
        
        return {
            'threats_found': len(threats) > 0,
            'threats': threats,
            'risk_score': risk_percentage,
            'action': action,
            'requires_review': risk_percentage >= 50,
            'recommendation': self._get_threat_recommendation(threats)
        }
    
    def _is_brute_force_pattern(self, data: str) -> bool:
        """تشخیص الگوی brute force"""
        # اینجا می‌توانید الگوهای خاص brute force را بررسی کنید
        return False
    
    def _get_threat_recommendation(self, threats: List[Dict]) -> str:
        """دریافت پیشنهادات امنیتی"""
        
        if not threats:
            return "هیچ تهدیدی شناسایی نشد"
        
        threat_types = [t['type'] for t in threats]
        
        if 'sql_injection' in threat_types:
            return "ورودی‌های کاربر را با prepared statements بررسی کنید"
        elif 'xss' in threat_types:
            return "داده‌های خروجی را encode کنید و از CSP استفاده نمایید"
        elif 'command_injection' in threat_types:
            return "از shell=True در subprocess اجتناب کنید"
        
        return "ورودی‌های کاربر را اعتبارسنجی و sanitize کنید"
    
    # ========== لایه 9: سیستم Session Management ==========
    
    def _setup_session_management(self):
        """راه‌اندازی سیستم مدیریت Session"""
        
        self.active_sessions: Dict[str, Dict] = {}
        self.session_timeout = self.config.get('session_timeout', 3600)
        
        # تنظیمات session
        self.session_config = {
            'max_sessions_per_user': self.config.get('max_sessions_per_user', 5),
            'inactive_timeout': self.config.get('inactive_timeout', 1800),
            'renew_threshold': self.config.get('renew_threshold', 300),
            'secure_cookies': self.config.get('secure_cookies', True),
            'http_only': self.config.get('http_only_cookies', True),
            'same_site': self.config.get('same_site_cookie', 'Lax')
        }
    
    async def create_session(self,
                           user_id: str,
                           ip: str,
                           user_agent: str,
                           device_info: Dict = None) -> Dict[str, Any]:
        """ایجاد session جدید"""
        
        # بررسی تعداد sessionهای فعال کاربر
        user_sessions = [
            s for s in self.active_sessions.values() 
            if s.get('user_id') == user_id
        ]
        
        if len(user_sessions) >= self.session_config['max_sessions_per_user']:
            # حذف قدیمی‌ترین session
            oldest_session = min(user_sessions, key=lambda x: x['created_at'])
            session_id_to_remove = oldest_session['session_id']
            
            if session_id_to_remove in self.active_sessions:
                del self.active_sessions[session_id_to_remove]
        
        # ایجاد session جدید
        session_id = secrets.token_urlsafe(32)
        now = datetime.now()
        
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': user_agent,
            'device_info': device_info or {},
            'created_at': now,
            'last_activity': now,
            'expires_at': now + timedelta(seconds=self.session_timeout),
            'is_active': True,
            'access_level': 'user',
            'metadata': {}
        }
        
        self.active_sessions[session_id] = session_data
        
        # ایجاد JWT token
        jwt_token = self._create_jwt_token(session_data)
        
        return {
            'session_id': session_id,
            'jwt_token': jwt_token,
            'expires_in': self.session_timeout,
            'created_at': now.isoformat()
        }
    
    def _create_jwt_token(self, session_data: Dict) -> str:
        """ایجاد JWT token"""
        
        payload = {
            'session_id': session_data['session_id'],
            'user_id': session_data['user_id'],
            'exp': int(time.time()) + self.session_timeout,
            'iat': int(time.time()),
            'iss': 'telegram_account_manager',
            'aud': 'api',
            'ip': session_data['ip_address'],
            'ua': session_data['user_agent'][:100] if session_data['user_agent'] else None
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
    
    async def validate_session(self, session_id: str, ip: str = None) -> Dict[str, Any]:
        """اعتبارسنجی session"""
        
        if session_id not in self.active_sessions:
            return {
                'valid': False,
                'reason': 'session_not_found',
                'session_id': session_id
            }
        
        session = self.active_sessions[session_id]
        now = datetime.now()
        
        # بررسی انقضا
        if now > session['expires_at']:
            del self.active_sessions[session_id]
            return {
                'valid': False,
                'reason': 'session_expired',
                'session_id': session_id
            }
        
        # بررسی IP (اختیاری)
        if ip and session['ip_address'] != ip:
            # ممکن است IP تغییر کرده باشد (مثلاً کاربر VPN روشن کرده)
            # می‌توانید این را به عنوان warning ثبت کنید
            session['ip_changed'] = True
            session['new_ip'] = ip
        
        # به‌روزرسانی آخرین فعالیت
        session['last_activity'] = now
        
        # بررسی نیاز به renew
        time_until_expiry = (session['expires_at'] - now).total_seconds()
        if time_until_expiry < self.session_config['renew_threshold']:
            # تمدید session
            session['expires_at'] = now + timedelta(seconds=self.session_timeout)
            session['renewed_at'] = now
        
        return {
            'valid': True,
            'session_data': {
                'user_id': session['user_id'],
                'created_at': session['created_at'].isoformat(),
                'expires_at': session['expires_at'].isoformat(),
                'device_info': session['device_info']
            },
            'remaining_time': int(time_until_expiry)
        }
    
    async def invalidate_session(self, session_id: str, reason: str = "user_logout"):
        """ابطال session"""
        
        if session_id in self.active_sessions:
            session_data = self.active_sessions.pop(session_id)
            
            await self.log_audit_event(
                event_type='SESSION_INVALIDATED',
                user_id=session_data['user_id'],
                ip=session_data['ip_address'],
                resource='session',
                action='invalidate',
                status='SUCCESS',
                details={'reason': reason}
            )
            
            return True
        
        return False
    
    # ========== لایه 10: سیستم Health Check ==========
    
    def _setup_health_monitoring(self):
        """راه‌اندازی سیستم سلامت"""
        
        self.health_metrics = {
            'startup_time': datetime.now(),
            'total_requests': 0,
            'blocked_requests': 0,
            'failed_auth': 0,
            'rate_limited': 0,
            'active_sessions': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # آستانه‌های هشدار
        self.alert_thresholds = {
            'failed_auth_rate': 0.1,  # 10% خطای احراز هویت
            'blocked_request_rate': 0.2,  # 20% درخواست مسدود شده
            'cache_miss_rate': 0.5,  # 50% cache miss
            'memory_usage_mb': 500,
            'active_sessions_count': 1000
        }
    
    async def get_health_status(self) -> Dict[str, Any]:
        """دریافت وضعیت سلامت سیستم"""
        
        now = datetime.now()
        uptime = (now - self.health_metrics['startup_time']).total_seconds()
        
        # محاسبه نرخ‌ها
        total_req = max(self.health_metrics['total_requests'], 1)
        
        failed_auth_rate = self.health_metrics['failed_auth'] / total_req
        blocked_rate = self.health_metrics['blocked_requests'] / total_req
        
        # محاسبه cache hit rate
        total_cache = self.health_metrics['cache_hits'] + self.health_metrics['cache_misses']
        cache_hit_rate = 0
        if total_cache > 0:
            cache_hit_rate = self.health_metrics['cache_hits'] / total_cache
        
        # بررسی هشدارها
        alerts = []
        
        if failed_auth_rate > self.alert_thresholds['failed_auth_rate']:
            alerts.append({
                'level': 'WARNING',
                'message': f'نرخ خطای احراز هویت بالا: {failed_auth_rate:.1%}',
                'metric': 'failed_auth_rate',
                'value': failed_auth_rate
            })
        
        if blocked_rate > self.alert_thresholds['blocked_request_rate']:
            alerts.append({
                'level': 'WARNING',
                'message': f'نرخ درخواست‌های مسدود شده بالا: {blocked_rate:.1%}',
                'metric': 'blocked_request_rate',
                'value': blocked_rate
            })
        
        if cache_hit_rate < (1 - self.alert_thresholds['cache_miss_rate']):
            alerts.append({
                'level': 'INFO',
                'message': f'نرخ cache hit پایین: {cache_hit_rate:.1%}',
                'metric': 'cache_hit_rate',
                'value': cache_hit_rate
            })
        
        # وضعیت کلی
        overall_status = 'HEALTHY'
        if any(alert['level'] == 'CRITICAL' for alert in alerts):
            overall_status = 'CRITICAL'
        elif any(alert['level'] == 'WARNING' for alert in alerts):
            overall_status = 'WARNING'
        
        return {
            'status': overall_status,
            'uptime_seconds': uptime,
            'metrics': {
                'total_requests': self.health_metrics['total_requests'],
                'blocked_requests': self.health_metrics['blocked_requests'],
                'failed_auth': self.health_metrics['failed_auth'],
                'rate_limited': self.health_metrics['rate_limited'],
                'active_sessions': len(self.active_sessions),
                'cache_hits': self.health_metrics['cache_hits'],
                'cache_misses': self.health_metrics['cache_misses'],
                'failed_auth_rate': failed_auth_rate,
                'blocked_request_rate': blocked_rate,
                'cache_hit_rate': cache_hit_rate
            },
            'alerts': alerts,
            'timestamp': now.isoformat(),
            'environment': self.environment
        }
    
    # ========== Middleware اصلی ==========
    
    @web.middleware
    async def middleware(self, request: web.Request, handler):
        """Middleware اصلی احراز هویت"""
        
        start_time = time.time()
        request_id = secrets.token_hex(8)
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # افزایش شمارنده درخواست‌ها
        self.health_metrics['total_requests'] += 1
        
        # 🔐 لایه 1: بررسی IP
        ip_check = self.check_ip_security(client_ip, user_agent)
        
        if ip_check['blocked']:
            self.health_metrics['blocked_requests'] += 1
            
            await self.log_audit_event(
                event_type='IP_BLOCKED',
                ip=client_ip,
                user_agent=user_agent,
                resource=request.path,
                action=request.method,
                status='FAILURE',
                details={'reason': ip_check['reason']}
            )
            
            return self._error_response(
                message='دسترسی از این IP مجاز نیست',
                status=403,
                request_id=request_id,
                error_code='IP_BLOCKED'
            )
        
        # ⚡ لایه 2: Rate Limiting
        rate_check = await self.check_rate_limit(
            identifier=client_ip,
            limit_type='per_ip',
            endpoint=request.path
        )
        
        if not rate_check['allowed']:
            self.health_metrics['rate_limited'] += 1
            
            return self._error_response(
                message='تعداد درخواست بیش از حد مجاز',
                status=429,
                request_id=request_id,
                error_code='RATE_LIMIT_EXCEEDED',
                headers={
                    'Retry-After': str(rate_check['retry_after'])
                }
            )
        
        # 🛡️ لایه 3: بررسی تهدیدات
        if request.can_read_body:
            try:
                body = await request.text()
                threat_check = self.detect_threats(body)
                
                if threat_check['action'] == 'block':
                    return self._error_response(
                        message='درخواست حاوی محتوای مشکوک است',
                        status=400,
                        request_id=request_id,
                        error_code='THREAT_DETECTED',
                        details={'threats': threat_check['threats']}
                    )
            except:
                pass
        
        # 🔑 لایه 4: احراز هویت
        auth_result = await self._authenticate_request(request, client_ip, user_agent)
        
        if not auth_result['authenticated']:
            self.health_metrics['failed_auth'] += 1
            
            return self._error_response(
                message=auth_result.get('message', 'احراز هویت ناموفق'),
                status=401,
                request_id=request_id,
                error_code=auth_result.get('error_code', 'AUTH_FAILED'),
                headers={
                    'WWW-Authenticate': f'Bearer realm="API", error="{auth_result.get("error_code")}"'
                }
            )
        
        # 👥 لایه 5: بررسی دسترسی
        user_data = auth_result['user_data']
        permission_check = self.check_permission(
            role=user_data.get('role', 'user'),
            permission=self._map_request_to_permission(request),
            context={'user_id': user_data.get('user_id')}
        )
        
        if not permission_check['allowed']:
            await self.log_audit_event(
                event_type='PERMISSION_DENIED',
                user_id=user_data.get('user_id'),
                ip=client_ip,
                user_agent=user_agent,
                resource=request.path,
                action=request.method,
                status='FAILURE',
                details={'required_permission': permission_check['required_permission']}
            )
            
            return self._error_response(
                message='شما دسترسی لازم برای این عملیات را ندارید',
                status=403,
                request_id=request_id,
                error_code='PERMISSION_DENIED'
            )
        
        # 🔐 لایه 6: بررسی نیاز به MFA
        if auth_result.get('requires_mfa', False):
            mfa_result = await self._check_mfa_requirement(
                request, 
                user_data.get('user_id'),
                client_ip,
                user_agent
            )
            
            if not mfa_result['verified']:
                return self._error_response(
                    message='تأیید دو مرحله‌ای مورد نیاز است',
                    status=403,
                    request_id=request_id,
                    error_code='MFA_REQUIRED',
                    details={'available_methods': mfa_result.get('available_methods')}
                )
        
        # 🎯 اضافه کردن اطلاعات کاربر به request
        request['user'] = user_data
        request['auth_method'] = auth_result['auth_method']
        request['request_id'] = request_id
        request['client_ip'] = client_ip
        
        # 🚀 اجرای درخواست
        try:
            response = await asyncio.wait_for(
                handler(request),
                timeout=self._get_timeout_for_endpoint(request.path)
            )
            
            # 📊 محاسبه زمان پردازش
            processing_time = time.time() - start_time
            
            # 📝 ثبت لاگ موفقیت
            await self.log_audit_event(
                event_type='REQUEST_SUCCESS',
                user_id=user_data.get('user_id'),
                ip=client_ip,
                user_agent=user_agent,
                resource=request.path,
                action=request.method,
                status='SUCCESS',
                details={
                    'processing_time': processing_time,
                    'status_code': response.status
                }
            )
            
            # 🛡️ اضافه کردن هدرهای امنیتی
            response = self._add_security_headers(response)
            response.headers['X-Request-ID'] = request_id
            response.headers['X-Processing-Time'] = f"{processing_time:.3f}"
            
            return response
            
        except asyncio.TimeoutError:
            return self._error_response(
                message='زمان پردازش درخواست به پایان رسید',
                status=504,
                request_id=request_id,
                error_code='TIMEOUT'
            )
        
        except Exception as e:
            logger.error(f"خطا در پردازش درخواست {request_id}: {str(e)}")
            
            return self._error_response(
                message='خطای داخلی سرور',
                status=500,
                request_id=request_id,
                error_code='INTERNAL_ERROR'
            )
    
    # ========== متدهای کمکی ==========
    
    async def _authenticate_request(self, 
                                  request: web.Request,
                                  client_ip: str,
                                  user_agent: str) -> Dict[str, Any]:
        """احراز هویت درخواست"""
        
        # روش 1: Bearer Token (JWT)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return await self._authenticate_jwt(
                auth_header[7:], 
                client_ip, 
                user_agent
            )
        
        # روش 2: API Key
        api_key = request.headers.get('X-API-Key') or request.query.get('api_key')
        if api_key:
            return await self._authenticate_api_key(api_key, client_ip)
        
        # روش 3: Session Cookie
        session_cookie = request.cookies.get('session_id')
        if session_cookie:
            return await self._authenticate_session(session_cookie, client_ip)
        
        # روش 4: Basic Auth (برای APIهای ساده)
        if auth_header and auth_header.startswith('Basic '):
            return await self._authenticate_basic(auth_header[6:], client_ip)
        
        return {
            'authenticated': False,
            'error_code': 'NO_AUTH_METHOD',
            'message': 'هیچ روش احراز هویت یافت نشد'
        }
    
    async def _authenticate_jwt(self, 
                              token: str, 
                              client_ip: str, 
                              user_agent: str) -> Dict[str, Any]:
        """احراز هویت JWT"""
        
        try:
            # بررسی کش
            cache_key = f"jwt:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
            cached = await self.cache_get(cache_key, 'token')
            
            if cached:
                return cached
            
            # بررسی revoked tokens
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash in self.revoked_hashes:
                return {
                    'authenticated': False,
                    'error_code': 'TOKEN_REVOKED',
                    'message': 'توکن ابطال شده است'
                }
            
            # رمزگشایی JWT
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_aud': False,
                    'verify_iss': False
                }
            )
            
            # بررسی اعتبار payload
            if not self._validate_jwt_payload(payload, client_ip, user_agent):
                return {
                    'authenticated': False,
                    'error_code': 'INVALID_TOKEN_PAYLOAD',
                    'message': 'اطلاعات توکن نامعتبر است'
                }
            
            user_data = {
                'user_id': payload.get('user_id'),
                'role': payload.get('role', 'user'),
                'session_id': payload.get('session_id'),
                'permissions': payload.get('permissions', []),
                'auth_method': 'jwt'
            }
            
            result = {
                'authenticated': True,
                'user_data': user_data,
                'auth_method': 'jwt',
                'requires_mfa': payload.get('requires_mfa', False),
                'token_expiry': payload.get('exp')
            }
            
            # ذخیره در کش
            await self.cache_set(cache_key, result, 'token', 300)
            
            return result
            
        except jwt.ExpiredSignatureError:
            return {
                'authenticated': False,
                'error_code': 'TOKEN_EXPIRED',
                'message': 'توکن منقضی شده است'
            }
        except jwt.InvalidTokenError as e:
            return {
                'authenticated': False,
                'error_code': 'INVALID_TOKEN',
                'message': f'توکن نامعتبر: {str(e)}'
            }
    
    def _validate_jwt_payload(self, 
                            payload: Dict, 
                            client_ip: str, 
                            user_agent: str) -> bool:
        """اعتبارسنجی محتوای JWT"""
        
        required_fields = ['user_id', 'exp', 'iat']
        
        # بررسی وجود فیلدهای ضروری
        for field in required_fields:
            if field not in payload:
                return False
        
        # بررسی IP (اگر در توکن ذخیره شده)
        if 'ip' in payload and payload['ip'] != client_ip:
            logger.warning(f"IP mismatch: {payload['ip']} != {client_ip}")
            # می‌توانید این را به عنوان warning بپذیرید یا reject کنید
            # در اینجا به عنوان warning می‌پذیریم
        
        # بررسی User-Agent (اگر در توکن ذخیره شده)
        if 'ua' in payload and user_agent:
            # می‌توانید بررسی دقیق‌تری انجام دهید
            pass
        
        return True
    
    async def _authenticate_api_key(self, 
                                  api_key: str, 
                                  client_ip: str) -> Dict[str, Any]:
        """احراز هویت با API Key"""
        
        # بررسی کش
        cache_key = f"apikey:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"
        cached = await self.cache_get(cache_key, 'apikey')
        
        if cached:
            return cached
        
        # بررسی در حافظه
        if api_key in self.api_keys:
            key_data = self.api_keys[api_key]
            
            # بررسی انقضا
            if 'expires_at' in key_data:
                if datetime.fromisoformat(key_data['expires_at']) < datetime.now():
                    del self.api_keys[api_key]
                    return {
                        'authenticated': False,
                        'error_code': 'API_KEY_EXPIRED',
                        'message': 'API Key منقضی شده است'
                    }
            
            # بررسی IP restrictions
            if 'allowed_ips' in key_data and client_ip not in key_data['allowed_ips']:
                return {
                    'authenticated': False,
                    'error_code': 'IP_NOT_ALLOWED',
                    'message': 'دسترسی از این IP مجاز نیست'
                }
            
            # افزایش شمارنده استفاده
            key_data['last_used'] = datetime.now().isoformat()
            key_data['usage_count'] = key_data.get('usage_count', 0) + 1
            
            user_data = {
                'user_id': key_data.get('user_id', 'api_client'),
                'role': key_data.get('role', 'api_client'),
                'permissions': key_data.get('permissions', []),
                'auth_method': 'api_key'
            }
            
            result = {
                'authenticated': True,
                'user_data': user_data,
                'auth_method': 'api_key'
            }
            
            # ذخیره در کش
            await self.cache_set(cache_key, result, 'apikey', 600)
            
            return result
        
        return {
            'authenticated': False,
            'error_code': 'INVALID_API_KEY',
            'message': 'API Key نامعتبر است'
        }
    
    async def _authenticate_session(self, 
                                  session_id: str, 
                                  client_ip: str) -> Dict[str, Any]:
        """احراز هویت با Session"""
        
        session_check = await self.validate_session(session_id, client_ip)
        
        if not session_check['valid']:
            return {
                'authenticated': False,
                'error_code': 'INVALID_SESSION',
                'message': f'Session نامعتبر: {session_check.get("reason")}'
            }
        
        session_data = session_check['session_data']
        
        # بازیابی اطلاعات کاربر از session
        # در پروژه واقعی باید از دیتابیس بخوانید
        user_data = {
            'user_id': session_data['user_id'],
            'role': 'user',  # باید از دیتابیس بخوانید
            'session_id': session_id,
            'permissions': [],  # باید از دیتابیس بخوانید
            'auth_method': 'session',
            'device_info': session_data.get('device_info', {})
        }
        
        return {
            'authenticated': True,
            'user_data': user_data,
            'auth_method': 'session',
            'session_data': session_data
        }
    
    async def _authenticate_basic(self, 
                                credentials: str, 
                                client_ip: str) -> Dict[str, Any]:
        """احراز هویت Basic Auth"""
        
        try:
            import base64
            decoded = base64.b64decode(credentials).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            # در پروژه واقعی باید از دیتابیس اعتبارسنجی کنید
            # اینجا فقط شبیه‌سازی شده
            if username == 'admin' and password == 'admin':
                user_data = {
                    'user_id': 'admin',
                    'role': 'admin',
                    'permissions': ['*'],
                    'auth_method': 'basic'
                }
                
                return {
                    'authenticated': True,
                    'user_data': user_data,
                    'auth_method': 'basic'
                }
            
            return {
                'authenticated': False,
                'error_code': 'INVALID_CREDENTIALS',
                'message': 'نام کاربری یا رمز عبور نامعتبر'
            }
            
        except:
            return {
                'authenticated': False,
                'error_code': 'INVALID_BASIC_AUTH',
                'message': 'احراز هویت Basic نامعتبر'
            }
    
    async def _check_mfa_requirement(self, 
                                   request: web.Request,
                                   user_id: str,
                                   client_ip: str,
                                   user_agent: str) -> Dict[str, Any]:
        """بررسی نیاز به MFA"""
        
        # بررسی مسیرهای حساس
        sensitive_paths = [
            '/api/accounts/delete',
            '/api/backup/create',
            '/api/admin/',
            '/api/users/create',
            '/api/system/restart'
        ]
        
        requires_mfa = any(request.path.startswith(p) for p in sensitive_paths)
        
        if not requires_mfa:
            return {'verified': True, 'method': 'not_required'}
        
        # بررسی دستگاه‌های معتبر
        if user_id in self.trusted_devices:
            device_hash = hashlib.sha256(
                f"{client_ip}:{user_agent}".encode()
            ).hexdigest()[:16]
            
            for device in self.trusted_devices[user_id]:
                if device['device_hash'] == device_hash:
                    # بررسی زمان آخرین استفاده
                    last_used = datetime.fromisoformat(device['last_used'])
                    if (datetime.now() - last_used).total_seconds() < 2592000:  # 30 روز
                        return {'verified': True, 'method': 'trusted_device'}
        
        # نیاز به MFA داریم
        return {
            'verified': False,
            'required': True,
            'available_methods': ['totp', 'sms', 'email']
        }
    
    def _map_request_to_permission(self, request: web.Request) -> str:
        """نگاشت درخواست به permission"""
        
        path = request.path
        method = request.method
        
        # ساختار: resource:action
        resource = path.split('/')[2] if len(path.split('/')) > 2 else 'general'
        
        action_map = {
            'GET': 'read',
            'POST': 'create',
            'PUT': 'update',
            'DELETE': 'delete',
            'PATCH': 'update'
        }
        
        action = action_map.get(method, 'read')
        
        return f"{resource}:{action}"
    
    def _get_timeout_for_endpoint(self, path: str) -> int:
        """تعیین timeout براساس endpoint"""
        
        timeout_map = {
            '/api/accounts/login': 30,
            '/api/backup/create': 300,
            '/api/messages/send': 10,
            '/api/admin/': 60,
            '/api/system/restart': 120
        }
        
        for endpoint, timeout in timeout_map.items():
            if path.startswith(endpoint):
                return timeout
        
        return 30  # timeout پیش‌فرض
    
    def _get_client_ip(self, request: web.Request) -> str:
        """دریافت IP واقعی کلاینت"""
        
        headers = ['X-Real-IP', 'X-Forwarded-For', 'CF-Connecting-IP']
        
        for header in headers:
            ip = request.headers.get(header)
            if ip:
                return ip.split(',')[0].strip()
        
        return request.remote
    
    def _add_security_headers(self, response: web.Response) -> web.Response:
        """اضافه کردن هدرهای امنیتی"""
        
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response
    
    def _error_response(self, 
                       message: str, 
                       status: int = 400,
                       request_id: str = None,
                       error_code: str = None,
                       details: Dict = None,
                       headers: Dict = None) -> web.Response:
        """ایجاد پاسخ خطا"""
        
        response_data = {
            'success': False,
            'error': message,
            'error_code': error_code or 'UNKNOWN_ERROR',
            'request_id': request_id or secrets.token_hex(8),
            'timestamp': datetime.now().isoformat()
        }
        
        if details:
            response_data['details'] = details
        
        response = web.json_response(response_data, status=status)
        
        if headers:
            for key, value in headers.items():
                response.headers[key] = value
        
        return response

# ========== تابع اصلی ==========

async def main():
    """تابع اصلی"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='سیستم مدیریت پیشرفته اکانت تلگرام',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
مثال‌ها:
  %(prog)s --interactive
  %(prog)s --login +989123456789
  %(prog)s --api --port 8080
  %(prog)s --config custom_config.json
        """
    )
    
    parser.add_argument('--interactive', action='store_true',
                       help='اجرای حالت تعاملی')
    parser.add_argument('--login', metavar='PHONE',
                       help='ورود مستقیم با شماره')
    parser.add_argument('--api', action='store_true',
                       help='شروع API سرور')
    parser.add_argument('--port', type=int, default=8080,
                       help='پورت API سرور')
    parser.add_argument('--config', default='config.json',
                       help='فایل تنظیمات')
    parser.add_argument('--debug', action='store_true',
                       help='حالت دیباگ')
    
    args = parser.parse_args()
    
    # تنظیم لاگ
    global logger
    logger = setup_logging(debug=args.debug)
    
    # بارگذاری config
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"❌ فایل config یافت نشد: {args.config}")
        return
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        print(f"❌ خطا در خواندن config: {e}")
        return
    
    # ایجاد مدیر اکانت
    manager = AdvancedAccountManager(
        base_dir=Path(config.get('accounts_dir', 'accounts')),
        encryption_key=config.get('encryption_key'),
        api_id=config.get('api_id'),
        api_hash=config.get('api_hash')
    )
    
    # تنظیم proxy اگر وجود دارد
    if 'proxy' in config:
        manager.proxy_settings = config['proxy']
    
    # تنظیم webhook اگر وجود دارد
    if 'webhook_url' in config:
        manager.webhook_url = config['webhook_url']
    
    try:
        if args.api:
            # شروع API سرور
            print(f"\n🚀 شروع API سرور روی پورت {args.port}...")
            await manager.start_api_server(port=args.port)
            
            # اجرای نامحدود
            await asyncio.Future()
            
        elif args.interactive:
            # حالت تعاملی
            cli = AdvancedCLI(manager)
            await cli.run()
            
        elif args.login:
            # ورود مستقیم
            print(f"\n🔐 ورود برای {args.login}...")
            success, client, account_id = await manager.login_with_phone_advanced(
                phone=args.login
            )
            
            if success:
                print(f"✅ ورود موفق: {account_id}")
                if client:
                    await client.disconnect()
            else:
                print(f"❌ ورود ناموفق: {account_id}")
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\n👋 برنامه توسط کاربر متوقف شد")
    except Exception as e:
        print(f"\n💥 خطای سیستمی: {e}")
        logger.exception("Main error")
        sys.exit(1)

if __name__ == "__main__":
    # بررسی وابستگی‌ها
    if not HAS_TELETHON:
        print("❌ Telethon ضروری است: pip install telethon")
        sys.exit(1)
    
    # اجرا
    asyncio.run(main())
