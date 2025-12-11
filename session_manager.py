#!/usr/bin/env python3
# session_manager.py - سیستم مدیریت session ایمن برای UserBot

import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from cryptography.fernet import Fernet
import pickle

logger = logging.getLogger(__name__)

class AdvancedSessionManager:
    """
    سیستم مدیریت session پیشرفته برای UserBot
    ویژگی‌ها:
    - رمزگذاری session‌ها
    - چرخش خودکار session
    - بازیابی از خطا
    - محدودیت امنیتی
    - لاگ کامل فعالیت‌ها
    """
    
    def __init__(self, base_dir: Path = Path("sessions")):
        self.base_dir = Path(base_dir)
        self.sessions_dir = self.base_dir / "telethon_sessions"
        self.backup_dir = self.base_dir / "backups"
        self.metadata_file = self.base_dir / "session_metadata.json"
        
        # ایجاد پوشه‌ها
        for directory in [self.base_dir, self.sessions_dir, self.backup_dir]:
            directory.mkdir(exist_ok=True)
        
        # کلید رمزگذاری
        self.key_file = self.base_dir / ".session_key"
        self.cipher = self._init_encryption()
        
        # تنظیمات
        self.config = self._load_config()
        self.metadata = self._load_metadata()
        
        # لاک برای thread-safe بودن
        self.lock = asyncio.Lock()
        
        logger.info("AdvancedSessionManager initialized")
    
    def _init_encryption(self) -> Optional[Fernet]:
        """راه‌اندازی سیستم رمزگذاری"""
        try:
            if self.key_file.exists():
                with open(self.key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                # فقط مالک بتواند بخواند
                self.key_file.chmod(0o600)
            
            return Fernet(key)
        except Exception as e:
            logger.error(f"Encryption init failed: {e}")
            return None
    
    def _load_config(self) -> Dict:
        """بارگذاری تنظیمات"""
        default_config = {
            'max_sessions': 3,
            'session_lifetime_hours': 24 * 7,  # 1 week
            'auto_rotate': True,
            'rotate_after_errors': 5,
            'backup_count': 5,
            'encryption_enabled': True,
            'compress_sessions': True,
            'geo_diversity': False,  # ایجاد session از موقعیت‌های مختلف
            'device_rotation': True,  # چرخش مدل دستگاه
        }
        
        config_file = self.base_dir / "session_config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        # ذخیره config
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2)
        
        return default_config
    
    def _load_metadata(self) -> Dict:
        """بارگذاری متادیتای session‌ها"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            'sessions': {},
            'active_session': None,
            'rotation_history': [],
            'error_stats': {},
            'created_at': datetime.now().isoformat()
        }
    
    def _save_metadata(self):
        """ذخیره متادیتا"""
        try:
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(self.metadata, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
    
    def _generate_session_name(self, prefix: str = "session") -> str:
        """تولید نام منحصربفرد برای session"""
        timestamp = int(time.time())
        random_part = secrets.token_hex(4)
        return f"{prefix}_{timestamp}_{random_part}"
    
    def _encrypt_session_data(self, data: bytes) -> bytes:
        """رمزگذاری داده‌های session"""
        if self.cipher and self.config['encryption_enabled']:
            return self.cipher.encrypt(data)
        return data
    
    def _decrypt_session_data(self, encrypted_data: bytes) -> bytes:
        """رمزگشایی داده‌های session"""
        if self.cipher and self.config['encryption_enabled']:
            return self.cipher.decrypt(encrypted_data)
        return encrypted_data
    
    def _generate_device_info(self, session_num: int = 0) -> Dict:
        """تولید اطلاعات دستگاه تصادفی"""
        devices = [
            {
                'device_model': 'iPhone 14 Pro',
                'system_version': 'iOS 16.6',
                'app_version': '9.4.1',
                'lang_code': 'en',
                'system_lang_code': 'en-US'
            },
            {
                'device_model': 'Samsung Galaxy S23',
                'system_version': 'Android 13',
                'app_version': '9.4',
                'lang_code': 'en',
                'system_lang_code': 'en-US'
            },
            {
                'device_model': 'Xiaomi Redmi Note 12',
                'system_version': 'Android 12',
                'app_version': '9.3',
                'lang_code': 'fa',
                'system_lang_code': 'fa-IR'
            },
            {
                'device_model': 'Google Pixel 7',
                'system_version': 'Android 14',
                'app_version': '9.5',
                'lang_code': 'en',
                'system_lang_code': 'en-GB'
            }
        ]
        
        if self.config.get('device_rotation', False):
            return devices[session_num % len(devices)]
        else:
            return devices[0]  # ثابت نگه داشتن
    
    async def create_new_session(self, api_id: int, api_hash: str, phone: str = None) -> Dict:
        """
        ایجاد session جدید
        Returns: اطلاعات session ایجاد شده
        """
        async with self.lock:
            try:
                # بررسی تعداد session‌ها
                active_sessions = self._get_active_sessions()
                if len(active_sessions) >= self.config['max_sessions']:
                    logger.warning("Max sessions reached, rotating...")
                    await self.rotate_sessions()
                
                # نام session جدید
                session_name = self._generate_session_name()
                session_path = self.sessions_dir / f"{session_name}.session"
                
                # اطلاعات session
                session_info = {
                    'name': session_name,
                    'path': str(session_path),
                    'api_id': api_id,
                    'api_hash': api_hash,
                    'phone': phone,
                    'created_at': datetime.now().isoformat(),
                    'last_used': None,
                    'usage_count': 0,
                    'error_count': 0,
                    'status': 'created',
                    'device_info': self._generate_device_info(len(active_sessions)),
                    'location_info': self._generate_location_info(),
                    'is_active': False
                }
                
                # ذخیره در متادیتا
                self.metadata['sessions'][session_name] = session_info
                
                if not self.metadata['active_session']:
                    self.metadata['active_session'] = session_name
                    session_info['is_active'] = True
                
                self._save_metadata()
                
                logger.info(f"Created new session: {session_name}")
                return session_info
                
            except Exception as e:
                logger.error(f"Error creating session: {e}")
                raise
    
    def _generate_location_info(self) -> Dict:
        """تولید اطلاعات موقعیت جغرافیایی"""
        if not self.config.get('geo_diversity', False):
            return {}
        
        locations = [
            {'ip': '5.202.192.0', 'country': 'Iran', 'city': 'Tehran'},
            {'ip': '185.143.223.0', 'country': 'Germany', 'city': 'Frankfurt'},
            {'ip': '104.244.72.0', 'country': 'USA', 'city': 'New York'},
            {'ip': '45.95.168.0', 'country': 'Netherlands', 'city': 'Amsterdam'},
        ]
        
        return secrets.choice(locations)
    
    async def rotate_sessions(self, force: bool = False):
        """چرخش session‌ها"""
        async with self.lock:
            try:
                active_session = self.metadata.get('active_session')
                sessions = self.metadata.get('sessions', {})
                
                if not sessions:
                    logger.warning("No sessions to rotate")
                    return
                
                # پیدا کردن session بعدی
                session_names = list(sessions.keys())
                if active_session in session_names:
                    current_index = session_names.index(active_session)
                    next_index = (current_index + 1) % len(session_names)
                else:
                    next_index = 0
                
                next_session_name = session_names[next_index]
                
                # بررسی نیاز به چرخش
                if active_session:
                    current_session = sessions[active_session]
                    
                    # بررسی عمر session
                    created_at = datetime.fromisoformat(current_session['created_at'])
                    lifetime = datetime.now() - created_at
                    
                    should_rotate = (
                        force or
                        lifetime.total_seconds() > self.config['session_lifetime_hours'] * 3600 or
                        current_session['error_count'] >= self.config['rotate_after_errors'] or
                        self.config['auto_rotate']
                    )
                    
                    if not should_rotate:
                        logger.debug("No need to rotate sessions yet")
                        return
                
                # انجام چرخش
                if active_session:
                    sessions[active_session]['is_active'] = False
                    sessions[active_session]['last_used'] = datetime.now().isoformat()
                
                sessions[next_session_name]['is_active'] = True
                self.metadata['active_session'] = next_session_name
                
                # ثبت در تاریخچه
                rotation_record = {
                    'timestamp': datetime.now().isoformat(),
                    'from': active_session,
                    'to': next_session_name,
                    'reason': 'auto_rotate' if not force else 'manual'
                }
                self.metadata['rotation_history'].append(rotation_record)
                
                # حفظ فقط آخرین 50 رکورد
                if len(self.metadata['rotation_history']) > 50:
                    self.metadata['rotation_history'] = self.metadata['rotation_history'][-50:]
                
                self._save_metadata()
                
                logger.info(f"Rotated session: {active_session} -> {next_session_name}")
                
                # پشتیبان‌گیری از session قدیمی
                if active_session:
                    await self.backup_session(active_session)
                
                return next_session_name
                
            except Exception as e:
                logger.error(f"Error rotating sessions: {e}")
                raise
    
    async def backup_session(self, session_name: str):
        """پشتیبان‌گیری از session"""
        try:
            sessions = self.metadata.get('sessions', {})
            if session_name not in sessions:
                return
            
            session_info = sessions[session_name]
            session_path = Path(session_info['path'])
            
            if not session_path.exists():
                return
            
            # نام فایل پشتیبان
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{session_name}_{timestamp}.bak"
            backup_path = self.backup_dir / backup_name
            
            # کپی فایل session
            import shutil
            shutil.copy2(session_path, backup_path)
            
            # رمزگذاری پشتیبان
            if self.config['encryption_enabled']:
                with open(backup_path, 'rb') as f:
                    data = f.read()
                
                encrypted = self._encrypt_session_data(data)
                
                with open(backup_path, 'wb') as f:
                    f.write(encrypted)
            
            # فشرده‌سازی
            if self.config['compress_sessions']:
                import gzip
                compressed_path = backup_path.with_suffix('.bak.gz')
                
                with open(backup_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        f_out.write(f_in.read())
                
                backup_path.unlink()  # حذف فایل غیرفشرده
                backup_path = compressed_path
            
            # مدیریت تعداد پشتیبان‌ها
            backups = list(self.backup_dir.glob(f"{session_name}_*.bak*"))
            backups.sort(key=os.path.getmtime)
            
            if len(backups) > self.config['backup_count']:
                for old_backup in backups[:-self.config['backup_count']]:
                    old_backup.unlink()
            
            logger.debug(f"Backup created: {backup_name}")
            
        except Exception as e:
            logger.error(f"Error backing up session: {e}")
    
    async def restore_session(self, session_name: str, backup_timestamp: str = None) -> bool:
        """بازیابی session از پشتیبان"""
        try:
            # یافتن پشتیبان مناسب
            if backup_timestamp:
                backup_pattern = f"{session_name}_{backup_timestamp}.bak*"
            else:
                # جدیدترین پشتیبان
                backups = list(self.backup_dir.glob(f"{session_name}_*.bak*"))
                if not backups:
                    return False
                backups.sort(key=os.path.getmtime, reverse=True)
                backup_path = backups[0]
            
            backup_path = list(self.backup_dir.glob(backup_pattern))[0]
            
            session_info = self.metadata['sessions'][session_name]
            session_path = Path(session_info['path'])
            
            # فشرده‌سازی
            if backup_path.suffix == '.gz':
                import gzip
                with gzip.open(backup_path, 'rb') as f_in:
                    data = f_in.read()
            else:
                with open(backup_path, 'rb') as f:
                    data = f.read()
            
            # رمزگشایی
            if self.config['encryption_enabled']:
                data = self._decrypt_session_data(data)
            
            # ذخیره session بازیابی شده
            with open(session_path, 'wb') as f:
                f.write(data)
            
            logger.info(f"Session restored: {session_name} from {backup_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring session: {e}")
            return False
    
    def _get_active_sessions(self) -> List[Dict]:
        """دریافت session‌های فعال"""
        return [
            session for session in self.metadata['sessions'].values()
            if session.get('is_active', False)
        ]
    
    async def get_active_session_info(self) -> Optional[Dict]:
        """دریافت اطلاعات session فعال"""
        active_name = self.metadata.get('active_session')
        if not active_name:
            return None
        
        sessions = self.metadata.get('sessions', {})
        return sessions.get(active_name)
    
    async def update_session_stats(self, session_name: str, success: bool = True, error_msg: str = None):
        """به‌روزرسانی آمار session"""
        async with self.lock:
            try:
                sessions = self.metadata.get('sessions', {})
                if session_name not in sessions:
                    return
                
                session_info = sessions[session_name]
                session_info['last_used'] = datetime.now().isoformat()
                session_info['usage_count'] = session_info.get('usage_count', 0) + 1
                
                if not success:
                    session_info['error_count'] = session_info.get('error_count', 0) + 1
                    session_info['last_error'] = error_msg
                    session_info['last_error_time'] = datetime.now().isoformat()
                else:
                    # ریست شمارش خطا پس از موفقیت‌های متوالی
                    if session_info.get('error_count', 0) > 0:
                        session_info['error_count'] = max(0, session_info['error_count'] - 1)
                
                self._save_metadata()
                
            except Exception as e:
                logger.error(f"Error updating session stats: {e}")
    
    async def cleanup_old_sessions(self):
        """پاکسازی session‌های قدیمی"""
        async with self.lock:
            try:
                sessions = self.metadata.get('sessions', {}).copy()
                now = datetime.now()
                
                for session_name, session_info in sessions.items():
                    created_at = datetime.fromisoformat(session_info['created_at'])
                    age_days = (now - created_at).days
                    
                    # شرایط حذف session
                    should_remove = (
                        age_days > 30 or  # بیشتر از 30 روز
                        session_info.get('error_count', 0) > 20 or  # خطاهای زیاد
                        (not session_info.get('is_active', False) and 
                         age_days > 7)  # غیرفعال و بیشتر از 7 روز
                    )
                    
                    if should_remove:
                        # حذف فایل session
                        session_path = Path(session_info['path'])
                        if session_path.exists():
                            session_path.unlink()
                        
                        # حذف از متادیتا
                        del self.metadata['sessions'][session_name]
                        
                        # اگر session فعال بود، انتخاب session جدید
                        if self.metadata.get('active_session') == session_name:
                            await self.rotate_sessions(force=True)
                        
                        logger.info(f"Removed old session: {session_name}")
                
                self._save_metadata()
                
            except Exception as e:
                logger.error(f"Error cleaning up sessions: {e}")
    
    async def export_session_report(self) -> Dict:
        """خروجی گزارش کامل session‌ها"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_sessions': len(self.metadata.get('sessions', {})),
            'active_sessions': len(self._get_active_sessions()),
            'sessions': [],
            'rotation_history': self.metadata.get('rotation_history', [])[-10:],
            'backup_count': len(list(self.backup_dir.glob('*.bak*'))),
            'config': self.config
        }
        
        for session_name, session_info in self.metadata.get('sessions', {}).items():
            session_report = {
                'name': session_name,
                'is_active': session_info.get('is_active', False),
                'created_at': session_info.get('created_at'),
                'last_used': session_info.get('last_used'),
                'usage_count': session_info.get('usage_count', 0),
                'error_count': session_info.get('error_count', 0),
                'status': session_info.get('status', 'unknown'),
                'device': session_info.get('device_info', {}).get('device_model', 'unknown'),
                'age_days': (
                    datetime.now() - datetime.fromisoformat(session_info['created_at'])
                ).days if 'created_at' in session_info else None
            }
            report['sessions'].append(session_report)
        
        return report
    
    async def validate_sessions(self) -> List[Tuple[str, bool, str]]:
        """اعتبارسنجی همه session‌ها"""
        results = []
        
        for session_name, session_info in self.metadata.get('sessions', {}).items():
            try:
                session_path = Path(session_info['path'])
                
                if not session_path.exists():
                    results.append((session_name, False, "File not found"))
                    continue
                
                # بررسی سایز فایل
                file_size = session_path.stat().st_size
                if file_size < 100:  # بسیار کوچک
                    results.append((session_name, False, "File too small (corrupted?)"))
                    continue
                
                # بررسی محتوای فایل (اگر رمزگذاری نشده)
                if not self.config['encryption_enabled']:
                    with open(session_path, 'rb') as f:
                        content = f.read(100)
                    
                    if b'sqlite' not in content and b'SQLite' not in content:
                        results.append((session_name, False, "Invalid session format"))
                        continue
                
                results.append((session_name, True, "Valid"))
                
            except Exception as e:
                results.append((session_name, False, str(e)))
        
        return results

class SessionClientWrapper:
    """
    wrapper برای Telethon Client با مدیریت session پیشرفته
    """
    
    def __init__(self, session_manager: AdvancedSessionManager):
        self.session_manager = session_manager
        self.client = None
        self.current_session = None
        
    async def get_client(self):
        """دریافت کلاینت فعال"""
        if self.client and self.client.is_connected():
            return self.client
        
        await self._reconnect()
        return self.client
    
    async def _reconnect(self):
        """اتصال مجدد با session فعال"""
        try:
            if self.client:
                await self.client.disconnect()
            
            session_info = await self.session_manager.get_active_session_info()
            if not session_info:
                raise Exception("No active session available")
            
            from telethon import TelegramClient
            
            self.current_session = session_info['name']
            
            self.client = TelegramClient(
                session=session_info['path'],
                api_id=session_info['api_id'],
                api_hash=session_info['api_hash'],
                device_model=session_info['device_info']['device_model'],
                system_version=session_info['device_info']['system_version'],
                app_version=session_info['device_info']['app_version'],
                lang_code=session_info['device_info']['lang_code'],
                system_lang_code=session_info['device_info']['system_lang_code']
            )
            
            await self.client.start()
            
            # به‌روزرسانی آمار
            await self.session_manager.update_session_stats(
                self.current_session, 
                success=True
            )
            
            logger.info(f"Connected with session: {self.current_session}")
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            
            # ثبت خطا
            if self.current_session:
                await self.session_manager.update_session_stats(
                    self.current_session,
                    success=False,
                    error_msg=str(e)
                )
                
                # چرخش session در صورت خطا
                if "FloodWaitError" in str(e) or "AuthKeyError" in str(e):
                    await self.session_manager.rotate_sessions(force=True)
            
            raise
    
    async def execute_with_retry(self, coroutine_func, max_retries: int = 3):
        """
        اجرای یک عمل با قابلیت تلاش مجدد و چرخش session
        """
        for attempt in range(max_retries):
            try:
                client = await self.get_client()
                result = await coroutine_func(client)
                
                # موفقیت
                if self.current_session:
                    await self.session_manager.update_session_stats(
                        self.current_session,
                        success=True
                    )
                
                return result
                
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {e}")
                
                # ثبت خطا
                if self.current_session:
                    await self.session_manager.update_session_stats(
                        self.current_session,
                        success=False,
                        error_msg=str(e)
                    )
                
                # تصمیم‌گیری برای چرخش session
                should_rotate = any([
                    "FloodWaitError" in str(e),
                    "AuthKeyError" in str(e),
                    "SessionRevokedError" in str(e),
                    attempt >= 1  # بعد از اولین تلاش ناموفق
                ])
                
                if should_rotate and attempt < max_retries - 1:
                    logger.info("Rotating session and retrying...")
                    await self.session_manager.rotate_sessions(force=True)
                    self.client = None  # force reconnect
                    await asyncio.sleep(2 ** attempt)  # exponential backoff
                    continue
                else:
                    raise
    
    async def close(self):
        """بستن ایمن"""
        if self.client and self.client.is_connected():
            await self.client.disconnect()
            logger.info("Client disconnected")

# تابع کمکی برای استفاده آسان
async def create_session_manager() -> AdvancedSessionManager:
    """ایجاد instance از Session Manager"""
    manager = AdvancedSessionManager()
    
    # اجرای پاکسازی دوره‌ای
    await manager.cleanup_old_sessions()
    
    # اعتبارسنجی session‌ها
    validation_results = await manager.validate_sessions()
    invalid_sessions = [r for r in validation_results if not r[1]]
    
    if invalid_sessions:
        logger.warning(f"Found {len(invalid_sessions)} invalid sessions")
        for session_name, is_valid, reason in invalid_sessions:
            logger.warning(f"  - {session_name}: {reason}")
    
    return manager

class CompleteSecureSystem:
    """سیستم کامل با همه حفاظت‌ها"""
    
    def __init__(self, token: str, api_id: int, api_hash: str):
        self.bot = telebot.TeleBot(token)
        
        # ماژول‌های امنیتی
        self.auth = UserAuthentication()
        self.session_mgr = IsolatedSessionManager()
        self.access_ctl = OwnershipBasedAccess()
        self.logout_sys = SafeLogoutSystem()
        self.activity_monitor = UserActivityMonitor()
        
        # تنظیمات
        self.settings = {
            'max_accounts_per_user': 2,
            'session_timeout_hours': 24,
            'require_phone_verification': True,
            'enable_auto_logout': True,
            'log_all_activities': True,
            'notify_on_new_login': True,
            'enable_two_step_verification': False
        }
        
        self.setup_handlers()
    
    def setup_handlers(self):
        @self.bot.message_handler(commands=['login'])
        def login_handler(message):
            user_id = message.from_user.id
            
            # 1. بررسی مجوز کاربر
            auth_result = self.auth.is_user_allowed(user_id)
            if not auth_result['allowed']:
                self.bot.send_message(user_id, "❌ دسترسی denied")
                return
            
            # 2. بررسی محدودیت تعداد اکانت
            user_accounts = self._count_user_accounts(user_id)
            if user_accounts >= self.settings['max_accounts_per_user']:
                self.bot.send_message(
                    user_id,
                    f"❌ شما حداکثر {self.settings['max_accounts_per_user']} اکانت می‌توانید اضافه کنید."
                )
                return
            
            # 3. درخواست شماره تلفن
            msg = self.bot.send_message(
                user_id,
                "📱 لطفاً شماره تلفن تلگرام خود را ارسال کنید:\n\n"
                "⚠️ توجه: این شماره فقط برای یکبار ورود استفاده می‌شود."
            )
            self.bot.register_next_step_handler(msg, process_login)
        
        def process_login(message):
            user_id = message.from_user.id
            phone = message.text
            
            # 1. اعتبارسنجی شماره
            if not self._validate_phone_number(phone):
                self.bot.send_message(user_id, "❌ شماره تلفن نامعتبر است")
                return
            
            # 2. ایجاد session مخصوص کاربر
            session_name = f"user_{user_id}_{int(time.time())}"
            session_path = self.session_mgr.create_user_session(user_id, session_name)
            
            # 3. ثبت مالکیت
            self.access_ctl.register_session_owner(session_name, user_id)
            
            # 4. شروع فرآیند login (در thread جدا)
            Thread(target=self._perform_login_async, 
                  args=(user_id, phone, session_name, session_path)).start()
            
            self.bot.send_message(
                user_id,
                "⏳ در حال اتصال...\n"
                "لطفاً کد تأیید را در تلگرام خود وارد کنید."
            )
        
        @self.bot.message_handler(commands=['myaccounts'])
        def list_accounts_handler(message):
            user_id = message.from_user.id
            
            # فقط مالک می‌تواند session‌های خود را ببیند
            sessions = self.session_mgr.list_user_sessions(user_id)
            
            if not sessions:
                self.bot.send_message(user_id, "📭 هیچ اکانتی ندارید.")
                return
            
            keyboard = types.InlineKeyboardMarkup()
            for session_path in sessions:
                session_name = session_path.stem
                btn_text = f"👤 {session_name}"
                
                keyboard.add(types.InlineKeyboardButton(
                    btn_text,
                    callback_data=f"view_session_{session_name}"
                ))
            
            self.bot.send_message(
                user_id,
                f"📋 اکانت‌های شما ({len(sessions)}):",
                reply_markup=keyboard
            )
        
        @self.bot.callback_query_handler(func=lambda call: call.data.startswith('logout_'))
        def logout_callback_handler(call):
            user_id = call.from_user.id
            session_name = call.data.replace('logout_', '')
            
            # بررسی مالکیت
            if not self.access_ctl.can_access_session(user_id, session_name):
                self.bot.answer_callback_query(call.id, "❌ دسترسی denied")
                return
            
            # درخواست logout با تأیید
            result = self.logout_sys.request_logout(user_id, session_name)
            
            if result['success']:
                if result.get('needs_confirmation'):
                    self.bot.answer_callback_query(
                        call.id, 
                        "لطفاً در پیام بعدی تأیید کنید"
                    )
                else:
                    self.bot.answer_callback_query(call.id, "✅ logout شد")
            else:
                self.bot.answer_callback_query(call.id, f"❌ {result.get('error')}")
        
        @self.bot.message_handler(func=lambda m: m.text.startswith('/confirm_logout_'))
        def confirm_logout_handler(message):
            user_id = message.from_user.id
            request_id = message.text.replace('/confirm_logout_', '')
            
            # پیدا کردن درخواست
            if request_id in self.logout_sys.logout_requests:
                req = self.logout_sys.logout_requests[request_id]
                
                if req['user_id'] == user_id and req['status'] == 'pending':
                    # اجرای logout
                    result = self.logout_sys._execute_logout(
                        user_id, 
                        req['session_name']
                    )
                    
                    if result['success']:
                        self.bot.send_message(user_id, "✅ با موفقیت logout شدید.")
                    else:
                        self.bot.send_message(user_id, f"❌ {result.get('error')}")
                    
                    # به‌روزرسانی وضعیت درخواست
                    req['status'] = 'completed'
                else:
                    self.bot.send_message(user_id, "❌ درخواست نامعتبر است.")
            else:
                self.bot.send_message(user_id, "❌ درخواست یافت نشد.")

class SafeLogoutSystem:
    """سیستم logout ایمن با تأیید کاربر"""
    
    def __init__(self):
        self.active_sessions = {}  # user_id -> {sessions: [], last_activity: timestamp}
        self.logout_requests = {}  # session_name -> {requested_by: user_id, timestamp}
        self.logout_settings = {
            'auto_logout_after_hours': 24,
            'inactivity_timeout_minutes': 60,
            'require_confirmation': True,
            'send_warning_before_logout': True,
            'warning_minutes_before': 5
        }
    
    async def check_auto_logout(self, user_id: int, session_name: str) -> bool:
        """بررسی نیاز به auto-logout"""
        if user_id not in self.active_sessions:
            return False
        
        session_info = self.active_sessions[user_id].get(session_name)
        if not session_info:
            return False
        
        last_activity = session_info['last_activity']
        now = time.time()
        
        # 1. بررسی عدم فعالیت
        inactive_minutes = (now - last_activity) / 60
        if inactive_minutes > self.logout_settings['inactivity_timeout_minutes']:
            logger.info(f"Session {session_name} inactive for {inactive_minutes:.1f} minutes")
            
            if self.logout_settings['send_warning_before_logout']:
                await self._send_inactivity_warning(user_id, session_name)
            
            return True
        
        # 2. بررسی مدت زمان کلی session
        session_age_hours = (now - session_info['created_at']) / 3600
        if session_age_hours > self.logout_settings['auto_logout_after_hours']:
            logger.info(f"Session {session_name} expired after {session_age_hours:.1f} hours")
            
            if self.logout_settings['send_warning_before_logout']:
                await self._send_expiry_warning(user_id, session_name)
            
            return True
        
        return False
    
    async def _send_inactivity_warning(self, user_id: int, session_name: str):
        """ارسال هشدار عدم فعالیت"""
        warning_msg = (
            f"⚠️ اخطار: session '{session_name}' به دلیل عدم فعالیت در حال انقضا است.\n\n"
            f"در صورت عدم فعالیت در {self.logout_settings['warning_minutes_before']} دقیقه آینده، "
            f"به صورت خودکار logout خواهد شد."
        )
        
        # ارسال به کاربر (مثلاً از طریق ربات)
        await self._send_message_to_user(user_id, warning_msg)
    
    async def request_logout(self, user_id: int, session_name: str, 
                           force: bool = False) -> dict:
        """درخواست logout"""
        
        # 1. بررسی مالکیت
        if not await self._validate_ownership(user_id, session_name):
            return {
                'success': False,
                'error': 'شما مالک این session نیستید'
            }
        
        # 2. اگر force نباشد، درخواست تأیید
        if not force and self.logout_settings['require_confirmation']:
            request_id = f"logout_req_{int(time.time())}"
            
            self.logout_requests[request_id] = {
                'user_id': user_id,
                'session_name': session_name,
                'request_time': time.time(),
                'status': 'pending'
            }
            
            # ارسال درخواست تأیید
            confirmation_msg = (
                f"🔐 درخواست logout از session '{session_name}'\n\n"
                f"آیا مطمئن هستید؟\n"
                f"✅ تأیید: /confirm_logout_{request_id}\n"
                f"❌ انصراف: /cancel_logout_{request_id}"
            )
            
            await self._send_message_to_user(user_id, confirmation_msg)
            
            return {
                'success': True,
                'needs_confirmation': True,
                'request_id': request_id
            }
        
        # 3. اجرای logout
        return await self._execute_logout(user_id, session_name)
    
    async def _execute_logout(self, user_id: int, session_name: str) -> dict:
        """اجرای logout"""
        try:
            # 1. قطع اتصال
            if session_name in self.active_sessions.get(user_id, {}):
                session_info = self.active_sessions[user_id][session_name]
                
                if session_info.get('client'):
                    await session_info['client'].disconnect()
            
            # 2. حذف از active sessions
            if user_id in self.active_sessions:
                if session_name in self.active_sessions[user_id]:
                    del self.active_sessions[user_id][session_name]
            
            # 3. حذف فایل session (اختیاری)
            if self.logout_settings.get('delete_session_file', False):
                session_path = Path(f"sessions/{session_name}.session")
                if session_path.exists():
                    session_path.unlink()
            
            # 4. ثبت در لاگ
            logger.info(f"User {user_id} logged out from {session_name}")
            
            return {
                'success': True,
                'message': 'با موفقیت logout شدید'
            }
            
        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return {
                'success': False,
                'error': f'خطا در logout: {str(e)}'
            }

class OwnershipBasedAccess:
    """دسترسی مبتنی بر مالکیت"""
    
    def __init__(self):
        self.ownership_db = {}  # session_name -> owner_user_id
        self.shared_sessions = {}  # session_name -> [user_ids]
    
    def register_session_owner(self, session_name: str, owner_user_id: int):
        """ثبت مالک session"""
        self.ownership_db[session_name] = owner_user_id
        
        # ذخیره در فایل
        self._save_ownership_db()
    
    def can_access_session(self, user_id: int, session_name: str) -> bool:
        """بررسی دسترسی کاربر به session"""
        # 1. بررسی مالک اصلی
        if session_name in self.ownership_db:
            if self.ownership_db[session_name] == user_id:
                return True
        
        # 2. بررسی دسترسی اشتراکی
        if session_name in self.shared_sessions:
            if user_id in self.shared_sessions[session_name]:
                return True
        
        # 3. بررسی ادمین بودن
        if self._is_admin(user_id):
            return True
        
        return False
    
    def share_session(self, session_name: str, owner_user_id: int, target_user_id: int):
        """اشتراک‌گذاری session"""
        if session_name not in self.ownership_db:
            return False
        
        if self.ownership_db[session_name] != owner_user_id:
            return False  # فقط مالک می‌تواند اشتراک بگذارد
        
        if session_name not in self.shared_sessions:
            self.shared_sessions[session_name] = []
        
        if target_user_id not in self.shared_sessions[session_name]:
            self.shared_sessions[session_name].append(target_user_id)
            self._save_shared_sessions()
            return True
        
        return False

class IsolatedSessionManager:
    """مدیریت session با جداسازی کامل"""
    
    def __init__(self, base_dir: Path = Path("sessions")):
        self.base_dir = base_dir
        
        # ساختار ایمن:
        # sessions/
        # ├── user_123456789/          # پوشه کاربر
        # │   ├── data/               # داده‌های کاربر
        # │   ├── session_abc.session # session‌ها
        # │   └── session_def.session
        # ├── user_987654321/
        # │   └── ...
        # └── user_{user_id}/
        #     └── ...
    
    def get_user_session_dir(self, user_id: int) -> Path:
        """دریافت پوشه مخصوص کاربر"""
        user_dir = self.base_dir / f"user_{user_id}"
        user_dir.mkdir(exist_ok=True, parents=True)
        
        # تنظیم مجوزهای امن
        user_dir.chmod(0o700)  # فقط مالک دسترسی دارد
        
        return user_dir
    
    def create_user_session(self, user_id: int, session_name: str) -> Path:
        """ایجاد session برای کاربر خاص"""
        user_dir = self.get_user_session_dir(user_id)
        session_dir = user_dir / "sessions"
        session_dir.mkdir(exist_ok=True)
        
        session_path = session_dir / f"{session_name}.session"
        return session_path
    
    def list_user_sessions(self, user_id: int) -> List[Path]:
        """لیست session‌های یک کاربر"""
        user_dir = self.base_dir / f"user_{user_id}"
        if not user_dir.exists():
            return []
        
        session_dir = user_dir / "sessions"
        if not session_dir.exists():
            return []
        
        return list(session_dir.glob("*.session"))
    
    def delete_user_session(self, user_id: int, session_name: str) -> bool:
        """حذف session کاربر"""
        session_path = self.base_dir / f"user_{user_id}" / "sessions" / f"{session_name}.session"
        
        if session_path.exists():
            session_path.unlink()
            return True
        return False
    
    def validate_user_access(self, user_id: int, session_path: Path) -> bool:
        """بررسی دسترسی کاربر به session"""
        try:
            # بررسی مالکیت فایل
            if not session_path.exists():
                return False
            
            # بررسی اینکه session در پوشه کاربر باشد
            user_dir = self.base_dir / f"user_{user_id}"
            return user_dir in session_path.parents
            
        except:
            return False

class UserAuthentication:
    """سیستم احراز هویت و محدودیت کاربران"""
    
    def __init__(self):
        self.allowed_users_file = Path("data/allowed_users.json")
        self.pending_requests_file = Path("data/pending_requests.json")
        self.user_limits_file = Path("data/user_limits.json")
        
        self.allowed_users = self._load_allowed_users()
        self.pending_requests = self._load_pending_requests()
        self.user_limits = self._load_user_limits()
    
    def _load_allowed_users(self):
        """بارگذاری کاربران مجاز"""
        if self.allowed_users_file.exists():
            with open(self.allowed_users_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {
            'admins': [123456789],  # آیدی عددی ادمین‌ها
            'verified_users': [],   # کاربران تأیید شده
            'banned_users': []      # کاربران مسدود شده
        }
    
    def is_user_allowed(self, user_id: int, username: str = None) -> dict:
        """بررسی مجوز کاربر"""
        
        # 1. بررسی مسدود بودن
        if user_id in self.allowed_users['banned_users']:
            return {'allowed': False, 'reason': 'اکانت شما مسدود شده است'}
        
        # 2. بررسی ادمین بودن
        if user_id in self.allowed_users['admins']:
            return {'allowed': True, 'role': 'admin', 'max_accounts': 5}
        
        # 3. بررسی کاربر تأیید شده
        if user_id in self.allowed_users['verified_users']:
            return {'allowed': True, 'role': 'verified', 'max_accounts': 2}
        
        # 4. کاربر جدید - نیاز به تأیید
        return {'allowed': False, 'reason': 'نیاز به تأیید ادمین', 'needs_approval': True}
    
    def request_access(self, user_id: int, username: str, phone: str = None):
        """درخواست دسترسی جدید"""
        request_id = f"req_{int(time.time())}_{user_id}"
        
        request_data = {
            'request_id': request_id,
            'user_id': user_id,
            'username': username,
            'phone_hash': hashlib.sha256(phone.encode()).hexdigest()[:16] if phone else None,
            'request_time': datetime.now().isoformat(),
            'status': 'pending',
            'reviewed_by': None,
            'review_time': None
        }
        
        self.pending_requests[request_id] = request_data
        self._save_pending_requests()
        
        # اطلاع به ادمین
        self._notify_admins_new_request(request_data)
        
        return request_id
    
    def approve_user(self, request_id: str, admin_id: int):
        """تأیید کاربر"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['status'] = 'approved'
            self.pending_requests[request_id]['reviewed_by'] = admin_id
            self.pending_requests[request_id]['review_time'] = datetime.now().isoformat()
            
            user_id = self.pending_requests[request_id]['user_id']
            self.allowed_users['verified_users'].append(user_id)
            
            self._save_pending_requests()
            self._save_allowed_users()
            
            return True
        return False
    
    def reject_user(self, request_id: str, admin_id: int, reason: str):
        """رد درخواست کاربر"""
        if request_id in self.pending_requests:
            self.pending_requests[request_id]['status'] = 'rejected'
            self.pending_requests[request_id]['reviewed_by'] = admin_id
            self.pending_requests[request_id]['review_time'] = datetime.now().isoformat()
            self.pending_requests[request_id]['rejection_reason'] = reason
            
            self._save_pending_requests()
            return True
        return False

class SecureLoginBot:
    """ربات با سیستم احراز هویت"""
    
    def __init__(self, token: str, api_id: int, api_hash: str):
        self.bot = telebot.TeleBot(token)
        self.auth = UserAuthentication()
        self.user_sessions = {}  # user_id -> {session_name: info}
        self.user_account_limits = {}  # user_id -> account_count
        
        self.setup_handlers()
    
    def setup_handlers(self):
        @self.bot.message_handler(commands=['start'])
        def start_handler(message):
            user_id = message.from_user.id
            username = message.from_user.username
            
            # بررسی مجوز
            auth_result = self.auth.is_user_allowed(user_id, username)
            
            if not auth_result['allowed']:
                if auth_result.get('needs_approval'):
                    # درخواست دسترسی
                    msg = self.bot.send_message(
                        user_id,
                        "👋 برای استفاده از ربات نیاز به تأیید دارید.\n\n"
                        "لطفاً شماره تلفن خود را ارسال کنید:"
                    )
                    self.bot.register_next_step_handler(msg, process_access_request)
                else:
                    self.bot.send_message(user_id, f"❌ {auth_result['reason']}")
                return
            
            # کاربر مجاز است
            keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True)
            
            if auth_result['role'] == 'admin':
                keyboard.row('🔐 ورود به اکانت', '👨‍💼 پنل ادمین')
                keyboard.row('📋 اکانت‌های من', '🚪 خروج')
            else:
                keyboard.row('🔐 ورود به اکانت', '📋 اکانت‌های من')
                keyboard.row('🚪 خروج', 'ℹ️ راهنما')
            
            self.bot.send_message(
                user_id,
                f"✅ شما دسترسی دارید.\n\n"
                f"🔄 می‌توانید حداکثر {auth_result.get('max_accounts', 1)} اکانت اضافه کنید.",
                reply_markup=keyboard
            )
        
        def process_access_request(message):
            user_id = message.from_user.id
            phone = message.text
            
            # ثبت درخواست
            request_id = self.auth.request_access(
                user_id=user_id,
                username=message.from_user.username,
                phone=phone
            )
            
            self.bot.send_message(
                user_id,
                "✅ درخواست شما ثبت شد.\n\n"
                "در صورت تأیید ادمین به شما اطلاع داده می‌شود.\n"
                "لطفاً صبور باشید."
            )



if __name__ == "__main__":
    # تست سیستم
    async def test():
        manager = await create_session_manager()
        
        # ایجاد session تست
        session = await manager.create_new_session(
            api_id=123456,
            api_hash="test_hash",
            phone="+1234567890"
        )
        
        print(f"Created session: {session['name']}")
        
        # دریافت گزارش
        report = await manager.export_session_report()
        print(f"Total sessions: {report['total_sessions']}")
        
        # چرخش session
        await manager.rotate_sessions()
        
        # پاکسازی
        await manager.cleanup_old_sessions()
    
    asyncio.run(test())
