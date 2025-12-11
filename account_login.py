#!/usr/bin/env python3
# account_login.py - سیستم ورود به اکانت کاربر با امنیت بالا

import asyncio
import json
import logging
from typing import Optional, Dict, Any
from pathlib import Path
import hashlib
import secrets
from datetime import datetime, timedelta

from telethon import TelegramClient
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneNumberInvalidError,
    FloodWaitError
)

logger = logging.getLogger(__name__)

class SecureAccountLogin:
    """
    سیستم ورود امن به اکانت کاربر
    ویژگی‌ها:
    - ورود دو مرحله‌ای
    - ذخیره ایمن session
    - بررسی صحت شماره
    - محدودیت تلاش‌های ناموفق
    """
    
    def __init__(self, base_dir: Path = Path("accounts")):
        self.base_dir = base_dir
        self.sessions_dir = base_dir / "sessions"
        self.credentials_dir = base_dir / "credentials"
        self.lock_dir = base_dir / "locks"
        
        # ایجاد پوشه‌ها
        for directory in [self.base_dir, self.sessions_dir, 
                         self.credentials_dir, self.lock_dir]:
            directory.mkdir(exist_ok=True)
        
        # فایل قفل برای جلوگیری از ورود همزمان
        self.lock_file = self.lock_dir / "login_lock"
        
        # تنظیمات امنیتی
        self.security_config = {
            'max_login_attempts': 3,
            'lockout_duration_minutes': 30,
            'session_expiry_days': 7,
            'auto_logout_inactive_hours': 24,
            'encrypt_sessions': True,
            'require_2fa_backup': True,
            'geo_check': True,
            'device_fingerprinting': True
        }
    
    def _check_login_lock(self, phone_hash: str) -> bool:
        """بررسی قفل ورود"""
        lock_path = self.lock_dir / f"{phone_hash}.lock"
        
        if lock_path.exists():
            with open(lock_path, 'r') as f:
                lock_data = json.load(f)
            
            lock_time = datetime.fromisoformat(lock_data['locked_until'])
            if datetime.now() < lock_time:
                remaining = (lock_time - datetime.now()).seconds // 60
                logger.warning(f"Account locked. Try again in {remaining} minutes")
                return False
        
        return True
    
    def _set_login_lock(self, phone_hash: str, duration_minutes: int = 30):
        """تنظیم قفل ورود"""
        lock_path = self.lock_dir / f"{phone_hash}.lock"
        
        lock_data = {
            'phone_hash': phone_hash,
            'locked_at': datetime.now().isoformat(),
            'locked_until': (datetime.now() + 
                           timedelta(minutes=duration_minutes)).isoformat(),
            'reason': 'too_many_failed_attempts'
        }
        
        with open(lock_path, 'w') as f:
            json.dump(lock_data, f, indent=2)
    
    def _clear_login_lock(self, phone_hash: str):
        """پاک کردن قفل ورود"""
        lock_path = self.lock_dir / f"{phone_hash}.lock"
        if lock_path.exists():
            lock_path.unlink()
    
    def _hash_phone_number(self, phone_number: str) -> str:
        """هش کردن شماره تلفن برای ذخیره امن"""
        salt = "telegram_login_salt_2024"
        return hashlib.sha256(f"{phone_number}{salt}".encode()).hexdigest()[:16]
    
    async def request_phone_number(self) -> str:
        """درخواست شماره تلفن از کاربر"""
        print("\n" + "="*50)
        print("📱 لطفاً شماره تلفن تلگرام خود را وارد کنید:")
        print("فرمت: +989123456789 یا 09123456789")
        print("="*50)
        
        phone = input("شماره تلفن: ").strip()
        
        # نرمال‌سازی شماره
        if phone.startswith('0'):
            phone = '+98' + phone[1:]
        elif not phone.startswith('+'):
            phone = '+' + phone
        
        return phone
    
    async def request_verification_code(self, phone: str) -> str:
        """درخواست کد تأیید از کاربر"""
        print("\n" + "="*50)
        print(f"📨 کد تأیید به شماره {phone} ارسال شد.")
        print("لطفاً کد ۵ رقمی را وارد کنید:")
        print("="*50)
        
        code = input("کد تأیید: ").strip()
        return code
    
    async def request_2fa_password(self) -> str:
        """درخواست رمز دو مرحله‌ای"""
        print("\n" + "="*50)
        print("🔒 این اکانت رمز دو مرحله‌ای دارد.")
        print("لطفاً رمز دو مرحله‌ای را وارد کنید:")
        print("="*50)
        
        password = input("رمز دو مرحله‌ای: ").strip()
        return password
    
    async def send_telegram_code(self, client: TelegramClient, phone: str):
        """ارسال کد تأیید به تلگرام"""
        try:
            # ارسال درخواست کد
            await client.send_code_request(phone)
            logger.info("Verification code requested")
            return True
            
        except FloodWaitError as e:
            logger.error(f"Flood wait: {e.seconds} seconds")
            print(f"\n⚠️ لطفاً {e.seconds} ثانیه صبر کنید و دوباره تلاش کنید.")
            return False
            
        except PhoneNumberInvalidError:
            logger.error("Invalid phone number")
            print("\n❌ شماره تلفن نامعتبر است.")
            return False
            
        except Exception as e:
            logger.error(f"Error sending code: {e}")
            print(f"\n❌ خطا در ارسال کد: {e}")
            return False
    
    async def login_with_phone(
        self, 
        api_id: int, 
        api_hash: str,
        phone: Optional[str] = None,
        session_name: Optional[str] = None
    ) -> Optional[TelegramClient]:
        """
        ورود به اکانت با شماره تلفن
        Returns: کلاینت متصل یا None
        """
        # بررسی قفل امنیتی
        phone_hash = self._hash_phone_number(phone) if phone else "unknown"
        
        if not self._check_login_lock(phone_hash):
            return None
        
        # درخواست شماره اگر داده نشده
        if not phone:
            phone = await self.request_phone_number()
            phone_hash = self._hash_phone_number(phone)
        
        # ایجاد نام session
        if not session_name:
            timestamp = int(datetime.now().timestamp())
            session_name = f"user_{phone_hash}_{timestamp}"
        
        session_path = self.sessions_dir / f"{session_name}.session"
        
        attempts = 0
        max_attempts = self.security_config['max_login_attempts']
        
        while attempts < max_attempts:
            try:
                attempts += 1
                print(f"\n🔐 تلاش ورود {attempts}/{max_attempts}")
                
                # ایجاد کلاینت
                client = TelegramClient(
                    session=str(session_path),
                    api_id=api_id,
                    api_hash=api_hash,
                    device_model="iPhone 14 Pro",
                    system_version="iOS 16.0",
                    app_version="9.4",
                    lang_code="fa",
                    system_lang_code="fa-IR"
                )
                
                await client.connect()
                
                # اگر session معتبر باشد، نیاز به ورود نیست
                if await client.is_user_authorized():
                    logger.info("Session is valid, already logged in")
                    print("\n✅ با session موجود وارد شدید.")
                    return client
                
                # ارسال کد تأیید
                if not await self.send_telegram_code(client, phone):
                    continue
                
                # دریافت کد از کاربر
                code = await self.request_verification_code(phone)
                
                try:
                    # تلاش برای ورود با کد
                    await client.sign_in(phone=phone, code=code)
                    logger.info("Login with code successful")
                    
                except SessionPasswordNeededError:
                    # نیاز به رمز دو مرحله‌ای
                    print("\n🔐 این اکانت رمز دو مرحله‌ای دارد.")
                    
                    password = await self.request_2fa_password()
                    await client.sign_in(password=password)
                    logger.info("Login with 2FA successful")
                
                except PhoneCodeInvalidError:
                    print("\n❌ کد تأیید نامعتبر است.")
                    continue
                
                # تأیید ورود موفق
                if await client.is_user_authoried():
                    print(f"\n✅ ورود موفق به اکانت: {phone}")
                    
                    # دریافت اطلاعات کاربر
                    me = await client.get_me()
                    print(f"\n👤 اطلاعات کاربر:")
                    print(f"   نام: {me.first_name} {me.last_name or ''}")
                    print(f"   یوزرنیم: @{me.username or 'ندارد'}")
                    print(f"   شماره: {me.phone}")
                    print(f"   Session: {session_name}")
                    
                    # ذخیره اطلاعات ایمن
                    await self._save_account_info(client, phone, session_name)
                    
                    # پاک کردن قفل
                    self._clear_login_lock(phone_hash)
                    
                    return client
                
            except FloodWaitError as e:
                logger.error(f"Flood wait during login: {e.seconds}s")
                print(f"\n⚠️ لطفاً {e.seconds} ثانیه صبر کنید.")
                
                # تنظیم قفل
                self._set_login_lock(phone_hash, e.seconds // 60)
                return None
                
            except Exception as e:
                logger.error(f"Login attempt {attempts} failed: {e}")
                print(f"\n❌ خطا در ورود: {e}")
                
                if attempts >= max_attempts:
                    print(f"\n🔒 تعداد تلاش‌ها بیش از حد مجاز. لطفاً بعداً تلاش کنید.")
                    self._set_login_lock(phone_hash)
                    return None
        
        return None
    
    async def _save_account_info(self, client: TelegramClient, phone: str, session_name: str):
        """ذخیره ایمن اطلاعات اکانت"""
        try:
            me = await client.get_me()
            
            account_info = {
                'session_name': session_name,
                'phone_hash': self._hash_phone_number(phone),
                'user_id': me.id,
                'username': me.username,
                'first_name': me.first_name,
                'last_name': me.last_name,
                'login_time': datetime.now().isoformat(),
                'last_activity': datetime.now().isoformat(),
                'is_bot': me.bot,
                'premium': me.premium,
                'client_info': {
                    'device_model': client.session.device_model,
                    'system_version': client.session.system_version,
                    'app_version': client.session.app_version
                }
            }
            
            # ذخیره در فایل
            info_file = self.credentials_dir / f"{session_name}.json"
            with open(info_file, 'w', encoding='utf-8') as f:
                json.dump(account_info, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Account info saved: {session_name}")
            
        except Exception as e:
            logger.error(f"Error saving account info: {e}")
    
    async def logout_account(self, session_name: str) -> bool:
        """خروج از اکانت"""
        try:
            session_path = self.sessions_dir / f"{session_name}.session"
            
            if not session_path.exists():
                logger.warning(f"Session file not found: {session_name}")
                return False
            
            # حذف فایل session
            session_path.unlink()
            
            # حذف اطلاعات ذخیره شده
            info_file = self.credentials_dir / f"{session_name}.json"
            if info_file.exists():
                info_file.unlink()
            
            logger.info(f"Logged out from session: {session_name}")
            print(f"\n✅ از اکانت خارج شدید. Session حذف شد.")
            
            return True
            
        except Exception as e:
            logger.error(f"Error logging out: {e}")
            return False
    
    async def list_active_sessions(self) -> list:
        """لیست session‌های فعال"""
        sessions = []
        
        for session_file in self.sessions_dir.glob("*.session"):
            session_name = session_file.stem
            
            try:
                # خواندن اطلاعات ذخیره شده
                info_file = self.credentials_dir / f"{session_name}.json"
                if info_file.exists():
                    with open(info_file, 'r', encoding='utf-8') as f:
                        account_info = json.load(f)
                    
                    sessions.append({
                        'session_name': session_name,
                        'user_id': account_info.get('user_id'),
                        'username': account_info.get('username'),
                        'first_name': account_info.get('first_name'),
                        'last_name': account_info.get('last_name'),
                        'login_time': account_info.get('login_time'),
                        'file_size': session_file.stat().st_size,
                        'is_valid': self._validate_session_file(session_file)
                    })
                    
            except Exception as e:
                logger.error(f"Error reading session {session_name}: {e}")
        
        return sessions
    
    def _validate_session_file(self, session_path: Path) -> bool:
        """اعتبارسنجی فایل session"""
        try:
            if not session_path.exists():
                return False
            
            # بررسی سایز فایل
            file_size = session_path.stat().st_size
            if file_size < 100:  # بسیار کوچک
                return False
            
            # خواندن بخشی از فایل
            with open(session_path, 'rb') as f:
                header = f.read(100)
            
            # بررسی signature فایل session
            if b'sqlite' in header.lower():
                return True
            
            return False
            
        except:
            return False
    
    async def validate_session(self, session_name: str, 
                             api_id: int, api_hash: str) -> bool:
        """اعتبارسنجی session با اتصال به تلگرام"""
        session_path = self.sessions_dir / f"{session_name}.session"
        
        if not session_path.exists():
            return False
        
        client = None
        try:
            client = TelegramClient(
                session=str(session_path),
                api_id=api_id,
                api_hash=api_hash
            )
            
            await client.connect()
            
            if await client.is_user_authorized():
                logger.info(f"Session {session_name} is valid")
                return True
            else:
                logger.warning(f"Session {session_name} is not authorized")
                return False
                
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return False
            
        finally:
            if client:
                await client.disconnect()

class AccountManager:
    """مدیریت چندین اکانت"""
    
    def __init__(self, api_id: int, api_hash: str):
        self.api_id = api_id
        self.api_hash = api_hash
        self.login_manager = SecureAccountLogin()
        self.active_clients = {}
        
        # بارگذاری session‌های ذخیره شده
        self.load_saved_sessions()
    
    def load_saved_sessions(self):
        """بارگذاری session‌های ذخیره شده"""
        sessions = asyncio.run(self.login_manager.list_active_sessions())
        
        for session_info in sessions:
            if session_info['is_valid']:
                session_name = session_info['session_name']
                self.active_clients[session_name] = {
                    'info': session_info,
                    'client': None,
                    'last_used': None
                }
        
        logger.info(f"Loaded {len(self.active_clients)} saved sessions")
    
    async def login_new_account(self) -> Optional[str]:
        """ورود به اکانت جدید"""
        print("\n" + "="*50)
        print("➕ ورود به اکانت جدید")
        print("="*50)
        
        client = await self.login_manager.login_with_phone(
            api_id=self.api_id,
            api_hash=self.api_hash,
            phone=None,
            session_name=None
        )
        
        if client:
            # دریافت نام session
            session_name = client.session.filename.replace('.session', '')
            
            # ذخیره در لیست فعال
            me = await client.get_me()
            self.active_clients[session_name] = {
                'info': {
                    'session_name': session_name,
                    'user_id': me.id,
                    'username': me.username,
                    'first_name': me.first_name,
                    'last_name': me.last_name
                },
                'client': client,
                'last_used': datetime.now()
            }
            
            print(f"\n✅ اکانت جدید اضافه شد: @{me.username or me.first_name}")
            return session_name
        
        return None
    
    async def get_client(self, session_name: str) -> Optional[TelegramClient]:
        """دریافت کلاینت برای session مشخص"""
        if session_name not in self.active_clients:
            # تلاش برای بارگذاری session
            is_valid = await self.login_manager.validate_session(
                session_name, self.api_id, self.api_hash
            )
            
            if not is_valid:
                logger.warning(f"Session {session_name} is not valid")
                return None
            
            # ایجاد کلاینت جدید
            session_path = self.login_manager.sessions_dir / f"{session_name}.session"
            
            try:
                client = TelegramClient(
                    session=str(session_path),
                    api_id=self.api_id,
                    api_hash=self.api_hash
                )
                
                await client.connect()
                
                if not await client.is_user_authorized():
                    logger.error(f"Session {session_name} not authorized")
                    await client.disconnect()
                    return None
                
                # ذخیره در لیست فعال
                me = await client.get_me()
                self.active_clients[session_name] = {
                    'info': {
                        'session_name': session_name,
                        'user_id': me.id,
                        'username': me.username,
                        'first_name': me.first_name,
                        'last_name': me.last_name
                    },
                    'client': client,
                    'last_used': datetime.now()
                }
                
                return client
                
            except Exception as e:
                logger.error(f"Error loading session {session_name}: {e}")
                return None
        
        # به‌روزرسانی زمان استفاده
        self.active_clients[session_name]['last_used'] = datetime.now()
        
        # اگر کلاینت قطع شده، مجدداً وصل شو
        client_info = self.active_clients[session_name]
        client = client_info['client']
        
        if client and not client.is_connected():
            await client.connect()
        
        return client
    
    async def logout_account(self, session_name: str) -> bool:
        """خروج از یک اکانت"""
        if session_name in self.active_clients:
            client_info = self.active_clients[session_name]
            client = client_info['client']
            
            if client and client.is_connected():
                await client.disconnect()
            
            # حذف از لیست فعال
            del self.active_clients[session_name]
        
        # حذف session
        return await self.login_manager.logout_account(session_name)
    
    async def list_accounts(self) -> list:
        """لیست همه اکانت‌ها"""
        accounts = []
        
        # session‌های فعال
        for session_name, client_info in self.active_clients.items():
            accounts.append({
                'type': 'active',
                'session_name': session_name,
                'user_info': client_info['info'],
                'last_used': client_info['last_used'].isoformat() 
                if client_info['last_used'] else None,
                'is_connected': (
                    client_info['client'] and 
                    client_info['client'].is_connected()
                )
            })
        
        # session‌های ذخیره شده اما غیرفعال
        all_sessions = await self.login_manager.list_active_sessions()
        active_session_names = set(self.active_clients.keys())
        
        for session_info in all_sessions:
            if session_info['session_name'] not in active_session_names:
                accounts.append({
                    'type': 'inactive',
                    'session_name': session_info['session_name'],
                    'user_info': {
                        'user_id': session_info.get('user_id'),
                        'username': session_info.get('username'),
                        'first_name': session_info.get('first_name'),
                        'last_name': session_info.get('last_name')
                    },
                    'login_time': session_info.get('login_time'),
                    'is_valid': session_info['is_valid']
                })
        
        return accounts
    
    async def cleanup_inactive_sessions(self, max_age_days: int = 7):
        """پاکسازی session‌های غیرفعال قدیمی"""
        accounts = await self.list_accounts()
        cleaned = 0
        
        for account in accounts:
            if account['type'] == 'inactive':
                # بررسی تاریخ ایجاد
                login_time_str = account.get('login_time')
                if login_time_str:
                    login_time = datetime.fromisoformat(login_time_str)
                    age_days = (datetime.now() - login_time).days
                    
                    if age_days > max_age_days:
                        # حذف session قدیمی
                        await self.logout_account(account['session_name'])
                        cleaned += 1
        
        logger.info(f"Cleaned up {cleaned} inactive sessions")
        return cleaned

# رابط خط فرمان
async def interactive_login():
    """ورود تعاملی از طریق CLI"""
    from pathlib import Path
    
    print("\n" + "="*60)
    print("🔐 سیستم ورود پیشرفته به اکانت تلگرام")
    print("="*60)
    
    # خواندن API از فایل config
    config_path = Path("config.json")
    if not config_path.exists():
        print("\n❌ فایل config.json یافت نشد.")
        print("لطفاً ابتدا config.json را ایجاد کنید.")
        return
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    api_id = config.get('api_id')
    api_hash = config.get('api_hash')
    
    if not api_id or not api_hash:
        print("\n❌ api_id یا api_hash در config.json تنظیم نشده.")
        return
    
    # ایجاد مدیر اکانت
    manager = AccountManager(api_id, api_hash)
    
    while True:
        print("\n" + "="*50)
        print("منوی مدیریت اکانت:")
        print("="*50)
        print("1. 📱 ورود به اکانت جدید")
        print("2. 📋 لیست اکانت‌های موجود")
        print("3. 🔌 اتصال به اکانت")
        print("4. 🚪 خروج از اکانت")
        print("5. 🧹 پاکسازی session‌های قدیمی")
        print("6. 📊 نمایش وضعیت")
        print("7. ❌ خروج")
        print("="*50)
        
        choice = input("\nانتخاب شما: ").strip()
        
        if choice == '1':
            # ورود به اکانت جدید
            session_name = await manager.login_new_account()
            if session_name:
                print(f"\n✅ اکانت با نام session '{session_name}' اضافه شد.")
        
        elif choice == '2':
            # لیست اکانت‌ها
            accounts = await manager.list_accounts()
            
            print(f"\n👥 تعداد اکانت‌ها: {len(accounts)}")
            print("-" * 50)
            
            for i, account in enumerate(accounts, 1):
                user = account['user_info']
                print(f"{i}. {account['type'].upper()} - {account['session_name']}")
                print(f"   👤 {user.get('first_name', '')} {user.get('last_name', '')}")
                print(f"   📱 @{user.get('username', 'ندارد')}")
                print(f"   🆔 {user.get('user_id', '')}")
                if account['type'] == 'active':
                    print(f"   🔗 {'متصل' if account['is_connected'] else 'قطع'}")
                print()
        
        elif choice == '3':
            # اتصال به اکانت
            accounts = await manager.list_accounts()
            
            if not accounts:
                print("\n❌ هیچ اکانتی وجود ندارد.")
                continue
            
            print("\nاکانت‌های موجود:")
            for i, account in enumerate(accounts, 1):
                user = account['user_info']
                print(f"{i}. {user.get('first_name')} (@{user.get('username')})")
            
            try:
                selection = int(input("\nشماره اکانت: ")) - 1
                if 0 <= selection < len(accounts):
                    session_name = accounts[selection]['session_name']
                    
                    client = await manager.get_client(session_name)
                    if client:
                        print(f"\n✅ به اکانت متصل شدید.")
                        
                        # نمایش منوی عملیات
                        await account_operations_menu(client, session_name)
                    else:
                        print("\n❌ اتصال ناموفق.")
                else:
                    print("\n❌ انتخاب نامعتبر.")
            except ValueError:
                print("\n❌ لطفاً عدد وارد کنید.")
        
        elif choice == '4':
            # خروج از اکانت
            accounts = await manager.list_accounts()
            
            if not accounts:
                print("\n❌ هیچ اکانتی وجود ندارد.")
                continue
            
            print("\nاکانت‌های موجود:")
            for i, account in enumerate(accounts, 1):
                user = account['user_info']
                print(f"{i}. {user.get('first_name')} (@{user.get('username')})")
            
            try:
                selection = int(input("\nشماره اکانت برای خروج: ")) - 1
                if 0 <= selection < len(accounts):
                    session_name = accounts[selection]['session_name']
                    
                    confirm = input(f"\n⚠️ آیا مطمئن هستید می‌خواهید از '{session_name}' خارج شوید؟ (y/n): ")
                    if confirm.lower() == 'y':
                        success = await manager.logout_account(session_name)
                        if success:
                            print("\n✅ از اکانت خارج شدید.")
                        else:
                            print("\n❌ خطا در خروج.")
                else:
                    print("\n❌ انتخاب نامعتبر.")
            except ValueError:
                print("\n❌ لطفاً عدد وارد کنید.")
        
        elif choice == '5':
            # پاکسازی
            confirm = input("\n⚠️ آیا مطمئن هستید می‌خواهید session‌های قدیمی را پاک کنید؟ (y/n): ")
            if confirm.lower() == 'y':
                cleaned = await manager.cleanup_inactive_sessions()
                print(f"\n✅ {cleaned} session قدیمی پاک شد.")
        
        elif choice == '6':
            # نمایش وضعیت
            accounts = await manager.list_accounts()
            
            active_count = sum(1 for a in accounts if a['type'] == 'active')
            inactive_count = len(accounts) - active_count
            
            print("\n📊 وضعیت سیستم:")
            print(f"   • اکانت‌های فعال: {active_count}")
            print(f"   • اکانت‌های غیرفعال: {inactive_count}")
            print(f"   • کل session‌ها: {len(accounts)}")
            
            if accounts:
                print("\n📋 آخرین اکانت‌ها:")
                for account in accounts[:5]:  # فقط 5 تا اول
                    user = account['user_info']
                    print(f"   • {user.get('first_name')} (@{user.get('username')}) - {account['type']}")
        
        elif choice == '7':
            print("\n👋 خروج از سیستم...")
            break
        
        else:
            print("\n❌ انتخاب نامعتبر.")

async def account_operations_menu(client: TelegramClient, session_name: str):
    """منوی عملیات برای اکانت متصل"""
    while True:
        print("\n" + "="*50)
        print(f"🛠️ عملیات اکانت: {session_name}")
        print("="*50)
        print("1. 👤 دریافت اطلاعات کاربر")
        print("2. 📞 دریافت لیست مخاطبین")
        print("3. 💬 دریافت چت‌های اخیر")
        print("4. 📥 دانلود فایل از چت")
        print("5. 🔙 بازگشت به منوی اصلی")
        print("="*50)
        
        choice = input("\nانتخاب شما: ").strip()
        
        if choice == '1':
            # اطلاعات کاربر
            me = await client.get_me()
            print(f"\n👤 اطلاعات شما:")
            print(f"   نام: {me.first_name} {me.last_name or ''}")
            print(f"   یوزرنیم: @{me.username or 'ندارد'}")
            print(f"   شماره: {me.phone}")
            print(f"   آیدی: {me.id}")
            print(f"   ربات: {'بله' if me.bot else 'خیر'}")
            print(f"   پریمیوم: {'بله' if me.premium else 'خیر'}")
        
        elif choice == '2':
            # مخاطبین
            print("\n📞 در حال دریافت مخاطبین...")
            contacts = await client.get_contacts()
            
            print(f"\nمخاطبین ({len(contacts)}):")
            for contact in contacts[:10]:  # فقط 10 تا اول
                print(f"   • {contact.first_name} {contact.last_name or ''} - @{contact.username or 'ندارد'}")
            
            if len(contacts) > 10:
                print(f"   ... و {len(contacts) - 10} مخاطب دیگر")
        
        elif choice == '3':
            # چت‌های اخیر
            print("\n💬 در حال دریافت چت‌ها...")
            dialogs = await client.get_dialogs(limit=10)
            
            print(f"\nچت‌های اخیر ({len(dialogs)}):")
            for dialog in dialogs:
                entity = dialog.entity
                if hasattr(entity, 'title'):
                    name = entity.title
                else:
                    name = f"{entity.first_name} {entity.last_name or ''}"
                
                print(f"   • {name} - {dialog.unread_count} پیام نخوانده")
        
        elif choice == '4':
            # دانلود فایل
            print("\n📥 دانلود فایل")
            chat_input = input("آیدی یا یوزرنیم چت: ").strip()
            limit = input("تعداد پیام برای بررسی (پیش‌فرض: 10): ").strip()
            limit = int(limit) if limit.isdigit() else 10
            
            try:
                entity = await client.get_entity(chat_input)
                print(f"در حال بررسی {limit} پیام از {entity.title if hasattr(entity, 'title') else entity.first_name}...")
                
                downloaded = 0
                async for message in client.iter_messages(entity, limit=limit):
                    if message.document or message.photo or message.video:
                        file_name = f"download_{message.id}"
                        await message.download_media(file=file_name)
                        downloaded += 1
                        print(f"   ✅ دانلود شد: {file_name}")
                
                print(f"\n🎉 {downloaded} فایل دانلود شد.")
                
            except Exception as e:
                print(f"\n❌ خطا: {e}")
        
        elif choice == '5':
            # بازگشت
            print("\nبازگشت به منوی اصلی...")
            break
        
        else:
            print("\n❌ انتخاب نامعتبر.")

# تابع اصلی
async def main():
    """تابع اصلی"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Telegram Account Login System')
    parser.add_argument('--interactive', action='store_true', 
                       help='Run in interactive mode')
    parser.add_argument('--login', metavar='PHONE', 
                       help='Login with phone number')
    parser.add_argument('--list', action='store_true',
                       help='List all accounts')
    parser.add_argument('--validate', metavar='SESSION',
                       help='Validate a session')
    parser.add_argument('--logout', metavar='SESSION',
                       help='Logout from session')
    
    args = parser.parse_args()
    
    if args.interactive:
        await interactive_login()
    
    elif args.login:
        # ورود مستقیم
        config_path = Path("config.json")
        if not config_path.exists():
            print("❌ config.json not found")
            return
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        login_manager = SecureAccountLogin()
        client = await login_manager.login_with_phone(
            api_id=config['api_id'],
            api_hash=config['api_hash'],
            phone=args.login
        )
        
        if client:
            print("✅ Login successful")
            await client.disconnect()
    
    elif args.list:
        # لیست اکانت‌ها
        login_manager = SecureAccountLogin()
        accounts = await login_manager.list_active_sessions()
        
        print(f"\n📋 Active Sessions: {len(accounts)}")
        for acc in accounts:
            print(f"\n• {acc['session_name']}")
            print(f"  👤 {acc.get('first_name', '')} {acc.get('last_name', '')}")
            print(f"  📱 @{acc.get('username', 'N/A')}")
            print(f"  📅 Login: {acc.get('login_time', 'N/A')}")
            print(f"  ✅ Valid: {acc['is_valid']}")
    
    elif args.validate:
        # اعتبارسنجی session
        config_path = Path("config.json")
        if not config_path.exists():
            print("❌ config.json not found")
            return
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        login_manager = SecureAccountLogin()
        is_valid = await login_manager.validate_session(
            args.validate, config['api_id'], config['api_hash']
        )
        
        print(f"Session {args.validate}: {'✅ Valid' if is_valid else '❌ Invalid'}")
    
    elif args.logout:
        # خروج
        login_manager = SecureAccountLogin()
        success = await login_manager.logout_account(args.logout)
        
        print(f"Logout {args.logout}: {'✅ Success' if success else '❌ Failed'}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    # تنظیمات لاگ
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # اجرای برنامه
    asyncio.run(main())
