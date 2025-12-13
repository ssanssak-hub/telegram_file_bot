# -*- coding: utf-8 -*-
# main.py - فایل اصلی ربات تلگرام

import asyncio
import sys
import logging
from pathlib import Path

# تنظیمات logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# رفع مشکل asyncio در ویندوز
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

async def main():
    """نقطه شروع برنامه - سبک و بهینه"""
    try:
        logger.info("🚀 شروع سیستم مدیریت اکانت تلگرام...")
        
        # ایمپورت مدیر اکانت پیشرفته
        try:
            from advanced_account_manager import AdvancedAccountManager
        except ImportError as e:
            logger.error(f"❌ خطا در ایمپورت ماژول: {e}")
            print("\n📦 لطفا وابستگی‌ها را نصب کنید:")
            print("pip install telethon cryptography aiohttp psutil")
            return
        
        # مسیر تنظیمات
        config_path = Path("config.json")
        
        if not config_path.exists():
            # ایجاد config پیش‌فرض
            print("⚠️ فایل config یافت نشد. ایجاد config پیش‌فرض...")
            
            config = {
                "api_id": "YOUR_API_ID",
                "api_hash": "YOUR_API_HASH",
                "accounts_dir": "accounts",
                "encryption_key": None,
                "webhook_url": None,
                "proxy": None
            }
            
            import json
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            print("✅ فایل config.json ایجاد شد")
            print("📝 لطفا api_id و api_hash خود را در config.json وارد کنید")
            return
        
        # بارگذاری config
        import json
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # بررسی api_id و api_hash
        if config.get("api_id") == "YOUR_API_ID" or config.get("api_hash") == "YOUR_API_HASH":
            print("\n❌ لطفا api_id و api_hash خود را از my.telegram.org دریافت و در config.json وارد کنید")
            return
        
        # ایجاد مدیر اکانت
        manager = AdvancedAccountManager(
            base_dir=Path(config.get("accounts_dir", "accounts")),
            encryption_key=config.get("encryption_key"),
            api_id=config.get("api_id"),
            api_hash=config.get("api_hash")
        )
        
        # تنظیمات اختیاری
        if config.get("proxy"):
            manager.proxy_settings = config["proxy"]
        
        if config.get("webhook_url"):
            manager.webhook_url = config["webhook_url"]
        
        # نمایش منوی اصلی
        print("\n" + "="*60)
        print("🤖 سیستم مدیریت پیشرفته اکانت تلگرام")
        print("="*60)
        
        while True:
            print("\n" + "─"*40)
            print("📋 منوی اصلی:")
            print("─"*40)
            print("1. 📱 ورود با شماره تلفن")
            print("2. 📷 ورود با QR Code")
            print("3. 📊 لیست اکانت‌ها")
            print("4. 🛡️  بررسی امنیتی")
            print("5. 💾 Backup اکانت")
            print("6. ⚙️  شروع API سرور")
            print("7. 🚪 خروج")
            print("─"*40)
            
            choice = input("\n📝 انتخاب شما: ").strip()
            
            if choice == '1':
                await login_with_phone(manager)
            elif choice == '2':
                await login_with_qr(manager)
            elif choice == '3':
                await list_accounts(manager)
            elif choice == '4':
                await security_check(manager)
            elif choice == '5':
                await backup_account(manager)
            elif choice == '6':
                await start_api_server(manager)
            elif choice == '7':
                print("\n👋 خروج از برنامه...")
                break
            else:
                print("❌ انتخاب نامعتبر")
                
    except KeyboardInterrupt:
        print("\n\n🛑 برنامه توسط کاربر متوقف شد")
    except Exception as e:
        logger.error(f"💥 خطای سیستمی: {e}")
        print(f"\n❌ خطا: {e}")

# ========== توابع کمکی ==========

async def login_with_phone(manager):
    """ورود با شماره تلفن"""
    print("\n📱 ورود با شماره تلفن")
    phone = input("شماره (مثال: +989123456789): ").strip()
    
    if not phone:
        print("❌ شماره الزامی است")
        return
    
    use_proxy = input("استفاده از proxy؟ (y/n): ").strip().lower() == 'y'
    
    print("⏳ در حال ورود...")
    try:
        success, client, account_id = await manager.login_with_phone_advanced(
            phone=phone,
            session_name=None,
            use_proxy=use_proxy,
            enable_2fa=True
        )
        
        if success:
            print(f"✅ ورود موفق! Account ID: {account_id}")
            
            # نمایش اطلاعات کاربر
            if client:
                try:
                    me = await client.get_me()
                    print(f"\n👤 اطلاعات کاربر:")
                    print(f"   نام: {me.first_name} {me.last_name or ''}")
                    print(f"   یوزرنیم: @{me.username or 'ندارد'}")
                    print(f"   شماره: {me.phone}")
                    
                    # پرسش برای ادامه کار با اکانت
                    while True:
                        print("\n" + "─"*30)
                        print("📱 عملیات روی اکانت:")
                        print("1. 📤 ارسال پیام تست")
                        print("2. 🔍 دریافت اطلاعات")
                        print("3. 🔙 بازگشت به منوی اصلی")
                        
                        sub_choice = input("\nانتخاب: ").strip()
                        
                        if sub_choice == '1':
                            # ارسال پیام تست
                            test_msg = "👋 سلام! این یک پیام تست از سیستم مدیریت اکانت است."
                            await client.send_message('me', test_msg)
                            print("✅ پیام تست ارسال شد")
                            
                        elif sub_choice == '2':
                            # دریافت اطلاعات بیشتر
                            dialogs = await client.get_dialogs(limit=5)
                            print(f"\n📁 آخرین مکالمه‌ها ({len(dialogs)}):")
                            for dialog in dialogs[:3]:
                                name = dialog.name or "بدون نام"
                                print(f"   • {name}")
                            
                        elif sub_choice == '3':
                            break
                            
                except Exception as e:
                    print(f"⚠️ خطا در دریافت اطلاعات: {e}")
        else:
            print(f"❌ ورود ناموفق: {account_id}")
            
    except Exception as e:
        print(f"💥 خطا در ورود: {e}")
        logger.exception("خطای ورود")

async def login_with_qr(manager):
    """ورود با QR Code"""
    print("\n📷 ورود با QR Code")
    print("⏳ در حال آماده‌سازی...")
    
    try:
        # اصلاح: استفاده از login_with_qr به جای login_with_qr_code
        success, client, account_id = await manager.login_with_qr()
        
        if success:
            print(f"✅ ورود موفق! Account ID: {account_id}")
        else:
            print(f"❌ ورود ناموفق: {account_id}")
    except AttributeError:
        print("❌ متد login_with_qr_code در manager وجود ندارد!")
        print("⚠️ لطفا advanced_account_manager.py را اصلاح کنید")
    except Exception as e:
        print(f"💥 خطا: {e}")

async def list_accounts(manager):
    """لیست اکانت‌ها"""
    print("\n📊 لیست اکانت‌های فعال:")
    
    if not hasattr(manager, 'active_accounts') or not manager.active_accounts:
        print("⚠️ هیچ اکانت فعالی وجود ندارد")
        return
    
    for i, (account_id, data) in enumerate(manager.active_accounts.items(), 1):
        print(f"\n{i}. 🆔 {account_id}")
        print(f"   📞 {data.get('phone', 'نامشخص')}")
        print(f"   👤 {data.get('session_name', 'نامشخص')}")
        print(f"   📍 وضعیت: {data.get('status', 'نامشخص')}")

async def security_check(manager):
    """بررسی امنیتی"""
    print("\n🛡️ بررسی امنیتی اکانت")
    
    if not hasattr(manager, 'active_accounts') or not manager.active_accounts:
        print("⚠️ هیچ اکانت فعالی وجود ندارد")
        return
    
    account_id = input("Account ID: ").strip()
    
    if account_id not in manager.active_accounts:
        print("❌ اکانت یافت نشد")
        return
    
    print("⏳ در حال بررسی امنیتی...")
    try:
        report = await manager.security_audit(account_id)
        
        print(f"\n✅ امتیاز امنیتی: {report.get('score', 0)}/100")
        if report.get('recommendations'):
            print("📋 پیشنهادات:")
            for rec in report['recommendations']:
                print(f"   • {rec}")
    except Exception as e:
        print(f"❌ خطا در بررسی امنیتی: {e}")

async def backup_account(manager):
    """Backup اکانت"""
    print("\n💾 Backup اکانت")
    
    if not hasattr(manager, 'active_accounts') or not manager.active_accounts:
        print("⚠️ هیچ اکانت فعالی وجود ندارد")
        return
    
    account_id = input("Account ID: ").strip()
    
    if account_id not in manager.active_accounts:
        print("❌ اکانت یافت نشد")
        return
    
    backup_type = input("نوع backup (full/minimal): ").strip() or "full"
    
    print("⏳ در حال ایجاد backup...")
    try:
        backup_path = await manager.backup_account(account_id, backup_type)
        
        if backup_path:
            print(f"✅ Backup ایجاد شد: {backup_path}")
        else:
            print("❌ خطا در ایجاد backup")
    except Exception as e:
        print(f"❌ خطا: {e}")

async def start_api_server(manager):
    """شروع API سرور"""
    try:
        port = int(input("پورت (پیش‌فرض: 8080): ").strip() or "8080")
        
        print(f"⏳ در حال شروع API سرور روی پورت {port}...")
        
        # اصلاح: بررسی وجود متد start_api_server
        if not hasattr(manager, 'start_api_server'):
            print("❌ متد start_api_server در manager وجود ندارد!")
            print("⚠️ لطفا advanced_account_manager.py را اصلاح کنید")
            return
        
        try:
            server_task = await manager.start_api_server(port=port)
            
            if server_task:
                print(f"✅ API سرور شروع شد: http://127.0.0.1:{port}")
                print("🛑 برای توقف: Ctrl+C")
                
                # اجرای نامحدود
                try:
                    await asyncio.Future()  # اجرای نامحدود
                except asyncio.CancelledError:
                    print("\n🛑 API سرور متوقف شد")
            else:
                print("⚠️ API سرور شروع نشد - بررسی کنید aiohttp نصب است")
                
        except Exception as e:
            print(f"❌ خطا در شروع API سرور: {e}")
            
    except KeyboardInterrupt:
        print("\n🛑 توسط کاربر لغو شد")
    except Exception as e:
        print(f"❌ خطا: {e}")

# ========== نقطه شروع ==========

if __name__ == "__main__":
    print("🔍 بررسی وابستگی‌ها...")
    
    # بررسی وابستگی‌های ضروری
    required = ['telethon', 'cryptography', 'aiohttp', 'psutil']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"\n❌ وابستگی‌های مفقود: {', '.join(missing)}")
        print("📦 لطفا نصب کنید:")
        print(f"   pip install {' '.join(missing)}")
        sys.exit(1)
    
    print("✅ همه وابستگی‌ها نصب شده‌اند")
    
    # اجرای برنامه
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 برنامه توسط کاربر متوقف شد")
