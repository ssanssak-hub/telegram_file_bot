#main.py
# -*- coding: utf-8 -*-

import asyncio
import sys
from pathlib import Path

# اضافه کردن مسیر پروژه
sys.path.insert(0, str(Path(__file__).parent))

async def main():
    print("🤖 ربات تلگرام در حال راه‌اندازی...")
    
    # ۱. بارگذاری تنظیمات
    try:
        from config import TOKEN
    except:
        print("❌ فایل config.py را ایجاد کنید")
        return
    
    # ۲. ایجاد اپلیکیشن تلگرام
    from telegram.ext import ApplicationBuilder
    app = ApplicationBuilder().token(TOKEN).build()
    
    # ۳. ثبت دستورات اصلی
    from handlers import setup_handlers
    await setup_handlers(app)
    
    # ۴. اجرای ربات
    print("✅ ربات آماده است!")
    await app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())
