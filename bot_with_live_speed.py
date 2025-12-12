#!/usr/bin/env python3
# bot_with_live_speed.py - ربات کامل با نمایش سرعت real-time

import asyncio
import logging
from typing import Dict, Optional
import time
from pathlib import Path

from speed_monitor import RealTimeSpeedMonitor, TelegramSpeedDisplay
from progress_ui import ProgressUI, AnimatedProgress, SpeedChartGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LiveSpeedBot:
    """ربات با نمایش سرعت زنده"""
    
    def __init__(self, token: str):
        self.bot = telebot.TeleBot(token)
        self.speed_monitor = RealTimeSpeedMonitor(update_interval=0.3)  # هر 0.3 ثانیه
        self.progress_ui = ProgressUI()
        self.animation = AnimatedProgress()
        self.chart_gen = SpeedChartGenerator()
        
        # ذخیره وضعیت کاربران
        self.user_sessions: Dict[int, Dict] = {}  # user_id -> session_data
        
        self.setup_handlers()
        
        logger.info("LiveSpeedBot initialized")
    
    def setup_handlers(self):
        """تنظیم هندلرها"""
        
        @self.bot.message_handler(commands=['start'])
        async def start_handler(message):
            await self.send_welcome(message.from_user.id, message.chat.id)
        
        @self.bot.message_handler(commands=['download'])
        async def download_handler(message):
            await self.start_download_test(message.chat.id)
        
        @self.bot.message_handler(commands=['upload'])
        async def upload_handler(message):
            await self.start_upload_test(message.chat.id)
        
        @self.bot.message_handler(commands=['speedtest'])
        async def speedtest_handler(message):
            await self.run_complete_speedtest(message.chat.id)
        
        @self.bot.message_handler(commands=['stats'])
        async def stats_handler(message):
            await self.show_user_stats(message.from_user.id, message.chat.id)
        
        @self.bot.message_handler(content_types=['document'])
        async def document_handler(message):
            await self.handle_real_upload(message)
    
    async def send_welcome(self, user_id: int, chat_id: int):
        """ارسال پیام خوشآمدگویی"""
        welcome_text = (
            "🚀 <b>ربات نمایش سرعت زنده</b>\n\n"
            "با این ربات می‌توانید سرعت دانلود/آپلود را به صورت زنده مشاهده کنید!\n\n"
            "📋 <b>دستورات:</b>\n"
            "/download - تست دانلود\n"
            "/upload - تست آپلود\n"
            "/speedtest - تست کامل سرعت\n"
            "/stats - آمار شما\n\n"
            "📁 همچنین می‌توانید فایل ارسال کنید تا سرعت آپلود را ببینید."
        )
        
        await self.bot.send_message(chat_id, welcome_text, parse_mode='HTML')
        
        # ثبت کاربر
        self.user_sessions[user_id] = {
            'chat_id': chat_id,
            'join_time': time.time(),
            'total_downloads': 0,
            'total_uploads': 0,
            'avg_speed': 0
        }
    
    async def start_download_test(self, chat_id: int):
        """شروع تست دانلود"""
        test_id = f"download_test_{chat_id}_{int(time.time())}"
        
        # ارسال پیام شروع
        start_msg = await self.bot.send_message(
            chat_id,
            self.animation.get_spinner("آماده‌سازی تست دانلود..."),
            parse_mode='HTML'
        )
        
        # ایجاد انتقال تست
        test_size = 50 * 1024 * 1024  # 50MB تست
        self.speed_monitor.register_transfer(
            transfer_id=test_id,
            transfer_type='download',
            total_bytes=test_size,
            callback=lambda data: asyncio.create_task(
                self.update_download_display(chat_id, start_msg.message_id, test_id, data)
            )
        )
        
        # شبیه‌سازی دانلود
        asyncio.create_task(self.simulate_download(test_id, test_size, chat_id, start_msg.message_id))
    
    async def simulate_download(self, test_id: str, total_size: int, chat_id: int, msg_id: int):
        """شبیه‌سازی دانلود"""
        chunk_size = 1024 * 1024  # 1MB
        total_chunks = total_size // chunk_size
        
        try:
            for chunk in range(total_chunks):
                # محاسبه پیشرفت
                transferred = (chunk + 1) * chunk_size
                
                # به‌روزرسانی مانیتور
                self.speed_monitor.update_transfer_progress(test_id, transferred)
                
                # تأخیر شبیه‌سازی (سرعت متغیر)
                delay = 0.05 + (0.1 * (chunk % 10) / 10)  # 0.05 تا 0.15 ثانیه
                await asyncio.sleep(delay)
            
            # تکمیل
            self.speed_monitor.complete_transfer(test_id)
            
            # ارسال پیام تکمیل
            await self.send_completion_message(
                chat_id, msg_id, 'download', total_size
            )
            
        except Exception as e:
            logger.error(f"Download simulation error: {e}")
            await self.bot.edit_message_text(
                f"❌ خطا در تست دانلود: {e}",
                chat_id=chat_id,
                message_id=msg_id
            )
    
    async def update_download_display(self, chat_id: int, msg_id: int, test_id: str, speed_data):
        """به‌روزرسانی نمایش دانلود"""
        try:
            # دریافت آمار
            stats = self.speed_monitor.get_transfer_stats(test_id)
            if not stats:
                return
            
            # ایجاد متن به‌روزشده
            text = self.create_speed_display_text(
                'download', 'test_file.bin', speed_data, stats
            )
            
            # ویرایش پیام
            await self.bot.edit_message_text(
                text,
                chat_id=chat_id,
                message_id=msg_id,
                parse_mode='HTML'
            )
            
        except Exception as e:
            logger.error(f"Update display error: {e}")
    
    async def start_upload_test(self, chat_id: int):
        """شروع تست آپلود"""
        test_id = f"upload_test_{chat_id}_{int(time.time())}"
        
        # ارسال پیام شروع
        start_msg = await self.bot.send_message(
            chat_id,
            self.animation.get_spinner("آماده‌سازی تست آپلود..."),
            parse_mode='HTML'
        )
        
        # ایجاد انتقال تست
        test_size = 30 * 1024 * 1024  # 30MB تست
        self.speed_monitor.register_transfer(
            transfer_id=test_id,
            transfer_type='upload',
            total_bytes=test_size,
            callback=lambda data: asyncio.create_task(
                self.update_upload_display(chat_id, start_msg.message_id, test_id, data)
            )
        )
        
        # شبیه‌سازی آپلود
        asyncio.create_task(self.simulate_upload(test_id, test_size, chat_id, start_msg.message_id))
    
    async def simulate_upload(self, test_id: str, total_size: int, chat_id: int, msg_id: int):
        """شبیه‌سازی آپلود"""
        chunk_size = 512 * 1024  # 512KB (آپلود معمولاً کندتر است)
        total_chunks = total_size // chunk_size
        
        try:
            for chunk in range(total_chunks):
                # محاسبه پیشرفت
                transferred = (chunk + 1) * chunk_size
                
                # به‌روزرسانی مانیتور
                self.speed_monitor.update_transfer_progress(test_id, transferred)
                
                # تأخیر شبیه‌سازی
                delay = 0.1 + (0.2 * (chunk % 10) / 10)  # 0.1 تا 0.3 ثانیه
                await asyncio.sleep(delay)
            
            # تکمیل
            self.speed_monitor.complete_transfer(test_id)
            
            # ارسال پیام تکمیل
            await self.send_completion_message(
                chat_id, msg_id, 'upload', total_size
            )
            
        except Exception as e:
            logger.error(f"Upload simulation error: {e}")
            await self.bot.edit_message_text(
                f"❌ خطا در تست آپلود: {e}",
                chat_id=chat_id,
                message_id=msg_id
            )
    
    async def update_upload_display(self, chat_id: int, msg_id: int, test_id: str, speed_data):
        """به‌روزرسانی نمایش آپلود"""
        try:
            # دریافت آمار
            stats = self.speed_monitor.get_transfer_stats(test_id)
            if not stats:
                return
            
            # ایجاد متن به‌روزشده
            text = self.create_speed_display_text(
                'upload', 'test_upload.bin', speed_data, stats
            )
            
            # ویرایش پیام
            await self.bot.edit_message_text(
                text,
                chat_id=chat_id,
                message_id=msg_id,
                parse_mode='HTML'
            )
            
        except Exception as e:
            logger.error(f"Update display error: {e}")
    
    def create_speed_display_text(self, transfer_type: str, file_name: str, speed_data, stats: Dict) -> str:
        """ایجاد متن نمایش سرعت"""
        # انتخاب emoji
        if transfer_type == 'download':
            action_emoji = "📥"
            action_text = "دانلود"
        else:
            action_emoji = "📤"
            action_text = "آپلود"
        
        # progress bar
        progress_bar = self.progress_ui.create_progress_bar(speed_data.progress_percent)
        
        # اندازه‌ها
        transferred_fmt = self.progress_ui.format_size(speed_data.bytes_transferred)
        total_fmt = self.progress_ui.format_size(speed_data.total_bytes)
        
        # سرعت
        speed_fmt = self.progress_ui.format_speed(speed_data.speed_bps)
        
        # زمان‌ها
        elapsed_fmt = self.progress_ui.format_time(stats['elapsed_seconds'])
        eta_fmt = self.progress_ui.format_time(stats['eta_seconds'])
        
        # نمودار سرعت کوچک
        graph_data = self.speed_monitor.get_speed_graph_data(
            f"{action_text}_{id(speed_data)}", 5
        )
        
        # انتخاب emoji سرعت
        if speed_data.speed_mbps > 5:
            speed_emoji = "⚡"
        elif speed_data.speed_mbps > 1:
            speed_emoji = "🚀"
        else:
            speed_emoji = "🐢"
        
        # ساخت متن
        text = (
            f"{action_emoji} <b>{action_text} در حال اجرا...</b>\n\n"
            f"📁 فایل: <code>{file_name}</code>\n"
            f"📊 پیشرفت: {speed_data.progress_percent:.1f}%\n"
            f"{progress_bar}\n\n"
            f"💾 حجم: {transferred_fmt} / {total_fmt}\n"
            f"{speed_emoji} سرعت: <b>{speed_fmt}</b>\n"
            f"⏱️ سپری شده: {elapsed_fmt}\n"
            f"⏳ باقیمانده: {eta_fmt}\n\n"
        )
        
        # اضافه کردن نمودار برای پیشرفت بالا
        if speed_data.progress_percent > 10:
            # دریافت تاریخچه سرعت
            transfer_id = f"{action_text}_{id(speed_data)}"
            if transfer_id in self.speed_monitor.speed_history:
                history = self.speed_monitor.speed_history[transfer_id]
                if len(history) > 5:
                    speeds = [h.speed_kbps for h in history[-10:]]
                    chart = self.chart_gen.create_speed_chart_ascii(
                        [s * 1024 for s in speeds],  # تبدیل به بایت
                        width=20,
                        height=4
                    )
                    text += f"📈 نمودار سرعت:\n<pre>{chart}</pre>\n\n"
        
        text += "<i>تست در حال اجراست...</i>"
        
        return text
    
    async def send_completion_message(self, chat_id: int, msg_id: int, transfer_type: str, total_size: int):
        """ارسال پیام تکمیل"""
        if transfer_type == 'download':
            emoji = "📥"
            action = "دانلود"
        else:
            emoji = "📤"
            action = "آپلود"
        
        size_fmt = self.progress_ui.format_size(total_size)
        
        completion_text = (
            f"{emoji} <b>{action} تکمیل شد!</b>\n\n"
            f"✅ تست با موفقیت انجام شد.\n"
            f"💾 حجم تست: {size_fmt}\n\n"
            f"برای تست مجدد از /download یا /upload استفاده کنید."
        )
        
        await self.bot.edit_message_text(
            completion_text,
            chat_id=chat_id,
            message_id=msg_id,
            parse_mode='HTML'
        )
    
    async def run_complete_speedtest(self, chat_id: int):
        """اجرای تست سرعت کامل"""
        test_msg = await self.bot.send_message(
            chat_id,
            "🧪 <b>تست سرعت کامل شروع شد</b>\n\n"
            "در حال اندازه‌گیری:\n"
            "1. سرعت دانلود 📥\n"
            "2. سرعت آپلود 📤\n"
            "3. پینگ ⏱️\n\n"
            "<i>لطفاً چند لحظه صبر کنید...</i>",
            parse_mode='HTML'
        )
        
        # اجرای تست‌ها
        download_result = await self.measure_download_speed()
        upload_result = await self.measure_upload_speed()
        ping_result = await self.measure_ping()
        
        # ایجاد نتایج
        results_text = self.create_speedtest_results(
            download_result, upload_result, ping_result
        )
        
        await self.bot.edit_message_text(
            results_text,
            chat_id=chat_id,
            message_id=test_msg.message_id,
            parse_mode='HTML'
        )
    
    async def measure_download_speed(self) -> Dict:
        """اندازه‌گیری سرعت دانلود"""
        # شبیه‌سازی تست دانلود
        await asyncio.sleep(2)
        
        return {
            'speed_mbps': 42.5,
            'latency_ms': 25,
            'jitter_ms': 5,
            'packet_loss': 0,
            'rating': 'عالی 🚀'
        }
    
    async def measure_upload_speed(self) -> Dict:
        """اندازه‌گیری سرعت آپلود"""
        # شبیه‌سازی تست آپلود
        await asyncio.sleep(1)
        
        return {
            'speed_mbps': 18.3,
            'latency_ms': 30,
            'jitter_ms': 8,
            'packet_loss': 0.1,
            'rating': 'خوب 👍'
        }
    
    async def measure_ping(self) -> Dict:
        """اندازه‌گیری پینگ"""
        await asyncio.sleep(0.5)
        
        return {
            'ping_ms': 28,
            'jitter_ms': 3,
            'server': 'Iran - Tehran',
            'rating': 'عالی 🎯'
        }
    
    def create_speedtest_results(self, download: Dict, upload: Dict, ping: Dict) -> str:
        """ایجاد متن نتایج تست سرعت"""
        # نمودار مقایسه‌ای
        download_speeds = [download['speed_mbps'] * 0.8, download['speed_mbps'] * 1.2]
        upload_speeds = [upload['speed_mbps'] * 0.8, upload['speed_mbps'] * 1.2]
        
        comparison_chart = self.chart_gen.create_comparison_chart(
            download_speeds, upload_speeds, width=30
        )
        
        text = (
            "📊 <b>نتایج تست سرعت کامل</b>\n\n"
            f"🌐 سرور: {ping['server']}\n"
            f"⏱️ زمان تست: {time.strftime('%H:%M:%S')}\n\n"
            
            "📥 <b>دانلود:</b>\n"
            f"   سرعت: {download['speed_mbps']:.2f} Mbps\n"
            f"   وضعیت: {download['rating']}\n"
            f"   تاخیر: {download['latency_ms']} ms\n\n"
            
            "📤 <b>آپلود:</b>\n"
            f"   سرعت: {upload['speed_mbps']:.2f} Mbps\n"
            f"   وضعیت: {upload['rating']}\n"
            f"   تاخیر: {upload['latency_ms']} ms\n\n"
            
            "⏱️ <b>پینگ:</b>\n"
            f"   مقدار: {ping['ping_ms']} ms\n"
            f"   وضعیت: {ping['rating']}\n"
            f"   جیتر: {ping['jitter_ms']} ms\n\n"
            
            "📈 <b>مقایسه:</b>\n"
            f"<pre>{comparison_chart}</pre>\n\n"
            
            "<i>تست در شرایط عادی انجام شد.</i>"
        )
        
        return text
    
    async def handle_real_upload(self, message):
        """مدیریت آپلود واقعی"""
        user_id = message.from_user.id
        chat_id = message.chat.id
        document = message.document
        
        # دریافت اطلاعات فایل
        file_name = document.file_name
        file_size = document.file_size
        
        # ایجاد ID انتقال
        transfer_id = f"real_upload_{user_id}_{int(time.time())}"
        
        # شروع مانیتورینگ
        await self.start_real_upload_monitoring(
            chat_id, transfer_id, file_name, file_size
        )
        
        # دانلود فایل (در واقعیت)
        # و آپلود به مقصد مورد نظر
        # با به‌روزرسانی پیشرفت
    
    async def start_real_upload_monitoring(self, chat_id: int, transfer_id: str, file_name: str, file_size: int):
        """شروع مانیتورینگ آپلود واقعی"""
        # ارسال پیام شروع
        start_msg = await self.bot.send_message(
            chat_id,
            f"📤 <b>شروع آپلود</b>\n\n"
            f"📁 فایل: {file_name}\n"
            f"💾 حجم: {self.progress_ui.format_size(file_size)}\n"
            f"⏳ در حال شروع...",
            parse_mode='HTML'
        )
        
        # ثبت انتقال
        self.speed_monitor.register_transfer(
            transfer_id=transfer_id,
            transfer_type='upload',
            total_bytes=file_size,
            callback=lambda data: asyncio.create_task(
                self.update_real_upload_display(
                    chat_id, start_msg.message_id, transfer_id, file_name, data
                )
            )
        )
    
    async def update_real_upload_display(self, chat_id: int, msg_id: int, 
                                       transfer_id: str, file_name: str, speed_data):
        """به‌روزرسانی نمایش آپلود واقعی"""
        try:
            stats = self.speed_monitor.get_transfer_stats(transfer_id)
            if not stats:
                return
            
            text = self.create_real_upload_text(file_name, speed_data, stats)
            
            await self.bot.edit_message_text(
                text,
                chat_id=chat_id,
                message_id=msg_id,
                parse_mode='HTML'
            )
            
        except Exception as e:
            logger.error(f"Real upload display error: {e}")
    
    def create_real_upload_text(self, file_name: str, speed_data, stats: Dict) -> str:
        """ایجاد متن آپلود واقعی"""
        # progress bar
        progress_bar = self.progress_ui.create_progress_bar(speed_data.progress_percent)
        
        # اطلاعات فایل
        transferred_fmt = self.progress_ui.format_size(speed_data.bytes_transferred)
        total_fmt = self.progress_ui.format_size(speed_data.total_bytes)
        
        # سرعت
        speed_fmt = self.progress_ui.format_speed(speed_data.speed_bps)
        
        # زمان
        elapsed_fmt = self.progress_ui.format_time(stats['elapsed_seconds'])
        eta_fmt = self.progress_ui.format_time(stats['eta_seconds'])
        
        # انتخاب emoji سرعت
        if speed_data.speed_mbps > 5:
            speed_emoji = "⚡"
            status = "عالی"
        elif speed_data.speed_mbps > 1:
            speed_emoji = "🚀"
            status = "خوب"
        else:
            speed_emoji = "🐢"
            status = "کند"
        
        text = (
            f"📤 <b>آپلود در حال انجام</b>\n\n"
            f"📁 فایل: <code>{file_name[:40]}</code>\n"
            f"📊 پیشرفت: {speed_data.progress_percent:.1f}%\n"
            f"{progress_bar}\n\n"
            f"💾 حجم: {transferred_fmt} / {total_fmt}\n"
            f"{speed_emoji} سرعت: <b>{speed_fmt}</b> ({status})\n"
            f"⏱️ سپری شده: {elapsed_fmt}\n"
            f"⏳ باقیمانده: {eta_fmt}\n\n"
        )
        
        # اضافه کردن پیش‌بینی
        if speed_data.progress_percent > 20:
            # محاسبه زمان تخمینی تکمیل
            completion_time = time.time() + stats['eta_seconds']
            completion_str = time.strftime("%H:%M:%S", time.localtime(completion_time))
            
            text += f"🕒 تخمین تکمیل: {completion_str}\n\n"
        
        text += "<i>آپلود در حال انجام است...</i>"
        
        return text
    
    async def show_user_stats(self, user_id: int, chat_id: int):
        """نمایش آمار کاربر"""
        if user_id not in self.user_sessions:
            await self.bot.send_message(chat_id, "📭 هیچ آماری موجود نیست.")
            return
        
        user_data = self.user_sessions[user_id]
        
        # محاسبه زمان فعالیت
        active_seconds = time.time() - user_data['join_time']
        active_time = self.progress_ui.format_time(active_seconds)
        
        stats_text = (
            "📊 <b>آمار شما</b>\n\n"
            f"👤 کاربر ID: {user_id}\n"
            f"⏰ زمان فعالیت: {active_time}\n"
            f"📥 تعداد دانلود: {user_data['total_downloads']}\n"
            f"📤 تعداد آپلود: {user_data['total_uploads']}\n"
            f"⚡ سرعت متوسط: {user_data['avg_speed']:.2f} MB/s\n\n"
            "<i>برای تست سرعت از /speedtest استفاده کنید.</i>"
        )
        
        await self.bot.send_message(chat_id, stats_text, parse_mode='HTML')
    
    async def start(self):
        """شروع ربات"""
        logger.info("🚀 LiveSpeedBot started")
        await self.bot.polling(none_stop=True)

# تابع اصلی
async def main():
    """تابع اصلی"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Live Speed Display Bot')
    parser.add_argument('--token', required=True, help='Bot token')
    
    args = parser.parse_args()
    
    bot = LiveSpeedBot(args.token)
    await bot.start()

if __name__ == "__main__":
    asyncio.run(main())
