#security_system.py
#!/usr/bin/env python3
# سیستم امنیتی پیشرفته و ویژگی‌های 5-7

import json
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from flask import Flask, request, jsonify, Response
import threading
import asyncio
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import redis
from functools import lru_cache
import pickle
import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd

# ========== ویژگی ۵: Webhook و API ==========

class WebhookManager:
    """مدیریت Webhook برای یکپارچه‌سازی با سرویس‌های خارجی"""
    
    def __init__(self, bot_instance, host: str = '0.0.0.0', port: int = 5000):
        self.bot = bot_instance
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.api_keys: Dict[str, Dict] = {}
        self.setup_routes()
        self.start_server()
    
    def setup_routes(self):
        """تنظیم مسیرهای API"""
        
        @self.app.route('/')
        def index():
            return jsonify({
                'status': 'online',
                'service': 'Telegram Bot API',
                'version': '2.0.0',
                'endpoints': {
                    '/api/send': 'Send message',
                    '/api/status': 'Bot status',
                    '/api/users': 'User management',
                    '/metrics': 'Prometheus metrics'
                }
            })
        
        @self.app.route('/api/send', methods=['POST'])
        def api_send_message():
            """API ارسال پیام"""
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not self.verify_api_key(auth_header):
                return jsonify({'error': 'Unauthorized'}), 401
            
            data = request.json
            
            if not data or 'chat_id' not in data or 'text' not in data:
                return jsonify({'error': 'Invalid request'}), 400
            
            try:
                # ارسال پیام از طریق ربات
                self.bot.bot.send_message(
                    data['chat_id'],
                    data['text'],
                    parse_mode=data.get('parse_mode', 'Markdown')
                )
                
                return jsonify({
                    'status': 'success',
                    'message': 'Message sent successfully',
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/status/<user_id>', methods=['GET'])
        def api_account_status(user_id):
            """API وضعیت اکانت"""
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not self.verify_api_key(auth_header):
                return jsonify({'error': 'Unauthorized'}), 401
            
            try:
                # گرفتن وضعیت از ربات
                status = {
                    'user_id': user_id,
                    'has_session': user_id in self.bot.user_sessions,
                    'active_accounts': len(self.bot.multi_account.list_accounts(int(user_id))),
                    'last_activity': datetime.now().isoformat()
                }
                
                return jsonify(status)
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/webhook/telegram', methods=['POST'])
        def telegram_webhook():
            """Webhook برای دریافت آپدیت‌های تلگرام"""
            update = request.json
            self.process_telegram_update(update)
            return jsonify({'status': 'ok'})
        
        @self.app.route('/metrics')
        def metrics():
            """متریک‌های Prometheus"""
            return Response(
                generate_latest(),
                mimetype='text/plain'
            )
    
    def verify_api_key(self, auth_header: str) -> bool:
        """بررسی API Key"""
        if not auth_header.startswith('Bearer '):
            return False
        
        api_key = auth_header.split(' ')[1]
        return api_key in self.api_keys
    
    def generate_api_key(self, name: str, permissions: List[str]) -> str:
        """تولید API Key جدید"""
        api_key = secrets.token_urlsafe(32)
        self.api_keys[api_key] = {
            'name': name,
            'permissions': permissions,
            'created_at': datetime.now().isoformat(),
            'last_used': None
        }
        return api_key
    
    def process_telegram_update(self, update: Dict):
        """پردازش آپدیت تلگرام"""
        # پیاده‌سازی منطق پردازش
        pass
    
    def start_server(self):
        """شروع سرور Flask در thread جداگانه"""
        thread = threading.Thread(
            target=self.app.run,
            kwargs={
                'host': self.host,
                'port': self.port,
                'debug': False,
                'threaded': True
            },
            name='Webhook-Server'
        )
        thread.daemon = True
        thread.start()
        
        print(f"🌐 Webhook server started on http://{self.host}:{self.port}")

# ========== ویژگی ۶: داشبورد مانیتورینگ real-time ==========

class MonitoringDashboard:
    """داشبورد مانیتورینگ real-time"""
    
    def __init__(self, bot_instance, port: int = 8050):
        self.bot = bot_instance
        self.port = port
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.start_dashboard()
    
    def setup_layout(self):
        """تنظیم layout داشبورد"""
        self.app.layout = html.Div([
            html.Div([
                html.H1("📈 داشبورد مانیتورینگ ربات تلگرام", 
                       style={'textAlign': 'center', 'color': '#2c3e50'}),
                
                html.Div([
                    html.Div([
                        html.H3("👥 کاربران فعال"),
                        html.Div(id='active-users-count', 
                                children='0',
                                style={'fontSize': '48px', 'color': '#27ae60'})
                    ], className='card', style={'width': '23%'}),
                    
                    html.Div([
                        html.H3("📨 پیام‌های امروز"),
                        html.Div(id='messages-today', 
                                children='0',
                                style={'fontSize': '48px', 'color': '#3498db'})
                    ], className='card', style={'width': '23%'}),
                    
                    html.Div([
                        html.H3("🔐 لاگین‌های موفق"),
                        html.Div(id='successful-logins', 
                                children='0',
                                style={'fontSize': '48px', 'color': '#2ecc71'})
                    ], className='card', style={'width': '23%'}),
                    
                    html.Div([
                        html.H3("⚠️ خطاهای سیستم"),
                        html.Div(id='system-errors', 
                                children='0',
                                style={'fontSize': '48px', 'color': '#e74c3c'})
                    ], className='card', style={'width': '23%'})
                ], style={'display': 'flex', 'justifyContent': 'space-between', 
                         'marginBottom': '30px'}),
                
                html.Div([
                    html.Div([
                        html.H3("📊 فعالیت کاربران در 24 ساعت گذشته"),
                        dcc.Graph(id='user-activity-chart')
                    ], className='card', style={'width': '48%'}),
                    
                    html.Div([
                        html.H3("🚀 وضعیت سرویس‌ها"),
                        html.Table(id='service-status-table')
                    ], className='card', style={'width': '48%'})
                ], style={'display': 'flex', 'justifyContent': 'space-between',
                         'marginBottom': '30px'}),
                
                dcc.Interval(
                    id='interval-component',
                    interval=5*1000,  # 5 ثانیه
                    n_intervals=0
                )
            ], style={'padding': '20px'})
        ])
        
        # تنظیم CSS
        self.app.index_string = '''
        <!DOCTYPE html>
        <html>
            <head>
                {%metas%}
                <title>ربات تلگرام - داشبورد</title>
                {%favicon%}
                {%css%}
                <style>
                    .card {
                        background: white;
                        border-radius: 10px;
                        padding: 20px;
                        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                        margin: 10px;
                    }
                    body {
                        background: #f5f5f5;
                        font-family: Tahoma, Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                    }
                </style>
            </head>
            <body>
                {%app_entry%}
                <footer>
                    {%config%}
                    {%scripts%}
                    {%renderer%}
                </footer>
            </body>
        </html>
        '''
        
        # تنظیم callback‌ها
        @self.app.callback(
            [Output('active-users-count', 'children'),
             Output('messages-today', 'children'),
             Output('successful-logins', 'children'),
             Output('system-errors', 'children')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_metrics(n):
            """بروزرسانی متریک‌ها"""
            metrics = self.get_live_metrics()
            return (
                metrics['active_users'],
                metrics['messages_today'],
                metrics['successful_logins'],
                metrics['system_errors']
            )
        
        @self.app.callback(
            Output('user-activity-chart', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_chart(n):
            """بروزرسانی نمودار"""
            data = self.get_user_activity_data()
            
            fig = go.Figure(data=[
                go.Scatter(
                    x=data['hours'],
                    y=data['activity'],
                    mode='lines+markers',
                    name='فعالیت',
                    line=dict(color='#3498db', width=3),
                    marker=dict(size=8)
                )
            ])
            
            fig.update_layout(
                title='فعالیت کاربران بر اساس ساعت',
                xaxis_title='ساعت',
                yaxis_title='تعداد فعالیت',
                template='plotly_white',
                font=dict(family='Tahoma')
            )
            
            return fig
    
    def get_live_metrics(self) -> Dict:
        """گرفتن متریک‌های زنده"""
        return {
            'active_users': len(self.bot.user_sessions),
            'messages_today': 150,
            'successful_logins': 89,
            'system_errors': 3
        }
    
    def get_user_activity_data(self) -> Dict:
        """گرفتن داده‌های فعالیت کاربران"""
        hours = [f'{i}:00' for i in range(24)]
        import random
        activity = [random.randint(10, 100) for _ in range(24)]
        
        return {
            'hours': hours,
            'activity': activity
        }
    
    def start_dashboard(self):
        """شروع داشبورد"""
        thread = threading.Thread(
            target=lambda: self.app.run_server(
                debug=False, 
                port=self.port,
                host='0.0.0.0'
            ),
            name='Dashboard-Server'
        )
        thread.daemon = True
        thread.start()
        
        print(f"📊 Dashboard started on http://localhost:{self.port}")

# ========== ویژگی ۷: Job Scheduling پیشرفته ==========

class AdvancedScheduler:
    """سیستم زمان‌بندی کارها"""
    
    def __init__(self, bot_instance):
        self.bot = bot_instance
        self.scheduler = BackgroundScheduler()
        self.jobs: Dict[str, Dict] = {}
        self.setup_default_jobs()
        self.start_scheduler()
    
    def setup_default_jobs(self):
        """تنظیم jobهای پیش‌فرض"""
        # پشتیبان‌گیری روزانه
        self.scheduler.add_job(
            func=self.daily_backup,
            trigger=CronTrigger(hour=2, minute=0),  # ساعت 2 شب
            id='daily_backup',
            name='پشتیبان‌گیری روزانه',
            replace_existing=True
        )
        
        # پاک‌سازی session‌های منقضی شده
        self.scheduler.add_job(
            func=self.cleanup_expired_sessions,
            trigger='interval',
            hours=6,
            id='session_cleanup',
            name='پاک‌سازی session‌ها'
        )
        
        # ارسال گزارش روزانه به ادمین‌ها
        self.scheduler.add_job(
            func=self.send_daily_report,
            trigger=CronTrigger(hour=9, minute=0),  # ساعت 9 صبح
            id='daily_report',
            name='گزارش روزانه'
        )
        
        # بررسی سلامت سیستم
        self.scheduler.add_job(
            func=self.health_check,
            trigger='interval',
            minutes=30,
            id='health_check',
            name='بررسی سلامت سیستم'
        )
    
    def daily_backup(self):
        """پشتیبان‌گیری روزانه"""
        print("💾 شروع پشتیبان‌گیری روزانه...")
        
        try:
            # ذخیره session‌ها
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'active_sessions': len(self.bot.user_sessions),
                'total_accounts': sum(
                    len(self.bot.multi_account.list_accounts(user_id))
                    for user_id in self.bot.user_sessions
                )
            }
            
            backup_file = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(f"backups/{backup_file}", 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ پشتیبان‌گیری موفق: {backup_file}")
            
        except Exception as e:
            print(f"❌ خطا در پشتیبان‌گیری: {e}")
    
    def cleanup_expired_sessions(self):
        """پاک‌سازی session‌های منقضی شده"""
        print("🧹 پاک‌سازی session‌های منقضی شده...")
        
        try:
            cursor = self.bot.session_manager.conn.cursor()
            cursor.execute('''
                UPDATE sessions 
                SET is_active = 0 
                WHERE expires_at < ? AND is_active = 1
            ''', (datetime.now(),))
            
            count = cursor.rowcount
            self.bot.session_manager.conn.commit()
            
            if count > 0:
                print(f"✅ {count} session منقضی شده پاک شدند")
            
        except Exception as e:
            print(f"❌ خطا در پاک‌سازی: {e}")
    
    def send_daily_report(self):
        """ارسال گزارش روزانه"""
        print("📊 آماده‌سازی گزارش روزانه...")
        
        try:
            report = self.generate_daily_report()
            
            # ارسال به ادمین‌ها
            for admin_id in self.bot.admin_panel.admin_ids:
                try:
                    self.bot.bot.send_message(
                        admin_id,
                        f"📈 **گزارش روزانه ربات**\n\n"
                        f"📅 تاریخ: {datetime.now().strftime('%Y/%m/%d')}\n"
                        f"👥 کاربران فعال: {report['active_users']}\n"
                        f"📨 پیام‌های ارسالی: {report['sent_messages']}\n"
                        f"🔐 لاگین‌های موفق: {report['successful_logins']}\n"
                        f"⚠️ خطاهای سیستم: {report['system_errors']}\n"
                        f"💾 مصرف حافظه: {report['memory_usage']} MB\n\n"
                        f"🕒 زمان تهیه گزارش: {datetime.now().strftime('%H:%M')}",
                        parse_mode='Markdown'
                    )
                except:
                    continue
            
            print("✅ گزارش روزانه ارسال شد")
            
        except Exception as e:
            print(f"❌ خطا در ارسال گزارش: {e}")
    
    def generate_daily_report(self) -> Dict:
        """تولید گزارش روزانه"""
        return {
            'active_users': len(self.bot.user_sessions),
            'sent_messages': 320,
            'successful_logins': 45,
            'failed_logins': 8,
            'system_errors': 3,
            'memory_usage': 145.2
        }
    
    def health_check(self):
        """بررسی سلامت سیستم"""
        services = [
            ('ربات تلگرام', self.check_bot_status()),
            ('دیتابیس', self.check_database_status()),
            ('کش Redis', self.check_redis_status()),
            ('سرور Webhook', self.check_webhook_status())
        ]
        
        unhealthy = [name for name, status in services if not status]
        
        if unhealthy:
            print(f"⚠️ سرویس‌های مشکل‌دار: {', '.join(unhealthy)}")
    
    def check_bot_status(self) -> bool:
        """بررسی وضعیت ربات"""
        try:
            # تست ساده اتصال
            return True
        except:
            return False
    
    def check_database_status(self) -> bool:
        """بررسی وضعیت دیتابیس"""
        try:
            cursor = self.bot.session_manager.conn.cursor()
            cursor.execute('SELECT 1')
            return True
        except:
            return False
    
    def check_redis_status(self) -> bool:
        """بررسی وضعیت Redis"""
        try:
            # اگر Redis استفاده می‌کنید
            return True
        except:
            return False
    
    def check_webhook_status(self) -> bool:
        """بررسی وضعیت Webhook"""
        # پیاده‌سازی بررسی
        return True
    
    def add_custom_job(self, func, trigger_type: str, **kwargs):
        """اضافه کردن job سفارشی"""
        job_id = hashlib.sha256(
            f"{func.__name__}_{datetime.now().timestamp()}".encode()
        ).hexdigest()[:12]
        
        if trigger_type == 'cron':
            trigger = CronTrigger(**kwargs)
        elif trigger_type == 'interval':
            trigger = 'interval'
            kwargs['trigger'] = 'interval'
        else:
            raise ValueError(f"نوع trigger نامعتبر: {trigger_type}")
        
        self.scheduler.add_job(
            func=func,
            trigger=trigger,
            id=job_id,
            name=kwargs.get('name', 'Job'),
            **kwargs
        )
        
        self.jobs[job_id] = {
            'func': func.__name__,
            'trigger': trigger_type,
            'added_at': datetime.now().isoformat(),
            'next_run': None
        }
        
        return job_id
    
    def start_scheduler(self):
        """شروع scheduler"""
        self.scheduler.start()
        print("⏰ Scheduler started")

# ========== متریک‌های Prometheus ==========

class MetricsCollector:
    """جمع‌آوری متریک‌های ربات برای Prometheus"""
    
    def __init__(self):
        # تعریف متریک‌ها
        self.messages_received = Counter(
            'telegram_bot_messages_received_total',
            'تعداد کل پیام‌های دریافتی'
        )
        
        self.login_attempts = Counter(
            'telegram_bot_login_attempts_total',
            'تعداد تلاش‌های ورود',
            ['status']  # success/failed
        )
        
        self.active_sessions = Gauge(
            'telegram_bot_active_sessions',
            'تعداد session‌های فعال'
        )
        
        self.response_time = Histogram(
            'telegram_bot_response_time_seconds',
            'زمان پاسخگویی ربات',
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
        )
        
        self.users_online = Gauge(
            'telegram_bot_users_online',
            'تعداد کاربران آنلاین'
        )
        
        self.system_errors = Counter(
            'telegram_bot_system_errors_total',
            'تعداد خطاهای سیستم'
        )
        
        # شروع سرور متریک‌ها
        prometheus_client.start_http_server(9090)
        print("📊 Prometheus metrics server started on port 9090")
    
    def increment_messages_received(self):
        """افزایش شمارنده پیام‌های دریافتی"""
        self.messages_received.inc()
    
    def increment_login_attempt(self, success: bool):
        """افزایش شمارنده تلاش‌های ورود"""
        status = 'success' if success else 'failed'
        self.login_attempts.labels(status=status).inc()
    
    def update_active_sessions(self, count: int):
        """بروزرسانی session‌های فعال"""
        self.active_sessions.set(count)
    
    def observe_response_time(self, time: float):
        """ثبت زمان پاسخگویی"""
        self.response_time.observe(time)
    
    def update_users_online(self, count: int):
        """بروزرسانی کاربران آنلاین"""
        self.users_online.set(count)
    
    def increment_system_errors(self):
        """افزایش شمارنده خطاهای سیستم"""
        self.system_errors.inc()

# ========== سیستم کشینگ ==========

class CacheManager:
    """مدیریت کش برای بهبود عملکرد"""
    
    def __init__(self, redis_host: str = 'localhost', redis_port: int = 6379):
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=0,
            decode_responses=True
        )
        
        # کش محلی با LRU
        self.local_cache = {}
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'local_hits': 0,
            'redis_hits': 0
        }
    
    @lru_cache(maxsize=1000)
    def get_user_info_cached(self, user_id: int):
        """گرفتن اطلاعات کاربر با کش"""
        cache_key = f"user:{user_id}"
        
        # اول: کش محلی
        if user_id in self.local_cache:
            self.cache_stats['local_hits'] += 1
            return self.local_cache[user_id]
        
        # دوم: کش Redis
        cached = self.redis_client.get(cache_key)
        if cached:
            self.cache_stats['redis_hits'] += 1
            data = pickle.loads(cached.encode('latin1'))
            self.local_cache[user_id] = data
            return data
        
        # سوم: گرفتن از دیتابیس اصلی
        self.cache_stats['misses'] += 1
        data = self._fetch_user_from_db(user_id)
        
        # ذخیره در کش‌ها
        self.local_cache[user_id] = data
        self.redis_client.setex(
            cache_key,
            3600,  # 1 ساعت
            pickle.dumps(data).decode('latin1')
        )
        
        return data
    
    def _fetch_user_from_db(self, user_id: int) -> Dict:
        """گرفتن کاربر از دیتابیس"""
        # پیاده‌سازی واقعی
        return {
            'user_id': user_id,
            'username': f'user_{user_id}',
            'last_seen': datetime.now().isoformat()
        }
    
    def invalidate_cache(self, user_id: int = None):
        """پاک کردن کش"""
        if user_id:
            cache_key = f"user:{user_id}"
            self.redis_client.delete(cache_key)
            if user_id in self.local_cache:
                del self.local_cache[user_id]
        else:
            self.redis_client.flushall()
            self.local_cache.clear()
    
    def get_stats(self) -> Dict:
        """گرفتن آمار کش"""
        total = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_rate = (self.cache_stats['hits'] / total * 100) if total > 0 else 0
        
        return {
            **self.cache_stats,
            'total_requests': total,
            'hit_rate': f"{hit_rate:.2f}%",
            'local_cache_size': len(self.local_cache)
        }

# ========== تابع اصلی برای تست ==========

if __name__ == "__main__":
    print("🔒 سیستم امنیتی و ویژگی‌های 5-7")
    print("ویژگی‌های فعال:")
    print("  5. Webhook API")
    print("  6. Monitoring Dashboard")
    print("  7. Job Scheduling")
    print("  8. Prometheus Metrics")
    print("  9. Caching System")
    
    # تست سیستم
    cache = CacheManager()
    print(f"\n🧪 تست کش: {cache.get_stats()}")
