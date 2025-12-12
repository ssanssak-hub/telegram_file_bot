#!/usr/bin/env python3
# render_deployment.py - تنظیمات deployment برای Render.com

import os
import json
import logging
from typing import Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class RenderDeployment:
    """مدیریت deployment در Render.com"""
    
    @staticmethod
    def detect_render() -> bool:
        """تشخیص محیط Render"""
        return os.getenv('RENDER') == 'true' or 'RENDER' in os.environ
    
    @staticmethod
    def get_render_config() -> Dict[str, Any]:
        """دریافت تنظیمات Render"""
        return {
            'service_id': os.getenv('RENDER_SERVICE_ID'),
            'service_name': os.getenv('RENDER_SERVICE_NAME'),
            'service_type': os.getenv('RENDER_SERVICE_TYPE'),
            'instance_id': os.getenv('RENDER_INSTANCE_ID'),
            'instance_ip': os.getenv('RENDER_INSTANCE_IP'),
            'external_url': os.getenv('RENDER_EXTERNAL_URL'),
            'database_url': os.getenv('DATABASE_URL'),
            'redis_url': os.getenv('REDIS_URL'),
            'port': os.getenv('PORT', '8080'),
            'environment': os.getenv('ENVIRONMENT', 'production')
        }
    
    @staticmethod
    def setup_render_environment():
        """تنظیم محیط Render"""
        if not RenderDeployment.detect_render():
            return
        
        logger.info("🚀 Setting up Render environment")
        
        # تنظیم port
        port = os.getenv('PORT', '8080')
        os.environ['BOT_WEBHOOK_PORT'] = port
        os.environ['WEB_SERVER_PORT'] = port
        
        # تنظیم external URL
        external_url = os.getenv('RENDER_EXTERNAL_URL')
        if external_url and not os.getenv('WEBHOOK_URL'):
            os.environ['WEBHOOK_URL'] = f"{external_url}/webhook"
            logger.info(f"Set webhook URL: {external_url}/webhook")
        
        # تنظیم database URL
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            if db_url.startswith('postgres://'):
                # تبدیل به فرمت SQLAlchemy
                db_url = db_url.replace('postgres://', 'postgresql://', 1)
                os.environ['DATABASE_URL'] = db_url
            
            os.environ['DB_CONNECTION_STRING'] = db_url
            logger.info("Database URL configured")
        
        # تنظیم redis URL
        redis_url = os.getenv('REDIS_URL')
        if redis_url:
            os.environ['REDIS_CONNECTION_STRING'] = redis_url
            logger.info("Redis URL configured")
        
        # تنظیمات performance برای Render
        RenderDeployment._set_render_performance_settings()
    
    @staticmethod
    def _set_render_performance_settings():
        """تنظیمات performance مخصوص Render"""
        # تشخیص نوع instance
        instance_type = os.getenv('RENDER_SERVICE_TYPE', 'web')
        
        if instance_type == 'web':
            # تنظیمات برای web service
            os.environ['WORKER_COUNT'] = '2'
            os.environ['THREAD_COUNT'] = '4'
            os.environ['MAX_REQUESTS'] = '1000'
        
        elif instance_type == 'worker':
            # تنظیمات برای worker
            os.environ['WORKER_COUNT'] = '1'
            os.environ['THREAD_COUNT'] = '2'
            os.environ['MAX_TASKS'] = '100'
        
        elif instance_type == 'cron':
            # تنظیمات برای cron job
            os.environ['WORKER_COUNT'] = '1'
            os.environ['THREAD_COUNT'] = '1'
    
    @staticmethod
    def create_render_config_files():
        """ایجاد فایل‌های config مخصوص Render"""
        if not RenderDeployment.detect_render():
            return
        
        # 1. ایجاد فایل runtime.txt (Python version)
        runtime_content = "python-3.9.0"
        with open('runtime.txt', 'w') as f:
            f.write(runtime_content)
        
        # 2. ایجاد فایل render.yaml
        render_yaml = RenderDeployment._generate_render_yaml()
        with open('render.yaml', 'w') as f:
            f.write(render_yaml)
        
        # 3. ایجاد فایل start.sh
        start_script = RenderDeployment._generate_start_script()
        with open('start.sh', 'w') as f:
            f.write(start_script)
        os.chmod('start.sh', 0o755)
        
        # 4. ایجاد فایل health check
        health_check = RenderDeployment._generate_health_check()
        with open('health.py', 'w') as f:
            f.write(health_check)
        
        logger.info("✅ Render config files created")
    
    @staticmethod
    def _generate_render_yaml() -> str:
        """تولید فایل render.yaml"""
        return """
# render.yaml
# Telegram Bot Deployment on Render

services:
  - type: web
    name: telegram-bot
    env: python
    region: frankfurt  # یا singapore برای آسیا
    plan: free  # یا starter, professional
    buildCommand: pip install -r requirements.txt
    startCommand: python main.py --mode bot
    healthCheckPath: /health
    autoDeploy: true
    envVars:
      - key: ENVIRONMENT
        value: production
      - key: BOT_TOKEN
        sync: false
      - key: API_ID
        sync: false
      - key: API_HASH
        sync: false
      - key: ADMIN_ID
        sync: false
      - key: CONFIG_SERVER_URL
        value: https://your-config-server.com/api
      - key: CONFIG_AUTH_TOKEN
        sync: false
      - key: DATABASE_URL
        fromDatabase:
          name: botdb
          property: connectionString
      - key: REDIS_URL
        fromService:
          type: redis
          name: bot-redis
          property: connectionString

  - type: worker
    name: bot-worker
    env: python
    region: frankfurt
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: python main.py --mode userbot
    envVars:
      - key: ENVIRONMENT
        value: production
      - key: API_ID
        sync: false
      - key: API_HASH
        sync: false
      - key: CONFIG_SERVER_URL
        value: https://your-config-server.com/api
      - key: CONFIG_AUTH_TOKEN
        sync: false

  - type: redis
    name: bot-redis
    plan: free
    ipAllowList: []  # فقط سرویس‌های داخلی

  - type: cron
    name: bot-cleanup
    env: python
    region: frankfurt
    plan: free
    schedule: "0 3 * * *"  # هر روز 3 بامداد
    buildCommand: pip install -r requirements.txt
    startCommand: python scripts/cleanup.py
    envVars:
      - key: ENVIRONMENT
        value: production
      - key: DATABASE_URL
        fromDatabase:
          name: botdb
          property: connectionString

databases:
  - name: botdb
    plan: free
    databaseName: telegram_bot
"""

    @staticmethod
    def _generate_start_script() -> str:
        """تولید start script"""
        return """#!/bin/bash
# start.sh برای Render

# فعالسازی virtual environment اگر وجود دارد
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# بررسی وجود فایل requirements
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
fi

# ایجاد پوشه‌های لازم
mkdir -p data logs sessions config

# بارگذاری تنظیمات
python scripts/load_config.py

# شروع برنامه
if [ "$RENDER_SERVICE_TYPE" = "worker" ]; then
    echo "Starting worker..."
    python main.py --mode userbot
elif [ "$RENDER_SERVICE_TYPE" = "cron" ]; then
    echo "Running cron job..."
    python scripts/cleanup.py
else
    echo "Starting web service..."
    python main.py --mode bot
fi
"""

    @staticmethod
    def _generate_health_check() -> str:
        """تولید health check endpoint"""
        return """#!/usr/bin/env python3
# health.py - Health check برای Render

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import psutil
import os

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            # بررسی سلامت سیستم
            health_status = self.check_health()
            
            if health_status['status'] == 'healthy':
                self.send_response(200)
            else:
                self.send_response(503)
            
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            self.wfile.write(json.dumps(health_status).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def check_health(self):
        """بررسی سلامت سیستم"""
        checks = {
            'memory_usage': psutil.virtual_memory().percent < 90,
            'disk_usage': psutil.disk_usage('/').percent < 85,
            'cpu_usage': psutil.cpu_percent(interval=1) < 80,
            'bot_ready': self.check_bot_ready()
        }
        
        all_healthy = all(checks.values())
        
        return {
            'status': 'healthy' if all_healthy else 'unhealthy',
            'timestamp': time.time(),
            'service': os.getenv('RENDER_SERVICE_NAME', 'telegram-bot'),
            'instance': os.getenv('RENDER_INSTANCE_ID', 'unknown'),
            'checks': checks,
            'metrics': {
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'cpu_percent': psutil.cpu_percent(interval=1)
            }
        }
    
    def check_bot_ready(self):
        """بررسی آماده بودن ربات"""
        try:
            # بررسی وجود فایل‌های ضروری
            required_files = ['main.py', 'requirements.txt', 'config/']
            for file in required_files:
                if not os.path.exists(file):
                    return False
            return True
        except:
            return False
    
    def log_message(self, format, *args):
        # غیرفعال کردن لاگ‌های دسترسی
        pass

def run_health_server():
    """اجرای سرور health check"""
    port = int(os.getenv('HEALTH_PORT', '8081'))
    server = HTTPServer(('0.0.0.0', port), HealthHandler)
    
    print(f"Health check server running on port {port}")
    server.serve_forever()

if __name__ == '__main__':
    run_health_server()
"""

class RenderDatabaseManager:
    """مدیریت دیتابیس در Render"""
    
    @staticmethod
    def setup_database():
        """تنظیم دیتابیس برای Render"""
        db_url = os.getenv('DATABASE_URL')
        
        if not db_url:
            logger.warning("No database URL found, using SQLite")
            return None
        
        # تبدیل URL به فرمت SQLAlchemy
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
        # ایجاد connection string
        connection_config = {
            'url': db_url,
            'pool_size': 20,
            'max_overflow': 10,
            'pool_recycle': 3600,
            'pool_pre_ping': True,
            'echo': False
        }
        
        logger.info(f"Database configured: {db_url[:30]}...")
        return connection_config
    
    @staticmethod
    def run_migrations():
        """اجرای migrations در Render"""
        try:
            import alembic.config
            import alembic.command
            
            # اجرای migrations
            alembic_cfg = alembic.config.Config("alembic.ini")
            alembic.command.upgrade(alembic_cfg, "head")
            
            logger.info("✅ Database migrations applied")
            return True
        
        except Exception as e:
            logger.error(f"Migration error: {e}")
            return False

# تابع اصلی برای setup
def setup_for_render():
    """تنظیمات کامل برای Render"""
    if RenderDeployment.detect_render():
        logger.info("🚀 Setting up for Render deployment")
        
        # تنظیم محیط
        RenderDeployment.setup_render_environment()
        
        # ایجاد فایل‌های config
        RenderDeployment.create_render_config_files()
        
        # تنظیم دیتابیس
        db_config = RenderDatabaseManager.setup_database()
        
        # اجرای migrations
        RenderDatabaseManager.run_migrations()
        
        logger.info("✅ Render setup complete")
        return True
    else:
        logger.info("Not running on Render, skipping setup")
        return False

if __name__ == "__main__":
    setup_for_render()
