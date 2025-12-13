#anomaly_detector.py
"""
مانیتورینگ real-time اکانت‌ها
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from threading import Lock
from collections import defaultdict

import psutil

from models.enums import AlertLevel

logger = logging.getLogger(__name__)

class AccountMonitor:
    """مانیتورینگ real-time اکانت‌ها"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        
        self.account_metrics: Dict[str, Dict[str, Any]] = {}
        self.metrics_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.alerts: List[Dict[str, Any]] = []
        
        # آستانه‌های هشدار
        self.alert_thresholds = self.config.get('alert_thresholds', {
            'inactive_hours': 24,
            'flood_wait_count': 3,
            'login_failures': 5,
            'memory_usage_mb': 500,
            'api_errors': 10,
            'high_latency_seconds': 5.0,
            'disconnection_timeout': 300  # 5 دقیقه
        })
        
        self.lock = Lock()
        self.last_check = datetime.now()
        
        # تنظیمات مانیتورینگ
        self.monitoring_interval = self.config.get('monitoring_interval', 60)  # ثانیه
        self.max_history_size = self.config.get('max_history_size', 100)
        self.enable_system_monitoring = self.config.get('enable_system_monitoring', True)
        
        # شروع مانیتورینگ دوره‌ای
        self.monitoring_task = None
    
    async def start_monitoring(self):
        """شروع مانیتورینگ دوره‌ای"""
        if self.monitoring_task is None or self.monitoring_task.done():
            self.monitoring_task = asyncio.create_task(self._periodic_monitoring())
            logger.info("مانیتورینگ دوره‌ای شروع شد")
    
    async def stop_monitoring(self):
        """توقف مانیتورینگ دوره‌ای"""
        if self.monitoring_task and not self.monitoring_task.done():
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
            logger.info("مانیتورینگ دوره‌ای متوقف شد")
    
    async def _periodic_monitoring(self):
        """مانیتورینگ دوره‌ای"""
        while True:
            try:
                await asyncio.sleep(self.monitoring_interval)
                await self._check_all_accounts()
                await self._cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"خطا در مانیتورینگ دوره‌ای: {e}")
    
    async def monitor_account(self, account_id: str, client) -> Dict[str, Any]:
        """مانیتورینگ وضعیت اکانت"""
        
        try:
            metrics = {
                'timestamp': datetime.now(),
                'is_connected': client.is_connected() if hasattr(client, 'is_connected') else False,
                'last_seen': None,
                'unread_count': 0,
                'memory_usage': self._get_memory_usage(),
                'cpu_usage': self._get_cpu_usage(),
                'api_latency': await self._check_api_latency(client),
                'is_online': await self._check_online_status(client),
                'errors': [],
                'warnings': []
            }
            
            # جمع‌آوری اطلاعات اضافی
            try:
                if hasattr(client, 'get_me'):
                    me = await client.get_me()
                    metrics['user_info'] = {
                        'username': me.username,
                        'first_name': me.first_name,
                        'last_name': me.last_name,
                        'phone': me.phone,
                        'is_premium': getattr(me, 'premium', False)
                    }
            except Exception as e:
                metrics['errors'].append(f"خطا در دریافت اطلاعات کاربر: {str(e)}")
            
            with self.lock:
                self.account_metrics[account_id] = metrics
                
                # ذخیره تاریخچه
                self.metrics_history[account_id].append(metrics)
                
                # محدود کردن اندازه تاریخچه
                if len(self.metrics_history[account_id]) > self.max_history_size:
                    self.metrics_history[account_id] = self.metrics_history[account_id][-self.max_history_size:]
                
                # بررسی هشدارها
                await self._check_account_alerts(account_id, metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"خطا در مانیتورینگ اکانت {account_id}: {e}")
            
            error_metrics = {
                'timestamp': datetime.now(),
                'is_connected': False,
                'error': str(e),
                'memory_usage': self._get_memory_usage(),
                'cpu_usage': self._get_cpu_usage()
            }
            
            with self.lock:
                self.account_metrics[account_id] = error_metrics
            
            return error_metrics
    
    async def _check_all_accounts(self):
        """بررسی وضعیت همه اکانت‌ها"""
        with self.lock:
            account_ids = list(self.account_metrics.keys())
        
        for account_id in account_ids:
            try:
                # اینجا باید client مربوطه را پیدا و بررسی کنید
                # برای سادگی، فقط بررسی می‌کنیم که آخرین بررسی قدیمی نباشد
                last_metrics = self.account_metrics.get(account_id)
                if last_metrics:
                    time_since_last = (datetime.now() - last_metrics['timestamp']).total_seconds()
                    
                    if time_since_last > self.alert_thresholds['disconnection_timeout']:
                        alert = {
                            'alert_id': f"inactive_{account_id}_{int(datetime.now().timestamp())}",
                            'account_id': account_id,
                            'alert_type': 'ACCOUNT_INACTIVE',
                            'level': AlertLevel.WARNING.value,
                            'message': f'اکانت برای {int(time_since_last/60)} دقیقه غیرفعال است',
                            'details': {
                                'time_since_last_check': time_since_last,
                                'threshold': self.alert_thresholds['disconnection_timeout']
                            },
                            'created_at': datetime.now()
                        }
                        
                        await self.create_alert(alert)
            except Exception as e:
                logger.error(f"خطا در بررسی اکانت {account_id}: {e}")
    
    async def _check_account_alerts(self, account_id: str, metrics: Dict[str, Any]):
        """بررسی و ایجاد هشدار برای اکانت"""
        
        alerts = []
        
        # 1. بررسی اتصال
        if not metrics.get('is_connected', False):
            alerts.append({
                'alert_type': 'DISCONNECTED',
                'level': AlertLevel.ERROR.value,
                'message': 'اتصال اکانت قطع شده است',
                'details': {
                    'last_check': metrics['timestamp'].isoformat()
                }
            })
        
        # 2. بررسی تأخیر API
        api_latency = metrics.get('api_latency', 0)
        if api_latency > self.alert_thresholds['high_latency_seconds']:
            alerts.append({
                'alert_type': 'HIGH_LATENCY',
                'level': AlertLevel.WARNING.value,
                'message': f'تأخیر API بالا: {api_latency:.2f} ثانیه',
                'details': {
                    'latency': api_latency,
                    'threshold': self.alert_thresholds['high_latency_seconds']
                }
            })
        
        # 3. بررسی مصرف حافظه
        memory_usage = metrics.get('memory_usage', 0)
        if memory_usage > self.alert_thresholds['memory_usage_mb']:
            alerts.append({
                'alert_type': 'HIGH_MEMORY_USAGE',
                'level': AlertLevel.WARNING.value,
                'message': f'مصرف حافظه بالا: {memory_usage:.2f} مگابایت',
                'details': {
                    'memory_usage': memory_usage,
                    'threshold': self.alert_thresholds['memory_usage_mb']
                }
            })
        
        # 4. بررسی خطاها
        if metrics.get('errors'):
            for error in metrics['errors']:
                alerts.append({
                    'alert_type': 'API_ERROR',
                    'level': AlertLevel.ERROR.value,
                    'message': f'خطای API: {error[:100]}',
                    'details': {
                        'error': error
                    }
                })
        
        # 5. بررسی هشدارها
        if metrics.get('warnings'):
            for warning in metrics['warnings']:
                alerts.append({
                    'alert_type': 'WARNING',
                    'level': AlertLevel.WARNING.value,
                    'message': f'هشدار: {warning[:100]}',
                    'details': {
                        'warning': warning
                    }
                })
        
        # ذخیره هشدارها
        if alerts:
            for alert_data in alerts:
                alert = {
                    'alert_id': f"{alert_data['alert_type'].lower()}_{account_id}_{int(datetime.now().timestamp())}",
                    'account_id': account_id,
                    'alert_type': alert_data['alert_type'],
                    'level': alert_data['level'],
                    'message': alert_data['message'],
                    'details': alert_data.get('details', {}),
                    'created_at': datetime.now()
                }
                
                await self.create_alert(alert)
    
    async def _check_api_latency(self, client) -> float:
        """بررسی تأخیر API"""
        
        try:
            if hasattr(client, 'get_me'):
                start_time = time.time()
                await client.get_me()
                end_time = time.time()
                return end_time - start_time
        except Exception as e:
            logger.error(f"خطا در بررسی تأخیر API: {e}")
        
        return -1.0  # نشانگر خطا
    
    async def _check_online_status(self, client) -> bool:
        """بررسی وضعیت آنلاین"""
        
        try:
            if hasattr(client, 'get_me'):
                me = await client.get_me()
                return hasattr(me, 'status') and me.status is not None
        except Exception as e:
            logger.error(f"خطا در بررسی وضعیت آنلاین: {e}")
        
        return False
    
    def _get_memory_usage(self) -> float:
        """مصرف حافظه"""
        
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            return memory_info.rss / 1024 / 1024  # مگابایت
        except Exception as e:
            logger.error(f"خطا در دریافت مصرف حافظه: {e}")
        
        return 0.0
    
    def _get_cpu_usage(self) -> float:
        """مصرف CPU"""
        
        try:
            process = psutil.Process()
            return process.cpu_percent(interval=0.1)
        except Exception as e:
            logger.error(f"خطا در دریافت مصرف CPU: {e}")
        
        return 0.0
    
    async def create_alert(self, alert_data: Dict[str, Any]):
        """ایجاد هشدار"""
        
        with self.lock:
            self.alerts.append(alert_data)
            
            # محدود کردن تعداد هشدارها
            max_alerts = self.config.get('max_alerts', 1000)
            if len(self.alerts) > max_alerts:
                self.alerts = self.alerts[-max_alerts:]
        
        logger.warning(f"هشدار ایجاد شد: {alert_data['alert_type']} - {alert_data['message']}")
        
        # ارسال webhook (اگر تنظیم شده باشد)
        if self.config.get('webhook_url'):
            await self._send_webhook_alert(alert_data)
    
    async def _send_webhook_alert(self, alert_data: Dict[str, Any]):
        """ارسال هشدار به webhook"""
        
        try:
            import aiohttp
            
            webhook_url = self.config.get('webhook_url')
            webhook_secret = self.config.get('webhook_secret')
            
            if webhook_url:
                payload = {
                    'event': 'alert',
                    'timestamp': datetime.now().isoformat(),
                    'data': alert_data
                }
                
                headers = {'Content-Type': 'application/json'}
                if webhook_secret:
                    import hashlib
                    import hmac
                    signature = hmac.new(
                        webhook_secret.encode(),
                        json.dumps(payload).encode(),
                        hashlib.sha256
                    ).hexdigest()
                    headers['X-Webhook-Signature'] = signature
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(webhook_url, json=payload, headers=headers) as response:
                        if response.status != 200:
                            logger.warning(f"ارسال webhook ناموفق: {response.status}")
        except Exception as e:
            logger.error(f"خطا در ارسال webhook: {e}")
    
    async def _cleanup_old_data(self):
        """پاک کردن داده‌های قدیمی"""
        
        with self.lock:
            cutoff = datetime.now() - timedelta(days=7)
            
            # پاک کردن هشدارهای قدیمی
            self.alerts = [
                alert for alert in self.alerts
                if alert['created_at'] > cutoff
            ]
            
            # پاک کردن تاریخچه قدیمی
            for account_id in list(self.metrics_history.keys()):
                self.metrics_history[account_id] = [
                    metrics for metrics in self.metrics_history[account_id]
                    if metrics['timestamp'] > cutoff
                ]
                
                if not self.metrics_history[account_id]:
                    del self.metrics_history[account_id]
    
    def get_account_metrics(self, account_id: str) -> Optional[Dict[str, Any]]:
        """دریافت آخرین metrics اکانت"""
        
        with self.lock:
            return self.account_metrics.get(account_id)
    
    def get_account_history(self, account_id: str, 
                          hours: int = 24) -> List[Dict[str, Any]]:
        """دریافت تاریخچه metrics اکانت"""
        
        with self.lock:
            if account_id not in self.metrics_history:
                return []
            
            cutoff = datetime.now() - timedelta(hours=hours)
            history = [
                metrics for metrics in self.metrics_history[account_id]
                if metrics['timestamp'] > cutoff
            ]
            
            return history
    
    def get_active_alerts(self, account_id: Optional[str] = None,
                         level: Optional[str] = None) -> List[Dict[str, Any]]:
        """دریافت هشدارهای فعال"""
        
        with self.lock:
            alerts = self.alerts
            
            if account_id:
                alerts = [alert for alert in alerts if alert.get('account_id') == account_id]
            
            if level:
                alerts = [alert for alert in alerts if alert.get('level') == level]
            
            return alerts[-100:]  # آخرین 100 هشدار
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """دریافت metrics سیستم"""
        
        try:
            system_metrics = {
                'timestamp': datetime.now(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'network_io': {
                    'bytes_sent': psutil.net_io_counters().bytes_sent,
                    'bytes_recv': psutil.net_io_counters().bytes_recv
                },
                'process_count': len(psutil.pids()),
                'monitored_accounts': len(self.account_metrics),
                'active_alerts': len(self.alerts)
            }
            
            return system_metrics
            
        except Exception as e:
            logger.error(f"خطا در دریافت metrics سیستم: {e}")
            
            return {
                'timestamp': datetime.now(),
                'error': str(e)
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """دریافت آمار مانیتورینگ"""
        
        with self.lock:
            stats = {
                'total_accounts_monitored': len(self.account_metrics),
                'total_alerts': len(self.alerts),
                'active_alerts_by_level': {},
                'account_status_summary': {
                    'connected': 0,
                    'disconnected': 0,
                    'error': 0
                },
                'system_metrics': self.get_system_metrics()
            }
            
            # شمارش هشدارها براساس سطح
            for alert in self.alerts:
                level = alert.get('level', 'unknown')
                stats['active_alerts_by_level'][level] = stats['active_alerts_by_level'].get(level, 0) + 1
            
            # جمع‌آوری وضعیت اکانت‌ها
            for account_id, metrics in self.account_metrics.items():
                if metrics.get('is_connected'):
                    stats['account_status_summary']['connected'] += 1
                elif metrics.get('error'):
                    stats['account_status_summary']['error'] += 1
                else:
                    stats['account_status_summary']['disconnected'] += 1
            
            return stats
    
    async def export_metrics(self, account_id: str, 
                           format: str = 'json') -> Dict[str, Any]:
        """خروجی گرفتن از metrics"""
        
        history = self.get_account_history(account_id, hours=24)
        
        if format == 'json':
            return {
                'account_id': account_id,
                'export_timestamp': datetime.now().isoformat(),
                'metrics_count': len(history),
                'metrics': history,
                'current_metrics': self.get_account_metrics(account_id),
                'active_alerts': self.get_active_alerts(account_id)
            }
        else:
            raise ValueError(f"فرمت پشتیبانی نمی‌شود: {format}")
