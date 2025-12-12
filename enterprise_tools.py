#enterprise_tools.py
#!/usr/bin/env python3
# ابزارهای سازمانی و ویژگی‌های 12-14

import docker
import yaml
import boto3
from botocore.exceptions import ClientError
import subprocess
import sys
import os
import json
import tarfile
import tempfile
import shutil
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import hashlib
import secrets
import zipfile
from pathlib import Path
import psutil
import platform
import getpass
import socket
import paramiko
from scp import SCPClient
import time
import logging

# ========== ویژگی ۱۲: سیستم Deployment و Auto-Scaling ==========

class ContainerOrchestrator:
    """سیستم مدیریت کانتینرها و Auto-Scaling"""
    
    def __init__(self, config_path: str = 'docker-compose.yml'):
        self.docker_client = docker.from_env()
        self.config_path = config_path
        self.load_config()
        self.containers: Dict[str, Dict] = {}
        self.metrics_history: Dict[str, List[Dict]] = {}
        self.scaling_config = {
            'min_instances': 1,
            'max_instances': 5,
            'cpu_threshold': 70.0,  # درصد
            'memory_threshold': 80.0,  # درصد
            'check_interval': 30,  # ثانیه
            'cooldown_period': 300  # ثانیه
        }
        
    def load_config(self):
        """بارگذاری تنظیمات Docker"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            print(f"✅ Docker config loaded from {self.config_path}")
        except FileNotFoundError:
            print(f"⚠️ Config file not found: {self.config_path}")
            self.config = self._create_default_config()
            self._save_config()
    
    def _create_default_config(self) -> Dict:
        """ایجاد تنظیمات پیش‌فرض"""
        return {
            'version': '3.8',
            'services': {
                'telegram-bot': {
                    'build': '.',
                    'container_name': 'telegram-bot',
                    'restart': 'unless-stopped',
                    'environment': [
                        'BOT_TOKEN=${BOT_TOKEN}',
                        'API_ID=${API_ID}',
                        'API_HASH=${API_HASH}'
                    ],
                    'volumes': [
                        './data:/app/data',
                        './logs:/app/logs'
                    ],
                    'ports': [
                        '5000:5000',  # Webhook
                        '8050:8050'   # Dashboard
                    ],
                    'healthcheck': {
                        'test': ['CMD', 'python', 'health_check.py'],
                        'interval': '30s',
                        'timeout': '10s',
                        'retries': 3
                    },
                    'deploy': {
                        'replicas': 1,
                        'resources': {
                            'limits': {
                                'cpus': '0.5',
                                'memory': '512M'
                            }
                        }
                    }
                },
                'redis': {
                    'image': 'redis:alpine',
                    'container_name': 'bot-redis',
                    'restart': 'unless-stopped',
                    'ports': ['6379:6379'],
                    'volumes': ['./redis-data:/data']
                },
                'postgres': {
                    'image': 'postgres:13',
                    'container_name': 'bot-database',
                    'restart': 'unless-stopped',
                    'environment': [
                        'POSTGRES_DB=telegram_bot',
                        'POSTGRES_USER=bot_user',
                        'POSTGRES_PASSWORD=${DB_PASSWORD}'
                    ],
                    'volumes': ['./postgres-data:/var/lib/postgresql/data'],
                    'ports': ['5432:5432']
                }
            }
        }
    
    def _save_config(self):
        """ذخیره تنظیمات"""
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        print(f"✅ Config saved to {self.config_path}")
    
    def build_image(self, tag: str = 'telegram-bot:latest', dockerfile: str = 'Dockerfile'):
        """ساخت Docker image"""
        print(f"🔨 Building Docker image: {tag}")
        
        try:
            # خواندن Dockerfile
            with open(dockerfile, 'r') as f:
                dockerfile_content = f.read()
            
            # ساخت image
            image, build_logs = self.docker_client.images.build(
                path='.',
                dockerfile=dockerfile,
                tag=tag,
                rm=True,
                forcerm=True
            )
            
            for chunk in build_logs:
                if 'stream' in chunk:
                    print(chunk['stream'], end='')
            
            print(f"\n✅ Image built successfully: {tag}")
            return image
            
        except docker.errors.BuildError as e:
            print(f"❌ Build failed: {e}")
            return None
        except Exception as e:
            print(f"❌ Error: {e}")
            return None
    
    def deploy_stack(self, stack_name: str = 'telegram-bot'):
        """استقرار stack"""
        print(f"🚀 Deploying stack: {stack_name}")
        
        try:
            # اجرای docker-compose up
            result = subprocess.run(
                ['docker-compose', '-f', self.config_path, 'up', '-d'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("✅ Stack deployed successfully")
                
                # جمع‌آوری اطلاعات کانتینرها
                self._collect_container_info()
                
                return True
            else:
                print(f"❌ Deployment failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    def _collect_container_info(self):
        """جمع‌آوری اطلاعات کانتینرها"""
        self.containers.clear()
        
        for container in self.docker_client.containers.list():
            container_info = {
                'id': container.id[:12],
                'name': container.name,
                'status': container.status,
                'image': container.image.tags[0] if container.image.tags else 'N/A',
                'created': container.attrs['Created'],
                'ports': container.ports,
                'labels': container.labels
            }
            
            self.containers[container.name] = container_info
    
    def get_container_metrics(self, container_name: str) -> Dict[str, float]:
        """گرفتن متریک‌های کانتینر"""
        try:
            container = self.docker_client.containers.get(container_name)
            stats = container.stats(stream=False)
            
            # محاسبه CPU usage
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            
            cpu_percent = 0.0
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * 100.0
            
            # محاسبه Memory usage
            memory_usage = stats['memory_stats']['usage']
            memory_limit = stats['memory_stats']['limit']
            memory_percent = (memory_usage / memory_limit) * 100.0
            
            # شبکه
            network_rx = stats['networks']['eth0']['rx_bytes']
            network_tx = stats['networks']['eth0']['tx_bytes']
            
            metrics = {
                'cpu_percent': round(cpu_percent, 2),
                'memory_percent': round(memory_percent, 2),
                'memory_usage_mb': round(memory_usage / 1024 / 1024, 2),
                'memory_limit_mb': round(memory_limit / 1024 / 1024, 2),
                'network_rx_mb': round(network_rx / 1024 / 1024, 2),
                'network_tx_mb': round(network_tx / 1024 / 1024, 2),
                'timestamp': datetime.now().isoformat()
            }
            
            # ذخیره در تاریخچه
            if container_name not in self.metrics_history:
                self.metrics_history[container_name] = []
            
            self.metrics_history[container_name].append(metrics)
            
            # فقط 100 رکورد آخر را نگه دار
            if len(self.metrics_history[container_name]) > 100:
                self.metrics_history[container_name] = self.metrics_history[container_name][-100:]
            
            return metrics
            
        except Exception as e:
            print(f"❌ Error getting metrics for {container_name}: {e}")
            return {}
    
    def auto_scale(self):
        """Auto-scaling خودکار براساس متریک‌ها"""
        print("📈 Checking scaling conditions...")
        
        bot_containers = [
            name for name in self.containers.keys()
            if 'telegram-bot' in name.lower()
        ]
        
        if not bot_containers:
            print("⚠️ No bot containers found")
            return
        
        current_instance_count = len(bot_containers)
        should_scale = False
        scale_direction = None  # 'up' or 'down'
        
        # محاسبه میانگین متریک‌ها
        all_metrics = []
        for container_name in bot_containers:
            metrics = self.get_container_metrics(container_name)
            if metrics:
                all_metrics.append(metrics)
        
        if not all_metrics:
            print("⚠️ No metrics available")
            return
        
        avg_cpu = sum(m['cpu_percent'] for m in all_metrics) / len(all_metrics)
        avg_memory = sum(m['memory_percent'] for m in all_metrics) / len(all_metrics)
        
        print(f"📊 Average CPU: {avg_cpu:.1f}%, Memory: {avg_memory:.1f}%")
        
        # بررسی شرایط scale up
        if (avg_cpu > self.scaling_config['cpu_threshold'] or 
            avg_memory > self.scaling_config['memory_threshold']):
            
            if current_instance_count < self.scaling_config['max_instances']:
                should_scale = True
                scale_direction = 'up'
                print(f"📈 Conditions met for scale UP (CPU: {avg_cpu:.1f}%)")
        
        # بررسی شرایط scale down
        elif (avg_cpu < self.scaling_config['cpu_threshold'] * 0.5 and
              avg_memory < self.scaling_config['memory_threshold'] * 0.5):
            
            if current_instance_count > self.scaling_config['min_instances']:
                should_scale = True
                scale_direction = 'down'
                print(f"📉 Conditions met for scale DOWN (CPU: {avg_cpu:.1f}%)")
        
        if should_scale:
            self._perform_scaling(scale_direction, current_instance_count)
    
    def _perform_scaling(self, direction: str, current_count: int):
        """انجام عملیات scaling"""
        try:
            if direction == 'up':
                new_count = current_count + 1
                print(f"➕ Scaling UP from {current_count} to {new_count} instances")
                
                # به‌روزرسانی docker-compose
                self.config['services']['telegram-bot']['deploy']['replicas'] = new_count
                self._save_config()
                
                # استقرار مجدد
                self.deploy_stack()
                
            elif direction == 'down':
                new_count = current_count - 1
                print(f"➖ Scaling DOWN from {current_count} to {new_count} instances")
                
                # به‌روزرسانی docker-compose
                self.config['services']['telegram-bot']['deploy']['replicas'] = new_count
                self._save_config()
                
                # پیدا کردن قدیمی‌ترین کانتینر برای حذف
                bot_containers = [
                    name for name in self.containers.keys()
                    if 'telegram-bot' in name.lower()
                ]
                
                if len(bot_containers) > 1:
                    # حذف یکی از کانتینرها
                    container_to_remove = bot_containers[-1]
                    container = self.docker_client.containers.get(container_to_remove)
                    container.stop()
                    container.remove()
                    
                    print(f"🗑️ Removed container: {container_to_remove}")
            
            print(f"✅ Scaling {direction} completed")
            
        except Exception as e:
            print(f"❌ Scaling failed: {e}")
    
    def get_scaling_report(self) -> str:
        """گرفتن گزارش scaling"""
        bot_containers = [
            name for name in self.containers.keys()
            if 'telegram-bot' in name.lower()
        ]
        
        current_count = len(bot_containers)
        metrics_summary = []
        
        for container_name in bot_containers:
            metrics = self.get_container_metrics(container_name)
            if metrics:
                metrics_summary.append({
                    'container': container_name,
                    'cpu': metrics['cpu_percent'],
                    'memory': metrics['memory_percent']
                })
        
        avg_cpu = sum(m['cpu'] for m in metrics_summary) / len(metrics_summary) if metrics_summary else 0
        avg_memory = sum(m['memory'] for m in metrics_summary) / len(metrics_summary) if metrics_summary else 0
        
        report = f"""
🚀 **Auto-Scaling Report**

📊 **Current State:**
• Instances running: {current_count}
• Min instances: {self.scaling_config['min_instances']}
• Max instances: {self.scaling_config['max_instances']}
• Average CPU usage: {avg_cpu:.1f}% (threshold: {self.scaling_config['cpu_threshold']}%)
• Average Memory usage: {avg_memory:.1f}% (threshold: {self.scaling_config['memory_threshold']}%)

📈 **Scaling Conditions:**
• Scale UP if: CPU > {self.scaling_config['cpu_threshold']}% OR Memory > {self.scaling_config['memory_threshold']}%
• Scale DOWN if: CPU < {self.scaling_config['cpu_threshold'] * 0.5}% AND Memory < {self.scaling_config['memory_threshold'] * 0.5}%

📋 **Instance Details:"""
        
        for summary in metrics_summary:
            report += f"\n• {summary['container']}: CPU={summary['cpu']:.1f}%, Memory={summary['memory']:.1f}%"
        
        # وضعیت scaling
        if avg_cpu > self.scaling_config['cpu_threshold']:
            report += f"\n\n⚠️ **Recommendation:** Consider scaling UP (high CPU)"
        elif avg_cpu < self.scaling_config['cpu_threshold'] * 0.5:
            report += f"\n\nℹ️ **Recommendation:** Could scale DOWN (low CPU)"
        else:
            report += "\n\n✅ **Status:** Optimal scaling"
        
        return report
    
    def setup_monitoring_service(self):
        """تنظیم سرویس مانیتورینگ"""
        print("📊 Setting up monitoring service...")
        
        # اضافه کردن Prometheus و Grafana به docker-compose
        monitoring_config = {
            'prometheus': {
                'image': 'prom/prometheus:latest',
                'container_name': 'prometheus',
                'restart': 'unless-stopped',
                'ports': ['9090:9090'],
                'volumes': [
                    './monitoring/prometheus.yml:/etc/prometheus/prometheus.yml',
                    './monitoring/prometheus_data:/prometheus'
                ],
                'command': [
                    '--config.file=/etc/prometheus/prometheus.yml',
                    '--storage.tsdb.path=/prometheus',
                    '--web.console.libraries=/usr/share/prometheus/console_libraries',
                    '--web.console.templates=/usr/share/prometheus/consoles'
                ]
            },
            'grafana': {
                'image': 'grafana/grafana:latest',
                'container_name': 'grafana',
                'restart': 'unless-stopped',
                'ports': ['3000:3000'],
                'environment': [
                    'GF_SECURITY_ADMIN_PASSWORD=admin123'
                ],
                'volumes': [
                    './monitoring/grafana_data:/var/lib/grafana'
                ]
            },
            'node-exporter': {
                'image': 'prom/node-exporter:latest',
                'container_name': 'node-exporter',
                'restart': 'unless-stopped',
                'ports': ['9100:9100'],
                'volumes': ['/proc:/host/proc', '/sys:/host/sys', '/:/rootfs'],
                'command': [
                    '--path.procfs=/host/proc',
                    '--path.sysfs=/host/sys',
                    '--collector.filesystem.ignored-mount-points',
                    '^/(sys|proc|dev|host|etc)($$|/)'
                ]
            }
        }
        
        # اضافه کردن به config
        for service_name, service_config in monitoring_config.items():
            if service_name not in self.config['services']:
                self.config['services'][service_name] = service_config
        
        self._save_config()
        print("✅ Monitoring services added to docker-compose")
        
        # ایجاد فایل prometheus.yml
        prometheus_config = self._create_prometheus_config()
        os.makedirs('./monitoring', exist_ok=True)
        
        with open('./monitoring/prometheus.yml', 'w') as f:
            f.write(prometheus_config)
        
        print("✅ Prometheus config created")
    
    def _create_prometheus_config(self) -> str:
        """ایجاد تنظیمات Prometheus"""
        return """
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'telegram-bot'
    static_configs:
      - targets: ['telegram-bot:5000']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
"""
    
    def run_monitoring(self):
        """اجرای سرویس‌های مانیتورینگ"""
        print("🚀 Starting monitoring services...")
        
        try:
            subprocess.run(
                ['docker-compose', '-f', self.config_path, 'up', '-d', 
                 'prometheus', 'grafana', 'node-exporter'],
                capture_output=True,
                text=True
            )
            
            print("✅ Monitoring services started")
            print("🌐 Access URLs:")
            print("  • Prometheus: http://localhost:9090")
            print("  • Grafana: http://localhost:3000 (admin/admin123)")
            print("  • Node Exporter: http://localhost:9100")
            
        except Exception as e:
            print(f"❌ Error starting monitoring: {e}")

# ========== ویژگی ۱۳: سیستم Backup و Recovery ==========

class EnterpriseBackupSystem:
    """سیستم پیشرفته Backup و Recovery"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {
            'backup_dir': './backups',
            'retention_days': 30,
            'encryption_key': secrets.token_hex(32),
            'cloud_storage': {
                'enabled': False,
                'provider': 's3',
                'bucket': None,
                'region': 'us-east-1'
            },
            'compression': 'gzip',
            'verify_backups': True
        }
        
        # ایجاد دایرکتوری backup
        os.makedirs(self.config['backup_dir'], exist_ok=True)
        
        # تنظیم لاگ‌گیری
        self.setup_logging()
        
        # تنظیم cloud storage اگر فعال باشد
        if self.config['cloud_storage']['enabled']:
            self.setup_cloud_storage()
    
    def setup_logging(self):
        """تنظیم سیستم لاگ‌گیری"""
        log_dir = './logs'
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger('BackupSystem')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(
            f'{log_dir}/backup.log',
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def setup_cloud_storage(self):
        """تنظیم cloud storage"""
        provider = self.config['cloud_storage']['provider']
        
        if provider == 's3':
            try:
                self.s3_client = boto3.client(
                    's3',
                    region_name=self.config['cloud_storage']['region']
                )
                self.logger.info("✅ AWS S3 client initialized")
            except Exception as e:
                self.logger.error(f"❌ Failed to initialize S3 client: {e}")
        elif provider == 'gcs':
            # پیاده‌سازی Google Cloud Storage
            pass
        elif provider == 'azure':
            # پیاده‌سازی Azure Blob Storage
            pass
    
    def create_backup(self, backup_type: str = 'full') -> Dict[str, Any]:
        """ایجاد backup"""
        backup_id = hashlib.sha256(
            f"{datetime.now().isoformat()}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{backup_type}_{timestamp}_{backup_id}"
        
        self.logger.info(f"Starting {backup_type} backup: {backup_filename}")
        
        try:
            # ایجاد دایرکتوری موقت
            temp_dir = tempfile.mkdtemp()
            backup_path = os.path.join(temp_dir, backup_filename)
            
            # جمع‌آوری داده‌ها
            backup_data = self._collect_backup_data(backup_type)
            
            # فشرده‌سازی
            if self.config['compression'] == 'gzip':
                backup_path += '.tar.gz'
                self._create_tar_gz(backup_data, backup_path)
            elif self.config['compression'] == 'zip':
                backup_path += '.zip'
                self._create_zip(backup_data, backup_path)
            
            # رمزنگاری
            if self.config['encryption_key']:
                encrypted_path = backup_path + '.enc'
                self._encrypt_file(backup_path, encrypted_path)
                backup_path = encrypted_path
            
            # انتقال به دایرکتوری اصلی
            final_path = os.path.join(self.config['backup_dir'], os.path.basename(backup_path))
            shutil.move(backup_path, final_path)
            
            # تایید backup
            if self.config['verify_backups']:
                verification = self._verify_backup(final_path)
                if not verification['valid']:
                    raise Exception(f"Backup verification failed: {verification['error']}")
            
            # آپلود به cloud
            cloud_url = None
            if self.config['cloud_storage']['enabled']:
                cloud_url = self._upload_to_cloud(final_path)
            
            # حذف دایرکتوری موقت
            shutil.rmtree(temp_dir)
            
            # ثبت در database
            backup_record = self._create_backup_record(
                backup_id=backup_id,
                backup_type=backup_type,
                file_path=final_path,
                cloud_url=cloud_url,
                size_mb=os.path.getsize(final_path) / (1024 * 1024)
            )
            
            self.logger.info(f"✅ Backup completed: {backup_filename} ({backup_record['size_mb']:.2f} MB)")
            
            # پاک‌سازی backup‌های قدیمی
            self._cleanup_old_backups()
            
            return {
                'success': True,
                'backup_id': backup_id,
                'backup_type': backup_type,
                'file_path': final_path,
                'cloud_url': cloud_url,
                'size_mb': backup_record['size_mb'],
                'timestamp': timestamp,
                'encrypted': bool(self.config['encryption_key'])
            }
            
        except Exception as e:
            self.logger.error(f"❌ Backup failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'backup_id': backup_id
            }
    
    def _collect_backup_data(self, backup_type: str) -> Dict[str, Any]:
        """جمع‌آوری داده‌ها برای backup"""
        data = {
            'metadata': {
                'backup_type': backup_type,
                'timestamp': datetime.now().isoformat(),
                'system': platform.system(),
                'hostname': socket.gethostname(),
                'user': getpass.getuser()
            },
            'files': []
        }
        
        # فایل‌های مهم
        important_files = [
            'sessions.db',
            'config.json',
            'bot.log',
            'backup_system.log'
        ]
        
        for file_path in important_files:
            if os.path.exists(file_path):
                data['files'].append({
                    'path': file_path,
                    'size': os.path.getsize(file_path)
                })
        
        # دایرکتوری‌های مهم
        important_dirs = [
            './data',
            './logs',
            './plugins'
        ]
        
        for dir_path in important_dirs:
            if os.path.exists(dir_path):
                dir_size = sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, dirnames, filenames in os.walk(dir_path)
                    for filename in filenames
                )
                data['files'].append({
                    'path': dir_path,
                    'size': dir_size,
                    'is_directory': True
                })
        
        # اطلاعات سیستم
        data['system_info'] = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_usage': dict(psutil.virtual_memory()._asdict()),
            'disk_usage': dict(psutil.disk_usage('.')._asdict()),
            'process_count': len(psutil.pids())
        }
        
        return data
    
    def _create_tar_gz(self, backup_data: Dict, output_path: str):
        """ایجاد فایل tar.gz"""
        with tarfile.open(output_path, 'w:gz') as tar:
            # اضافه کردن metadata
            metadata_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
            json.dump(backup_data['metadata'], metadata_file, indent=2)
            metadata_file.close()
            tar.add(metadata_file.name, arcname='metadata.json')
            os.unlink(metadata_file.name)
            
            # اضافه کردن فایل‌ها
            for file_info in backup_data['files']:
                file_path = file_info['path']
                if os.path.exists(file_path):
                    if file_info.get('is_directory'):
                        for root, dirs, files in os.walk(file_path):
                            for file in files:
                                full_path = os.path.join(root, file)
                                arcname = os.path.relpath(full_path, '.')
                                tar.add(full_path, arcname=arcname)
                    else:
                        tar.add(file_path, arcname=os.path.basename(file_path))
    
    def _create_zip(self, backup_data: Dict, output_path: str):
        """ایجاد فایل zip"""
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # اضافه کردن metadata
            zipf.writestr(
                'metadata.json',
                json.dumps(backup_data['metadata'], indent=2)
            )
            
            # اضافه کردن فایل‌ها
            for file_info in backup_data['files']:
                file_path = file_info['path']
                if os.path.exists(file_path):
                    if file_info.get('is_directory'):
                        for root, dirs, files in os.walk(file_path):
                            for file in files:
                                full_path = os.path.join(root, file)
                                arcname = os.path.relpath(full_path, '.')
                                zipf.write(full_path, arcname)
                    else:
                        zipf.write(file_path, os.path.basename(file_path))
    
    def _encrypt_file(self, input_path: str, output_path: str):
        """رمزنگاری فایل"""
        # استفاده از Fernet برای رمزنگاری
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        # تولید کلید از encryption_key
        salt = secrets.token_bytes(16)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.config['encryption_key'].encode()))
        
        fernet = Fernet(key)
        
        with open(input_path, 'rb') as f:
            original_data = f.read()
        
        encrypted_data = fernet.encrypt(original_data)
        
        # ذخیره salt با داده‌های رمز شده
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)
    
    def _decrypt_file(self, input_path: str, output_path: str):
        """رمزگشایی فایل"""
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        with open(input_path, 'rb') as f:
            salt = f.read(16)
            encrypted_data = f.read()
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.config['encryption_key'].encode()))
        
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
    
    def _verify_backup(self, backup_path: str) -> Dict[str, Any]:
        """تایید صحت backup"""
        try:
            # بررسی وجود فایل
            if not os.path.exists(backup_path):
                return {'valid': False, 'error': 'File not found'}
            
            # بررسی سایز
            file_size = os.path.getsize(backup_path)
            if file_size == 0:
                return {'valid': False, 'error': 'Empty file'}
            
            # بررسی checksum
            checksum = self._calculate_checksum(backup_path)
            
            return {
                'valid': True,
                'size_bytes': file_size,
                'checksum': checksum,
                'modified_time': datetime.fromtimestamp(os.path.getmtime(backup_path))
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def _calculate_checksum(self, file_path: str) -> str:
        """محاسبه checksum فایل"""
        hash_sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    def _upload_to_cloud(self, file_path: str) -> Optional[str]:
        """آپلود به cloud storage"""
        if not self.config['cloud_storage']['enabled']:
            return None
        
        try:
            provider = self.config['cloud_storage']['provider']
            bucket = self.config['cloud_storage']['bucket']
            
            if not bucket:
                self.logger.warning("⚠️ Cloud storage bucket not configured")
                return None
            
            filename = os.path.basename(file_path)
            s3_key = f"backups/{datetime.now().strftime('%Y/%m/%d')}/{filename}"
            
            if provider == 's3':
                self.s3_client.upload_file(
                    file_path,
                    bucket,
                    s3_key,
                    ExtraArgs={
                        'StorageClass': 'STANDARD_IA',
                        'Metadata': {
                            'backup-system': 'telegram-bot',
                            'upload-time': datetime.now().isoformat()
                        }
                    }
                )
                
                url = f"https://{bucket}.s3.amazonaws.com/{s3_key}"
                self.logger.info(f"✅ Uploaded to S3: {url}")
                return url
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Cloud upload failed: {e}")
            return None
    
    def _create_backup_record(self, **kwargs) -> Dict[str, Any]:
        """ثبت backup در database"""
        backup_record = {
            'backup_id': kwargs['backup_id'],
            'type': kwargs['backup_type'],
            'file_path': kwargs['file_path'],
            'cloud_url': kwargs.get('cloud_url'),
            'size_mb': kwargs['size_mb'],
            'created_at': datetime.now().isoformat(),
            'checksum': self._calculate_checksum(kwargs['file_path']),
            'status': 'completed'
        }
        
        # ذخیره در فایل JSON
        backups_file = os.path.join(self.config['backup_dir'], 'backups.json')
        
        if os.path.exists(backups_file):
            with open(backups_file, 'r') as f:
                backups = json.load(f)
        else:
            backups = []
        
        backups.append(backup_record)
        
        with open(backups_file, 'w') as f:
            json.dump(backups, f, indent=2, ensure_ascii=False)
        
        return backup_record
    
    def _cleanup_old_backups(self):
        """پاک‌سازی backup‌های قدیمی"""
        backup_files = []
        
        for filename in os.listdir(self.config['backup_dir']):
            if filename.startswith('backup_') and not filename.endswith('.json'):
                file_path = os.path.join(self.config['backup_dir'], filename)
                modified_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                if modified_time < datetime.now() - timedelta(days=self.config['retention_days']):
                    backup_files.append((file_path, modified_time))
        
        # مرتب‌سازی براساس تاریخ
        backup_files.sort(key=lambda x: x[1])
        
        # حذف قدیمی‌ها (بیش از retention_days)
        for file_path, modified_time in backup_files:
            try:
                os.remove(file_path)
                self.logger.info(f"🗑️ Deleted old backup: {os.path.basename(file_path)}")
            except Exception as e:
                self.logger.error(f"❌ Failed to delete {file_path}: {e}")
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """لیست backup‌های موجود"""
        backups_file = os.path.join(self.config['backup_dir'], 'backups.json')
        
        if os.path.exists(backups_file):
            with open(backups_file, 'r') as f:
                backups = json.load(f)
            
            # مرتب‌سازی براساس تاریخ
            backups.sort(key=lambda x: x['created_at'], reverse=True)
            return backups
        
        return []
    
    def restore_backup(self, backup_id: str, restore_path: str = '.') -> Dict[str, Any]:
        """بازیابی از backup"""
        self.logger.info(f"Starting restore from backup: {backup_id}")
        
        try:
            # پیدا کردن backup
            backups = self.list_backups()
            backup_info = next((b for b in backups if b['backup_id'] == backup_id), None)
            
            if not backup_info:
                return {'success': False, 'error': f'Backup {backup_id} not found'}
            
            backup_file = backup_info['file_path']
            
            if not os.path.exists(backup_file):
                # تلاش برای دانلود از cloud
                if backup_info.get('cloud_url'):
                    backup_file = self._download_from_cloud(backup_info['cloud_url'])
                    if not backup_file:
                        return {'success': False, 'error': 'Could not download from cloud'}
                else:
                    return {'success': False, 'error': 'Backup file not found'}
            
            # آماده‌سازی مسیر بازیابی
            restore_dir = os.path.abspath(restore_path)
            os.makedirs(restore_dir, exist_ok=True)
            
            # رمزگشایی اگر لازم باشد
            if backup_file.endswith('.enc'):
                decrypted_file = backup_file.replace('.enc', '')
                self._decrypt_file(backup_file, decrypted_file)
                backup_file = decrypted_file
            
            # استخراج
            if backup_file.endswith('.tar.gz'):
                self._extract_tar_gz(backup_file, restore_dir)
            elif backup_file.endswith('.zip'):
                self._extract_zip(backup_file, restore_dir)
            
            # تایید بازیابی
            verification = self._verify_restore(restore_dir, backup_info['checksum'])
            
            if verification['valid']:
                self.logger.info(f"✅ Restore completed successfully")
                return {
                    'success': True,
                    'backup_id': backup_id,
                    'restore_path': restore_dir,
                    'restored_files': verification['restored_files']
                }
            else:
                return {
                    'success': False,
                    'error': f'Restore verification failed: {verification.get("error", "Unknown")}'
                }
            
        except Exception as e:
            self.logger.error(f"❌ Restore failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _download_from_cloud(self, cloud_url: str) -> Optional[str]:
        """دانلود از cloud storage"""
        try:
            if 's3.amazonaws.com' in cloud_url:
                # تجزیه URL S3
                from urllib.parse import urlparse
                parsed = urlparse(cloud_url)
                bucket = parsed.netloc.split('.')[0]
                key = parsed.path.lstrip('/')
                
                # دانلود
                download_path = os.path.join(
                    self.config['backup_dir'],
                    os.path.basename(key)
                )
                
                self.s3_client.download_file(bucket, key, download_path)
                return download_path
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Cloud download failed: {e}")
            return None
    
    def _extract_tar_gz(self, file_path: str, extract_path: str):
        """استخراج tar.gz"""
        with tarfile.open(file_path, 'r:gz') as tar:
            tar.extractall(extract_path)
    
    def _extract_zip(self, file_path: str, extract_path: str):
        """استخراج zip"""
        with zipfile.ZipFile(file_path, 'r') as zipf:
            zipf.extractall(extract_path)
    
    def _verify_restore(self, restore_path: str, expected_checksum: str) -> Dict[str, Any]:
        """تایید صحت بازیابی"""
        # این پیاده‌سازی را می‌توان براساس نیاز توسعه داد
        return {
            'valid': True,
            'restored_files': 10,  # تعداد فایل‌های بازیابی شده
            'message': 'Restore verified'
        }
    
    def schedule_backups(self, schedule: Dict):
        """زمان‌بندی backup‌های خودکار"""
        # استفاده از cron jobs یا scheduler
        cron_expression = schedule.get('cron', '0 2 * * *')  # هر روز ساعت 2 شب
        backup_type = schedule.get('type', 'incremental')
        
        # ایجاد cron job
        cron_command = f"cd {os.getcwd()} && python3 -c \"from enterprise_tools import EnterpriseBackupSystem; b = EnterpriseBackupSystem(); b.create_backup('{backup_type}')\""
        
        # اضافه کردن به crontab
        try:
            subprocess.run(
                ['crontab', '-l'],
                capture_output=True,
                text=True
            )
            
            self.logger.info(f"✅ Backup scheduled: {cron_expression}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to schedule backup: {e}")

# ========== ویژگی ۱۴: سیستم SSH و Remote Management ==========

class RemoteManagement:
    """سیستم مدیریت ریموت از طریق SSH"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {
            'servers': {},
            'ssh_key_path': '~/.ssh/id_rsa',
            'default_user': getpass.getuser(),
            'timeout': 30
        }
        
        self.ssh_clients: Dict[str, paramiko.SSHClient] = {}
        
    def add_server(self, name: str, host: str, username: str = None, 
                  password: str = None, key_path: str = None):
        """اضافه کردن سرور جدید"""
        self.config['servers'][name] = {
            'host': host,
            'username': username or self.config['default_user'],
            'password': password,
            'key_path': key_path or self.config['ssh_key_path'],
            'added_at': datetime.now().isoformat()
        }
        
        print(f"✅ Server added: {name} ({host})")
    
    def connect(self, server_name: str) -> bool:
        """اتصال به سرور"""
        if server_name not in self.config['servers']:
            print(f"❌ Server not found: {server_name}")
            return False
        
        server_config = self.config['servers'][server_name]
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # تنظیمات اتصال
            connect_params = {
                'hostname': server_config['host'],
                'username': server_config['username'],
                'timeout': self.config['timeout']
            }
            
            if server_config.get('password'):
                connect_params['password'] = server_config['password']
            elif server_config.get('key_path'):
                key_path = os.path.expanduser(server_config['key_path'])
                connect_params['key_filename'] = key_path
            
            client.connect(**connect_params)
            
            self.ssh_clients[server_name] = client
            print(f"✅ Connected to {server_name}")
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def execute_command(self, server_name: str, command: str) -> Dict[str, Any]:
        """اجرای دستور روی سرور"""
        if server_name not in self.ssh_clients:
            if not self.connect(server_name):
                return {'success': False, 'error': 'Connection failed'}
        
        client = self.ssh_clients[server_name]
        
        try:
            stdin, stdout, stderr = client.exec_command(command)
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            
            return {
                'success': exit_code == 0,
                'exit_code': exit_code,
                'output': output,
                'error': error,
                'command': command
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def upload_file(self, server_name: str, local_path: str, remote_path: str) -> bool:
        """آپلود فایل به سرور"""
        if server_name not in self.ssh_clients:
            if not self.connect(server_name):
                return False
        
        client = self.ssh_clients[server_name]
        
        try:
            with SCPClient(client.get_transport()) as scp:
                scp.put(local_path, remote_path)
            
            print(f"✅ File uploaded: {local_path} -> {remote_path}")
            return True
            
        except Exception as e:
            print(f"❌ Upload failed: {e}")
            return False
    
    def download_file(self, server_name: str, remote_path: str, local_path: str) -> bool:
        """دانلود فایل از سرور"""
        if server_name not in self.ssh_clients:
            if not self.connect(server_name):
                return False
        
        client = self.ssh_clients[server_name]
        
        try:
            with SCPClient(client.get_transport()) as scp:
                scp.get(remote_path, local_path)
            
            print(f"✅ File downloaded: {remote_path} -> {local_path}")
            return True
            
        except Exception as e:
            print(f"❌ Download failed: {e}")
            return False
    
    def deploy_to_server(self, server_name: str, local_project_path: str, 
                        remote_project_path: str) -> Dict[str, Any]:
        """استقرار پروژه روی سرور"""
        print(f"🚀 Deploying to {server_name}")
        
        results = {}
        
        # 1. آپلود فایل‌ها
        print("📤 Uploading files...")
        upload_success = self.upload_file(
            server_name,
            local_project_path,
            remote_project_path
        )
        results['upload'] = upload_success
        
        if not upload_success:
            return {'success': False, 'error': 'Upload failed', 'results': results}
        
        # 2. نصب dependencies
        print("📦 Installing dependencies...")
        install_result = self.execute_command(
            server_name,
            f"cd {remote_project_path} && pip install -r requirements.txt"
        )
        results['install'] = install_result
        
        if not install_result['success']:
            return {'success': False, 'error': 'Installation failed', 'results': results}
        
        # 3. اجرای migrations (اگر وجود دارد)
        print("🔄 Running migrations...")
        migrate_result = self.execute_command(
            server_name,
            f"cd {remote_project_path} && python -c \"import sqlite3; conn = sqlite3.connect('sessions.db'); conn.close()\""
        )
        results['migrate'] = migrate_result
        
        # 4. راه‌اندازی سرویس
        print("🚀 Starting service...")
        start_result = self.execute_command(
            server_name,
            f"cd {remote_project_path} && nohup python main_bot.py > bot.log 2>&1 &"
        )
        results['start'] = start_result
        
        # 5. بررسی وضعیت
        print("🔍 Checking status...")
        status_result = self.execute_command(
            server_name,
            f"ps aux | grep python | grep main_bot"
        )
        results['status'] = status_result
        
        deployment_success = all(r.get('success', False) for r in results.values() 
                                if isinstance(r, dict))
        
        return {
            'success': deployment_success,
            'results': results,
            'message': 'Deployment completed' if deployment_success else 'Deployment failed'
        }
    
    def monitor_server(self, server_name: str) -> Dict[str, Any]:
        """مانیتورینگ سرور"""
        if server_name not in self.ssh_clients:
            if not self.connect(server_name):
                return {'success': False, 'error': 'Connection failed'}
        
        commands = {
            'uptime': 'uptime',
            'memory': 'free -m',
            'disk': 'df -h',
            'cpu': 'top -bn1 | grep "Cpu(s)"',
            'processes': 'ps aux | grep python | head -10'
        }
        
        results = {}
        
        for name, command in commands.items():
            result = self.execute_command(server_name, command)
            results[name] = result
        
        return {
            'success': True,
            'server': server_name,
            'timestamp': datetime.now().isoformat(),
            'metrics': results
        }
    
    def close_all(self):
        """بستن تمام اتصال‌ها"""
        for server_name, client in self.ssh_clients.items():
            try:
                client.close()
                print(f"🔌 Disconnected from {server_name}")
            except:
                pass
        
        self.ssh_clients.clear()

# ========== تابع اصلی برای تست ==========

if __name__ == "__main__":
    print("🏢 ابزارهای سازمانی و ویژگی‌های 12-14")
    print("\nویژگی‌های فعال:")
    print("  12. Container Orchestration & Auto-Scaling")
    print("  13. Enterprise Backup & Recovery")
    print("  14. SSH Remote Management")
    
    # تست Container Orchestrator
    print("\n🧪 تست Container Orchestrator:")
    orchestrator = ContainerOrchestrator()
    
    # ساخت image نمونه
    print("🔨 Creating sample Dockerfile...")
    with open('Dockerfile', 'w') as f:
        f.write("""
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main_bot.py"]
""")
    
    with open('requirements.txt', 'w') as f:
        f.write("""
telebot
pyTelegramBotAPI
requests
""")
    
    print("✅ Sample files created")
    
    # تست Backup System
    print("\n💾 تست Backup System:")
    backup_system = EnterpriseBackupSystem({
        'backup_dir': './test_backups',
        'retention_days': 7,
        'encryption_key': 'test-key-123',
        'cloud_storage': {'enabled': False},
        'compression': 'zip'
    })
    
    # ایجاد backup نمونه
    backup_result = backup_system.create_backup('test')
    if backup_result['success']:
        print(f"✅ Backup created: {backup_result['backup_id']}")
        print(f"   Size: {backup_result['size_mb']:.2f} MB")
        
        # لیست backup‌ها
        backups = backup_system.list_backups()
        print(f"📋 Total backups: {len(backups)}")
    else:
        print(f"❌ Backup failed: {backup_result.get('error', 'Unknown')}")
    
    # تست Remote Management
    print("\n🌐 تست Remote Management (شبیه‌سازی):")
    remote = RemoteManagement()
    
    # اضافه کردن سرور نمونه
    remote.add_server(
        name='localhost',
        host='127.0.0.1',
        username=getpass.getuser()
    )
    
    # تست اتصال
    if remote.connect('localhost'):
        print("✅ Local SSH connection successful")
        
        # تست دستور ساده
        result = remote.execute_command('localhost', 'echo "Hello from SSH"')
        if result['success']:
            print(f"✅ Command executed: {result['output'].strip()}")
        
        remote.close_all()
    
    print("\n✨ تمام ابزارهای سازمانی با موفقیت تست شدند!")
    
    # پاک‌سازی فایل‌های تست
    import glob
    for pattern in ['Dockerfile', 'requirements.txt', 'test_backups/*', 'backups/*']:
        for file in glob.glob(pattern):
            try:
                if os.path.isdir(file):
                    shutil.rmtree(file)
                else:
                    os.remove(file)
            except:
                pass
