#!/usr/bin/env python3
# server_optimizer.py - بهینه‌سازی تنظیمات سرور برای سرعت

import subprocess
import sys
import os
import json
from pathlib import Path
import platform
import psutil
import socket
import speedtest
from typing import Dict, List, Optional

class ServerOptimizer:
    """بهینه‌سازی تنظیمات سرور"""
    
    def __init__(self):
        self.system_info = self._get_system_info()
        self.network_info = self._get_network_info()
        
    def _get_system_info(self) -> Dict:
        """دریافت اطلاعات سیستم"""
        info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'ram_total_gb': psutil.virtual_memory().total / (1024**3),
            'ram_available_gb': psutil.virtual_memory().available / (1024**3),
            'disk_total_gb': psutil.disk_usage('/').total / (1024**3),
            'disk_free_gb': psutil.disk_usage('/').free / (1024**3),
            'cpu_count': psutil.cpu_count(),
            'cpu_freq': psutil.cpu_freq().current if psutil.cpu_freq() else None
        }
        return info
    
    def _get_network_info(self) -> Dict:
        """دریافت اطلاعات شبکه"""
        try:
            # تست سرعت اینترنت
            st = speedtest.Speedtest()
            st.get_best_server()
            
            download_speed = st.download() / 1_000_000  # Mbps
            upload_speed = st.upload() / 1_000_000  # Mbps
            ping = st.results.ping
            
        except:
            download_speed = upload_speed = ping = 0
        
        return {
            'download_speed_mbps': download_speed,
            'upload_speed_mbps': upload_speed,
            'ping_ms': ping,
            'hostname': socket.gethostname(),
            'ip_address': socket.gethostbyname(socket.gethostname())
        }
    
    def get_optimization_recommendations(self) -> List[Dict]:
        """دریافت توصیه‌های بهینه‌سازی"""
        recommendations = []
        
        # 1. بررسی RAM
        ram_usage_percent = (self.system_info['ram_total_gb'] - 
                           self.system_info['ram_available_gb']) / self.system_info['ram_total_gb'] * 100
        
        if ram_usage_percent > 80:
            recommendations.append({
                'priority': 'high',
                'category': 'memory',
                'issue': 'مصرف رم بالا',
                'solution': 'افزایش RAM یا بهینه‌سازی برنامه',
                'details': f'مصرف رم: {ram_usage_percent:.1f}%'
            })
        
        # 2. بررسی CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 70:
            recommendations.append({
                'priority': 'high',
                'category': 'cpu',
                'issue': 'مصرف CPU بالا',
                'solution': 'بهینه‌سازی کد یا افزایش core',
                'details': f'مصرف CPU: {cpu_percent:.1f}%'
            })
        
        # 3. بررسی دیسک
        disk_percent = 100 - (self.system_info['disk_free_gb'] / 
                            self.system_info['disk_total_gb'] * 100)
        if disk_percent > 90:
            recommendations.append({
                'priority': 'critical',
                'category': 'disk',
                'issue': 'فضای دیسک کم',
                'solution': 'پاکسازی یا افزایش فضای دیسک',
                'details': f'فضای استفاده شده: {disk_percent:.1f}%'
            })
        
        # 4. بررسی شبکه
        if self.network_info['download_speed_mbps'] < 10:
            recommendations.append({
                'priority': 'medium',
                'category': 'network',
                'issue': 'سرعت دانلود پایین',
                'solution': 'ارتقاء اینترنت یا تغییر سرور',
                'details': f'سرعت دانلود: {self.network_info["download_speed_mbps"]:.1f} Mbps'
            })
        
        if self.network_info['upload_speed_mbps'] < 5:
            recommendations.append({
                'priority': 'medium',
                'category': 'network',
                'issue': 'سرعت آپلود پایین',
                'solution': 'ارتقاء اینترنت یا تغییر سرور',
                'details': f'سرعت آپلود: {self.network_info["upload_speed_mbps"]:.1f} Mbps'
            })
        
        # 5. بررسی تنظیمات سیستم
        if self.system_info['platform'].lower() == 'linux':
            # بررسی تنظیمات شبکه لینوکس
            recommendations.extend(self._check_linux_network_settings())
        
        return recommendations
    
    def _check_linux_network_settings(self) -> List[Dict]:
        """بررسی تنظیمات شبکه لینوکس"""
        recommendations = []
        
        try:
            # بررسی TCP buffer sizes
            with open('/proc/sys/net/ipv4/tcp_rmem', 'r') as f:
                tcp_rmem = f.read().strip()
            
            with open('/proc/sys/net/ipv4/tcp_wmem', 'r') as f:
                tcp_wmem = f.read().strip()
            
            rmem_values = [int(x) for x in tcp_rmem.split()]
            wmem_values = [int(x) for x in tcp_wmem.split()]
            
            if rmem_values[2] < 16777216:  # کمتر از 16MB
                recommendations.append({
                    'priority': 'medium',
                    'category': 'linux_network',
                    'issue': 'TCP read buffer کوچک',
                    'solution': 'افزایش net.ipv4.tcp_rmem',
                    'details': f'مقدار فعلی: {rmem_values[2] / 1024 / 1024:.1f}MB'
                })
            
            if wmem_values[2] < 16777216:  # کمتر از 16MB
                recommendations.append({
                    'priority': 'medium',
                    'category': 'linux_network',
                    'issue': 'TCP write buffer کوچک',
                    'solution': 'افزایش net.ipv4.tcp_wmem',
                    'details': f'مقدار فعلی: {wmem_values[2] / 1024 / 1024:.1f}MB'
                })
            
            # بررسی تعداد connections
            with open('/proc/sys/net/core/somaxconn', 'r') as f:
                somaxconn = int(f.read().strip())
            
            if somaxconn < 4096:
                recommendations.append({
                    'priority': 'low',
                    'category': 'linux_network',
                    'issue': 'حداکثر connections کم',
                    'solution': 'افزایش net.core.somaxconn',
                    'details': f'مقدار فعلی: {somaxconn}'
                })
        
        except Exception as e:
            print(f"Error checking Linux settings: {e}")
        
        return recommendations
    
    def apply_linux_optimizations(self):
        """اعمال بهینه‌سازی‌های لینوکس"""
        if self.system_info['platform'].lower() != 'linux':
            print("این تنظیمات فقط برای لینوکس کاربرد دارد")
            return
        
        optimizations = [
            # افزایش TCP buffer sizes
            ('net.ipv4.tcp_rmem', '4096 87380 16777216'),
            ('net.ipv4.tcp_wmem', '4096 65536 16777216'),
            
            # افزایش maximum connections
            ('net.core.somaxconn', '65536'),
            
            # بهینه‌سازی TCP
            ('net.ipv4.tcp_congestion_control', 'bbr'),
            ('net.ipv4.tcp_notsent_lowat', '16384'),
            ('net.ipv4.tcp_mtu_probing', '1'),
            
            # افزایش file descriptors
            ('fs.file-max', '2097152'),
            ('fs.nr_open', '2097152'),
        ]
        
        applied = []
        
        for key, value in optimizations:
            try:
                cmd = f'sysctl -w {key}={value}'
                subprocess.run(cmd, shell=True, check=True, capture_output=True)
                
                # ذخیره در تنظیمات دائمی
                with open('/etc/sysctl.d/99-optimize.conf', 'a') as f:
                    f.write(f'{key} = {value}\n')
                
                applied.append(key)
                
            except Exception as e:
                print(f"Failed to set {key}: {e}")
        
        # اعمال تنظیمات
        subprocess.run('sysctl -p /etc/sysctl.d/99-optimize.conf', 
                      shell=True, check=False)
        
        print(f"Applied {len(applied)} optimizations")
        return applied
    
    def optimize_python_settings(self):
        """بهینه‌سازی تنظیمات پایتون"""
        optimizations = {
            'PYTHONUNBUFFERED': '1',
            'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONHASHSEED': 'random',
            'PYTHONIOENCODING': 'UTF-8',
            'PYTHONWARNINGS': 'ignore',
        }
        
        for key, value in optimizations.items():
            os.environ[key] = value
        
        # تنظیمات threading
        import threading
        threading.stack_size(2 * 1024 * 1024)  # 2MB stack
        
        return optimizations
    
    def get_optimal_thread_counts(self) -> Dict:
        """محاسبه تعداد threadهای بهینه"""
        cpu_count = self.system_info['cpu_count']
        ram_gb = self.system_info['ram_total_gb']
        
        # فرمول‌های بهینه
        download_threads = min(16, cpu_count * 2)
        upload_threads = min(12, cpu_count * 1.5)
        database_threads = min(8, cpu_count)
        network_threads = min(10, cpu_count * 1.2)
        
        # تنظیم بر اساس RAM
        if ram_gb < 2:
            download_threads = max(2, download_threads // 2)
            upload_threads = max(1, upload_threads // 2)
        elif ram_gb > 16:
            download_threads = min(32, download_threads * 2)
            upload_threads = min(24, upload_threads * 2)
        
        return {
            'download_threads': int(download_threads),
            'upload_threads': int(upload_threads),
            'database_threads': int(database_threads),
            'network_threads': int(network_threads),
            'total_threads': int(download_threads + upload_threads + 
                               database_threads + network_threads)
        }
    
    def generate_nginx_config(self, domain: str = "example.com") -> str:
        """تولید config بهینه‌شده برای nginx"""
        config = f"""
# بهینه‌سازی‌های سرعت
user www-data;
worker_processes auto;
worker_rlimit_nofile 100000;

events {{
    worker_connections 4000;
    use epoll;
    multi_accept on;
}}

http {{
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript 
               application/xml application/xml+rss 
               application/javascript application/json 
               image/svg+xml;
    
    # Buffer sizes
    client_body_buffer_size 10K;
    client_header_buffer_size 1k;
    client_max_body_size 8m;
    large_client_header_buffers 2 1k;
    
    # Timeouts
    client_body_timeout 12;
    client_header_timeout 12;
    send_timeout 10;
    
    # Cache
    open_file_cache max=1000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
    
    # Security
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Server block
    server {{
        listen 80;
        listen [::]:80;
        server_name {domain};
        
        root /var/www/html;
        index index.html index.htm;
        
        location / {{
            try_files $uri $uri/ =404;
        }}
        
        # API endpoint برای ربات
        location /api/ {{
            proxy_pass http://localhost:8000;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # افزایش timeout برای دانلود/آپلود بزرگ
            proxy_connect_timeout 300s;
            proxy_send_timeout 300s;
            proxy_read_timeout 300s;
        }}
        
        # آپلود فایل‌های بزرگ
        location /upload {{
            client_max_body_size 2G;
            proxy_pass http://localhost:8000;
            proxy_request_buffering off;
        }}
    }}
}}
"""
        return config
    
    def save_report(self, filename: str = "optimization_report.json"):
        """ذخیره گزارش بهینه‌سازی"""
        report = {
            'system_info': self.system_info,
            'network_info': self.network_info,
            'recommendations': self.get_optimization_recommendations(),
            'optimal_threads': self.get_optimal_thread_counts(),
            'timestamp': time.time()
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"Report saved to {filename}")
        return report

# تابع اصلی
def main():
    """اجرای بهینه‌ساز"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Server Speed Optimizer')
    parser.add_argument('--analyze', action='store_true', help='Analyze system')
    parser.add_argument('--optimize-linux', action='store_true', help='Apply Linux optimizations')
    parser.add_argument('--generate-nginx', metavar='DOMAIN', help='Generate Nginx config')
    parser.add_argument('--report', action='store_true', help='Generate report')
    
    args = parser.parse_args()
    
    optimizer = ServerOptimizer()
    
    if args.analyze:
        print("=" * 50)
        print("📊 تحلیل سیستم:")
        print("=" * 50)
        
        print(f"\n💻 سیستم:")
        print(f"  پلتفرم: {optimizer.system_info['platform']}")
        print(f"  CPU: {optimizer.system_info['cpu_count']} core")
        print(f"  RAM: {optimizer.system_info['ram_total_gb']:.1f}GB")
        print(f"  دیسک: {optimizer.system_info['disk_total_gb']:.1f}GB")
        
        print(f"\n🌐 شبکه:")
        print(f"  دانلود: {optimizer.network_info['download_speed_mbps']:.1f} Mbps")
        print(f"  آپلود: {optimizer.network_info['upload_speed_mbps']:.1f} Mbps")
        print(f"  پینگ: {optimizer.network_info['ping_ms']:.1f} ms")
        
        print(f"\n🎯 Threadهای بهینه:")
        threads = optimizer.get_optimal_thread_counts()
        for key, value in threads.items():
            print(f"  {key}: {value}")
        
        print(f"\n⚠️ توصیه‌ها:")
        recommendations = optimizer.get_optimization_recommendations()
        for rec in recommendations:
            print(f"  [{rec['priority'].upper()}] {rec['issue']}: {rec['solution']}")
    
    if args.optimize_linux:
        print("\n🔧 اعمال بهینه‌سازی‌های لینوکس...")
        applied = optimizer.apply_linux_optimizations()
        print(f"✅ {len(applied)} تنظیمات اعمال شد")
    
    if args.generate_nginx:
        print(f"\n🌐 تولید config برای {args.generate_nginx}...")
        config = optimizer.generate_nginx_config(args.generate_nginx)
        
        config_file = f"nginx_{args.generate_nginx}.conf"
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(config)
        
        print(f"✅ config در {config_file} ذخیره شد")
    
    if args.report:
        print("\n📄 تولید گزارش...")
        optimizer.save_report()
        print("✅ گزارش ذخیره شد")

if __name__ == "__main__":
    main()
