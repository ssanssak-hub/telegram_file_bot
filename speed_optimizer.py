#!/usr/bin/env python3
# speed_optimizer.py - سیستم بهینه‌سازی سرعت دانلود/آپلود

import asyncio
import aiohttp
import aiofiles
import concurrent.futures
from typing import List, Dict, Optional, Tuple
import time
import json
import logging
from pathlib import Path
import threading
from queue import Queue
import hashlib
import zlib
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class TransferMode(Enum):
    """حالت‌های انتقال"""
    DOWNLOAD = "download"
    UPLOAD = "upload"
    STREAM = "stream"

@dataclass
class SpeedConfig:
    """تنظیمات سرعت"""
    max_connections: int = 10
    chunk_size: int = 1024 * 1024  # 1MB
    buffer_size: int = 10
    timeout: int = 30
    retry_attempts: int = 3
    compression_level: int = 6
    use_multipart: bool = True
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour
    parallel_uploads: int = 5
    download_threads: int = 8
    upload_threads: int = 6

class SpeedOptimizer:
    """سیستم بهینه‌سازی سرعت"""
    
    def __init__(self, config: Optional[SpeedConfig] = None):
        self.config = config or SpeedConfig()
        
        # کش برای فایل‌های پرکاربرد
        self.cache_dir = Path("cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # پول اتصالات
        self.session_pool = {}
        
        # Thread pool برای عملیات I/O
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.download_threads
        )
        
        # صف‌های اولویت‌بندی
        self.high_priority_queue = Queue()
        self.normal_priority_queue = Queue()
        self.low_priority_queue = Queue()
        
        # آمار سرعت
        self.stats = {
            'total_downloaded': 0,
            'total_uploaded': 0,
            'avg_download_speed': 0,
            'avg_upload_speed': 0,
            'peak_download_speed': 0,
            'peak_upload_speed': 0
        }
        
        # شروع مانیتور سرعت
        self._start_speed_monitor()
        
        logger.info(f"SpeedOptimizer initialized with {self.config.download_threads} threads")
    
    async def download_file(
        self, 
        url: str, 
        destination: Path,
        progress_callback = None,
        priority: str = "normal"
    ) -> Dict:
        """
        دانلود فایل با حداکثر سرعت
        Returns: {
            'success': bool,
            'path': Path,
            'size': int,
            'time': float,
            'speed_mbps': float,
            'checksum': str
        }
        """
        start_time = time.time()
        
        try:
            # بررسی کش
            cache_key = self._get_cache_key(url)
            cached_file = self.cache_dir / cache_key
            
            if self.config.enable_caching and cached_file.exists():
                # بررسی اعتبار کش
                if self._is_cache_valid(cached_file):
                    logger.info(f"Using cached file: {cached_file}")
                    
                    # کپی از کش
                    await self._copy_file(cached_file, destination)
                    
                    file_size = cached_file.stat().st_size
                    download_time = time.time() - start_time
                    speed = file_size / download_time / 1024 / 1024  # MB/s
                    
                    return {
                        'success': True,
                        'path': destination,
                        'size': file_size,
                        'time': download_time,
                        'speed_mbps': speed,
                        'cached': True,
                        'checksum': self._calculate_checksum(cached_file)
                    }
            
            # دریافت اطلاعات فایل
            file_size = await self._get_file_size(url)
            if not file_size:
                return {'success': False, 'error': 'Cannot get file size'}
            
            # انتخاب استراتژی دانلود بر اساس حجم
            if file_size < 10 * 1024 * 1024:  # کمتر از 10MB
                result = await self._download_small_file(url, destination)
            elif file_size < 100 * 1024 * 1024:  # کمتر از 100MB
                result = await self._download_medium_file(url, destination, file_size)
            else:  # بیشتر از 100MB
                result = await self._download_large_file(url, destination, file_size)
            
            # ذخیره در کش
            if result['success'] and self.config.enable_caching:
                await self._cache_file(destination, cache_key)
            
            # محاسبه سرعت
            download_time = time.time() - start_time
            result['time'] = download_time
            result['speed_mbps'] = result['size'] / download_time / 1024 / 1024
            
            # به‌روزرسانی آمار
            self._update_stats('download', result['size'], download_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return {
                'success': False, 
                'error': str(e),
                'time': time.time() - start_time
            }
    
    async def _download_small_file(self, url: str, destination: Path) -> Dict:
        """دانلود فایل کوچک (یک�پارچه)"""
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    return {'success': False, 'error': f'HTTP {response.status}'}
                
                content = await response.read()
                
                async with aiofiles.open(destination, 'wb') as f:
                    await f.write(content)
                
                checksum = hashlib.md5(content).hexdigest()
                
                return {
                    'success': True,
                    'path': destination,
                    'size': len(content),
                    'checksum': checksum
                }
    
    async def _download_medium_file(self, url: str, destination: Path, file_size: int) -> Dict:
        """دانلود فایل متوسط (چانکینگ)"""
        chunk_size = self.config.chunk_size
        num_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # دانلود همزمان چانک‌ها
        tasks = []
        for chunk_idx in range(num_chunks):
            start = chunk_idx * chunk_size
            end = min(start + chunk_size, file_size) - 1
            
            task = self._download_chunk(url, destination, chunk_idx, start, end)
            tasks.append(task)
        
        # اجرای موازی
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # بررسی خطاها
        errors = [r for r in results if isinstance(r, Exception)]
        if errors:
            return {'success': False, 'error': f'Chunk errors: {errors}'}
        
        # ترکیب چانک‌ها
        await self._merge_chunks(destination, num_chunks)
        
        # محاسبه checksum
        checksum = await self._calculate_file_checksum(destination)
        
        return {
            'success': True,
            'path': destination,
            'size': file_size,
            'checksum': checksum
        }
    
    async def _download_large_file(self, url: str, destination: Path, file_size: int) -> Dict:
        """دانلود فایل بزرگ (Multi-connection)"""
        # تعیین تعداد اتصالات بهینه
        optimal_connections = min(self.config.max_connections, max(4, file_size // (10 * 1024 * 1024)))
        
        logger.info(f"Downloading large file ({file_size:,} bytes) with {optimal_connections} connections")
        
        # محاسبه محدوده‌های هر اتصال
        chunk_size = file_size // optimal_connections
        ranges = []
        
        for i in range(optimal_connections):
            start = i * chunk_size
            end = (i + 1) * chunk_size - 1 if i < optimal_connections - 1 else file_size - 1
            ranges.append((i, start, end))
        
        # ایجاد فایل خروجی
        async with aiofiles.open(destination, 'wb') as f:
            await f.truncate(file_size)
        
        # دانلود همزمان همه بخش‌ها
        tasks = []
        for chunk_idx, start, end in ranges:
            task = self._download_range(url, destination, chunk_idx, start, end)
            tasks.append(task)
        
        # اجرا با محدودیت همزمانی
        semaphore = asyncio.Semaphore(self.config.max_connections)
        
        async def limited_task(task):
            async with semaphore:
                return await task
        
        limited_tasks = [limited_task(task) for task in tasks]
        results = await asyncio.gather(*limited_tasks, return_exceptions=True)
        
        # بررسی نتایج
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Range download failed: {result}")
                return {'success': False, 'error': f'Range error: {result}'}
        
        # محاسبه checksum
        checksum = await self._calculate_file_checksum(destination)
        
        return {
            'success': True,
            'path': destination,
            'size': file_size,
            'checksum': checksum,
            'connections': optimal_connections
        }
    
    async def _download_range(self, url: str, destination: Path, 
                            chunk_idx: int, start: int, end: int):
        """دانلود یک محدوده خاص از فایل"""
        headers = {'Range': f'bytes={start}-{end}'}
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                if response.status not in (200, 206):
                    raise Exception(f'HTTP {response.status} for range {start}-{end}')
                
                # خواندن chunk به chunk برای صرفه‌جویی در حافظه
                async with aiofiles.open(destination, 'r+b') as f:
                    await f.seek(start)
                    
                    async for chunk in response.content.iter_chunked(64 * 1024):  # 64KB chunks
                        await f.write(chunk)
        
        logger.debug(f"Downloaded range {start}-{end} for chunk {chunk_idx}")
    
    async def upload_file(
        self, 
        source: Path, 
        upload_url: str,
        progress_callback = None,
        compress: bool = False
    ) -> Dict:
        """
        آپلود فایل با حداکثر سرعت
        Returns: {
            'success': bool,
            'url': str,
            'size': int,
            'time': float,
            'speed_mbps': float
        }
        """
        start_time = time.time()
        
        try:
            # بررسی وجود فایل
            if not source.exists():
                return {'success': False, 'error': 'File not found'}
            
            file_size = source.stat().st_size
            
            # انتخاب استراتژی آپلود
            if file_size < 5 * 1024 * 1024:  # کمتر از 5MB
                result = await self._upload_small_file(source, upload_url, compress)
            else:
                result = await self._upload_large_file(source, upload_url, compress)
            
            # محاسبه سرعت
            upload_time = time.time() - start_time
            result['time'] = upload_time
            result['speed_mbps'] = file_size / upload_time / 1024 / 1024
            
            # به‌روزرسانی آمار
            self._update_stats('upload', file_size, upload_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            return {
                'success': False, 
                'error': str(e),
                'time': time.time() - start_time
            }
    
    async def _upload_small_file(self, source: Path, upload_url: str, compress: bool) -> Dict:
        """آپلود فایل کوچک"""
        async with aiofiles.open(source, 'rb') as f:
            content = await f.read()
        
        # فشرده‌سازی
        if compress:
            content = zlib.compress(content, level=self.config.compression_level)
        
        # آپلود
        async with aiohttp.ClientSession() as session:
            form_data = aiohttp.FormData()
            form_data.add_field('file', 
                              content, 
                              filename=source.name,
                              content_type='application/octet-stream')
            
            async with session.post(upload_url, data=form_data) as response:
                if response.status != 200:
                    return {'success': False, 'error': f'HTTP {response.status}'}
                
                result = await response.json()
                
                return {
                    'success': True,
                    'url': result.get('url', upload_url),
                    'size': len(content)
                }
    
    async def _upload_large_file(self, source: Path, upload_url: str, compress: bool) -> Dict:
        """آپلود فایل بزرگ با Multipart"""
        chunk_size = 5 * 1024 * 1024  # 5MB chunks
        file_size = source.stat().st_size
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        logger.info(f"Uploading large file ({file_size:,} bytes) in {total_chunks} chunks")
        
        # دریافت upload_id از سرور
        upload_id = await self._initiate_multipart_upload(upload_url, source.name, file_size)
        if not upload_id:
            return {'success': False, 'error': 'Cannot initiate multipart upload'}
        
        # آپلود همزمان chunk‌ها
        tasks = []
        async with aiofiles.open(source, 'rb') as f:
            for chunk_idx in range(total_chunks):
                start = chunk_idx * chunk_size
                await f.seek(start)
                chunk_data = await f.read(chunk_size)
                
                # فشرده‌سازی
                if compress:
                    chunk_data = zlib.compress(chunk_data, level=self.config.compression_level)
                
                task = self._upload_chunk(upload_url, upload_id, chunk_idx, chunk_data)
                tasks.append(task)
        
        # اجرای موازی با محدودیت
        semaphore = asyncio.Semaphore(self.config.parallel_uploads)
        
        async def limited_task(task):
            async with semaphore:
                return await task
        
        limited_tasks = [limited_task(task) for task in tasks]
        results = await asyncio.gather(*limited_tasks, return_exceptions=True)
        
        # بررسی خطاها
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Chunk upload failed: {result}")
                await self._abort_multipart_upload(upload_url, upload_id)
                return {'success': False, 'error': f'Chunk error: {result}'}
        
        # تکمیل آپلود
        final_url = await self._complete_multipart_upload(upload_url, upload_id, total_chunks)
        
        if not final_url:
            return {'success': False, 'error': 'Cannot complete multipart upload'}
        
        return {
            'success': True,
            'url': final_url,
            'size': file_size,
            'chunks': total_chunks
        }
    
    async def _upload_chunk(self, upload_url: str, upload_id: str, 
                          chunk_idx: int, chunk_data: bytes) -> Dict:
        """آپلود یک chunk"""
        async with aiohttp.ClientSession() as session:
            form_data = aiohttp.FormData()
            form_data.add_field('upload_id', upload_id)
            form_data.add_field('chunk_index', str(chunk_idx))
            form_data.add_field('chunk_data', 
                              chunk_data,
                              content_type='application/octet-stream')
            
            async with session.post(f"{upload_url}/chunk", data=form_data) as response:
                if response.status != 200:
                    raise Exception(f'HTTP {response.status} for chunk {chunk_idx}')
                
                return await response.json()
    
    async def stream_file(self, source: Path, stream_url: str, 
                         chunk_size: int = 1024 * 1024) -> Dict:
        """استریم فایل"""
        try:
            file_size = source.stat().st_size
            
            async with aiofiles.open(source, 'rb') as file:
                async with aiohttp.ClientSession() as session:
                    for chunk_start in range(0, file_size, chunk_size):
                        await file.seek(chunk_start)
                        chunk = await file.read(chunk_size)
                        
                        # ارسال chunk
                        async with session.post(
                            stream_url,
                            data=chunk,
                            headers={
                                'Content-Range': f'bytes {chunk_start}-{chunk_start+len(chunk)-1}/{file_size}'
                            }
                        ) as response:
                            if response.status != 200:
                                raise Exception(f'Stream error: HTTP {response.status}')
            
            return {'success': True, 'size': file_size}
            
        except Exception as e:
            logger.error(f"Stream failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_cache_key(self, url: str) -> str:
        """تولید کلید کش"""
        return hashlib.md5(url.encode()).hexdigest()
    
    def _is_cache_valid(self, cached_file: Path) -> bool:
        """بررسی اعتبار کش"""
        if not cached_file.exists():
            return False
        
        # بررسی TTL
        cache_age = time.time() - cached_file.stat().st_mtime
        return cache_age < self.config.cache_ttl
    
    async def _cache_file(self, source: Path, cache_key: str):
        """ذخیره فایل در کش"""
        cache_file = self.cache_dir / cache_key
        await self._copy_file(source, cache_file)
    
    async def _copy_file(self, source: Path, destination: Path):
        """کپی فایل"""
        async with aiofiles.open(source, 'rb') as src, \
                 aiofiles.open(destination, 'wb') as dst:
            # کپی chunk به chunk
            while True:
                chunk = await src.read(64 * 1024)  # 64KB
                if not chunk:
                    break
                await dst.write(chunk)
    
    async def _get_file_size(self, url: str) -> Optional[int]:
        """دریافت سایز فایل از URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url) as response:
                    if response.status == 200:
                        size = response.headers.get('Content-Length')
                        return int(size) if size else None
        except:
            pass
        return None
    
    async def _calculate_file_checksum(self, file_path: Path) -> str:
        """محاسبه checksum فایل"""
        md5 = hashlib.md5()
        
        async with aiofiles.open(file_path, 'rb') as f:
            while True:
                chunk = await f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
        
        return md5.hexdigest()
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """محاسبه checksum (همزمان)"""
        md5 = hashlib.md5()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
        
        return md5.hexdigest()
    
    async def _merge_chunks(self, destination: Path, num_chunks: int):
        """ترکیب chunk‌ها"""
        async with aiofiles.open(destination, 'wb') as outfile:
            for chunk_idx in range(num_chunks):
                chunk_file = Path(f"{destination}.part{chunk_idx}")
                
                if chunk_file.exists():
                    async with aiofiles.open(chunk_file, 'rb') as infile:
                        content = await infile.read()
                        await outfile.write(content)
                    
                    # حذف فایل chunk
                    chunk_file.unlink()
    
    async def _initiate_multipart_upload(self, upload_url: str, 
                                       filename: str, file_size: int) -> Optional[str]:
        """شروع آپلود multipart"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    'filename': filename,
                    'size': file_size
                }
                
                async with session.post(f"{upload_url}/init", json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('upload_id')
        except:
            pass
        return None
    
    async def _abort_multipart_upload(self, upload_url: str, upload_id: str):
        """لغو آپلود multipart"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {'upload_id': upload_id}
                await session.post(f"{upload_url}/abort", json=data)
        except:
            pass
    
    async def _complete_multipart_upload(self, upload_url: str, 
                                       upload_id: str, total_chunks: int) -> Optional[str]:
        """تکمیل آپلود multipart"""
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    'upload_id': upload_id,
                    'total_chunks': total_chunks
                }
                
                async with session.post(f"{upload_url}/complete", json=data) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('url')
        except:
            pass
        return None
    
    def _update_stats(self, transfer_type: str, size: int, duration: float):
        """به‌روزرسانی آمار سرعت"""
        speed_mbps = size / duration / 1024 / 1024
        
        if transfer_type == 'download':
            self.stats['total_downloaded'] += size
            self.stats['avg_download_speed'] = (
                self.stats['avg_download_speed'] * 0.9 + speed_mbps * 0.1
            )
            self.stats['peak_download_speed'] = max(
                self.stats['peak_download_speed'], speed_mbps
            )
        else:  # upload
            self.stats['total_uploaded'] += size
            self.stats['avg_upload_speed'] = (
                self.stats['avg_upload_speed'] * 0.9 + speed_mbps * 0.1
            )
            self.stats['peak_upload_speed'] = max(
                self.stats['peak_upload_speed'], speed_mbps
            )
    
    def _start_speed_monitor(self):
        """شروع مانیتور سرعت"""
        def monitor():
            while True:
                time.sleep(60)  # هر دقیقه
                self._log_speed_stats()
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def _log_speed_stats(self):
        """لاگ آمار سرعت"""
        logger.info(
            f"Speed Stats - "
            f"Down: {self.stats['avg_download_speed']:.2f}MB/s "
            f"(peak: {self.stats['peak_download_speed']:.2f}MB/s) | "
            f"Up: {self.stats['avg_upload_speed']:.2f}MB/s "
            f"(peak: {self.stats['peak_upload_speed']:.2f}MB/s) | "
            f"Total: DL: {self.stats['total_downloaded']:,} "
            f"UL: {self.stats['total_uploaded']:,}"
        )
    
    def get_speed_stats(self) -> Dict:
        """دریافت آمار سرعت"""
        return self.stats.copy()
    
    def optimize_for_speed(self, file_size: int) -> SpeedConfig:
        """بهینه‌سازی تنظیمات بر اساس حجم فایل"""
        optimized = SpeedConfig()
        
        if file_size < 10 * 1024 * 1024:  # کمتر از 10MB
            optimized.chunk_size = 512 * 1024  # 512KB
            optimized.max_connections = 4
            optimized.download_threads = 4
        elif file_size < 100 * 1024 * 1024:  # کمتر از 100MB
            optimized.chunk_size = 2 * 1024 * 1024  # 2MB
            optimized.max_connections = 8
            optimized.download_threads = 8
        else:  # بیشتر از 100MB
            optimized.chunk_size = 5 * 1024 * 1024  # 5MB
            optimized.max_connections = 16
            optimized.download_threads = 16
        
        return optimized

# تابع کمکی برای استفاده آسان
async def download_fast(url: str, destination: str, 
                       progress_callback=None) -> Dict:
    """دانلود سریع فایل"""
    optimizer = SpeedOptimizer()
    return await optimizer.download_file(
        url, Path(destination), progress_callback
    )

async def upload_fast(source: str, upload_url: str, 
                     progress_callback=None) -> Dict:
    """آپلود سریع فایل"""
    optimizer = SpeedOptimizer()
    return await optimizer.upload_file(
        Path(source), upload_url, progress_callback
    )
