#!/usr/bin/env python3
# telegram_optimizer.py - بهینه‌سازی سرعت برای تلگرام

import asyncio
import logging
from typing import List, Dict, Optional
from telethon import TelegramClient
from telethon.tl.types import Document, InputDocumentFileLocation
from telethon.tl.functions.upload import GetFileRequest
import math
import time
from pathlib import Path

logger = logging.getLogger(__name__)

class TelegramSpeedOptimizer:
    """بهینه‌سازی سرعت برای تلگرام"""
    
    def __init__(self, client: TelegramClient):
        self.client = client
        self.chunk_size = 1024 * 1024  # 1MB
        self.max_connections = 10
        self.download_semaphore = asyncio.Semaphore(self.max_connections)
        
        # آمار
        self.stats = {
            'total_downloaded': 0,
            'total_uploaded': 0,
            'download_speed_history': [],
            'upload_speed_history': []
        }
    
    async def download_document_fast(
        self, 
        document: Document,
        destination: Path,
        progress_callback = None
    ) -> Dict:
        """
        دانلود سریع سند از تلگرام با multi-connection
        Returns: {
            'success': bool,
            'path': Path,
            'size': int,
            'time': float,
            'speed_mbps': float,
            'connections': int
        }
        """
        start_time = time.time()
        
        try:
            file_size = document.size
            file_id = document.id
            access_hash = document.access_hash
            
            logger.info(f"Fast downloading document {file_id} ({file_size:,} bytes)")
            
            # تعیین تعداد اتصالات بهینه
            optimal_connections = self._calculate_optimal_connections(file_size)
            logger.info(f"Using {optimal_connections} connections")
            
            # محاسبه محدوده‌ها
            ranges = self._calculate_ranges(file_size, optimal_connections)
            
            # ایجاد فایل خروجی
            with open(destination, 'wb') as f:
                f.truncate(file_size)
            
            # دانلود همزمان همه بخش‌ها
            tasks = []
            for part_num, (start, end) in enumerate(ranges):
                task = self._download_part(
                    file_id, access_hash, part_num, start, end, 
                    destination, progress_callback
                )
                tasks.append(task)
            
            # اجرای موازی
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # بررسی خطاها
            errors = [r for r in results if isinstance(r, Exception)]
            if errors:
                logger.error(f"Part download errors: {errors}")
                return {
                    'success': False, 
                    'error': f'Part errors: {errors[:3]}'
                }
            
            # محاسبه سرعت
            download_time = time.time() - start_time
            speed_mbps = file_size / download_time / 1024 / 1024
            
            # ثبت آمار
            self.stats['total_downloaded'] += file_size
            self.stats['download_speed_history'].append(speed_mbps)
            if len(self.stats['download_speed_history']) > 100:
                self.stats['download_speed_history'].pop(0)
            
            logger.info(
                f"Download completed in {download_time:.2f}s "
                f"({speed_mbps:.2f} MB/s) using {optimal_connections} connections"
            )
            
            return {
                'success': True,
                'path': destination,
                'size': file_size,
                'time': download_time,
                'speed_mbps': speed_mbps,
                'connections': optimal_connections
            }
            
        except Exception as e:
            logger.error(f"Fast download failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'time': time.time() - start_time
            }
    
    async def _download_part(
        self, 
        file_id: int,
        access_hash: int,
        part_num: int,
        start: int,
        end: int,
        destination: Path,
        progress_callback = None
    ):
        """دانلود یک بخش از فایل"""
        async with self.download_semaphore:
            part_size = end - start + 1
            offset = start
            
            # ایجاد location برای فایل
            location = InputDocumentFileLocation(
                id=file_id,
                access_hash=access_hash,
                file_reference=b'',
                thumb_size=''
            )
            
            with open(destination, 'r+b') as f:
                while offset <= end:
                    chunk_end = min(offset + self.chunk_size - 1, end)
                    limit = chunk_end - offset + 1
                    
                    try:
                        # درخواست chunk
                        file_data = await self.client(GetFileRequest(
                            location=location,
                            offset=offset,
                            limit=limit
                        ))
                        
                        if not file_data or not file_data.bytes:
                            raise Exception(f"No data received for offset {offset}")
                        
                        # نوشتن chunk در فایل
                        f.seek(offset)
                        f.write(file_data.bytes)
                        
                        # گزارش پیشرفت
                        if progress_callback:
                            downloaded = offset - start + len(file_data.bytes)
                            percent = (downloaded / part_size) * 100
                            await progress_callback(part_num, percent)
                        
                        # به‌روزرسانی offset
                        offset += len(file_data.bytes)
                        
                    except Exception as e:
                        logger.error(f"Chunk download failed: {e}")
                        raise
            
            logger.debug(f"Part {part_num} downloaded: {start}-{end}")
    
    def _calculate_optimal_connections(self, file_size: int) -> int:
        """محاسبه تعداد اتصالات بهینه"""
        if file_size < 10 * 1024 * 1024:  # کمتر از 10MB
            return 2
        elif file_size < 100 * 1024 * 1024:  # کمتر از 100MB
            return min(8, math.ceil(file_size / (10 * 1024 * 1024)))
        else:  # بیشتر از 100MB
            return min(self.max_connections, math.ceil(file_size / (50 * 1024 * 1024)))
    
    def _calculate_ranges(self, file_size: int, num_parts: int) -> List[tuple]:
        """محاسبه محدوده‌های هر بخش"""
        part_size = file_size // num_parts
        ranges = []
        
        for i in range(num_parts):
            start = i * part_size
            if i == num_parts - 1:
                end = file_size - 1
            else:
                end = start + part_size - 1
            ranges.append((start, end))
        
        return ranges
    
    async def upload_document_fast(
        self,
        file_path: Path,
        chat_id: int,
        progress_callback = None,
        caption: str = ""
    ) -> Dict:
        """
        آپلود سریع سند به تلگرام
        Returns: {
            'success': bool,
            'message_id': int,
            'size': int,
            'time': float,
            'speed_mbps': float
        }
        """
        start_time = time.time()
        
        try:
            file_size = file_path.stat().st_size
            
            logger.info(f"Fast uploading {file_path} ({file_size:,} bytes)")
            
            # آپلود فایل
            message = await self.client.send_file(
                chat_id,
                file=str(file_path),
                caption=caption,
                progress_callback=progress_callback,
                part_size_kb=1024,  # 1MB parts (تلگرام max)
                workers=self.max_connections
            )
            
            # محاسبه سرعت
            upload_time = time.time() - start_time
            speed_mbps = file_size / upload_time / 1024 / 1024
            
            # ثبت آمار
            self.stats['total_uploaded'] += file_size
            self.stats['upload_speed_history'].append(speed_mbps)
            if len(self.stats['upload_speed_history']) > 100:
                self.stats['upload_speed_history'].pop(0)
            
            logger.info(
                f"Upload completed in {upload_time:.2f}s "
                f"({speed_mbps:.2f} MB/s)"
            )
            
            return {
                'success': True,
                'message_id': message.id,
                'size': file_size,
                'time': upload_time,
                'speed_mbps': speed_mbps
            }
            
        except Exception as e:
            logger.error(f"Fast upload failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'time': time.time() - start_time
            }
    
    def get_speed_stats(self) -> Dict:
        """دریافت آمار سرعت"""
        stats = self.stats.copy()
        
        # محاسبه سرعت متوسط
        if stats['download_speed_history']:
            stats['avg_download_speed'] = sum(stats['download_speed_history']) / len(stats['download_speed_history'])
        else:
            stats['avg_download_speed'] = 0
            
        if stats['upload_speed_history']:
            stats['avg_upload_speed'] = sum(stats['upload_speed_history']) / len(stats['upload_speed_history'])
        else:
            stats['avg_upload_speed'] = 0
        
        return stats
    
    async def benchmark(self, test_file_size: int = 10 * 1024 * 1024) -> Dict:
        """بنچمارک سرعت"""
        logger.info(f"Running benchmark with {test_file_size:,} bytes test")
        
        # ایجاد فایل تست
        test_file = Path("test_benchmark.bin")
        with open(test_file, 'wb') as f:
            f.write(b'0' * test_file_size)
        
        try:
            # آپلود تست
            upload_result = await self.upload_document_fast(
                test_file, 'me', caption="Benchmark test"
            )
            
            # دانلود تست
            if upload_result['success']:
                # پیدا کردن پیام آپلود شده
                messages = await self.client.get_messages('me', limit=1)
                if messages and messages[0].document:
                    download_file = Path("test_downloaded.bin")
                    download_result = await self.download_document_fast(
                        messages[0].document, download_file
                    )
                    
                    # پاکسازی
                    download_file.unlink()
            
            # پاکسازی
            test_file.unlink()
            
            return {
                'upload': upload_result,
                'download': download_result if 'download_result' in locals() else None
            }
            
        except Exception as e:
            logger.error(f"Benchmark failed: {e}")
            if test_file.exists():
                test_file.unlink()
            return {'error': str(e)}
