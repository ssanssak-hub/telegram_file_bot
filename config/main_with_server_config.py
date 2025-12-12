#!/usr/bin/env python3
# main_with_server_config.py - فایل اصلی با پشتیبانی از سرور تنظیمات

import asyncio
import logging
import sys
from pathlib import Path

# اضافه کردن مسیر
sys.path.append(str(Path(__file__).parent))

from config_server import create_config_manager, RenderDeployment
from bot.bot_core import TelegramBot
from userbot.userbot_core import UserBotManager
from core.database import DatabaseManager
from core.limits_manager import LimitsManager
from core.speed_optimizer import SpeedOptimizer

# تنظیمات لاگ
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name
