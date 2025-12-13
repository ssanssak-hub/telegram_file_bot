#auth_middleware.py
"""
سیستم احراز هویت Enterprise-Grade
"""

import asyncio
import time
import secrets
import hashlib
import jwt
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from ipaddress import ip_address, ip_network
from collections import defaultdict

import aiohttp
from aiohttp import web

from models.enums import PermissionLevel, AlertLevel
from monitoring.health_monitor import HealthMonitor

class AdvancedAuthMiddleware:
    """Middleware احراز هویت پیشرفته"""
    
    def __init__(self, config: Dict[str, Any], environment: str = "production"):
        self.config = config
        self.environment = environment
        
        # کلیدهای امنیتی
        self.jwt_secret = config.get('jwt_secret', secrets.token_urlsafe(64))
        self.jwt_algorithm = config.get('jwt_algorithm', 'HS256')
        self.jwt_expiry_hours = config.get('jwt_expiry_hours', 24)
        
        # Rate limiting
        self.rate_limits = config.get('rate_limits', {
            'global': 1000,
            'per_ip': 100,
            'per_user': 50,
            'login': 5
        })
        
        # لیست‌های IP
        self.ip_whitelist = self._parse_ip_list(config.get('ip_whitelist', []))
        self.ip_blacklist = self._parse_ip_list(config.get('ip_blacklist', []))
        
        # سیستم‌های داخلی
        self.request_counts = defaultdict(list)
        self.active_sessions = {}
        self.revoked_tokens = set()
        self.health_monitor = HealthMonitor()
        
        # Lock برای thread safety
        self.lock = asyncio.Lock()
    
    def _parse_ip_list(self, ip_list: List[str]) -> Set[str]:
        """تبدیل لیست IP به مجموعه"""
        parsed = set()
        
        for item in ip_list:
            try:
                if '/' in item:
                    network = ip_network(item, strict=False)
                    parsed.add(str(network))
                else:
                    ip_obj = ip_address(item)
                    parsed.add(str(ip_obj))
            except ValueError:
                pass
        
        return parsed
    
    @web.middleware
    async def middleware(self, request: web.Request, handler):
        """Middleware اصلی"""
        
        start_time = time.time()
        request_id = secrets.token_hex(8)
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # ثبت درخواست
        self.health_monitor.record_request()
        
        # 🔐 بررسی IP
        ip_check = self.check_ip_security(client_ip, user_agent)
        if ip_check['blocked']:
            return self._error_response(
                message='دسترسی از این IP مجاز نیست',
                status=403,
                request_id=request_id,
                error_code='IP_BLOCKED'
            )
        
        # ⚡ Rate Limiting
        rate_check = await self.check_rate_limit(client_ip, request.path)
        if not rate_check['allowed']:
            return self._error_response(
                message='تعداد درخواست بیش از حد مجاز',
                status=429,
                request_id=request_id,
                error_code='RATE_LIMIT_EXCEEDED',
                headers={'Retry-After': str(rate_check['retry_after'])}
            )
        
        # 🛡️ بررسی تهدیدات
        if request.can_read_body:
            try:
                body = await request.text()
                threat_check = self.detect_threats(body)
                if threat_check['action'] == 'block':
                    return self._error_response(
                        message='درخواست حاوی محتوای مشکوک است',
                        status=400,
                        request_id=request_id,
                        error_code='THREAT_DETECTED'
                    )
            except:
                pass
        
        # 🔑 احراز هویت
        auth_result = await self.authenticate_request(request, client_ip, user_agent)
        if not auth_result['authenticated']:
            return self._error_response(
                message=auth_result.get('message', 'احراز هویت ناموفق'),
                status=401,
                request_id=request_id,
                error_code=auth_result.get('error_code', 'AUTH_FAILED')
            )
        
        # 👥 بررسی دسترسی
        user_data = auth_result['user_data']
        if not self.check_permission(user_data, request):
            return self._error_response(
                message='شما دسترسی لازم برای این عملیات را ندارید',
                status=403,
                request_id=request_id,
                error_code='PERMISSION_DENIED'
            )
        
        # 🎯 اضافه کردن اطلاعات کاربر به request
        request['user'] = user_data
        request['auth_method'] = auth_result['auth_method']
        request['request_id'] = request_id
        request['client_ip'] = client_ip
        
        # 🚀 اجرای درخواست
        try:
            response = await handler(request)
            processing_time = time.time() - start_time
            
            # اضافه کردن هدرهای امنیتی
            response = self._add_security_headers(response)
            response.headers['X-Request-ID'] = request_id
            response.headers['X-Processing-Time'] = f"{processing_time:.3f}"
            
            return response
            
        except Exception as e:
            import logging
            logging.error(f"خطا در پردازش درخواست: {e}")
            return self._error_response(
                message='خطای داخلی سرور',
                status=500,
                request_id=request_id,
                error_code='INTERNAL_ERROR'
            )
    
    async def authenticate_request(self, request: web.Request, client_ip: str, user_agent: str) -> Dict[str, Any]:
        """احراز هویت درخواست"""
        
        # 1. Bearer Token
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return await self.authenticate_jwt(auth_header[7:], client_ip)
        
        # 2. API Key
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return await self.authenticate_api_key(api_key, client_ip)
        
        # 3. Session Cookie
        session_id = request.cookies.get('session_id')
        if session_id:
            return await self.authenticate_session(session_id, client_ip)
        
        return {
            'authenticated': False,
            'error_code': 'NO_AUTH',
            'message': 'روش احراز هویت مشخص نشده'
        }
    
    async def authenticate_jwt(self, token: str, client_ip: str) -> Dict[str, Any]:
        """احراز هویت JWT"""
        try:
            # بررسی revoked tokens
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if token_hash in self.revoked_tokens:
                return {
                    'authenticated': False,
                    'error_code': 'TOKEN_REVOKED'
                }
            
            # رمزگشایی
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm]
            )
            
            user_data = {
                'user_id': payload.get('user_id'),
                'role': payload.get('role', 'user'),
                'permissions': payload.get('permissions', []),
                'auth_method': 'jwt'
            }
            
            return {
                'authenticated': True,
                'user_data': user_data,
                'auth_method': 'jwt'
            }
            
        except jwt.ExpiredSignatureError:
            return {'authenticated': False, 'error_code': 'TOKEN_EXPIRED'}
        except jwt.InvalidTokenError:
            return {'authenticated': False, 'error_code': 'INVALID_TOKEN'}
    
    async def authenticate_api_key(self, api_key: str, client_ip: str) -> Dict[str, Any]:
        """احراز هویت API Key"""
        # در پروژه واقعی باید از دیتابیس بررسی شود
        # اینجا شبیه‌سازی شده
        valid_keys = self.config.get('api_keys', {})
        
        if api_key in valid_keys:
            key_info = valid_keys[api_key]
            
            # بررسی IP restrictions
            if 'allowed_ips' in key_info and client_ip not in key_info['allowed_ips']:
                return {'authenticated': False, 'error_code': 'IP_NOT_ALLOWED'}
            
            user_data = {
                'user_id': key_info.get('user_id', 'api_client'),
                'role': key_info.get('role', 'api_client'),
                'permissions': key_info.get('permissions', []),
                'auth_method': 'api_key'
            }
            
            return {
                'authenticated': True,
                'user_data': user_data,
                'auth_method': 'api_key'
            }
        
        return {'authenticated': False, 'error_code': 'INVALID_API_KEY'}
    
    async def authenticate_session(self, session_id: str, client_ip: str) -> Dict[str, Any]:
        """احراز هویت Session"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            
            # بررسی انقضا
            if datetime.now() > session['expires_at']:
                del self.active_sessions[session_id]
                return {'authenticated': False, 'error_code': 'SESSION_EXPIRED'}
            
            # به‌روزرسانی فعالیت
            session['last_activity'] = datetime.now()
            
            user_data = {
                'user_id': session['user_id'],
                'role': session.get('role', 'user'),
                'permissions': session.get('permissions', []),
                'auth_method': 'session'
            }
            
            return {
                'authenticated': True,
                'user_data': user_data,
                'auth_method': 'session'
            }
        
        return {'authenticated': False, 'error_code': 'INVALID_SESSION'}
    
    def check_ip_security(self, ip: str, user_agent: str) -> Dict[str, Any]:
        """بررسی امنیت IP"""
        risk_score = 0
        blocked = False
        reason = ""
        
        # بررسی لیست سیاه
        if self._is_ip_in_list(ip, self.ip_blacklist):
            blocked = True
            reason = "ip_blacklisted"
        
        # بررسی لیست سفید
        elif self.ip_whitelist and not self._is_ip_in_list(ip, self.ip_whitelist):
            blocked = True
            reason = "ip_not_whitelisted"
        
        return {
            'ip': ip,
            'blocked': blocked,
            'reason': reason,
            'risk_score': risk_score
        }
    
    def _is_ip_in_list(self, ip: str, ip_list: Set[str]) -> bool:
        """بررسی وجود IP در لیست"""
        try:
            ip_obj = ip_address(ip)
            
            for item in ip_list:
                if '/' in item:
                    if ip_obj in ip_network(item):
                        return True
                elif str(ip_obj) == item:
                    return True
            
            return False
        except ValueError:
            return False
    
    async def check_rate_limit(self, ip: str, endpoint: str) -> Dict[str, Any]:
        """بررسی Rate Limiting"""
        async with self.lock:
            now = datetime.now()
            key = f"{ip}:{endpoint}"
            
            # پاک‌سازی درخواست‌های قدیمی
            window_start = now - timedelta(minutes=1)
            self.request_counts[key] = [
                t for t in self.request_counts[key] 
                if t > window_start
            ]
            
            limit = self.rate_limits.get('per_ip', 100)
            current = len(self.request_counts[key])
            
            if current >= limit:
                retry_time = 60  # 60 ثانیه
                return {
                    'allowed': False,
                    'retry_after': retry_time,
                    'current': current,
                    'limit': limit
                }
            
            self.request_counts[key].append(now)
            
            return {
                'allowed': True,
                'current': current + 1,
                'limit': limit,
                'remaining': limit - (current + 1)
            }
    
    def check_permission(self, user_data: Dict[str, Any], request: web.Request) -> bool:
        """بررسی دسترسی کاربر"""
        role = user_data.get('role', 'user')
        method = request.method
        path = request.path
        
        # نقش‌های ادمین دسترسی کامل دارند
        if role in ['admin', 'super_admin']:
            return True
        
        # نقش‌های معمولی
        if role == 'user':
            allowed_methods = ['GET', 'POST']
            allowed_paths = ['/api/accounts', '/api/profile']
            
            if method in allowed_methods and any(path.startswith(p) for p in allowed_paths):
                return True
        
        return False
    
    def detect_threats(self, data: str) -> Dict[str, Any]:
        """تشخیص تهدیدات امنیتی"""
        threats = []
        
        # بررسی SQL Injection
        sql_patterns = [
            r"('(''|[^'])*')",
            r"\b(union|select|insert|update|delete|drop|create|alter)\b",
            r"(--|#|\/\*)"
        ]
        
        import re
        for pattern in sql_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                threats.append('sql_injection')
                break
        
        # بررسی XSS
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"on\w+\s*="
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                threats.append('xss')
                break
        
        action = "allow"
        if threats:
            action = "block"
        
        return {
            'threats_found': len(threats) > 0,
            'threats': threats,
            'action': action
        }
    
    def _get_client_ip(self, request: web.Request) -> str:
        """دریافت IP واقعی کلاینت"""
        headers = ['X-Real-IP', 'X-Forwarded-For', 'CF-Connecting-IP']
        
        for header in headers:
            ip = request.headers.get(header)
            if ip:
                return ip.split(',')[0].strip()
        
        return request.remote
    
    def _add_security_headers(self, response: web.Response) -> web.Response:
        """اضافه کردن هدرهای امنیتی"""
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        }
        
        for key, value in headers.items():
            response.headers[key] = value
        
        return response
    
    def _error_response(self, message: str, status: int, 
                       request_id: str, error_code: str,
                       headers: Dict[str, str] = None) -> web.Response:
        """ایجاد پاسخ خطا"""
        response_data = {
            'success': False,
            'error': message,
            'error_code': error_code,
            'request_id': request_id,
            'timestamp': datetime.now().isoformat()
        }
        
        response = web.json_response(response_data, status=status)
        
        if headers:
            for key, value in headers.items():
                response.headers[key] = value
        
        return response
    
    async def create_session(self, user_id: str, ip: str, 
                           user_agent: str) -> Dict[str, Any]:
        """ایجاد session جدید"""
        session_id = secrets.token_urlsafe(32)
        now = datetime.now()
        
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'ip_address': ip,
            'user_agent': user_agent,
            'created_at': now,
            'last_activity': now,
            'expires_at': now + timedelta(hours=self.jwt_expiry_hours)
        }
        
        self.active_sessions[session_id] = session_data
        
        # ایجاد JWT token
        jwt_token = self.create_jwt_token(user_id, 'user', [])
        
        return {
            'session_id': session_id,
            'jwt_token': jwt_token,
            'expires_in': self.jwt_expiry_hours * 3600
        }
    
    def create_jwt_token(self, user_id: str, role: str, 
                        permissions: List[str]) -> str:
        """ایجاد JWT token"""
        payload = {
            'user_id': user_id,
            'role': role,
            'permissions': permissions,
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiry_hours),
            'iat': datetime.utcnow()
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
    
    async def revoke_token(self, token: str):
        """ابطال token"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self.revoked_tokens.add(token_hash)
    
    def get_health_status(self) -> Dict[str, Any]:
        """دریافت وضعیت سلامت"""
        return self.health_monitor.get_status()
