from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.datastructures import URL, MutableHeaders
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.requests import Request
from itsdangerous import BadSignature
from itsdangerous.url_safe import URLSafeSerializer


import functools
import http.cookies
import secrets
from re import Pattern
from typing import Optional, cast, List, Set, Dict


__all__ = [
    "CORSMiddleware",
    "GZipMiddleware",
    "TrustedHostMiddleware",
    "HTTPSRedirectMiddleware",
    "CSRFMiddleware",
]


class CSRFMiddleware:
    """
    Starlette middleware used to provide CSRF (Cross-Site Request Forgery) protection.

    This middleware employs the double-submit cookie pattern to prevent CSRF attacks:
    1. Sets a signed CSRF token cookie for each request.
    2. Requires requests with non-safe HTTP methods to include the same token in the request header.
    """

    def __init__(
        self,
        app: ASGIApp,
        secret: str,
        *,
        required_urls: Optional[List[Pattern]] = None,
        exempt_urls: Optional[List[Pattern]] = None,
        sensitive_cookies: Optional[Set[str]] = None,
        safe_methods: Set[str] = {"GET", "HEAD", "OPTIONS", "TRACE"},
        cookie_name: str = "csrftoken",
        cookie_path: str = "/",
        cookie_domain: Optional[str] = None,
        cookie_secure: bool = False,
        cookie_httponly: bool = False,
        cookie_samesite: str = "lax",
        header_name: str = "x-csrftoken",
    ) -> None:
        """
        Initialize the CSRF middleware.

        Parameters:
            app: The ASGI application to protect
            secret: The key used to sign the CSRF token
            required_urls: List of URL patterns that must undergo CSRF verification
            exempt_urls: List of URL patterns exempt from CSRF verification
            sensitive_cookies: Set of sensitive cookies that trigger CSRF protection when present
            safe_methods: Set of HTTP methods that do not require CSRF protection
            cookie_name: Name of the CSRF cookie
            cookie_path: Path attribute of the cookie
            cookie_domain: Domain attribute of the cookie
            cookie_secure: Whether the cookie should only be sent over HTTPS
            cookie_httponly: Whether to prohibit JavaScript from accessing the cookie
            cookie_samesite: SameSite attribute of the cookie
            header_name: Name of the HTTP request header containing the CSRF token
        """
        self.app = app
        self.serializer = URLSafeSerializer(secret, "csrftoken")
        self.secret = secret

        # URL Filtering Configuration
        self.required_urls = required_urls
        self.exempt_urls = exempt_urls
        self.sensitive_cookies = sensitive_cookies
        self.safe_methods = safe_methods

        # Cookie Configuration
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_domain = cookie_domain
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite

        # Header Configuration
        self.header_name = header_name

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        ASGI application entry point, handling each request and applying CSRF protection.
        """
        # Only handle HTTP and WebSocket requests
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        csrf_cookie = request.cookies.get(self.cookie_name)

        if self._requires_csrf_validation(request, csrf_cookie):
            submitted_csrf_token = await self._get_submitted_csrf_token(request)

            if not self._is_valid_csrf_token(csrf_cookie, submitted_csrf_token):
                response = self._get_error_response(request)
                await response(scope, receive, send)
                return

        wrapped_send = functools.partial(self._set_csrf_cookie, send=send, scope=scope)
        await self.app(scope, receive, wrapped_send)

    def _requires_csrf_validation(
        self, request: Request, csrf_cookie: Optional[str]
    ) -> bool:
        """
        Determine whether the request requires CSRF verification.

        Verification is required in the following cases:
        1. The URL is in the list of URLs that must be verified.
        2. All of the following conditions are met:
            - The request method is not a safe method.
            - The URL is not in the exempt list.
            - The request contains sensitive cookies.
        """
        if self._url_is_required(request.url):
            return True

        if request.method in self.safe_methods:
            return False

        if self._url_is_exempt(request.url):
            return False

        return self._has_sensitive_cookies(request.cookies)

    def _is_valid_csrf_token(
        self, cookie_token: Optional[str], submitted_token: Optional[str]
    ) -> bool:
        """
        Validate the CSRF token.
        """
        if not cookie_token or not submitted_token:
            return False

        return self._csrf_tokens_match(cookie_token, submitted_token)

    async def _set_csrf_cookie(
        self, message: Message, send: Send, scope: Scope
    ) -> None:
        """
        Set the CSRF cookie in the response.
        """
        if message["type"] != "http.response.start":
            await send(message)
            return

        request = Request(scope)
        csrf_cookie = request.cookies.get(self.cookie_name)

        if csrf_cookie is None:
            message.setdefault("headers", [])
            headers = MutableHeaders(scope=message)

            cookie = self._create_csrf_cookie()
            headers.append("set-cookie", cookie.output(header="").strip())

        await send(message)

    def _create_csrf_cookie(self) -> http.cookies.SimpleCookie:
        """
        Create a new CSRF cookie.
        """
        cookie = http.cookies.SimpleCookie()
        cookie_name = self.cookie_name
        cookie[cookie_name] = self._generate_csrf_token()
        cookie[cookie_name]["path"] = self.cookie_path
        cookie[cookie_name]["secure"] = self.cookie_secure
        cookie[cookie_name]["httponly"] = self.cookie_httponly
        cookie[cookie_name]["samesite"] = self.cookie_samesite
        if self.cookie_domain is not None:
            cookie[cookie_name]["domain"] = self.cookie_domain

        return cookie

    def _has_sensitive_cookies(self, cookies: Dict[str, str]) -> bool:
        """
        Check if the request contains sensitive cookies.
        """
        if not self.sensitive_cookies:
            return True

        for sensitive_cookies in self.sensitive_cookies:
            if sensitive_cookies in cookies:
                return True

        return False

    def _url_is_required(self, url: URL) -> bool:
        """
        Check if the URL is in the list of URLs that must be verified.
        """
        if not self.required_urls:
            return False

        for required_url in self.required_urls:
            if required_url.match(url.path):
                return True

        return False

    def _url_is_exempt(self, url: URL) -> bool:
        """
        Check if the URL is in the list of URLs that are exempt from verification.
        """
        if not self.exempt_urls:
            return False

        for exempt_url in self.exempt_urls:
            if exempt_url.match(url.path):
                return True

        return False

    async def _get_submitted_csrf_token(self, request: Request) -> Optional[str]:
        """
        Get the submitted CSRF token from the request.
        """
        return request.headers.get(self.header_name)

    def _generate_csrf_token(self) -> str:
        """
        Generate a new CSRF token.
        """
        random_token = secrets.token_urlsafe(128)
        return cast(str, self.serializer.dumps(random_token))

    def _csrf_tokens_match(self, token1: str, token2: str) -> bool:
        """
        Check if two CSRF tokens match.
        """
        try:
            decoded1: str = self.serializer.loads(token1)
            decoded2: str = self.serializer.loads(token2)

            return secrets.compare_digest(decoded1, decoded2)
        except (BadSignature, ValueError):
            return False

    def _get_error_response(self, request: Request) -> Response:
        """
        Generate an error response.
        """
        return PlainTextResponse(
            content="CSRF token verification failed", status_code=403
        )
