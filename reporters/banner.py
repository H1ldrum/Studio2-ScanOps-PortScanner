import math
import socket
from collections import Counter
from sys import stderr
from typing import Tuple

import requests
import urllib3

urllib3.disable_warnings()
# TODO: refactor so that banner is not part of reporters-module
server_headers = ["server", "x-server", "powered-by", "x-powered-by"]
version_headers = ["x-aspnet-version"]


def clean_banner(target: str, port: int, raw_banner: str) -> str:
    if not raw_banner:
        return ""
    if port == 9929:
        garbled, _ = is_garbled_text(raw_banner.strip())
        if garbled:
            return "nping echo (garbled)"
    # If this is an HTTP response, extract meaningful information
    if raw_banner.startswith("HTTP/"):
        lines = raw_banner.split("\n")
        status_line = lines[0].strip()

        # Extract server info if available
        server_info = ""
        for line in lines:
            line_low = line.lower()
            for h in server_headers:
                to_find = h + ":"
                if line_low.startswith(to_find):
                    server_info = line_low.replace(to_find, "").strip()
                    if server_info:
                        return server_info
            for h in version_headers:
                to_find = h + ":"
                if line_low.startswith(to_find):
                    return server_info

        else:
            # Just return the status line if no server header
            return status_line

    # For non-HTTP or shorter banners, return as-is
    return raw_banner.strip()


def extract_banner(target: str, port: int, raw_banner: str, timeout=3.0) -> str:
    if raw_banner.strip():
        return clean_banner(target, port, raw_banner)
    tcpBanner = grabTcpBanner(target, port, timeout=timeout)
    if tcpBanner:
        return clean_banner(target, port, tcpBanner)
    try:
        banner = grabHttpBanner(target, port, timeout=timeout)
        if banner:
            return clean_banner(target, port, banner)
    except Exception as e:
        print(
            f"Failed to detect banner for {target}:{port} over http: {e}", file=stderr
        )
    return ""


def grabHttpBanner(target: str, port: int, scheme="", timeout=3.0):
    if not scheme:
        if port in [443, 8443, 4443, 9443, 10443]:
            scheme = "https"
        else:
            scheme = "http"
    try:
        url = f"{scheme}://{target}:{port}"
        response = requests.head(
            url,
            timeout=timeout,
            verify=False,
        )
        prefix = f"{scheme.upper()}/{response.raw.version / 10}"

        for h in server_headers:
            if h in response.headers:
                return response.headers[h]
        for h in version_headers:
            if h in response.headers:
                return h + response.headers[h]

        return f"{prefix} {response.status_code}"
    except Exception as e:
        if scheme == "http" and is_connection_reset_error(e):
            return grabHttpBanner(target, port, "https", timeout=timeout)
        raise e


def is_connection_reset_error(exception):
    """Check if an exception is or contains a ConnectionResetError."""

    # Direct check for ConnectionResetError
    if isinstance(exception, ConnectionResetError):
        return True

    # For requests.exceptions.ConnectionError with nested ConnectionResetError
    if isinstance(exception, requests.exceptions.ConnectionError):
        # Check if ConnectionResetError appears in the exception args
        for arg in exception.args:
            # Check if this arg is a tuple containing ConnectionResetError
            if isinstance(arg, tuple) and len(arg) == 2:
                _, inner_exc = arg
                if isinstance(inner_exc, ConnectionResetError):
                    return True

    # Fallback to string check if needed
    error_str = str(exception).lower()
    return "connection reset" in error_str


def grabTcpBanner(target: str, port: int, timeout=3.0):
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        # Connect to target
        s.connect((target, port))

        # Receive banner (up to 4096 bytes)
        banner = s.recv(4096).decode("utf-8", errors="ignore").strip()

        # Close connection
        s.close()

        return banner

    except Exception as e:
        return None


def is_garbled_text(text: str) -> Tuple[bool, float]:
    """
    Checks if text appears to be garbled using multiple heuristics.

    Args:
        text: The text to check

    Returns:
        Tuple of (is_garbled, confidence_score)
    """
    if not text or len(text) < 5:
        return (False, 0.0)

    # Check 1: Entropy calculation
    char_counts = Counter(text)
    entropy = -sum(
        (count / len(text)) * math.log2(count / len(text))
        for count in char_counts.values()
    )

    # Check 2: Special character ratio
    special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
    special_ratio = special_chars / len(text)

    # Check 3: Control characters presence
    control_chars = sum(1 for c in text if ord(c) < 32 or ord(c) == 127)
    control_ratio = control_chars / len(text) if len(text) > 0 else 0

    # Check 4: Unicode character ratio
    unicode_chars = sum(1 for c in text if ord(c) > 127)
    unicode_ratio = unicode_chars / len(text)

    # Calculate overall score (weighted combination)
    garbled_score = (
        0.3 * min(entropy / 4.5, 1.0)  # Typical text has entropy ~4.0-4.5
        + 0.3 * min(special_ratio * 3, 1.0)  # >30% special chars is suspicious
        + 0.2 * min(control_ratio * 10, 1.0)  # Any control chars are suspicious
        + 0.2 * min(unicode_ratio * 2, 1.0)  # High unicode ratio can be suspicious
    )

    return (garbled_score > 0.6, garbled_score)
