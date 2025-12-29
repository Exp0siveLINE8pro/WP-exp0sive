import requests

DEFAULT_HEADERS = {
    "User-Agent": "Exp0siveLINE8pro-Scanner/1.0",
    "Accept": "*/*",
    "Connection": "close"
}

DEFAULT_TIMEOUT = 8


def get(url, headers=None, timeout=None, allow_redirects=True):
    try:
        h = DEFAULT_HEADERS.copy()
        if headers:
            h.update(headers)

        r = requests.get(
            url,
            headers=h,
            timeout=timeout or DEFAULT_TIMEOUT,
            allow_redirects=allow_redirects
        )
        return r
    except Exception:
        return None
