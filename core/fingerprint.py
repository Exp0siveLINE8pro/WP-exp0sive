import re

def is_wordpress(html):
    if not html:
        return False

    indicators = [
        "wp-content",
        "wp-includes",
        "wordpress"
    ]
    html = html.lower()
    return any(i in html for i in indicators)


def extract_wp_version(html):
    if not html:
        return None

    m = re.search(
        r'<meta name="generator" content="WordPress\s*([0-9\.]+)"',
        html,
        re.I
    )
    if m:
        return m.group(1)

    m = re.search(r"wp-includes/.*?\?ver=([0-9\.]+)", html)
    if m:
        return m.group(1)

    return None
