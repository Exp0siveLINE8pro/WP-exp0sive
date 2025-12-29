import datetime

def _ts():
    return datetime.datetime.utcnow().strftime("%H:%M:%S")


def info(msg):
    print(f"[{_ts()}] [INFO] {msg}")


def warn(msg):
    print(f"[{_ts()}] [WARN] {msg}")


def error(msg):
    print(f"[{_ts()}] [ERROR] {msg}")
