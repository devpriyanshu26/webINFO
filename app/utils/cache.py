import time
import hashlib
import json
from threading import Lock

class ScanCache:
    def __init__(self, ttl=300):
        self.cache = {}
        self.ttl = ttl
        self.lock = Lock()

    def get(self, key):
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() - entry["time"] < self.ttl:
                    return entry["data"]
                del self.cache[key]
        return None

    def set(self, key, data):
        with self.lock:
            self.cache[key] = {"data": data, "time": time.time()}

    def make_key(self, url):
        return hashlib.md5(url.encode()).hexdigest()

    def clear(self):
        with self.lock:
            self.cache.clear()

    def cleanup(self):
        with self.lock:
            now = time.time()
            expired = [k for k, v in self.cache.items() if now - v["time"] >= self.ttl]
            for k in expired:
                del self.cache[k]
            return len(expired)

scan_cache = ScanCache(ttl=300)
