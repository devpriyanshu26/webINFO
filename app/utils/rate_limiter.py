import time
from threading import Lock

class RateLimiter:
    def __init__(self, max_requests=60, window=60):
        self.max_requests = max_requests
        self.window = window
        self.clients = {}
        self.lock = Lock()

    def is_allowed(self, client_id):
        now = time.time()
        with self.lock:
            if client_id not in self.clients:
                self.clients[client_id] = []
            self.clients[client_id] = [t for t in self.clients[client_id] if now - t < self.window]
            if len(self.clients[client_id]) >= self.max_requests:
                return False
            self.clients[client_id].append(now)
            return True

    def get_remaining(self, client_id):
        now = time.time()
        with self.lock:
            if client_id not in self.clients:
                return self.max_requests
            self.clients[client_id] = [t for t in self.clients[client_id] if now - t < self.window]
            return self.max_requests - len(self.clients[client_id])

    def cleanup(self):
        now = time.time()
        with self.lock:
            expired = [k for k, v in self.clients.items() if now - max(v) > self.window if v]
            for k in expired:
                del self.clients[k]

rate_limiter = RateLimiter(max_requests=60, window=60)
