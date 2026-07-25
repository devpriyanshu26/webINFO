import requests
import concurrent.futures
from urllib.parse import urlparse
from config import Config

SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/security.txt",
    "/.well-known/security.txt", "/.well-known/", "/.env", "/.env.example",
    "/.env.backup", "/.env.production", "/.env.local", "/env",
    "/.git/config", "/.git/HEAD", "/.gitignore", "/.gitattributes",
    "/.htaccess", "/.htpasswd", "/.svn/entries", "/.svnignore",
    "/.DS_Store", "/Thumbs.db", "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/admin", "/login", "/wp-admin", "/administrator", "/backend",
    "/backup", "/config", "/config.php", "/config.php.bak",
    "/config.php.old", "/config.bak", "/config.json", "/config.xml",
    "/phpinfo.php", "/info.php", "/test.php", "/test",
    "/api", "/api/", "/swagger", "/swagger-ui.html", "/api-docs",
    "/graphql", "/graphiql", "/voyager",
    "/wp-json", "/wp-includes", "/wp-content",
    "/.npmrc", "/.docker/config.json",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/package.json", "/composer.json", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/yarn.lock",
    "/README.md", "/CHANGELOG.md", "/LICENSE",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/phpMyAdmin", "/phpmyadmin", "/pma", "/adminer.php",
    "/sql", "/database", "/db", "/dbadmin",
    "/manager", "/console", "/panel", "/cpanel",
    "/wizard", "/setup", "/install", "/install.php",
    "/upgrade", "/migration", "/migrate",
    "/logs", "/log", "/error.log", "/access.log", "/debug.log",
    "/server-status", "/server-info",
    "/ws", "/websocket", "/sockjs", "/socket.io",
    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
    "/.expo", "/.expo-shared",
    "/server.key", "/server.crt", "/private.key", "/private.pem",
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/npm-debug.log", "/yarn-error.log",
    "/tmp", "/temp", "/cache",
    "/xmlrpc.php", "/xmlrpc",
    "/shell", "/cmd", "/exec",
    "/web-console", "/console", "/h2-console",
    "/jmx", "/jolokia",
    "/heapdump", "/heapdump.json",
    "/.npm/_cacache",
    "/.vscode", "/.idea", "/.project", "/.classpath",
    "/.terraform", "/terraform.tfstate",
    "/kube-config", "/kubeconfig", "/.kube/config",
    "/credentials", "/credential",
    "/secrets", "/secret",
    "/oauth", "/oauth2", "/oauth2callback",
    "/callback", "/redirect",
    "/webhook", "/webhooks",
    "/metrics", "/prometheus",
]

class SensitiveFilesScanner:
    def __init__(self, url):
        self.url = url

    def scan(self):
        parsed = urlparse(self.url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        found = []

        def check(path):
            try:
                r = requests.get(root + path, timeout=6, allow_redirects=False,
                                 headers={"User-Agent": Config.USER_AGENT})
                if r.status_code in (200, 201, 401, 403):
                    size = len(r.content)
                    content_type = r.headers.get("Content-Type", "").split(";")[0]
                    return {
                        "path": path,
                        "status": r.status_code,
                        "size": size,
                        "size_kb": round(size / 1024, 1),
                        "content_type": content_type,
                    }
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(check, p): p for p in SENSITIVE_PATHS}
            for future in concurrent.futures.as_completed(futures, timeout=60):
                result = future.result()
                if result:
                    found.append(result)

        return sorted(found, key=lambda x: x["path"])
