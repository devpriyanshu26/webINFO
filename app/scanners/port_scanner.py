import socket
import concurrent.futures

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IKE", 512: "rexec", 513: "rlogin", 514: "syslog",
    587: "SMTP Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1352: "Lotus Notes", 1433: "MSSQL",
    1434: "MSSQL Browser", 1521: "Oracle DB", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel SSL", 2086: "WHM", 2087: "WHM SSL", 2181: "ZooKeeper",
    2222: "DirectAdmin", 2375: "Docker", 2376: "Docker TLS",
    2424: "OrientDB", 2483: "Oracle DB", 2484: "Oracle DB SSL",
    3128: "Squid Proxy", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4000: "Default", 4333: "mSQL", 4369: "Erlang Port Mapper",
    4444: "Metasploit", 4560: "Default", 4848: "GlassFish",
    5000: "Flask/Dev", 5001: "Dev SSL", 5002: "Dev", 5003: "Dev",
    5060: "SIP", 5061: "SIPS", 5222: "XMPP", 5223: "XMPP SSL",
    5347: "gRPC", 5353: "mDNS", 5432: "PostgreSQL", 5555: "Android ADB",
    5601: "Kibana", 5666: "Nagios", 5672: "AMQP RabbitMQ",
    5800: "VNC", 5900: "VNC", 5901: "VNC", 5984: "CouchDB",
    5985: "WinRM", 5986: "WinRM SSL", 6000: "X11", 6001: "X11",
    6379: "Redis", 6380: "Redis SSL", 6443: "Kubernetes API",
    6580: "Parallels", 7001: "WebLogic", 7002: "WebLogic SSL",
    7070: "RealServer", 7077: "Mesos", 8000: "HTTP Alt", 8001: "HTTP Alt",
    8008: "HTTP Alt", 8009: "AJP", 8010: "HTTP Alt", 8080: "HTTP Proxy",
    8081: "HTTP Alt", 8082: "HTTP Alt", 8086: "InfluxDB", 8088: "HTTP Alt",
    8090: "HTTP Alt", 8181: "HTTP Alt", 8222: "VMware", 8332: "Bitcoin",
    8333: "Bitcoin", 8443: "HTTPS Alt", 8444: "HTTPS Alt",
    8500: "Consul", 8686: "Jetty", 8761: "Eureka", 8800: "HTTP Alt",
    8834: "Nessus", 8888: "HTTP Alt", 9000: "HTTP Alt", 9001: "Dev",
    9042: "Cassandra", 9050: "Tor SOCKS", 9090: "HTTP Alt",
    9092: "Kafka", 9100: "Printer", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9418: "Git", 9999: "HTTP Alt",
    10000: "Webmin", 10001: "Webmin SSL", 11211: "Memcached",
    11214: "Memcached", 11215: "Memcached SSL", 12000: "HTTP Alt",
    12345: "NetBus", 13579: "Unknown", 16010: "HBase", 16379: "Redis",
    17000: "HTTP Alt", 18080: "HTTP Alt", 18081: "HTTP Alt",
    19000: "HTTP Alt", 19150: "Gitea", 19200: "HTTP Alt",
    20000: "Webmin Alt", 22000: "HTTP Alt", 22222: "DirectAdmin Alt",
    23456: "Unknown", 25565: "Minecraft", 25672: "RabbitMQ",
    26000: "HTTP Alt", 26257: "CockroachDB", 27017: "MongoDB",
    27018: "MongoDB", 27019: "MongoDB", 27374: "Sub7",
    28015: "RethinkDB", 28017: "MongoDB Web", 29015: "RethinkDB",
    30000: "HTTP Alt", 31337: "Back Orifice", 32400: "Plex",
    32764: "Router", 33434: "traceroute", 37777: "IPTV",
    39213: "Unknown", 50070: "Hadoop NameNode", 50075: "Hadoop DataNode",
    50090: "Hadoop Secondary", 54328: "Unknown", 60000: "HTTP Alt",
    60001: "HTTP Alt", 65535: "Unknown",
}

class PortScanner:
    def __init__(self, hostname, fast=True):
        self.hostname = hostname
        self.fast = fast
        self.ports_to_scan = list(COMMON_PORTS.keys()) if not fast else [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389,
            443, 445, 465, 500, 587, 636, 993, 995, 1433, 1521, 2049,
            2082, 2083, 2181, 2375, 3306, 3389, 4444, 4848, 5000, 5432,
            5555, 5601, 5800, 5900, 5984, 6379, 6443, 7001, 7077, 8000,
            8008, 8009, 8080, 8086, 8443, 8500, 8761, 8834, 8888, 9000,
            9042, 9090, 9092, 9200, 9418, 10000, 11211, 12345, 15672,
            16010, 16379, 17000, 18080, 20000, 22222, 25565, 25672,
            27017, 28015, 31337, 32400, 32764, 37777, 50070, 60000,
        ]

    def scan(self):
        open_ports = []
        danger_ports = {21, 23, 25, 110, 135, 139, 445, 1433, 1521, 2049,
                        2375, 3306, 3389, 5432, 5555, 5900, 5984, 6379,
                        9200, 10000, 11211, 12345, 27017, 27374, 31337, 32764}

        def check_port(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.hostname, port))
                if result == 0:
                    try:
                        s.send(b"\r\n")
                        banner = s.recv(256).decode("utf-8", errors="ignore").strip()[:100]
                    except:
                        banner = None
                    s.close()
                    return {
                        "port": port,
                        "service": COMMON_PORTS.get(port, "unknown"),
                        "state": "open",
                        "banner": banner,
                        "dangerous": port in danger_ports,
                    }
                s.close()
            except:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check_port, p): p for p in self.ports_to_scan}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                result = future.result()
                if result:
                    open_ports.append(result)

        return sorted(open_ports, key=lambda x: x["port"])
