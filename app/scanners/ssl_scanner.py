import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class SSLScanner:
    def __init__(self, hostname):
        self.hostname = hostname

    def scan(self):
        if not self.hostname:
            return {"error": "No hostname provided", "grade": "N/A"}

        cert_info = self._get_certificate()
        if not cert_info:
            return {"error": "Could not connect via SSL", "grade": "F"}

        grade = self._calculate_grade(cert_info)
        return {**cert_info, "grade": grade}

    def _get_certificate(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with ctx.wrap_socket(socket.socket(), server_hostname=self.hostname) as s:
                s.settimeout(10)
                s.connect((self.hostname, 443))
                cert_der = s.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                cipher = s.cipher()

                try:
                    cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                except:
                    cert_pem = None

                try:
                    alt_names = cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    ).value.get_values_for_type(x509.DNSName)
                except:
                    alt_names = []

                issuer = {k: v for k, v in cert.issuer.rfc4519_string().split("=") for k, v in [cert.issuer.rfc4519_string().split("=", 1)]} if "=" in cert.issuer.rfc4519_string() else {}
                subject = {k: v for k, v in [cert.subject.rfc4519_string().split("=", 1)]} if "=" in cert.subject.rfc4519_string() else {}

                valid_from = cert.not_valid_utc.isoformat() if cert.not_valid_utc else None
                valid_to = cert.not_valid_utc.isoformat() if cert.not_valid_utc else None
                days_remaining = (cert.not_valid_utc - datetime.now(timezone.utc)).days if cert.not_valid_utc else 0

                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    san_count = len(san_ext.value.get_values_for_type(x509.DNSName))
                except:
                    san_count = 0

                return {
                    "subject": str(cert.subject.rfc4519_string()),
                    "issuer": str(cert.issuer.rfc4519_string()),
                    "serial": hex(cert.serial_number),
                    "version": cert.version.value,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "days_remaining": days_remaining,
                    "expired": days_remaining < 0,
                    "expiring_soon": 0 <= days_remaining < 30,
                    "san_count": san_count,
                    "san_list": alt_names[:20],
                    "cipher_suite": cipher[0] if cipher else None,
                    "tls_version": cipher[1] if cipher else None,
                    "key_bits": cipher[2] if cipher else None,
                    "self_signed": self._is_self_signed(cert),
                    "wildcard": self._is_wildcard(alt_names),
                    "signature_algorithm": cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid),
                    "public_key_type": type(cert.public_key()).__name__ if cert.public_key() else None,
                }
        except Exception as e:
            return {"error": str(e)}

    def _is_self_signed(self, cert):
        try:
            return cert.subject == cert.issuer
        except:
            return False

    def _is_wildcard(self, alt_names):
        return any(n.startswith("*.") for n in alt_names)

    def _calculate_grade(self, info):
        score = 100
        if info.get("error"):
            return "F"
        if info.get("expired"):
            score -= 50
        if info.get("self_signed"):
            score -= 40
        if info.get("expiring_soon"):
            score -= 20
        tls = (info.get("tls_version") or "").lower()
        if "tlsv1" in tls and "tlsv1.3" not in tls and "tlsv1.2" not in tls:
            score -= 30
        if "tlsv1.2" in tls:
            score -= 5
        bits = info.get("key_bits", 0)
        if bits and bits < 2048:
            score -= 25
        if bits and bits < 4096:
            score -= 5
        if info.get("wildcard"):
            score -= 10
        if info.get("san_count", 0) > 50:
            score -= 5

        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 50:
            return "C"
        elif score >= 30:
            return "D"
        else:
            return "F"
