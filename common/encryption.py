import ssl
import os


def create_ssl_context(server_side: bool = False) -> ssl.SSLContext:
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH if server_side else ssl.Purpose.SERVER_AUTH
    )

    if server_side:
        cert_path = os.path.join("certs", "cert.pem")
        key_path = os.path.join("certs", "key.pem")
       
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            raise FileNotFoundError(
                f"Server TLS certificate not found. Expected: {cert_path} and {key_path}"
            )
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    return context