from vidstream import ScreenShareClient
import threading


class StreamSender:
    def __init__(self, host: str, port: int) -> None:
        self.client = ScreenShareClient(host, port)
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self.client.start_stream, daemon=True)
        self.thread.start()
        print("[*] Screen sharing started")

    def stop(self) -> None:
        self.client.stop_stream()
        print("[*] Screen sharing stopped")