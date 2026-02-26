import cv2
import numpy as np
from vidstream import StreamingServer
import threading
import queue


class StreamReceiver:
    def __init__(self, port: int = 9999) -> None:
        self.server = StreamingServer("0.0.0.0", port)
        self.thread: threading.Thread | None = None
        self.frame_queue: queue.Queue = queue.Queue(maxsize=1)
        self.running = False

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._capture_frames, daemon=True)
        self.thread.start()
        print("[*] Stream receiver started")

    def _capture_frames(self) -> None:
        self.server.start_server()
        while self.running:
            try:
                frame = self.server.frame
                if frame is not None:
                    try:
                        self.frame_queue.put(frame.copy(), block=False)
                    except queue.Full:
                        pass
            except Exception as e:
                print(f"Frame capture error: {e}")
                break

    def get_frame(self):
        try:
            return self.frame_queue.get(block=False)
        except queue.Empty:
            return None

    def stop(self) -> None:
        self.running = False
        self.server.stop_server()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)
        print("[*] Stream receiver stopped")