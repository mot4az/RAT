import struct


def encode_message(message_type: str, data: str) -> bytes:
    """Return header+payload bytes for a text message."""
    message = f"{message_type}:{data}".encode("utf-8", errors="replace")
    return struct.pack("!I", len(message)) + message


def decode_message(data: bytes) -> tuple[str | None, str | None]:
    """Decode to (type, content).

    Accepts either:
    - full packet (4-byte big-endian size + payload), or
    - just the payload ("TYPE:content").
    """
    if not data:
        return None, None

   
    if len(data) >= 4:
        try:
            size = struct.unpack("!I", data[:4])[0]
            if size == len(data) - 4:
                data = data[4:]
        except Exception:
            pass

    try:
        message = data.decode("utf-8", errors="replace")
        if ":" not in message:
            return message, ""
        message_type, content = message.split(":", 1)
        return message_type, content
    except Exception as e:
        print(f"Decode error: {e}")
        return None, None