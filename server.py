from datetime import datetime, timezone

from loguru import logger
from syft_event import SyftEvents

# Import shared crypto utilities
from crypto_utils import EncryptedPayload, decrypt_message, encrypt_message

box = SyftEvents("pingpong-enc")


@box.on_request("/ping")
def ping_handler(ping: EncryptedPayload) -> EncryptedPayload:
    """Handle a ping request and return a pong response."""
    # Load client to access keys and DIDs
    logger.info(f"Got encrypted ping from {ping.sender} to {ping.receiver}")

    # Decrypt the incoming message
    decrypted_message = decrypt_message(ping, box.client)
    logger.info(f"Decrypted message: {decrypted_message}")

    # Create pong response
    utc_now = datetime.now(timezone.utc).isoformat()
    pong_message = f"PONG: {utc_now}"

    # Encrypt pong response back to sender
    encrypted_pong = encrypt_message(pong_message, ping.sender, box.client)
    logger.info(f"🏓 Sending encrypted pong back to {ping.sender}")

    return encrypted_pong


if __name__ == "__main__":
    try:
        box.run_forever()
    except Exception as e:
        print(e)
