import json
import sys
import time
from datetime import datetime, timezone

import syft_rpc
from syft_core import Client
from syft_rpc.rpc import make_url

# Import bootstrap functionality
from bootstrap import bootstrap_user

# Import shared crypto utilities
from crypto_utils import (
    EncryptedPayload,
    decrypt_message,
    encrypt_message,
    private_key_path,
)

# EncryptedPayload imported from crypto_utils


# Bootstrap functions moved to bootstrap.py


def ping_user(to: str, client: Client):
    uri = make_url(datasite=to, app_name="pingpong-enc", endpoint="ping")
    utc_now = datetime.now(timezone.utc).isoformat()
    msg = f"PING: {utc_now}"
    enc = encrypt_message(msg, to, client)

    try:
        tstart = time.time()
        # Send encrypted ping and get encrypted pong response
        future = syft_rpc.send(url=uri, body=enc)
        print(f"📡 Sent encrypted ping to {to}")
        response = future.wait(timeout=300)
        response.raise_for_status()
        print(f"📨 Received encrypted pong from {to}")
        pong_response = response.model(EncryptedPayload)
        # Decrypt the pong response
        decrypted_pong = decrypt_message(pong_response, client)
        print(f"🎉 Decrypted pong: {decrypted_pong}")
        print(f"🕒 Time taken: {time.time() - tstart}s")
    except Exception as e:
        print(f"❌ Error during ping: {e}")
        sys.exit(1)


def main():
    # For testing, ping ourselves since we have our own DID document
    client = Client.load()
    to = client.config.email  # Ping ourselves for testing
    print(f"🌐 Logged in to {client.config.server_url} as {client.config.email}")

    print(f"🏓 Testing encrypt/decrypt by pinging ourselves: {to}")
    ping_user(to, client)


if __name__ == "__main__":
    main()
