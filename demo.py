#!/usr/bin/env python3
"""
Demo script showing client/server encrypted message exchange
"""

from syft_core import Client

from crypto_utils import EncryptedPayload, decrypt_message, encrypt_message


def simulate_client_side():
    """Simulate what the client does"""
    print("👤 CLIENT SIDE:")
    print("=" * 50)

    client = Client.load()
    recipient = client.config.email  # Send to ourselves for demo
    message = "Hello from client! 🚀"

    print(f"📝 Sending message: '{message}'")
    print(f"📧 To: {recipient}")

    # Encrypt the message
    encrypted_payload = encrypt_message(message, recipient, client)
    print("📦 Created encrypted payload:")
    print(f"   - Sender: {encrypted_payload.sender}")
    print(f"   - Receiver: {encrypted_payload.receiver}")
    print(f"   - Ephemeral key: {len(encrypted_payload.ek)} bytes")
    print(f"   - Ciphertext: {len(encrypted_payload.ciphertext)} bytes")

    return encrypted_payload


def simulate_server_side(incoming_payload: EncryptedPayload):
    """Simulate what the server does when it receives an encrypted message"""
    print("\n🖥️  SERVER SIDE:")
    print("=" * 50)

    client = Client.load()  # Server loads its own client to access keys

    print(f"📨 Received encrypted payload:")
    print(f"   - From: {incoming_payload.sender}")
    print(f"   - To: {incoming_payload.receiver}")

    # Decrypt the message
    decrypted_message = decrypt_message(incoming_payload, client)
    print(f"📖 Decrypted message: '{decrypted_message}'")

    # Create response
    response_message = f"Pong! Server received: '{decrypted_message}' 🏓"
    print(f"💬 Server responding with: '{response_message}'")

    # Encrypt response back to sender
    encrypted_response = encrypt_message(
        response_message, incoming_payload.sender, client
    )
    print("📦 Created encrypted response")

    return encrypted_response


def simulate_client_receives_response(response_payload: EncryptedPayload):
    """Simulate client receiving the server response"""
    print("\n👤 CLIENT RECEIVES RESPONSE:")
    print("=" * 50)

    client = Client.load()

    print(f"📨 Received encrypted response:")
    print(f"   - From: {response_payload.sender}")
    print(f"   - To: {response_payload.receiver}")

    # Decrypt the response
    decrypted_response = decrypt_message(response_payload, client)
    print(f"🎉 Final decrypted response: '{decrypted_response}'")


def main():
    print("🔐 ENCRYPTED RPC DEMO")
    print("=" * 60)
    print("This demo simulates encrypted client-server communication\n")

    try:
        # 1. Client sends encrypted message
        encrypted_request = simulate_client_side()

        # 2. Server receives and processes encrypted message
        encrypted_response = simulate_server_side(encrypted_request)

        # 3. Client receives encrypted response
        simulate_client_receives_response(encrypted_response)

        print("\n✅ SUCCESS: Full encrypted roundtrip completed!")
        print(
            "🎯 Both client and server can encrypt/decrypt messages using shared crypto utilities"
        )

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
