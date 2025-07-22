#!/usr/bin/env python3
"""
Test script to demonstrate shared encrypt/decrypt functionality
"""

from syft_core import Client

from crypto_utils import decrypt_message, encrypt_message


def test_encrypt_decrypt():
    """Test encrypt/decrypt roundtrip"""
    print("🧪 Testing encrypt/decrypt roundtrip...")

    # Load client
    client = Client.load()

    # Test message
    original_message = "Hello, this is a secret message! 🔐"

    # For testing, we'll encrypt to ourselves
    recipient = client.config.email

    try:
        # Encrypt message
        print(f"📝 Original message: {original_message}")
        encrypted_payload = encrypt_message(original_message, recipient, client)
        print("✅ Encryption successful!")
        print(f"   - Sender: {encrypted_payload.sender}")
        print(f"   - Receiver: {encrypted_payload.receiver}")
        print(f"   - Ephemeral key length: {len(encrypted_payload.ek)} bytes")
        print(f"   - IV length: {len(encrypted_payload.iv)} bytes")
        print(f"   - Ciphertext length: {len(encrypted_payload.ciphertext)} bytes")
        print(f"   - Tag length: {len(encrypted_payload.tag)} bytes")

        # Decrypt message
        decrypted_message = decrypt_message(encrypted_payload, client)
        print(f"📖 Decrypted message: {decrypted_message}")

        # Verify roundtrip
        if original_message == decrypted_message:
            print("🎉 SUCCESS: Encrypt/Decrypt roundtrip works perfectly!")
        else:
            print("❌ ERROR: Messages don't match!")
            print(f"   Original:  '{original_message}'")
            print(f"   Decrypted: '{decrypted_message}'")

    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_encrypt_decrypt()
