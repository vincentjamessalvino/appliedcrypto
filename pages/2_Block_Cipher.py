import streamlit as st
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

st.header("WELCOME TO SIMPLE BLOCK CIPHER! :sunglasses::lock:")

# Example block cipher encryption (substitution cipher for demonstration)
BLOCK_SIZE = 8  # Block size (in bytes)

def block_encrypt(plaintext, key):
    """Encrypts plaintext using a block cipher with the given key."""
    padded_text = pad(plaintext.encode(), BLOCK_SIZE)
    encrypted_blocks = []

    for i in range(0, len(padded_text), BLOCK_SIZE):
        block = padded_text[i:i + BLOCK_SIZE]
        encrypted_block = bytes([b ^ key[i % len(key)] for i, b in enumerate(block)])
        encrypted_blocks.append(encrypted_block)

    return b''.join(encrypted_blocks)

def block_decrypt(ciphertext, key):
    """Decrypts ciphertext using a block cipher with the given key."""
    decrypted_blocks = []

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = bytes([b ^ key[i % len(key)] for i, b in enumerate(block)])
        decrypted_blocks.append(decrypted_block)

    decrypted_text = b''.join(decrypted_blocks)
    return unpad(decrypted_text, BLOCK_SIZE).decode()

# User inputs
plaintext = st.text_area("Plaintext:")
key = st.text_area("Key (16, 24, or 32 characters):")

# Ensure the key is 16, 24, or 32 bytes long for AES
if len(key) not in (16, 24, 32):
    st.error("Key must be 16, 24, or 32 characters long.")

if st.button("Submit"):
    if plaintext and key:
        try:
            # Encrypt
            key_bytes = key.encode()
            ciphertext = block_encrypt(plaintext, key_bytes)
            st.write("Ciphertext (hex):", ciphertext.hex())
            
            # Decrypt
            decrypted = block_decrypt(ciphertext, key_bytes)
            st.write("Decrypted:", decrypted)
        except Exception as e:
            st.error(f"Error during encryption/decryption: {e}")
    else:
        st.error("Please enter both plaintext and key.")
