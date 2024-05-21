import streamlit as st

st.header("WELCOME TO CAESAR CIPHER! :sunglasses::scroll:")

def caesar_encrypt(plaintext, shift):
    """Encrypts plaintext using Caesar cipher with the given shift."""
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    """Decrypts ciphertext using Caesar cipher with the given shift."""
    return caesar_encrypt(ciphertext, -shift)

# User inputs
plaintext = st.text_area("Plaintext:")
shift = st.number_input("Shift (0-25):", min_value=0, max_value=25, value=0, step=1)

if st.button("Submit"):
    if plaintext:
        try:
            # Encrypt
            ciphertext = caesar_encrypt(plaintext, shift)
            st.write("Ciphertext:", ciphertext)
            
            # Decrypt
            decrypted = caesar_decrypt(ciphertext, shift)
            st.write("Decrypted:", decrypted)
        except Exception as e:
            st.error(f"Error during encryption/decryption: {e}")
    else:
        st.error("Please enter plaintext.")
