import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# ------------------------------
# 🧠 In-Memory + File Storage
# ------------------------------
DATA_FILE = "data.json"
KEY_FILE = "key.key"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

if "stored_data" not in st.session_state:
    st.session_state.stored_data = load_data()
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ------------------------------
# 🔐 Encryption Setup
# ------------------------------
if "cipher" not in st.session_state:
    KEY = load_key()
    st.session_state.cipher = Fernet(KEY)

cipher = st.session_state.cipher

# ------------------------------
# 🔧 Helper Functions
# ------------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    stored_data = st.session_state.stored_data

    if encrypted_text in stored_data:
        if stored_data[encrypted_text]["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# ------------------------------
# 📺 UI
# ------------------------------
st.set_page_config(page_title="Secure Data App", page_icon="🛡️")
st.title("🛡️ Secure Data Encryption System")

st.markdown("""
<style>
    .instructions {
        background-color: black;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 1.5rem;
        border-left: 5px solid #1e90ff;
    }
</style>
""", unsafe_allow_html=True)

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📂 Navigation", menu)

# ------------------------------
# 🏠 Home Page
# ------------------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.markdown("""
    <div class="instructions">
    👋 **Instructions for Use:**

    - Navigate using the sidebar on the left.
    - Go to **Store Data** to encrypt and save your private data.
    - Later, go to **Retrieve Data** to decrypt and view it using your secret passkey.
    - After 3 failed attempts, you'll need to **Login** again for security reasons.
    </div>
    """, unsafe_allow_html=True)
    st.info("Use this app to **securely store and retrieve data** using unique passkeys.")

# ------------------------------
# 💾 Store Data Page
# ------------------------------
elif choice == "Store Data":
    st.subheader("🔐 Store Data Securely")
    st.markdown("""
    <div class="instructions">
    ✅ **How to Store Data:**
    - Enter the data you want to store in the first box.
    - Provide a secure passkey in the second field.
    - Click the button to encrypt and store it safely.
    </div>
    """, unsafe_allow_html=True)

    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter a secret passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            save_data(st.session_state.stored_data)
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

# ------------------------------
# 🔍 Retrieve Data Page
# ------------------------------
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3:
        st.warning("🚨 Too many failed attempts! Please reauthorize from the Login Page.")
    else:
        st.subheader("🔍 Retrieve Your Data")
        st.markdown("""
        <div class="instructions">
        🔓 **How to Retrieve Data:**
        - Paste your encrypted data string.
        - Enter your secret passkey used at the time of storing.
        - If everything matches, your original data will be shown.
        </div>
        """, unsafe_allow_html=True)

        encrypted_text = st.text_area("Enter your encrypted data:")
        passkey = st.text_input("Enter your secret passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted = decrypt_data(encrypted_text, passkey)
                if decrypted:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted, language="text")
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
            else:
                st.error("⚠️ Both fields are required!")

# ------------------------------
# 🔑 Login Page (Reauthorization)
# ------------------------------
elif choice == "Login":
    st.subheader("🔐 Reauthorization Required")
    st.markdown("""
    <div class="instructions">
    🔐 **Login Instructions:**
    - If you entered the wrong passkey 3 times, use this page to reset attempts.
    - Enter the master password to unlock decryption again.
    </div>
    """, unsafe_allow_html=True)

    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Simple hardcoded login
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! You can now try retrieving data again.")
        else:
            st.error("❌ Incorrect password. Try again.")