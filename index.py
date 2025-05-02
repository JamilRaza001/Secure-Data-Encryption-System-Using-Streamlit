import streamlit as st
import time
import json 
import os
import base64
import hashlib 
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Configuration

Data_File = "data.json"

LockOut_Time = 90 # in seconds

Failed_Attempts = 3

# Functions 

def load_data():
    # Load user data from the JSON file
    if os.path.exists(Data_File):
        with open(Data_File, "r") as f:
            return json.load(f)
    else:
        return {'users': {}}

def save_data(data):
    # Save user data to the JSON file
    with open(Data_File, "w") as f:
        json.dump(data, f, indent=4)


Data_storage = load_data()

def generate_salt():
    # return a base64 encoded random salt for password hashing
    return base64.urlsafe_b64encode(os.urandom(16)).decode()

def hash_password(password, salt):
    # Hash the password with the salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
    )
    hashed = base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()
    return hashed

def verify_value(input_password, stored_hash, salt):

#  Verify that input_password, when hashed with the given salt, matches the stored hash
   return hash_password(input_password, salt) == stored_hash

def derive_encryption_key(passkey, salt):
    # Derive a key from the passkey and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(data, passkey, salt):
    # Encrypt the data using the derived key and Fernet and return the token (to a string) 
    key = derive_encryption_key(passkey, salt)
    cipher = Fernet(key)
    token = cipher.encrypt(data.encode())
    return token.decode()


def decrypt_data(token, passkey, salt):
    # Decrypt the token using the derived key and Fernet and return the data (to a string)
    key = derive_encryption_key(passkey, salt)
    cipher = Fernet(key)
    try:
        decrypted_data = cipher.decrypt(token.encode())
        return decrypted_data.decode()
    except Exception as e:
        return None  # Return None if decryption fails

# Session Management

def is_locked_out(user):
    # Check if the user is locked out, Return True if the user is currently locked out
    if 'lockout_time' in user and user['lockout_time']:
        louckout_until = datatime.fromisoformat(user['lockout_time'])
        if datetime.now() < lockout_until:
            return True
        
        else:
            user['lockout_time'] = None # lockout expired 
            user['failed_attempts'] = 0
            user['lockout_time'] = None
            return False
    else:
        return False

def record_failed_attempt(user):
    user['failed_attempts'] = user.get('failed_attempts', 0) + 1
    if user['failed_attempts'] >= Failed_Attempts:
        lockout_time = datetime.now() + timedelta(seconds=LockOut_Time)
        user['lockout_time'] = lockout_time.isoformat()
        st.error(f"Too many failed attempts. You are locked out until {lockout_until.strftime('%Y-%m-%d %H:%M:%S')}.")
      

# St Session initialization

if 'current_user' not in st.session_state:
    st.session_state.current_user = None # holds the username of the logged in user

if 'active_page' not in st.session_state:
    st.session_state.active_page = 'Home' # holds the current page (home)

# Page Functions

def registration_page():
    st.header("User Registration")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if not username or not password:
            st.error("Please fill in all fields.")
            return

        if password != confirm_password:
            st.error("Passwords do not match.")
            return

        if username in Data_storage['users']:
            st.error("Username already exists.")
            return    

        # Generate a salt and hash the password
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        # Store the new user data in the JSON file
        Data_storage['users'][username] = {
            'password_hash': pwd_hash,
            'salt': salt,
            'failed_attempts': 0,
            'lockout_time': None,
            'data': {} # Each key for each entry
        }

        save_data(Data_storage)
        st.success("User registered successfully!")

def login_page():
    st.header("User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username not in data_store["users"]:
            st.error("User not found. Please register first.")
            return
        
        user = data_store["users"][username]
        if is_locked(user):
            st.error("Your account is currently locked due to too many failed attempts. Please try later.")
            return
        
        if verify_hash(password, user["password_hash"], user["salt"]):
            st.success("Login successful!")
            user["failed_attempts"] = 0
            user["lockout_time"] = None
            save_data(data_store)
            st.session_state.current_user = username
        else:
            st.error("Incorrect username or password!")
            record_failed_attempt(user)
            save_data(data_store)

def home_page():
    st.header("Secure Data Encryption System")
    st.write(
        """
        **Welcome to your secure vault!**  
        - Use **Insert Data** to encrypt and store your personal text.
        - Use **Retrieve Data** to decrypt and view your stored text.
        - After too many incorrect passkey attempts, your account will be locked for a period.
        """
    )
    st.write(f"Logged in as: **{st.session_state.current_user}**")

def insert_data_page():
    if not st.session_state.current_user:
        st.error("You need to log in first!")
        return
    st.header("Insert New Data")
    identifier = st.text_input("Data Identifier (e.g., note1)")
    secret_text = st.text_area("Text to encrypt and store:")
    # Now prompt for a passkey (instead of reentering password)
    passkey = st.text_input("Enter a passkey for encryption:", type="password")
    
    if st.button("Store Data"):
        if not identifier or not secret_text or not passkey:
            st.warning("Please provide all required fields.")
            return
        
        current_user = data_store["users"][st.session_state.current_user]
        # Encrypt the secret text using the provided passkey and the user's salt.
        encrypted_text = encrypt_message(secret_text, passkey, current_user["salt"])
        # Store the hash of the provided passkey for later verification.
        passkey_hash = hash_value(passkey, current_user["salt"])
        # Save the data under the user's data dictionary.
        current_user["data"][identifier] = {
            "encrypted_text": encrypted_text,
            "passkey_hash": passkey_hash
        }
        save_data(data_store)
        st.success(f"Data under '{identifier}' stored securely!")

def retrieve_data_page():
    if not st.session_state.current_user:
        st.error("You need to log in first!")
        return
    st.header("Retrieve Stored Data")
    identifier = st.text_input("Data Identifier (e.g., note1)")
    passkey = st.text_input("Enter the passkey for decryption:", type="password")
    
    if st.button("Decrypt Data"):
        current_user = data_store["users"][st.session_state.current_user]
        if is_locked(current_user):
            st.error("Your account is locked due to failed attempts. Please try later.")
            return
        
        if identifier not in current_user["data"]:
            st.error("Data identifier not found!")
            return
        
        record = current_user["data"][identifier]
        # Verify that the provided passkey, when hashed, matches the stored passkey hash.
        if verify_hash(passkey, record["passkey_hash"], current_user["salt"]):
            try:
                decrypted_text = decrypt_message(record["encrypted_text"], passkey, current_user["salt"])
                st.success("Data decrypted successfully!")
                st.write(decrypted_text)
                # Reset failure counter on successful decryption.
                current_user["failed_attempts"] = 0
                current_user["lockout_time"] = None
                save_data(data_store)
            except Exception as e:
                st.error("Decryption failed. Data may be corrupted.")
        else:
            st.error("Incorrect passkey for decryption!")
            record_failed_attempt(current_user)
            save_data(data_store)

def logout():
    st.session_state.current_user = None
    st.success("You have been logged out.")

# Navigation Sidebar
pages = {
    "Home": home_page,
    "Insert Data": insert_data_page,
    "Retrieve Data": retrieve_data_page,
    "Login": login_page,
    "Register": registration_page,
    "Logout": logout,
}

selected_page = st.sidebar.radio("Navigation", list(pages.keys()))
pages[selected_page]()
