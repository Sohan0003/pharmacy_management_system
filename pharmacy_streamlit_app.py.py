import streamlit as st
import sqlite3
import random
import requests
from typing import Optional
import os
%%html
<h2 style="color:green;">This is HTML</h2>
<p>Written directly in the cell using the HTML magic command.</p>

# --------------------
# Configurations
# --------------------

DB_PATH = "pharmacy.db"

# Read API key from file
def load_api_key(file_path="fast2sms_verify.txt"):
    try:
        with open(file_path, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        st.error(f"API key file '{file_path}' not found.")
        return None

FAST2SMS_API_KEY = load_api_key()

# --------------------
# OTP Sending
# --------------------

def send_otp_sms(mobile_number, otp):
    if not FAST2SMS_API_KEY:
        return {"error": "API key not loaded."}

    url = "https://www.fast2sms.com/dev/bulk"
    payload = {
        'sender_id': 'TXTIND',
        'message': f'Your Pharmacy App OTP is {otp}',
        'language': 'english',
        'route': 'v3',
        'numbers': mobile_number
    }
    headers = {
        'authorization': FAST2SMS_API_KEY,
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(url, data=payload, headers=headers)
        print("Response status code:", response.status_code)
        print("Response text:", response.text)

        if not response.text:
            return {"error": "Empty response from SMS API"}

        try:
            return response.json()
        except ValueError:
            return {"error": "Invalid JSON response from SMS API"}

    except Exception as e:
        return {"error": str(e)}

# --------------------
# Database Functions
# --------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    role TEXT,
                    mobile TEXT,
                    first_name TEXT,
                    middle_name TEXT,
                    last_name TEXT,
                    shop_name TEXT,
                    city TEXT,
                    state TEXT,
                    pincode TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS medicines (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    price REAL NOT NULL,
                    expiry_date TEXT NOT NULL
                )''')
    try:
        c.execute("INSERT OR IGNORE INTO users (username, password, role, mobile, first_name, middle_name, last_name, shop_name, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  ("admin", "admin", "admin", "0000000000", "Admin", "", "User", "Admin Shop", "City", "State", "000000"))
    except Exception:
        pass
    conn.commit()
    conn.close()

# --------------------
# Session State Init
# --------------------

def init_session():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = ""
    if 'role' not in st.session_state:
        st.session_state.role = ""
    if 'page' not in st.session_state:
        st.session_state.page = "login"
    if 'otp_verified' not in st.session_state:
        st.session_state.otp_verified = False

# --------------------
# Authentication
# --------------------

def login(username: str, password: str) -> Optional[str]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def signup(username: str, password: str, mobile: str, first_name: str, middle_name: str, last_name: str, shop_name: str, city: str, state: str, pincode: str, role: str = 'user') -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role, mobile, first_name, middle_name, last_name, shop_name, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (username, password, role, mobile, first_name, middle_name, last_name, shop_name, city, state, pincode))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def is_valid_pincode(pincode: str) -> bool:
    return pincode.isdigit() and len(pincode) == 6

# --------------------
# Login / Signup UI
# --------------------

def login_page():
    st.markdown("<h1 style='text-align:center; color:#4CAF50;'>💊 Pharmacy Management System</h1>", unsafe_allow_html=True)
    st.markdown("#### 👤 Please login or sign up below")

    tab1, tab2 = st.tabs(["Login", "Sign Up"])

    # Login Tab
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                role = login(username, password)
                if role:
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.role = role
                    st.session_state.page = "dashboard"
                    st.success(f"Logged in as {username} ({role})")
                    st.rerun()
                else:
                    st.error("Invalid credentials")

    # Sign Up Tab
    with tab2:
        with st.form("signup_form"):
            first_name = st.text_input("First Name")
            middle_name = st.text_input("Middle Name (optional)")
            last_name = st.text_input("Last Name")
            new_user = st.text_input("Username")
            new_pass = st.text_input("New Password", type="password")
            shop_name = st.text_input("Shop Name")
            city = st.text_input("City")
            state = st.text_input("State")
            pincode = st.text_input("Pincode", max_chars=6)
            mobile_num = st.text_input("Mobile Number (10 digits)", max_chars=10)
            send_otp = st.form_submit_button("Send OTP")

            if send_otp:
                if mobile_num.isdigit() and len(mobile_num) == 10 and is_valid_pincode(pincode):
                    otp = str(random.randint(100000, 999999))
                    st.session_state.generated_otp = otp

                    sms_response = send_otp_sms(mobile_num, otp)

                    if "error" in sms_response:
                        st.error(f"Failed to send OTP: {sms_response['error']}")
                    elif sms_response.get("return") == True:
                        st.success(f"OTP sent successfully to {mobile_num}. Please check your SMS.")
                    else:
                        st.error(f"Failed to send OTP. Response: {sms_response}")
                else:
                    st.error("Invalid mobile number or pincode.")

            if 'generated_otp' in st.session_state:
                entered_otp = st.text_input("Enter OTP")
                verify_otp = st.form_submit_button("Verify OTP")
                if verify_otp:
                    if entered_otp == st.session_state.generated_otp:
                        st.session_state.otp_verified = True
                        st.success("OTP Verified! You can now sign up.")
                    else:
                        st.error("Invalid OTP.")

            role = st.selectbox("Role", ["user", "admin"]) if st.session_state.get('role') == 'admin' else st.selectbox("Role", ["user"])
            signed = st.form_submit_button("Sign Up")

            if signed:
                if not all([first_name, last_name, new_user, new_pass, shop_name, city, state, pincode, mobile_num]):
                    st.warning("Please fill all required fields.")
                elif not st.session_state.get('otp_verified', False):
                    st.warning("Please verify your OTP before signing up.")
                elif not is_valid_pincode(pincode):
                    st.warning("Invalid Pincode.")
                else:
                    if signup(new_user, new_pass, mobile_num, first_name, middle_name, last_name, shop_name, city, state, pincode, role):
                        st.success("User registered. Please login.")
                        st.session_state.otp_verified = False
                        st.session_state.generated_otp = None
                    else:
                        st.error("User already exists!")

# --------------------
# Medicine CRUD + Billing
# --------------------
# (rest of your medicine management functions stay the same)

# --------------------
# Main App
# --------------------

def main():
    st.set_page_config(page_title="Pharmacy Management", layout="wide")
    init_db()
    init_session()

    if not st.session_state.logged_in:
        login_page()
    else:
        page = st.session_state.page
        if page == "dashboard":
            dashboard_page()
        elif page == "view_inventory":
            view_inventory_ui()
            if st.button("⬅️ Back to Dashboard"):
                st.session_state.page = "dashboard"
                st.rerun()
        elif page == "add_medicine":
            add_medicine_ui()
            if st.button("⬅️ Back to Dashboard"):
                st.session_state.page = "dashboard"
                st.rerun()
        elif page == "update_stock":
            update_stock_ui()
            if st.button("⬅️ Back to Dashboard"):
                st.session_state.page = "dashboard"
                st.rerun()
        elif page == "billing":
            billing_ui()
            if st.button("⬅️ Back to Dashboard"):
                st.session_state.page = "dashboard"
                st.rerun()
        elif page == "delete_medicine":
            delete_medicine_ui()
            if st.button("⬅️ Back to Dashboard"):
                st.session_state.page = "dashboard"
                st.rerun()
        elif page == "logout":
            logout_confirmation()

if __name__ == "__main__":
    main()
