import streamlit as st
import sqlite3
import random
import requests
from typing import Optional

DB_PATH = "pharmacy.db"

def send_otp_local(mobile_number, otp):
    # Display OTP on screen and console instead of sending via Fast2SMS
    st.success(f"Your OTP is: {otp}")
    print(f"Generated OTP for {mobile_number}: {otp}")
    return {"return": True}


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
                    expiry_date TEXTNOT NULL
                )''')
    try:
        c.execute("INSERT OR IGNORE INTO users (username, password, role, mobile, first_name, middle_name, last_name, shop_name, city, state, pincode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  ("admin", "admin", "admin", "0000000000", "Admin", "", "User", "Admin Shop", "City", "State", "000000"))
    except Exception:
        pass
    conn.commit()
    conn.close()

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

def login_page():
    st.markdown("<h1 style='text-align:center; color:#4CAF50;'>💊 Pharmacy Management System</h1>", unsafe_allow_html=True)
    st.markdown("#### 👤 Please login or sign up below")

    tab1, tab2 = st.tabs(["Login", "Sign Up"])

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
                        st.success(f"OTP sent successfully to {mobile_num}. Please check your SMS. ")
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

def add_medicine_ui():
    st.header("➕ Add Medicine")
    med_id = st.text_input("Medicine ID")
    name = st.text_input("Name")
    qty = st.number_input("Quantity", min_value=0, step=1, value=0)
    expiry = st.date_input("Expiry Date")
    price = st.number_input("Price per unit", min_value=0.0, step=0.01, format="%.2f")

    if st.button("Add"):
        if not med_id or not name:
            st.warning("Please provide Medicine ID and Name.")
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO medicines (id, name, quantity, expiry_date, price) VALUES (?, ?, ?, ?, ?)",(med_id, name, int(qty), expiry.strftime("%Y-%m-%d"), float(price)))


            conn.commit()
            st.success("Medicine added!")
        except sqlite3.IntegrityError:
            st.error("Medicine ID already exists.")
        finally:
            conn.close()


def view_inventory_ui():
    st.header("📦 Inventory")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, quantity, expiry_date, price FROM medicines")
    rows = c.fetchall()
    conn.close()
    if rows:
        import pandas as pd
        df = pd.DataFrame(rows, columns=["ID", "Name", "Quantity","Expiry Date", "Price"])
        st.dataframe(df)
    else:
        st.info("No medicines found.")


def update_stock_ui():
    st.header("🔄 Update Stock")
    med_id = st.text_input("Enter Medicine ID to update")
    qty_change = st.number_input("Quantity change (can be negative)", step=1, value=0)
    change_expiry = st.checkbox("Update Expiry Date?")

    new_expiry = None
    if change_expiry:
        new_expiry = st.date_input("New Expiry Date")

    if st.button("Update"):
        if not med_id:
            st.warning("Please enter Medicine ID")
            return

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Check if medicine exists
        c.execute("SELECT name, quantity, expiry_date FROM medicines WHERE id = ?", (med_id,))
        row = c.fetchone()
        if not row:
            st.error("Medicine not found.")
            conn.close()
            return

        updates = []
        params = []

        # Quantity change
        if qty_change != 0:
            updates.append("quantity = quantity + ?")
            params.append(qty_change)

        # Expiry change
        if change_expiry and new_expiry:
            updates.append("expiry_date = ?")
            params.append(new_expiry.strftime("%Y-%m-%d"))

        if not updates:
            st.info("No changes provided.")
            conn.close()
            return

        params.append(med_id)
        sql = f"UPDATE medicines SET {', '.join(updates)} WHERE id = ?"
        c.execute(sql, tuple(params))
        conn.commit()
        conn.close()

        st.success("Medicine updated successfully!")

    

def delete_medicine_ui():
    st.header("🗑️ Delete Medicine")
    med_id = st.text_input("Enter Medicine ID to delete")
    if st.button("Delete"):
        if not med_id:
            st.warning("Please enter Medicine ID")
            return
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM medicines WHERE id = ?", (med_id,))
        if c.rowcount > 0:
            st.success("Medicine deleted.")
        else:
            st.warning("Medicine not found.")
        conn.commit()
        conn.close()


def billing_ui():
    st.header("🧾 Generate Bill (Multiple Items)")

    num_items = st.number_input("Number of different medicines", min_value=1, step=1, value=1)
    cart = []
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    for i in range(num_items):
        st.subheader(f"Medicine {i+1}")
        med_id = st.text_input(f"Medicine ID {i+1}", key=f"med_id_{i}")
        qty = st.number_input(f"Quantity {i+1}", min_value=1, step=1, value=1, key=f"qty_{i}")

        if med_id:
            c.execute("SELECT name, quantity, price, expiry_date FROM medicines WHERE id = ?", (med_id,))
            result = c.fetchone()
            if result:
                name, stock, price, expiry = result
                if qty <= stock:
                    cart.append({
                        "id": med_id,
                        "name": name,
                        "qty": qty,
                        "price": price,
                        "total": qty * price,
                        "expiry": expiry
                    })
                else:
                    st.warning(f"⚠ Not enough stock for {name} (Available: {stock})")
            else:
                st.error(f"❌ Medicine ID {med_id} not found.")

    if st.button("Generate Bill"):
        if not cart:
            st.warning("No valid medicines in cart.")
        else:
            total_amount = 0
            for item in cart:
                total_amount += item["total"]
                # Update stock
                c.execute("UPDATE medicines SET quantity = quantity - ? WHERE id = ?", (item["qty"], item["id"]))
            conn.commit()

            st.success(f"💰 Total Bill: ₹{total_amount:.2f}")

            # Show bill details
            import pandas as pd
            df = pd.DataFrame(cart, columns=["id", "name", "qty", "price", "total", "expiry"])
            df.columns = ["ID", "Name", "Quantity", "Price", "Total", "Expiry Date"]
            st.table(df)

    conn.close()

# --------------------
# Dashboard and navigation
# --------------------

def dashboard_page():
    st.title("💊 Pharmacy Management Dashboard")
    st.write(f"Welcome, **{st.session_state.username}** — _{st.session_state.role}_")
    st.write("Choose an action below:")

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📦 View Inventory"):
            st.session_state.page = "view_inventory"
            st.rerun()
    with col2:
        if st.button("➕ Add Medicine"):
            st.session_state.page = "add_medicine"
            st.rerun()
    with col3:
        if st.button("🔄 Update Stock"):
            st.session_state.page = "update_stock"
            st.rerun()

    col4, col5, col6 = st.columns(3)
    with col4:
        if st.button("🧾 Generate Bill"):
            st.session_state.page = "billing"
            st.rerun()
    with col5:
        if st.button("🗑️ Delete Medicine"):
            st.session_state.page = "delete_medicine"
            st.rerun()
    with col6:
        if st.button("🚪 Logout"):
            st.session_state.page = "logout"
            st.rerun()


def logout_confirmation():
    st.warning("⚠️ Do you want to logout from this session?")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("✅ Yes, Logout and Close"):
            # Clear session and run JS to close the tab/window
            st.session_state.clear()
            st.markdown(
                """
                <script>
                    setTimeout(function() {
                        window.open('', '_self', '');
                        window.close();
                    }, 100);
                </script>
                """,
                unsafe_allow_html=True
            )
            st.stop()

    with col2:
        if st.button("❌ No, Stay Logged In"):
            st.session_state.page = "dashboard"
            st.rerun()

# --------------------
# Main
# --------------------

def main():
    st.set_page_config(page_title="Pharmacy Management", layout="wide")
    init_db()
    init_session()

    if not st.session_state.logged_in:
        login_page()
    else:
        # show pages according to the st.session_state.page
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
