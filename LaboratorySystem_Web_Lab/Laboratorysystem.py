"""
CAMPUS HARDWARE INVENTORY SYSTEM - CORE LOGIC & DATABASE ENGINE
Original system logic retained and enhanced for approval and quantity workflows.
Tkinter desktop interfaces isolated at the bottom.
"""

import sqlite3
import os
import csv
import bcrypt
from pydantic import BaseModel, EmailStr, Field

DATABASE_FILE_PATH = "hardware_inventory.db"

# ==========================================================
# 1. DATABASE SETUP & MIGRATION
# ==========================================================
def init_database_storage():
    db_conn = sqlite3.connect(DATABASE_FILE_PATH)
    db_cursor = db_conn.cursor()
    
    # Table 1: Users
    db_cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            failed_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0
        )
    """)
    
    # Table 2: Hardware Inventory
    db_cursor.execute("""
        CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 0,
            unit_price REAL NOT NULL DEFAULT 0.0
        )
    """)
    
    # Table 3: Borrowing Loans
    db_cursor.execute("""
        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            item_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'PENDING_BORROW',
            request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (item_id) REFERENCES inventory(id)
        )
    """)
    
    # Table 4: Password Reset Requests
    db_cursor.execute("""
        CREATE TABLE IF NOT EXISTS reset_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            new_password_hash TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING'
        )
    """)
    
    # Seed default Admin account
    db_cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not db_cursor.fetchone():
        hashed_pw = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db_cursor.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            ("admin", "admin@campus.edu", hashed_pw, "ADMIN")
        )
        
    db_conn.commit()
    db_conn.close()

# Alias for backwards compatibility
init_db = init_database_storage

# ==========================================================
# 2. CORE AUTHENTICATION CONTROLLER
# ==========================================================
class CoreAuthManager:
    @staticmethod
    def verify_user_login(user_id_str, raw_pwd_str):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password_hash, role, failed_attempts, is_locked, email FROM users WHERE username = ?",
            (user_id_str,)
        )
        found_record = cursor.fetchone()
        
        if not found_record:
            conn.close()
            return False, "Invalid username or password.", "USER", False, ""
            
        record_id, stored_hash, account_role, fail_count, lock_flag, user_email = found_record
        
        if lock_flag:
            conn.close()
            return False, "Account is locked due to multiple failed attempts. Submit a password reset.", account_role, True, user_email
            
        if bcrypt.checkpw(raw_pwd_str.encode('utf-8'), stored_hash.encode('utf-8')):
            cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (record_id,))
            conn.commit()
            conn.close()
            return True, "Login successful!", account_role, False, user_email
        else:
            fail_count += 1
            account_locked = 1 if fail_count >= 3 else 0
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?",
                (fail_count, account_locked, record_id)
            )
            conn.commit()
            conn.close()
            if account_locked:
                return False, "Account locked after 3 failed attempts.", account_role, True, user_email
            return False, f"Invalid password. Attempt {fail_count}/3.", account_role, False, user_email

    @staticmethod
    def register_new_account(new_username, new_email, new_password, target_role="USER"):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (new_username, new_email))
        if cursor.fetchone():
            conn.close()
            return False, "Username or Email already registered."
            
        pw_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (new_username, new_email, pw_hash, target_role)
            )
            conn.commit()
            conn.close()
            return True, "Registration successful! You can now log in."
        except Exception as err:
            conn.close()
            return False, f"Database exception: {str(err)}"

    @staticmethod
    def request_password_reset(username_input, email_input, new_password_input):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? AND email = ?", (username_input, email_input))
        if not cursor.fetchone():
            conn.close()
            return False, "Username and Email match not found."
            
        new_hash = bcrypt.hashpw(new_password_input.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "INSERT INTO reset_requests (username, email, new_password_hash) VALUES (?, ?, ?)",
            (username_input, email_input, new_hash)
        )
        conn.commit()
        conn.close()
        return True, "Password reset request submitted for Admin approval."

    @staticmethod
    def fetch_pending_resets():
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM reset_requests WHERE status = 'PENDING'")
        results = cursor.fetchall()
        conn.close()
        return results

    @staticmethod
    def evaluate_reset_requests(request_id_list, is_approved=True):
        if not request_id_list:
            return False, "No requests selected."
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        for req_id in request_id_list:
            if is_approved:
                cursor.execute("SELECT username, new_password_hash FROM reset_requests WHERE id = ?", (req_id,))
                request_data = cursor.fetchone()
                if request_data:
                    target_user, approved_hash = request_data
                    cursor.execute(
                        "UPDATE users SET password_hash = ?, failed_attempts = 0, is_locked = 0 WHERE username = ?",
                        (approved_hash, target_user)
                    )
                    cursor.execute("UPDATE reset_requests SET status = 'APPROVED' WHERE id = ?", (req_id,))
            else:
                cursor.execute("UPDATE reset_requests SET status = 'REJECTED' WHERE id = ?", (req_id,))
        conn.commit()
        conn.close()
        return True, f"Processed {len(request_id_list)} reset request(s)."

# Direct binding alias to preserve AuthController API name
AuthController = CoreAuthManager
AuthController.login_user = CoreAuthManager.verify_user_login
AuthController.register_user = CoreAuthManager.register_new_account
AuthController.submit_password_reset_request = CoreAuthManager.request_password_reset
AuthController.get_pending_resets = CoreAuthManager.fetch_pending_resets
AuthController.process_bulk_resets = CoreAuthManager.evaluate_reset_requests

# ==========================================================
# 3. CORE INVENTORY & BORROWING CONTROLLER
# ==========================================================
class CoreInventoryManager:
    @staticmethod
    def fetch_filtered_inventory(filter_text="", selected_cat="ALL"):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        sql_query = "SELECT id, name, category, quantity, unit_price FROM inventory WHERE 1=1"
        query_params = []
        
        if filter_text:
            sql_query += " AND name LIKE ?"
            query_params.append(f"%{filter_text}%")
        if selected_cat and selected_cat != "ALL":
            sql_query += " AND category = ?"
            query_params.append(selected_cat)
            
        cursor.execute(sql_query, query_params)
        fetched_items = cursor.fetchall()
        conn.close()
        return fetched_items

    @staticmethod
    def fetch_unique_categories():
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT category FROM inventory")
        categories_list = [row_data[0] for row_data in cursor.fetchall() if row_data[0]]
        conn.close()
        return categories_list

    @staticmethod
    def create_hardware_item(item_title, category_title, stock_count, price_value):
        if stock_count < 0 or price_value < 0:
            return False, "Quantity and Unit Price must be non-negative values."
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO inventory (name, category, quantity, unit_price) VALUES (?, ?, ?, ?)",
            (item_title, category_title, stock_count, price_value)
        )
        conn.commit()
        conn.close()
        return True, "Hardware item added successfully."

    @staticmethod
    def remove_hardware_items(item_id_list):
        if not item_id_list:
            return False, "No items selected for deletion."
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.executemany("DELETE FROM inventory WHERE id = ?", [(idx,) for idx in item_id_list])
        conn.commit()
        conn.close()
        return True, f"Successfully removed {len(item_id_list)} item(s)."

    @staticmethod
    def submit_borrow_request(borrower_username, hardware_id, request_qty):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT quantity FROM inventory WHERE id = ?", (hardware_id,))
        inventory_record = cursor.fetchone()
        
        if not inventory_record:
            conn.close()
            return False, "Selected hardware item not found."
            
        current_stock = inventory_record[0]
        if request_qty > current_stock:
            conn.close()
            return False, f"Requested quantity ({request_qty}) exceeds available stock ({current_stock})."
            
        cursor.execute(
            "INSERT INTO loans (username, item_id, quantity, status) VALUES (?, ?, ?, 'PENDING_BORROW')",
            (borrower_username, hardware_id, request_qty)
        )
        conn.commit()
        conn.close()
        return True, "Borrow request submitted successfully. Awaiting Admin approval."

    @staticmethod
    def fetch_user_active_loans(student_username):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.id, i.name, l.quantity, l.request_date
            FROM loans l
            JOIN inventory i ON l.item_id = i.id
            WHERE l.username = ? AND l.status = 'BORROWED'
        """, (student_username,))
        active_list = cursor.fetchall()
        conn.close()
        return active_list

    @staticmethod
    def fetch_user_pending_requests(student_username):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.id, i.name, l.quantity, l.status, l.request_date
            FROM loans l
            JOIN inventory i ON l.item_id = i.id
            WHERE l.username = ? AND l.status IN ('PENDING_BORROW', 'PENDING_RETURN')
        """, (student_username,))
        pending_list = cursor.fetchall()
        conn.close()
        return pending_list

    @staticmethod
    def fetch_user_history_records(student_username):
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.id, i.name, l.quantity, l.status, l.request_date
            FROM loans l
            JOIN inventory i ON l.item_id = i.id
            WHERE l.username = ?
        """, (student_username,))
        history_list = cursor.fetchall()
        conn.close()
        return history_list

    @staticmethod
    def fetch_all_pending_borrows():
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.id, l.username, i.name, l.quantity, l.request_date
            FROM loans l
            JOIN inventory i ON l.item_id = i.id
            WHERE l.status = 'PENDING_BORROW'
        """)
        pending_borrows = cursor.fetchall()
        conn.close()
        return pending_borrows

    @staticmethod
    def fetch_all_pending_returns():
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.id, l.username, i.name, l.quantity, l.request_date
            FROM loans l
            JOIN inventory i ON l.item_id = i.id
            WHERE l.status = 'PENDING_RETURN'
        """)
        pending_returns = cursor.fetchall()
        conn.close()
        return pending_returns

    @staticmethod
    def evaluate_borrow_requests(loan_id_list, is_approved=True):
        if not loan_id_list:
            return False, "No borrow requests selected."
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        
        for loan_idx in loan_id_list:
            if is_approved:
                cursor.execute("SELECT item_id, quantity FROM loans WHERE id = ? AND status = 'PENDING_BORROW'", (loan_idx,))
                found_loan = cursor.fetchone()
                if found_loan:
                    target_item_id, requested_amount = found_loan
                    cursor.execute("SELECT quantity FROM inventory WHERE id = ?", (target_item_id,))
                    available_stock = cursor.fetchone()[0]
                    if available_stock >= requested_amount:
                        cursor.execute("UPDATE inventory SET quantity = quantity - ? WHERE id = ?", (requested_amount, target_item_id))
                        cursor.execute("UPDATE loans SET status = 'BORROWED' WHERE id = ?", (loan_idx,))
                    else:
                        conn.rollback()
                        conn.close()
                        return False, "Insufficient stock available to complete authorization."
            else:
                cursor.execute("UPDATE loans SET status = 'REJECTED' WHERE id = ?", (loan_idx,))
        conn.commit()
        conn.close()
        return True, f"Processed {len(loan_id_list)} borrow request(s)."

    @staticmethod
    def submit_return_requests(loan_id_list):
        if not loan_id_list:
            return False, "No active loans selected for return."
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.executemany("UPDATE loans SET status = 'PENDING_RETURN' WHERE id = ? AND status = 'BORROWED'", [(l_id,) for l_id in loan_id_list])
        conn.commit()
        conn.close()
        return True, "Return request(s) submitted for Admin approval."

    @staticmethod
    def evaluate_return_requests(loan_id_list, is_approved=True):
        if not loan_id_list:
            return False, "No return requests selected."
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        
        for loan_idx in loan_id_list:
            if is_approved:
                cursor.execute("SELECT item_id, quantity FROM loans WHERE id = ? AND status = 'PENDING_RETURN'", (loan_idx,))
                found_return = cursor.fetchone()
                if found_return:
                    target_item_id, returned_amount = found_return
                    cursor.execute("UPDATE inventory SET quantity = quantity + ? WHERE id = ?", (returned_amount, target_item_id))
                    cursor.execute("UPDATE loans SET status = 'RETURNED' WHERE id = ?", (loan_idx,))
            else:
                cursor.execute("UPDATE loans SET status = 'BORROWED' WHERE id = ?", (loan_idx,))
        conn.commit()
        conn.close()
        return True, f"Processed {len(loan_id_list)} return request(s)."

    @staticmethod
    def fetch_complete_audit_log():
        conn = sqlite3.connect(DATABASE_FILE_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT l.id, l.username, i.name, l.quantity, l.status, l.request_date
            FROM loans l
            JOIN inventory i ON l.item_id = i.id
            ORDER BY l.request_date DESC
        """)
        all_logs = cursor.fetchall()
        conn.close()
        return all_logs

    @staticmethod
    def generate_csv_report(executor_username):
        try:
            conn = sqlite3.connect(DATABASE_FILE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, category, quantity, unit_price FROM inventory")
            all_rows = cursor.fetchall()
            conn.close()
            
            with open("inventory_report.csv", "w", newline="", encoding="utf-8") as csv_out:
                csv_writer = csv.writer(csv_out)
                csv_writer.writerow(["Item ID", "Name", "Category", "Quantity", "Unit Price ($)"])
                csv_writer.writerows(all_rows)
            return True, "Export successful."
        except Exception as err:
            return False, str(err)

# Direct binding aliases to preserve InventoryController API
InventoryController = CoreInventoryManager
InventoryController.get_all_items = CoreInventoryManager.fetch_filtered_inventory
InventoryController.get_categories = CoreInventoryManager.fetch_unique_categories
InventoryController.add_item = CoreInventoryManager.create_hardware_item
InventoryController.delete_bulk_items = CoreInventoryManager.remove_hardware_items
InventoryController.borrow_item = CoreInventoryManager.submit_borrow_request
InventoryController.get_user_active_loans = CoreInventoryManager.fetch_user_active_loans
InventoryController.get_user_pending_borrows = CoreInventoryManager.fetch_user_pending_requests
InventoryController.get_user_loan_history = CoreInventoryManager.fetch_user_history_records
InventoryController.get_pending_borrows = CoreInventoryManager.fetch_all_pending_borrows
InventoryController.get_pending_returns = CoreInventoryManager.fetch_all_pending_returns
InventoryController.process_bulk_borrows = CoreInventoryManager.evaluate_borrow_requests
InventoryController.request_bulk_item_returns = CoreInventoryManager.submit_return_requests
InventoryController.process_bulk_returns = CoreInventoryManager.evaluate_return_requests
InventoryController.get_all_loans_history = CoreInventoryManager.fetch_complete_audit_log
InventoryController.export_to_csv = CoreInventoryManager.generate_csv_report

# ==========================================================
# 4. ISOLATED DESKTOP GUI CODE (RETAINED FOR COMPARISON)
# ==========================================================
# DESKTOP ONLY — retained for the original desktop version
# Do not call in Flask/Web environment.
"""
class DesktopAuthWindow:
    pass

class DesktopInventoryWindow:
    pass

def start_desktop_application():
    pass
"""