# ==========================================================
# CAMPUS HARDWARE INVENTORY SYSTEM
# Flask Web Application Bridge
# ==========================================================

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)
from functools import wraps
import os

from Laboratorysystem import (
    init_database_storage,
    CoreAuthManager,
    CoreInventoryManager
)

web_app = Flask(__name__)
web_app.secret_key = os.environ.get("SECRET_KEY", "lab1-development-secret-change-me")

# ==========================================================
# ROUTE PROTECTION DECORATORS
# ==========================================================
def require_active_login(target_view):
    @wraps(target_view)
    def login_protection_wrapper(*args, **kwargs):
        if "username" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("render_login_page"))
        return target_view(*args, **kwargs)
    return login_protection_wrapper

def require_admin_privilege(target_view):
    @wraps(target_view)
    def admin_protection_wrapper(*args, **kwargs):
        if session.get("role") != "ADMIN":
            flash("Administrator access required.", "danger")
            return redirect(url_for("render_dashboard_view"))
        return target_view(*args, **kwargs)
    return admin_protection_wrapper

# ==========================================================
# FLASK WEB ROUTES
# ==========================================================
@web_app.route("/")
def entry_index():
    if "username" in session:
        return redirect(url_for("render_dashboard_view"))
    return redirect(url_for("render_login_page"))

@web_app.route("/login", methods=["GET", "POST"])
def render_login_page():
    if request.method == "POST":
        input_user = request.form.get("username", "").strip()
        input_pass = request.form.get("password", "").strip()

        if not input_user or not input_pass:
            flash("Username and password are required.", "danger")
            return render_template("login.html")

        is_auth, auth_msg, user_role, lock_status, user_email = CoreAuthManager.verify_user_login(input_user, input_pass)

        if is_auth:
            session.clear()
            session["username"] = input_user
            session["role"] = user_role
            session["email"] = user_email
            flash(auth_msg, "success")
            return redirect(url_for("render_dashboard_view"))

        flash(auth_msg, "danger")
        return render_template("login.html", locked=lock_status, locked_username=input_user)

    return render_template("login.html")

@web_app.route("/register", methods=["GET", "POST"])
def render_register_page():
    if request.method == "GET":
        return render_template("register.html")

    reg_username = request.form.get("username", "").strip()
    reg_email = request.form.get("email", "").strip()
    reg_password = request.form.get("password", "").strip()
    selected_role = request.form.get("role", "USER").strip().upper()

    if selected_role not in ("USER", "ADMIN"):
        selected_role = "USER"

    if not reg_username or not reg_email or not reg_password:
        flash("All registration fields are required.", "danger")
        return redirect(url_for("render_login_page"))

    reg_status, reg_message = CoreAuthManager.register_new_account(
        reg_username, reg_email, reg_password, target_role=selected_role
    )
    flash(reg_message, "success" if reg_status else "warning")
    return redirect(url_for("render_login_page"))

@web_app.route("/reset-request", methods=["GET", "POST"])
def render_reset_page():
    if request.method == "GET":
        return render_template("reset.html")

    reset_user = request.form.get("username", "").strip()
    reset_email = request.form.get("email", "").strip()
    new_pw = request.form.get("new_password", "").strip()
    confirm_pw = request.form.get("confirm_password", "").strip()

    if not reset_user or not reset_email or not new_pw or not confirm_pw:
        flash("All reset fields are required.", "danger")
        return redirect(url_for("render_login_page"))

    if new_pw != confirm_pw:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("render_login_page"))

    reset_ok, reset_msg = CoreAuthManager.request_password_reset(reset_user, reset_email, new_pw)
    flash(reset_msg, "success" if reset_ok else "danger")
    return redirect(url_for("render_login_page"))

@web_app.route("/dashboard")
@require_active_login
def render_dashboard_view():
    query_search = request.args.get("search", "").strip()
    query_category = request.args.get("category", "ALL")
    if not query_category:
        query_category = "ALL"

    hardware_items = CoreInventoryManager.fetch_filtered_inventory(filter_text=query_search, selected_cat=query_category)
    available_categories = CoreInventoryManager.fetch_unique_categories()

    # Calculate Total Stocks across all inventory items
    all_inventory_records = CoreInventoryManager.fetch_filtered_inventory(filter_text="", selected_cat="ALL")
    computed_total_stocks = sum(record[3] for record in all_inventory_records)

    user_active_loans = []
    user_history_list = []
    admin_pending_returns = []
    admin_pending_borrows = []
    user_pending_requests = []
    admin_audit_logs = []
    admin_pending_resets = []

    if session["role"] == "USER":
        user_active_loans = CoreInventoryManager.fetch_user_active_loans(session["username"])
        user_pending_requests = CoreInventoryManager.fetch_user_pending_requests(session["username"])
        user_history_list = CoreInventoryManager.fetch_user_history_records(session["username"])
    else:
        admin_pending_returns = CoreInventoryManager.fetch_all_pending_returns()
        admin_pending_borrows = CoreInventoryManager.fetch_all_pending_borrows()
        admin_audit_logs = CoreInventoryManager.fetch_complete_audit_log()
        admin_pending_resets = CoreAuthManager.fetch_pending_resets()

    return render_template(
        "dashboard.html",
        items=hardware_items,
        categories=available_categories,
        search=query_search,
        selected_category=query_category,
        total_stocks=computed_total_stocks,
        active_loans=user_active_loans,
        history=user_history_list,
        pending_returns=admin_pending_returns,
        pending_borrows=admin_pending_borrows,
        pending_borrow_requests=user_pending_requests,
        all_loans=admin_audit_logs,
        pending_resets=admin_pending_resets
    )

@web_app.route("/borrow", methods=["POST"])
@require_active_login
def handle_borrow_action():
    try:
        selected_item_id = int(request.form["item_id"])
        requested_quantity = int(request.form.get("quantity", "1"))
    except (KeyError, ValueError):
        flash("Invalid item or borrow quantity.", "danger")
        return redirect(url_for("render_dashboard_view"))

    if requested_quantity < 1:
        flash("Borrow quantity must be at least 1.", "danger")
        return redirect(url_for("render_dashboard_view"))

    if session["role"] != "USER":
        flash("Only USER accounts can borrow equipment.", "danger")
        return redirect(url_for("render_dashboard_view"))

    borrow_status, borrow_msg = CoreInventoryManager.submit_borrow_request(
        session["username"], selected_item_id, requested_quantity
    )
    flash(borrow_msg, "success" if borrow_status else "danger")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/return-request", methods=["POST"])
@require_active_login
def handle_return_request_action():
    raw_loan_ids = request.form.getlist("loan_ids")
    try:
        parsed_loan_ids = [int(val) for val in raw_loan_ids]
    except ValueError:
        parsed_loan_ids = []

    if session["role"] != "USER":
        flash("Only USER accounts can request returns.", "danger")
        return redirect(url_for("render_dashboard_view"))

    ret_status, ret_msg = CoreInventoryManager.submit_return_requests(parsed_loan_ids)
    flash(ret_msg, "success" if ret_status else "warning")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/admin/add", methods=["POST"])
@require_admin_privilege
def handle_admin_add_hardware():
    try:
        new_name = request.form.get("item_name", "").strip()
        new_category = request.form.get("category", "").strip()
        new_quantity = int(request.form.get("quantity", ""))
        new_unit_price = float(request.form.get("unit_price", ""))
    except ValueError:
        flash("Quantity must be an integer and unit price must be numeric.", "danger")
        return redirect(url_for("render_dashboard_view"))

    add_ok, add_msg = CoreInventoryManager.create_hardware_item(new_name, new_category, new_quantity, new_unit_price)
    flash(add_msg, "success" if add_ok else "danger")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/admin/delete", methods=["POST"])
@require_admin_privilege
def handle_admin_delete_hardware():
    raw_item_ids = request.form.getlist("item_ids")
    try:
        parsed_item_ids = [int(val) for val in raw_item_ids]
    except ValueError:
        parsed_item_ids = []

    del_ok, del_msg = CoreInventoryManager.remove_hardware_items(parsed_item_ids)
    flash(del_msg, "success" if del_ok else "warning")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/admin/borrow-action", methods=["POST"])
@require_admin_privilege
def handle_admin_borrow_decision():
    raw_loan_ids = request.form.getlist("loan_ids")
    should_approve = request.form.get("action") == "approve"
    try:
        parsed_loan_ids = [int(val) for val in raw_loan_ids]
    except ValueError:
        parsed_loan_ids = []

    proc_ok, proc_msg = CoreInventoryManager.evaluate_borrow_requests(parsed_loan_ids, is_approved=should_approve)
    flash(proc_msg, "success" if proc_ok else "danger")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/admin/return-action", methods=["POST"])
@require_admin_privilege
def handle_admin_return_decision():
    raw_loan_ids = request.form.getlist("loan_ids")
    should_approve = request.form.get("action") == "approve"
    try:
        parsed_loan_ids = [int(val) for val in raw_loan_ids]
    except ValueError:
        parsed_loan_ids = []

    proc_ok, proc_msg = CoreInventoryManager.evaluate_return_requests(parsed_loan_ids, is_approved=should_approve)
    flash(proc_msg, "success" if proc_ok else "danger")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/admin/reset-action", methods=["POST"])
@require_admin_privilege
def handle_admin_reset_decision():
    raw_req_ids = request.form.getlist("request_ids")
    should_approve = request.form.get("action") == "approve"
    try:
        parsed_req_ids = [int(val) for val in raw_req_ids]
    except ValueError:
        parsed_req_ids = []

    res_ok, res_msg = CoreAuthManager.evaluate_reset_requests(parsed_req_ids, is_approved=should_approve)
    flash(res_msg, "success" if res_ok else "danger")
    return redirect(url_for("render_dashboard_view"))

@web_app.route("/export")
@require_active_login
def handle_csv_export():
    export_ok, export_msg = CoreInventoryManager.generate_csv_report(session["username"])
    if not export_ok:
        flash(export_msg, "danger")
        return redirect(url_for("render_dashboard_view"))

    file_abs_path = os.path.abspath("inventory_report.csv")
    if not os.path.exists(file_abs_path):
        flash("The CSV report file was not found.", "danger")
        return redirect(url_for("render_dashboard_view"))

    return send_file(file_abs_path, as_attachment=True, download_name="inventory_report.csv")

@web_app.route("/logout")
def handle_user_logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("render_login_page"))

# Standard entry point mapping for Flask runner compatibility
app = web_app

if __name__ == "__main__":
    init_database_storage()
    print()
    print("=" * 58)
    print(" CAMPUS HARDWARE INVENTORY - WEB PORTAL")
    print("=" * 58)
    print()
    print(" Open Google Chrome and go to:")
    print(" http://127.0.0.1:5000")
    print()
    print(" Press CTRL+C to stop the server.")
    print("=" * 58)
    print()
    web_app.run(debug=True)