# SmartSpaza Backend
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Blueprint, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, bcrypt, os, io, csv, random, secrets
from datetime import datetime, timedelta
from fpdf import FPDF
from functools import wraps
from flask import Response
from io import StringIO, BytesIO
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.secret_key = 'smartspaza_secret'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

db_url = os.environ.get("DATABASE_URL_EXTERNAL")
if not db_url:
    # fallback for local dev (SQLite)
    db_url = "sqlite:///local.db"

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


load_dotenv()

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # Gmail from .env
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # App Password from .env

mail = Mail(app)

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def insert_default_developer():
    conn = get_db()
    username = "admin"
    password = "devpass123"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Check if developer already exists
    existing = conn.execute("SELECT * FROM developer WHERE username = ?", (username,)).fetchone()
    if not existing:
        conn.execute("INSERT INTO developer (username, password_hash) VALUES (?, ?)", (username, hashed))
        conn.commit()
        print("✅ Developer account created.")
    else:
        print("ℹ️ Developer account already exists.")
    conn.close()

@app.route('/test_email')
def test_email():
    from flask_mail import Message
    msg = Message(
        subject="SmartSpaza Test Email",
        sender=app.config['MAIL_USERNAME'],
        recipients=["smartspaza.reset@example.com"],  # replace with your real inbox
        body="This is a test email from SmartSpaza."
    )
    mail.send(msg)
    return "Test email sent!"


# ---------- INDEX ----------
@app.route('/')
def index():
    return render_template('index.html')


# ---------- OWNER AUTH ----------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form

        # Password confirmation check
        if data['password'] != data['confirm_password']:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        hashed_pw = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())

        conn = get_db()
        try:
            # Check if username or email already exists
            existing = conn.execute(
                "SELECT 1 FROM owners WHERE username=? OR email=?",
                (data['username'], data['email'])
            ).fetchone()

            if existing:
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('signup'))

            # Insert new owner
            conn.execute("""
                INSERT INTO owners 
                (username, email, location, cellnumber, office_number, shop_name, password_hash, passcode)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data['username'],
                data['email'],
                data['location'],
                data['cellnumber'],
                data['office_number'],
                data['shop_name'],
                hashed_pw,
                data['passcode']
            ))

            conn.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            # Only triggered if UNIQUE constraint fails
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('signup'))

        except Exception as e:
            # Catch other unexpected errors
            flash(f'Unexpected error: {e}', 'danger')
            return redirect(url_for('signup'))

        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        conn = get_db()
        conn.row_factory = sqlite3.Row  # access columns by name
        owner = conn.execute("SELECT * FROM owners WHERE username = ?", (data['username'],)).fetchone()
        conn.close()

        if not owner:
            flash('Invalid username.', 'danger')
            return render_template('login.html')

        # 🔒 Block check
        if owner['status']== 'blocked':
            flash('Your account has been blocked. Contact support.', 'danger')
            return render_template('login.html')

        # ✅ Password check (form password vs stored BLOB hash)
        if bcrypt.checkpw(data['password'].encode(), owner['password_hash']):
            session['owner_id'] = owner['id']
            session['owner_name'] = owner['username']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password.', 'danger')

    return render_template('login.html')


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form.get('email')
    conn = get_db()

    try:
        # Check if owner exists
        owner = conn.execute(
            "SELECT id FROM owners WHERE email = ?", (email,)
        ).fetchone()

        if not owner:
            flash("Email not found.", "danger")
            return redirect(url_for('login'))

        # Generate secure 6-digit code
        code = f"{random.randint(100000, 999999)}"
        expiry = datetime.utcnow() + timedelta(minutes=10)

        # Save code + expiry in DB (ISO string for portability)
        conn.execute("""
            UPDATE owners
            SET reset_code = ?, reset_expiry = ?
            WHERE id = ?
        """, (code, expiry.isoformat(sep=" ", timespec="seconds"), owner['id']))
        conn.commit()

        # Send reset email
        msg = Message(
            subject="SmartSpaza Reset Code",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email],
            body=f"Your SmartSpaza reset code is {code}. It expires in 10 minutes."
        )
        mail.send(msg)

        flash("Verification code sent to your email.", "info")
        return redirect(url_for('login'))

    except Exception as e:
        # Log error for debugging
        print(f"Error in forgot_password: {e}")
        flash("Something went wrong. Please try again.", "danger")
        return redirect(url_for('login'))

    finally:
        conn.close()

@app.route('/reset_credentials', methods=['POST'])
def reset_credentials():
    code = request.form.get('code')
    new_password = request.form.get('new_password')
    new_passcode = request.form.get('new_passcode')

    conn = get_db()
    try:
        # Validate reset code
        owner = conn.execute(
            "SELECT id, reset_code, reset_expiry FROM owners WHERE reset_code = ?",
            (code,)
        ).fetchone()

        if not owner:
            flash("Invalid code.", "danger")
            return redirect(url_for('login'))

        # Parse expiry timestamp
        expiry_str = owner['reset_expiry']
        try:
            expiry_dt = datetime.fromisoformat(expiry_str)
        except Exception:
            expiry_dt = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")

        if datetime.utcnow() > expiry_dt:
            flash("Code expired.", "danger")
            return redirect(url_for('login'))

        # Hash new credentials with bcrypt (store as BLOBs)
        hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        hashed_pc = bcrypt.hashpw(new_passcode.encode(), bcrypt.gensalt())

        # Update DB and clear reset fields
        conn.execute("""
            UPDATE owners
            SET password_hash = ?, passcode = ?, reset_code = NULL, reset_expiry = NULL
            WHERE id = ?
        """, (hashed_pw, hashed_pc, owner['id']))
        conn.commit()

        flash("Credentials updated successfully!", "success")
        return redirect(url_for('login'))

    except Exception as e:
        print(f"Error in reset_credentials: {e}")
        flash("Something went wrong. Please try again.", "danger")
        return redirect(url_for('login'))

    finally:
        conn.close()

@app.route('/check_passcode', methods=['POST'])
def check_passcode():
    if 'owner_id' not in session:
        return jsonify({"success": False})

    entered_passcode = request.form.get('passcode')

    conn = get_db()
    cursor = conn.cursor()
    owner = cursor.execute(
        "SELECT passcode FROM owners WHERE id=?",
        (session['owner_id'],)
    ).fetchone()
    conn.close()

    if owner and entered_passcode == owner[0]:
        return jsonify({"success": True})
    return jsonify({"success": False})

        
# ---------- OWNER DASHBOARD ----------
@app.route('/dashboard')
def dashboard():
    if 'owner_id' not in session:
        return redirect(url_for('login'))

    owner_id = session['owner_id']   # ✅ define once
    conn = get_db()

    # Total products
    total_products = conn.execute(
        "SELECT COUNT(*) FROM products WHERE owner_id = ?", 
        (owner_id,)
    ).fetchone()[0]

    # Total sales
    total_sales_row = conn.execute(
        "SELECT SUM(price * quantity) AS total FROM sales WHERE owner_id = ?", 
        (owner_id,)
    ).fetchone()
    total_sales = total_sales_row['total'] if total_sales_row['total'] else 0.0

    # Top product by sales
    top_product_row = conn.execute("""
        SELECT p.name, SUM(s.quantity) AS total_sold
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ?
        GROUP BY p.id
        ORDER BY total_sold DESC
        LIMIT 1
    """, (owner_id,)).fetchone()
    top_product_name = top_product_row['name'] if top_product_row else "N/A"

    # Low stock count
    low_stock_count = conn.execute(
        "SELECT COUNT(*) FROM products WHERE owner_id = ? AND quantity <= 9",
        (owner_id,)
    ).fetchone()[0]

    # Top 5 best-selling products
    top_products = conn.execute("""
        SELECT p.name, p.sell_price, SUM(s.quantity) AS quantity_sold, SUM(s.price * s.quantity) AS total_sales
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ?
        GROUP BY p.id
        ORDER BY quantity_sold DESC
        LIMIT 5
    """, (owner_id,)).fetchall()

    conn.close()

    return render_template(
        'dashboard.html',
        total_products=total_products,
        total_sales=total_sales,
        top_product_name=top_product_name,
        low_stock_count=low_stock_count,
        top_products=top_products
    )


@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        data = request.form
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO products (owner_id, name, category, buy_price, sell_price, quantity, description)
                          VALUES (?, ?, ?, ?, ?, ?, ?)""",
                       (session['owner_id'], data['name'], data['category'], data['buy_price'],
                        data['sell_price'], data['quantity'], data['description']))
        product_id = cursor.lastrowid

        # ✅ Record purchase
        cost = float(data['buy_price']) * int(data['quantity'])
        cursor.execute("""INSERT INTO purchases (owner_id, product_id, quantity, cost, date)
                          VALUES (?, ?, ?, ?, DATE('now'))""",
                       (session['owner_id'], product_id, data['quantity'], cost))

        conn.commit()
        conn.close()
        flash('Product added successfully!', 'success')
        
    return render_template('add_product.html')

@app.route('/manage_product')
def manage_product():
    if 'owner_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    products = conn.execute("""
        SELECT id, name, buy_price, sell_price, quantity
        FROM products WHERE owner_id = ?
    """, (session['owner_id'],)).fetchall()
    conn.close()

    return render_template('manage_product.html', products=products)


@app.route('/update_products', methods=['POST'])
def update_products():
    data = request.get_json()
    conn = get_db()
    cursor = conn.cursor()

    for prod in data['products']:
        product_id = prod['id']
        add_qty = int(prod.get('add_quantity', 0))   # new quantity entered
        new_name = prod['name']
        new_buy = float(prod['buy_price'])
        new_sell = float(prod['sell_price'])
        new_qty = int(prod.get('quantity', 0))       # ✅ value sent from frontend

        # Fetch current available stock and buy price
        old = cursor.execute("""
            SELECT quantity, buy_price 
            FROM products 
            WHERE id=? AND owner_id=?
        """, (product_id, session['owner_id'])).fetchone()

        old_qty, buy_price = old

        # ✅ Decide new available
        if add_qty > 0:
            # Increase stock
            new_available = old_qty + add_qty
        else:
            # Allow manual decrease
            new_available = new_qty

        # Update product table
        cursor.execute("""
            UPDATE products
            SET name=?, buy_price=?, sell_price=?, quantity=?
            WHERE id=? AND owner_id=?
        """, (new_name, new_buy, new_sell, new_available, product_id, session['owner_id']))

        # ✅ If stock increased, record purchase
        if add_qty > 0:
            cost = buy_price * add_qty
            cursor.execute("""
                INSERT INTO purchases (owner_id, product_id, quantity, cost, date)
                VALUES (?, ?, ?, ?, DATE('now'))
            """, (session['owner_id'], product_id, add_qty, cost))

    conn.commit()
    conn.close()
    return jsonify({"message": "Products updated successfully!"})


@app.route('/delete_products', methods=['POST'])
def delete_products():
    data = request.get_json()
    conn = get_db()
    for prod_id in data['ids']:
        conn.execute("DELETE FROM products WHERE id=? AND owner_id=?", (prod_id, session['owner_id']))
    conn.commit()
    conn.close()
    return jsonify({"message": "Selected products deleted successfully!"})

@app.route('/record_sale', methods=['GET', 'POST'])
def record_sale():
    if 'owner_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    conn.row_factory = sqlite3.Row

    if request.method == 'POST':
        products = conn.execute("SELECT * FROM products WHERE owner_id = ?", (session['owner_id'],)).fetchall()
        for product in products:
            qty_sold = int(request.form.get(f"qty_{product['id']}", 0))
            if qty_sold > 0:
                total = qty_sold * product['sell_price']
                conn.execute("""
                    INSERT INTO sales (owner_id, product_id, quantity, price, total, date)
                    VALUES (?, ?, ?, ?, ?, DATE('now'))
                """, (session['owner_id'], product['id'], qty_sold, product['sell_price'], total))
                conn.execute("""
                    UPDATE products
                    SET quantity = quantity - ?
                    WHERE id = ? AND owner_id = ?
                """, (qty_sold, product['id'], session['owner_id']))
        conn.commit()
        flash("Sale recorded successfully!", "success")
        return redirect(url_for('dashboard'))

    # --- GET request ---
    order = request.args.get('order', 'default')  # ?order=low or ?order=high

    if order == 'low':
        products = conn.execute("""
            SELECT * FROM products WHERE owner_id = ? ORDER BY quantity ASC
        """, (session['owner_id'],)).fetchall()
    elif order == 'high':
        products = conn.execute("""
            SELECT * FROM products WHERE owner_id = ? ORDER BY quantity DESC
        """, (session['owner_id'],)).fetchall()
    else:
        products = conn.execute("""
            SELECT * FROM products WHERE owner_id = ? ORDER BY name ASC
        """, (session['owner_id'],)).fetchall()

    # Sold data
    sold_data = conn.execute("""
        SELECT product_id, SUM(quantity) AS sold
        FROM sales
        WHERE owner_id = ?
        GROUP BY product_id
    """, (session['owner_id'],)).fetchall()
    sold_map = {row['product_id']: row['sold'] for row in sold_data}

    enriched_products = []
    for product in products:
        sold_qty = sold_map.get(product['id'], 0)
        total = sold_qty * product['sell_price']
        enriched_products.append({
        "id": product['id'],
        "name": product['name'],
        "available": product['quantity'],
        "sold": sold_qty,
        "price": product['sell_price'],
        "total": total,
        "low_stock": product['quantity'] <= 10
    })


    conn.close()
    return render_template('record_sale.html', products=enriched_products, order=order)


@app.route('/report/<int:year>')
def report(year):
    owner_id = session.get('owner_id')
    if not owner_id:
        flash("No owner is logged in.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Monthly stats query
    c.execute("""
       SELECT strftime('%Y-%m', s.date) AS month,
              SUM(s.quantity) AS products_sold,
              SUM(s.total) AS sales_revenue,
              SUM(s.total) - (
                  SELECT SUM(cost) FROM purchases
                  WHERE owner_id = s.owner_id
                    AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)
              ) AS profit,
              (SELECT SUM(quantity) FROM purchases
                  WHERE owner_id = s.owner_id
                  AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)) AS products_bought,
              (SELECT SUM(cost) FROM purchases
                  WHERE owner_id = s.owner_id
                  AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)) AS stock_cost
       FROM sales s
       JOIN products p ON s.product_id = p.id
       WHERE s.owner_id = ? AND strftime('%Y', s.date) = ?
       GROUP BY strftime('%Y-%m', s.date)
       ORDER BY month ASC
    """, (owner_id, str(year)))
    monthly_stats = c.fetchall()
    monthly_headers = [desc[0] for desc in c.description]  # dynamic headers

    # Yearly summary query
    c.execute("""
        SELECT SUM(s.quantity) AS products_sold,
               SUM(s.total) AS sales_revenue,
               SUM((s.price - p.buy_price) * s.quantity) AS profit,
               (SELECT SUM(quantity) FROM purchases
                WHERE owner_id = ? AND strftime('%Y', date) = ?) AS products_bought,
               (SELECT SUM(cost) FROM purchases
                WHERE owner_id = ? AND strftime('%Y', date) = ?) AS stock_cost
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ? AND strftime('%Y', s.date) = ?
    """, (owner_id, str(year), owner_id, str(year), owner_id, str(year)))
    yearly_summary = c.fetchone()
    yearly_headers = [desc[0] for desc in c.description]  # dynamic headers

    conn.close()

    return render_template(
        'report.html',
        monthly_stats=monthly_stats,
        monthly_headers=monthly_headers,
        yearly_summary=yearly_summary,
        yearly_headers=yearly_headers,
        year=year,
        datetime=datetime
    )

@app.route('/report')
def report_default():
    current_year = datetime.now().year
    return redirect(url_for('report', year=current_year))


@app.route('/shop', methods=['GET', 'POST'])
def shop():
    if 'owner_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    products = conn.execute(
        "SELECT * FROM products WHERE owner_id = ?", 
        (session['owner_id'],)
    ).fetchall()
    fixed_fee = 3.00

    if request.method == 'POST':
        total_sale = 0
        for product in products:
            product_id = product['id']
            sell_price = float(product['sell_price'])
            available_qty = int(product['quantity'])

            qty_str = request.form.get(f'qty_{product_id}', '0')
            try:
                qty = int(qty_str)
            except ValueError:
                qty = 0

            if qty > 0 and qty <= available_qty:
                line_total = qty * sell_price
                total_sale += line_total

                # Insert into sales table
                conn.execute("""
                    INSERT INTO sales (owner_id, product_id, quantity, price, total, date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    session['owner_id'], product_id, qty, sell_price, 
                    line_total, datetime.now()
                ))

                # Update product stock
                conn.execute(
                    "UPDATE products SET quantity = quantity - ? WHERE id = ?", 
                    (qty, product_id)
                )

        # Commit DB changes
        conn.commit()

        # Check payment method
        payment_method = request.form.get('payment_method', 'cash')
        if payment_method == 'card':
            grand_total = total_sale + fixed_fee
            flash(f'Order confirmed with Card! Total (incl. R{fixed_fee:.2f} fee): R{grand_total:.2f}', 'success')
        else:
            grand_total = total_sale
            flash(f'Order confirmed with Cash! Total: R{grand_total:.2f}', 'success')

        return redirect(url_for('shop'))

    return render_template('shop.html', products=products, fixed_fee=fixed_fee)

# ---------- PROGRESS ----------
@app.route('/progress')
def progress():
    if 'owner_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    owner_id = session['owner_id']
    current_year = datetime.now().strftime('%Y')
    current_month = datetime.now().strftime('%Y-%m')

    # Weekly sales data
    weekly_sales = [
        dict(row) for row in conn.execute("""
            SELECT strftime('%W', date) AS week,
                   AVG(price) AS avg_price,
                   SUM(quantity * price) AS revenue
            FROM sales
            WHERE owner_id = ?
              AND strftime('%Y', date) = ?
            GROUP BY week
            ORDER BY week ASC
        """, (owner_id, current_year)).fetchall()
    ]

    # Top products
    top_products = [
        dict(row) for row in conn.execute("""
            SELECT p.name,
                SUM(s.quantity) AS sold,
                SUM(s.quantity * s.price) AS revenue,
                SUM((s.price - p.buy_price) * s.quantity) AS profit,
                p.quantity AS stock
            FROM sales s
            JOIN products p ON s.product_id = p.id
            WHERE s.owner_id = ?
            AND strftime('%Y-%m', s.date) = ?
            GROUP BY p.id
            ORDER BY revenue DESC
            LIMIT 6;
        """, (owner_id, current_month)).fetchall()
    ]

    # Current revenue for this month
    current_revenue = conn.execute("""
        SELECT SUM(quantity * price) FROM sales
        WHERE owner_id = ? AND strftime('%Y-%m', date) = ?
    """, (owner_id, current_month)).fetchone()[0] or 0

    # Max possible revenue (using estimated_max_units if available)
    max_possible = conn.execute("""
        SELECT SUM(sell_price * COALESCE(estimated_max_units, 100)) AS max_possible
        FROM products
        WHERE owner_id = ?
    """, (owner_id,)).fetchone()[0] or 0

    # Get or set monthly target
    target_row = conn.execute("""
        SELECT target, achieved FROM revenue_targets
        WHERE owner_id = ? AND month = ?
    """, (owner_id, current_month)).fetchone()

    milestone_message = None
    if target_row:
        target_revenue = target_row[0]
        # If target reached early, increase by 30% (capped at max_possible)
        if current_revenue >= target_revenue and datetime.now().day < 28:
            new_target = round(min(target_revenue * 1.3, max_possible), 2)
            conn.execute("""
                UPDATE revenue_targets SET target = ?, updated_at = CURRENT_TIMESTAMP
                WHERE owner_id = ? AND month = ?
            """, (new_target, owner_id, current_month))
            conn.commit()
            milestone_message = f"🎉 Target reached! New target set to R{new_target:.2f}"
            target_revenue = new_target

        # At month end, record achieved revenue
        if datetime.now().day >= 28:  # adjust cutoff if needed
            conn.execute("""
                UPDATE revenue_targets SET achieved = ?, updated_at = CURRENT_TIMESTAMP
                WHERE owner_id = ? AND month = ?
            """, (current_revenue, owner_id, current_month))
            conn.commit()
    else:
        # Baseline target
        baseline = 10000.00
        target_revenue = min(baseline, max_possible * 0.9)
        conn.execute("""
            INSERT INTO revenue_targets (owner_id, month, target, achieved)
            VALUES (?, ?, ?, ?)
        """, (owner_id, current_month, target_revenue, 0))
        conn.commit()

    monthly_progress = int((current_revenue / target_revenue) * 100) if target_revenue else 0

    # Categories
    categories = [
        row['category'] for row in conn.execute("""
            SELECT DISTINCT category FROM products WHERE owner_id = ?
        """, (owner_id,)).fetchall() if row['category']
    ]

    # Low stock alerts
    low_stock_products = [
        row['name'] for row in conn.execute("""
            SELECT name FROM products WHERE owner_id = ? AND quantity < 10
        """, (owner_id,)).fetchall()
    ]

    conn.close()

    return render_template('progress.html',
                           weekly_sales=weekly_sales,
                           top_products=top_products,
                           current_revenue=current_revenue,
                           target_revenue=target_revenue,
                           monthly_progress=monthly_progress,
                           categories=categories,
                           low_stock_products=low_stock_products,
                           milestone_message=milestone_message)

@app.route('/admin/owner/<int:owner_id>')
def admin_view_owner(owner_id):
    if not session.get('developer'):
        flash("Developer access required.", "error")
        return redirect(url_for('dev_login'))

    conn = get_db()
    owner = conn.execute("SELECT * FROM owners WHERE id = ?", (owner_id,)).fetchone()
    if not owner:
        flash("Owner not found.", "error")
        return redirect(url_for('dashboard'))

    product_count = conn.execute("SELECT COUNT(*) FROM products WHERE owner_id = ?", (owner_id,)).fetchone()[0]
    total_sales = conn.execute("SELECT SUM(quantity * price) FROM sales WHERE owner_id = ?", (owner_id,)).fetchone()[0] or 0
    low_stock_count = conn.execute("SELECT COUNT(*) FROM products WHERE owner_id = ? AND quantity < 5", (owner_id,)).fetchone()[0]
    products = conn.execute("""
        SELECT p.*, 
               (SELECT SUM(s.quantity * s.price) FROM sales s WHERE s.product_id = p.id) AS total_sales
        FROM products p WHERE p.owner_id = ?
    """, (owner_id,)).fetchall()
    conn.close()

    return render_template('admin_owner_view.html', owner={
        'id': owner['id'],
        'name': owner['username'],
        'email': owner['email'],
        'avatar_url': owner['avatar_url'],
        'shop_name': owner['shop_name'],
        'product_count': product_count,
        'total_sales': total_sales,
        'low_stock_count': low_stock_count,
        'products': products,
        'is_blocked': owner['is_blocked']  # optional if you add block logic
    })

@app.route('/update_owner', methods=['POST'])
def update_owner():
    owner_id = session.get('owner_id')
    if not owner_id:
        flash("No owner is logged in.", "error")
        return redirect(url_for('dashboard'))

    shop_name = request.form['shop_name']  # ✅ Matches your SQL column
    email = request.form['email']
    avatar_url = None

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Handle avatar upload
    avatar = request.files.get('avatar')
    if avatar and avatar.filename:
        filename = secure_filename(avatar.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        avatar.save(filepath)
        avatar_url = f'/static/uploads/{filename}'  # ✅ Correct path

    conn = get_db()
    if avatar_url:
        conn.execute("""
            UPDATE owners SET shop_name = ?, email = ?, avatar_url = ? WHERE id = ?
        """, (shop_name, email, avatar_url, owner_id))
    else:
        conn.execute("""
            UPDATE owners SET shop_name = ?, email = ? WHERE id = ?
        """, (shop_name, email, owner_id))
    conn.commit()
    conn.close()

    flash("Profile updated successfully!", "success")
    return redirect(url_for('owner_details'))  # ✅ No owner_id needed


@app.route('/owner/details')
def owner_details():
    owner_id = session.get('owner_id')
    if not owner_id:
        flash("No owner is logged in.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db()
    conn.row_factory = sqlite3.Row  # ✅ Ensure dictionary-like access
    owner = conn.execute("SELECT * FROM owners WHERE id = ?", (owner_id,)).fetchone()

    if not owner:
        flash("Owner not found.", "error")
        return redirect(url_for('dashboard'))

    # ✅ Calculate total profit based on sales joined with product buy_price
    total_profit = conn.execute("""
        SELECT SUM((s.price - p.buy_price) * s.quantity) AS total_profit
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ?
    """, (owner_id,)).fetchone()[0] or 0

    # Safe access with fallback values
    avatar_url = owner['avatar_url'] if 'avatar_url' in owner.keys() else '/static/default-avatar.png'
    is_blocked = owner['is_blocked'] if 'is_blocked' in owner.keys() else 0
    shop_name = owner['shop_name'] if 'shop_name' in owner.keys() else 'N/A'

    product_count = conn.execute("SELECT COUNT(*) FROM products WHERE owner_id = ?", (owner_id,)).fetchone()[0]
    total_sales = conn.execute("SELECT SUM(quantity * price) FROM sales WHERE owner_id = ?", (owner_id,)).fetchone()[0] or 0
    low_stock_count = conn.execute("SELECT COUNT(*) FROM products WHERE owner_id = ? AND quantity < 5", (owner_id,)).fetchone()[0]

    # ✅ Include per-product profit as well
    products = conn.execute("""
        SELECT p.*, 
               (SELECT SUM((s.price - p.buy_price) * s.quantity) 
                FROM sales s WHERE s.product_id = p.id) AS total_profit,
               (SELECT SUM(s.quantity * s.price) 
                FROM sales s WHERE s.product_id = p.id) AS total_sales
        FROM products p WHERE p.owner_id = ?
    """, (owner_id,)).fetchall()

    conn.close()

    return render_template('owner_details.html', owner={
        'id': owner['id'],
        'username': owner['username'],
        'email': owner['email'],
        'location': owner['location'],
        'cellnumber': owner['cellnumber'],
        'avatar_url': avatar_url,
        'is_blocked': is_blocked,
        'shop_name': shop_name,
        'product_count': product_count,
        'total_sales': total_sales,
        'total_profit': total_profit,   # ✅ now correct
        'low_stock_count': low_stock_count,
        'products': products
    })


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# ---------- EXPORT ----------

def export_query(owner_id, query, filetype="csv"):
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(query, (owner_id,))
    rows = c.fetchall()
    headers = [desc[0] for desc in c.description]  # dynamic column names
    conn.close()

    if filetype == "csv":
        # Build CSV dynamically
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([row[h] for h in headers])
        response = Response(output.getvalue(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename=export.csv'
        return response

    elif filetype == "pdf":
        # Build PDF dynamically
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Report Export", ln=True, align='C')
        pdf.ln(10)

        # Table header
        pdf.set_font("Arial", 'B', 12)
        for h in headers:
            pdf.cell(40, 10, h.title(), 1)
        pdf.ln()

        # Table rows
        pdf.set_font("Arial", '', 12)
        for row in rows:
            for h in headers:
                pdf.cell(40, 10, str(row[h]), 1)
            pdf.ln()

        pdf_bytes = pdf.output(dest='S').encode('latin1')
        return send_file(BytesIO(pdf_bytes),
                         mimetype='application/pdf',
                         as_attachment=True,
                         download_name='export.pdf')
    
@app.route('/export_sales_csv/<int:year>')
def export_sales_csv(year):
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id = session['owner_id']

    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Monthly stats
    c.execute("""
        SELECT strftime('%Y-%m', s.date) AS month,
               (SELECT SUM(quantity) FROM purchases
                WHERE owner_id = s.owner_id AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)) AS products_bought,
               (SELECT SUM(cost) FROM purchases
                WHERE owner_id = s.owner_id AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)) AS stock_cost,
               SUM(s.quantity) AS products_sold,
               SUM(s.total) AS sales_revenue,
               SUM(s.total) - (
                   SELECT SUM(cost) FROM purchases
                   WHERE owner_id = s.owner_id AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)
               ) AS profit
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ? AND strftime('%Y', s.date) = ?
        GROUP BY strftime('%Y-%m', s.date)
        ORDER BY month ASC
    """, (owner_id, str(year)))
    monthly_stats = c.fetchall()

    # Yearly summary
    c.execute("""
        SELECT (SELECT SUM(quantity) FROM purchases
                WHERE owner_id = ? AND strftime('%Y', date) = ?) AS products_bought,
               (SELECT SUM(cost) FROM purchases
                WHERE owner_id = ? AND strftime('%Y', date) = ?) AS stock_cost,
               SUM(s.quantity) AS products_sold,
               SUM(s.total) AS sales_revenue,
               SUM((s.price - p.buy_price) * s.quantity) AS profit
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ? AND strftime('%Y', s.date) = ?
    """, (owner_id, str(year), owner_id, str(year), owner_id, str(year)))
    yearly_summary = c.fetchone()
    conn.close()

    # Build CSV
    output = StringIO()
    writer = csv.writer(output)

    # Monthly section
    writer.writerow(['Month', 'Products Bought', 'Stock Cost (R)', 'Products Sold', 'Sales Revenue (R)', 'Profit (R)'])
    for stat in monthly_stats:
        writer.writerow([
            stat['month'],
            stat['products_bought'] or 0,
            f"{stat['stock_cost'] or 0:.2f}",
            stat['products_sold'] or 0,
            f"{stat['sales_revenue'] or 0:.2f}",
            f"{stat['profit'] or 0:.2f}"
        ])

    # Blank line then yearly summary
    writer.writerow([])
    writer.writerow(['Year', 'Products Bought', 'Stock Cost (R)', 'Products Sold', 'Sales Revenue (R)', 'Profit (R)'])
    writer.writerow([
        year,
        yearly_summary['products_bought'] or 0,
        f"{yearly_summary['stock_cost'] or 0:.2f}",
        yearly_summary['products_sold'] or 0,
        f"{yearly_summary['sales_revenue'] or 0:.2f}",
        f"{yearly_summary['profit'] or 0:.2f}"
    ])

    resp = Response(output.getvalue(), mimetype='text/csv')
    resp.headers['Content-Disposition'] = f'attachment; filename=report_{year}.csv'
    return resp

@app.route('/export_sales_pdf/<int:year>')
def export_sales_pdf(year):
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id = session['owner_id']

    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Monthly stats query
    c.execute("""
        SELECT strftime('%Y-%m', s.date) AS month,
               (SELECT SUM(quantity) FROM purchases
                WHERE owner_id = s.owner_id AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)) AS products_bought,
               (SELECT SUM(cost) FROM purchases
                WHERE owner_id = s.owner_id AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)) AS stock_cost,
               SUM(s.quantity) AS products_sold,
               SUM(s.total) AS sales_revenue,
               SUM(s.total) - (
                   SELECT SUM(cost) FROM purchases
                   WHERE owner_id = s.owner_id AND strftime('%Y-%m', date) = strftime('%Y-%m', s.date)
               ) AS profit
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ? AND strftime('%Y', s.date) = ?
        GROUP BY strftime('%Y-%m', s.date)
        ORDER BY month ASC
    """, (owner_id, str(year)))
    monthly_stats = c.fetchall()

    # Yearly summary query
    c.execute("""
        SELECT (SELECT SUM(quantity) FROM purchases
                WHERE owner_id = ? AND strftime('%Y', date) = ?) AS products_bought,
               (SELECT SUM(cost) FROM purchases
                WHERE owner_id = ? AND strftime('%Y', date) = ?) AS stock_cost,
               SUM(s.quantity) AS products_sold,
               SUM(s.total) AS sales_revenue,
               SUM((s.price - p.buy_price) * s.quantity) AS profit
        FROM sales s
        JOIN products p ON s.product_id = p.id
        WHERE s.owner_id = ? AND strftime('%Y', s.date) = ?
    """, (owner_id, str(year), owner_id, str(year), owner_id, str(year)))
    yearly_summary = c.fetchone()
    conn.close()

    # Build PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Sales Report {year}", ln=True, align='C')
    pdf.ln(10)

    # Headers
    headers = ['Month', 'Products Bought', 'Stock Cost (R)', 'Products Sold', 'Sales Revenue (R)', 'Profit (R)']

    header_map = {
        "Month": "month",
        "Products Bought": "products_bought",
        "Stock Cost (R)": "stock_cost",
        "Products Sold": "products_sold",
        "Sales Revenue (R)": "sales_revenue",
        "Profit (R)": "profit"
    }

    # 🔎 Auto-calculate column widths
    pdf.set_font("Arial", '', 12)
    col_widths = []
    for h in headers:
        max_width = pdf.get_string_width(h) + 6
        for stat in monthly_stats:
            text = str(stat[header_map[h]] or 0)
            max_width = max(max_width, pdf.get_string_width(text) + 6)
        col_widths.append(max_width)
    # Monthly table
    pdf.set_font("Arial", 'B', 12)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 10, h, 1)
    pdf.ln()

    pdf.set_font("Arial", '', 12)
    for stat in monthly_stats:
        pdf.cell(col_widths[0], 10, stat['month'], 1)
        pdf.cell(col_widths[1], 10, str(stat['products_bought'] or 0), 1)
        pdf.cell(col_widths[2], 10, f"{stat['stock_cost'] or 0:.2f}", 1)
        pdf.cell(col_widths[3], 10, str(stat['products_sold'] or 0), 1)
        pdf.cell(col_widths[4], 10, f"{stat['sales_revenue'] or 0:.2f}", 1)
        pdf.cell(col_widths[5], 10, f"{stat['profit'] or 0:.2f}", 1)
        pdf.ln()

    pdf.ln(10)

    # Yearly summary table
    pdf.set_font("Arial", 'B', 12)
    summary_headers = ['Year', 'Products Bought', 'Stock Cost (R)', 'Products Sold', 'Sales Revenue (R)', 'Profit (R)']
    for i, h in enumerate(summary_headers):
        pdf.cell(col_widths[i], 10, h, 1)
    pdf.ln()

    pdf.set_font("Arial", '', 12)
    pdf.cell(col_widths[0], 10, str(year), 1)
    pdf.cell(col_widths[1], 10, str(yearly_summary['products_bought'] or 0), 1)
    pdf.cell(col_widths[2], 10, f"{yearly_summary['stock_cost'] or 0:.2f}", 1)
    pdf.cell(col_widths[3], 10, str(yearly_summary['products_sold'] or 0), 1)
    pdf.cell(col_widths[4], 10, f"{yearly_summary['sales_revenue'] or 0:.2f}", 1)
    pdf.cell(col_widths[5], 10, f"{yearly_summary['profit'] or 0:.2f}", 1)

    pdf_bytes = pdf.output(dest='S').encode('latin1')
    return send_file(BytesIO(pdf_bytes),
                     mimetype='application/pdf',
                     as_attachment=True,
                     download_name=f"report_{year}.pdf")

# ---------- DEVELOPER ----------
@app.route('/dev_login', methods=['GET', 'POST'])
def dev_login():
    if request.method == 'POST':
        data = request.form
        conn = get_db()
        dev = conn.execute("SELECT * FROM developer WHERE username = ?", (data['username'],)).fetchone()
        conn.close()

        # Check credentials
        if dev and bcrypt.checkpw(data['password'].encode(), dev['password_hash']):
            # Store the actual developer ID in the session
            session['developer_id'] = dev['id']
            flash('Login successful!', 'success')
            return redirect(url_for('dev_dashboard'))
        else:
            flash('Invalid developer credentials.', 'danger')

    return render_template('dev_login.html')

@app.route('/dev_dashboard')
def dev_dashboard():
    if not session.get('developer_id'):
        flash("Developer access required.", "error")
        return redirect(url_for('dev_login'))

    conn = get_db()
    conn.row_factory = sqlite3.Row

    # Summary counts
    total_owners = conn.execute("SELECT COUNT(*) FROM owners").fetchone()[0]
    active_accounts = conn.execute("SELECT COUNT(*) FROM owners WHERE status='active'").fetchone()[0]
    blocked_accounts = conn.execute("SELECT COUNT(*) FROM owners WHERE status='blocked'").fetchone()[0]
    owners_paid = conn.execute("""
        SELECT COUNT(DISTINCT owner_id)
        FROM transactions
        WHERE status='paid'
          AND strftime('%m', date)=strftime('%m','now')
          AND strftime('%Y', date)=strftime('%Y','now')
    """).fetchone()[0]

    # Top 5 performing owners by profit percentage
    top_owners = conn.execute("""
        WITH owner_stats AS (
            SELECT o.id,
                o.username,
                -- Current profit = total sales revenue - total stock cost
                COALESCE(SUM(s.price * s.quantity), 0) 
                    - COALESCE(SUM(p.cost), 0) AS current_profit,

                -- Max possible profit = (sell_price - buy_price) * total quantity bought
                COALESCE(SUM((pr.sell_price - pr.buy_price) * pr.quantity), 0) AS max_profit
            FROM owners o
            LEFT JOIN purchases p ON o.id = p.owner_id
            LEFT JOIN sales s ON o.id = s.owner_id
            LEFT JOIN products pr ON o.id = pr.owner_id
            GROUP BY o.id
        )
        SELECT username,
            ROUND((current_profit * 100.0) / NULLIF(max_profit, 0), 2) AS progress
        FROM owner_stats
        WHERE max_profit > 0
        ORDER BY progress DESC
        LIMIT 5;
    """).fetchall()

    top_owners = [dict(row) for row in top_owners]


    # Payment compliance (paid vs unpaid this month)
    compliance = conn.execute("""
        SELECT status, COUNT(*) AS count
        FROM transactions
        WHERE strftime('%m', date)=strftime('%m','now')
          AND strftime('%Y', date)=strftime('%Y','now')
        GROUP BY status
    """).fetchall()
    compliance = [dict(row) for row in compliance]   # ✅ convert to dicts

    # Monthly registrations vs attrition
    registered_this_month = conn.execute("""
        SELECT COUNT(*) FROM owners
        WHERE strftime('%m', registered_date)=strftime('%m','now')
          AND strftime('%Y', registered_date)=strftime('%Y','now')
    """).fetchone()[0]

    left_this_month = conn.execute("""
        SELECT COUNT(*) FROM owners
        WHERE status='blocked'
          AND strftime('%m', blocked_date)=strftime('%m','now')
          AND strftime('%Y', blocked_date)=strftime('%Y','now')
    """).fetchone()[0]

    # Registration growth by quarter
    growth = conn.execute("""
        SELECT
          CASE
            WHEN strftime('%m', registered_date) IN ('01','02','03') THEN 'Q1'
            WHEN strftime('%m', registered_date) IN ('04','05','06') THEN 'Q2'
            WHEN strftime('%m', registered_date) IN ('07','08','09') THEN 'Q3'
            ELSE 'Q4'
          END AS quarter,
          COUNT(*) AS registrations
        FROM owners
        GROUP BY quarter
    """).fetchall()
    growth = [dict(row) for row in growth]   # ✅ convert to dicts

    conn.close()

    return render_template(
        'dev_dashboard.html',
        total_owners=total_owners,
        active_accounts=active_accounts,
        blocked_accounts=blocked_accounts,
        owners_paid=owners_paid,
        top_owners=top_owners,
        compliance=compliance,
        registered_this_month=registered_this_month,
        left_this_month=left_this_month,
        growth=growth
    )


@app.route('/dev_change_password', methods=['GET', 'POST'])
def dev_change_password():
    if not session.get('developer'):
        return redirect(url_for('dev_login'))
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        conn = get_db()
        dev = conn.execute("SELECT * FROM developer WHERE id = 1").fetchone()
        if not bcrypt.checkpw(current.encode(), dev['password_hash']):
            flash('Incorrect current password.', 'danger')
        elif new != confirm:
            flash('New passwords do not match.', 'warning')
        else:
            hashed = bcrypt.hashpw(new.encode(), bcrypt.gensalt())
            conn.execute("UPDATE developer SET password_hash = ? WHERE id = 1", (hashed,))
            conn.commit()
            flash('Password updated successfully.', 'success')
        conn.close()
    return render_template('dev_change_password.html')

@app.route('/account_management')
def account_management():
    conn = get_db()
    conn.row_factory = sqlite3.Row
    owners = conn.execute("""
        SELECT o.id, o.username, o.email, o.cellnumber, o.location,
               o.status, COUNT(p.id) AS product_count
        FROM owners o
        LEFT JOIN products p ON o.id = p.owner_id
        GROUP BY o.id
    """).fetchall()
    conn.close()
    return render_template('account_management.html', owners=owners)


@app.route('/manage_accounts', methods=['POST'])
def manage_accounts():
    selected_ids = request.form.getlist('selected_ids')
    action = request.form['action']

    if not selected_ids:
        flash("No accounts selected.", "warning")
        return redirect(url_for('account_management'))

    conn = get_db()
    if action == 'block':
        conn.executemany("UPDATE owners SET status = 'blocked' WHERE id = ?", [(oid,) for oid in selected_ids])
        flash(f"Blocked {len(selected_ids)} accounts.", "success")

    elif action == 'unblock':
        conn.executemany("UPDATE owners SET status = 'active' WHERE id = ?", [(oid,) for oid in selected_ids])
        flash(f"Unblocked {len(selected_ids)} accounts.", "success")

    elif action == 'delete':
        conn.executemany("DELETE FROM owners WHERE id = ?", [(oid,) for oid in selected_ids])
        flash(f"Deleted {len(selected_ids)} accounts.", "danger")

    conn.commit()
    conn.close()
    return redirect(url_for('account_management'))

@app.route('/transactions')
def transactions():
    if not session.get('developer_id'):
        flash("Developer access required.", "error")
        return redirect(url_for('dev_login'))

    conn = get_db()
    conn.row_factory = sqlite3.Row

    # Get all owners
    owners = conn.execute("SELECT id, username FROM owners").fetchall()

    # Get all transactions for current year
    txns = conn.execute("""
        SELECT owner_id, strftime('%m', date) AS month, status
        FROM transactions
        WHERE strftime('%Y', date) = strftime('%Y', 'now')
    """).fetchall()
    conn.close()

    # Organize into dict {owner_id: {month: status}}
    owner_data = {}
    for o in owners:
        owner_data[o['id']] = {
            'username': o['username'],
            'months': {}
        }
    for t in txns:
        month = int(t['month'])
        owner_data[t['owner_id']]['months'][month] = t['status']

    return render_template("transactions.html", owners=owner_data)


if __name__ == "__main__":
    app.run(debug=True)
