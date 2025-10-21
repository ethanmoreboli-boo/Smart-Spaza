from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3, os, io, csv
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from fpdf import FPDF
from io import StringIO, BytesIO

app = Flask(__name__)
app.secret_key = os.getenv("SMARTSPAZA_SECRET", "smartspaza_secret")
DATABASE = "database/shop.db"

# -----------------------------
# DB Init
# -----------------------------
def init_db():
    os.makedirs("database", exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS owners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        business_name TEXT NOT NULL
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        buy_price REAL NOT NULL,
        sell_price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        owner_id INTEGER,
        FOREIGN KEY(owner_id) REFERENCES owners(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        total REAL NOT NULL,
        date TEXT NOT NULL,
        owner_id INTEGER,
        FOREIGN KEY(product_id) REFERENCES products(id),
        FOREIGN KEY(owner_id) REFERENCES owners(id)
    )''')
    conn.commit()
    conn.close()
init_db()

def get_db_conn():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=='POST':
        username=request.form.get('username','').strip()
        password=request.form.get('password')
        business_name=request.form.get('business_name','').strip()
        if not username or not password or not business_name:
            flash("Please fill all fields.", "error")
            return redirect(url_for('signup'))
        hashed=generate_password_hash(password)
        conn=get_db_conn()
        c=conn.cursor()
        try:
            c.execute("INSERT INTO owners(username,password,business_name) VALUES(?,?,?)",
                      (username,hashed,business_name))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username exists.", "error")
            conn.close()
            return redirect(url_for('signup'))
        conn.close()
        flash("Account created. Login.", "success")
        return redirect(url_for('login'))
    return render_template("signup.html")

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form.get('username').strip()
        password=request.form.get('password')
        conn=get_db_conn()
        c=conn.cursor()
        c.execute("SELECT id,password FROM owners WHERE username=?",(username,))
        owner=c.fetchone()
        conn.close()
        if owner and check_password_hash(owner['password'], password):
            session['owner_id']=owner['id']
            flash("Logged in successfully.","success")
            return redirect(url_for('main'))
        flash("Invalid login.","error")
        return redirect(url_for('login'))
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('owner_id', None)
    flash("Logged out.","info")
    return redirect(url_for('index'))

# -----------------------------
# Dashboard
# -----------------------------
@app.route('/main')
def main():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id=session['owner_id']
    conn=get_db_conn()
    c=conn.cursor()
    c.execute("SELECT business_name FROM owners WHERE id=?",(owner_id,))
    row=c.fetchone()
    business_name=row['business_name'] if row else "My Shop"
    c.execute("SELECT id,name,buy_price,sell_price,quantity FROM products WHERE owner_id=?",(owner_id,))
    products=c.fetchall()
    conn.close()
    return render_template("main.html", business_name=business_name, products=products)

# -----------------------------
# Add Product
# -----------------------------
@app.route('/add_product', methods=['GET','POST'])
def add_product():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    if request.method=='POST':
        owner_id=session['owner_id']
        name=request.form.get('name','').strip()
        try:
            buy_price=float(request.form['buy_price'])
            sell_price=float(request.form['sell_price'])
            quantity=int(request.form['quantity'])
        except:
            flash("Invalid input","error")
            return redirect(url_for('add_product'))
        conn=get_db_conn()
        c=conn.cursor()
        c.execute("INSERT INTO products(name,buy_price,sell_price,quantity,owner_id) VALUES(?,?,?,?,?)",
                  (name,buy_price,sell_price,quantity,owner_id))
        conn.commit()
        conn.close()
        flash("Product added.","success")
        return redirect(url_for('main'))
    return render_template("add_product.html")

# -----------------------------
# Record Sale
# -----------------------------
@app.route('/record_sale')
def record_sale():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id=session['owner_id']
    conn=get_db_conn()
    c=conn.cursor()
    c.execute("""SELECT s.id, p.name, s.quantity, s.total, s.date
                 FROM sales s JOIN products p ON s.product_id=p.id
                 WHERE s.owner_id=?
                 ORDER BY s.date DESC""",(owner_id,))
    sales=c.fetchall()
    conn.close()
    return render_template("record_sale.html", sales=sales)

# -----------------------------
# Report Page
# -----------------------------
@app.route('/report')
def report():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id=session['owner_id']
    conn=get_db_conn()
    c=conn.cursor()
    c.execute("""SELECT p.name, SUM(s.quantity) AS qty, SUM(s.total) AS revenue,
                 SUM(s.total - (p.buy_price*s.quantity)) AS profit
                 FROM sales s JOIN products p ON s.product_id=p.id
                 WHERE s.owner_id=? GROUP BY p.name""",(owner_id,))
    report_data=c.fetchall()
    grand_total=sum(row['profit'] for row in report_data)
    conn.close()
    return render_template("report.html", report=report_data, grand_total=grand_total)

# -----------------------------
# CSV Export
# -----------------------------
@app.route('/export_sales_csv')
def export_sales_csv():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id=session['owner_id']
    conn=get_db_conn()
    c=conn.cursor()
    c.execute("""SELECT p.name, s.quantity, s.total, (s.total - p.buy_price*s.quantity) AS profit
                 FROM sales s JOIN products p ON s.product_id=p.id
                 WHERE s.owner_id=?""",(owner_id,))
    rows=c.fetchall()
    conn.close()
    output=StringIO()
    writer=csv.writer(output)
    writer.writerow(['Product','Quantity','Total','Profit'])
    for row in rows:
        writer.writerow([row['name'],row['quantity'],"%.2f"%row['total'],"%.2f"%row['profit']])
    output.seek(0)
    return send_file(BytesIO(output.getvalue().encode('utf-8')),
                     mimetype='text/csv', as_attachment=True, download_name='sales.csv')

# -----------------------------
# PDF Export
# -----------------------------
@app.route('/export_sales_pdf')
def export_sales_pdf():
    if 'owner_id' not in session:
        return redirect(url_for('login'))
    owner_id=session['owner_id']
    conn=get_db_conn()
    c=conn.cursor()
    c.execute("""SELECT p.name, s.quantity, s.total, (s.total - p.buy_price*s.quantity) AS profit
                 FROM sales s JOIN products p ON s.product_id=p.id
                 WHERE s.owner_id=?""",(owner_id,))
    rows=c.fetchall()
    conn.close()
    pdf=FPDF()
    pdf.add_page()
    pdf.set_font("Arial",'B',16)
    pdf.cell(0,10,"Sales Report",ln=True,align='C')
    pdf.ln(10)
    pdf.set_font("Arial",'',12)
    for row in rows:
        pdf.cell(0,8,f"{row['name']} | Qty: {row['quantity']} | Total: R{row['total']:.2f} | Profit: R{row['profit']:.2f}",ln=True)
    pdf_output=BytesIO()
    pdf.output(pdf_output)
    pdf_output.seek(0)
    return send_file(pdf_output,mimetype='application/pdf',as_attachment=True,download_name='sales_report.pdf')

# -----------------------------
# Progress Page
# -----------------------------

# -----------------------------
# Customer Shop
# -----------------------------
@app.route('/shop/<int:owner_id>', methods=['GET','POST'])
def shop(owner_id):
    conn=get_db_conn()
    c=conn.cursor()
    c.execute("SELECT id,name,sell_price,quantity FROM products WHERE owner_id=?",(owner_id,))
    products=c.fetchall()
    conn.close()
    VAT_RATE=0.15
    FIXED_CHARGE=3
    if request.method=='POST':
        order_data=request.form
        conn=get_db_conn()
        c=conn.cursor()
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        purchased=[k for k in order_data if k.startswith("qty_") and int(order_data[k])>0]
        num_products=len(purchased) if purchased else 1
        for key,value in order_data.items():
            if key.startswith("qty_"):
                pid=int(key.split("_")[1])
                qty=int(value)
                if qty<=0: continue
                c.execute("SELECT sell_price,quantity FROM products WHERE id=? AND owner_id=?",(pid,owner_id))
                product=c.fetchone()
                if not product: continue
                sell_price,current_stock=product
                if qty>current_stock: continue
                subtotal=sell_price*qty
                vat=subtotal*VAT_RATE
                charge=FIXED_CHARGE/num_products
                total=subtotal+vat+charge
                c.execute("INSERT INTO sales(product_id,quantity,total,date,owner_id) VALUES(?,?,?,?,?)",
                          (pid,qty,total,date,owner_id))
                c.execute("UPDATE products SET quantity=? WHERE id=?",(current_stock-qty,pid))
        conn.commit()
        conn.close()
        flash("Order confirmed!","success")
        return redirect(url_for('shop',owner_id=owner_id))
    return render_template("shop.html",products=products,owner_id=owner_id,vat=VAT_RATE,fixed_fee=FIXED_CHARGE)


@app.route('/progress')
def progress():
    if 'owner_id' not in session:
        return redirect(url_for('login'))

    owner_id = session['owner_id']
    conn = get_db_conn()
    c = conn.cursor()

    # --- Top 4 Products ---
    c.execute("""SELECT p.name, SUM(s.quantity) AS sold,
                        SUM(s.total) AS revenue,
                        SUM(s.total - p.buy_price*s.quantity) AS profit,
                        p.quantity AS stock
                 FROM products p LEFT JOIN sales s ON s.product_id=p.id
                 WHERE p.owner_id=?
                 GROUP BY p.id
                 ORDER BY revenue DESC LIMIT 4""", (owner_id,))
    top_products_data = c.fetchall()
    top_products = []
    for row in top_products_data:
        top_products.append({
            'name': row['name'],
            'sold': row['sold'] or 0,
            'revenue': row['revenue'] or 0.0,
            'profit': row['profit'] or 0.0,
            'stock': row['stock']
        })

    # --- Weekly Profits (Last 4 weeks) ---
    weekly_sales = []
    today = datetime.today()
    for i in range(4, 0, -1):
        start_week = today - timedelta(days=i*7)
        end_week = start_week + timedelta(days=6)
        c.execute("""SELECT SUM(s.total - p.buy_price*s.quantity) AS profit
                     FROM sales s JOIN products p ON p.id=s.product_id
                     WHERE s.owner_id=? AND date(s.date) BETWEEN ? AND ?""",
                  (owner_id, start_week.strftime("%Y-%m-%d"), end_week.strftime("%Y-%m-%d")))
        row = c.fetchone()
        weekly_sales.append({
            'week': f"Week {today.isocalendar()[1]-i+1}",
            'profit': row['profit'] or 0.0
        })

    # --- Low stock products ---
    c.execute("SELECT name FROM products WHERE owner_id=? AND quantity<5", (owner_id,))
    low_stock = [r['name'] for r in c.fetchall()]

    # --- Monthly Revenue ---
    c.execute("SELECT SUM(total) AS revenue FROM sales WHERE owner_id=? AND strftime('%m',date)=?",
              (owner_id, today.strftime("%m")))
    current_revenue = c.fetchone()['revenue'] or 0.0
    target_revenue = 20000  # example target
    monthly_progress = int((current_revenue/target_revenue)*100) if target_revenue > 0 else 0
    monthly_progress = min(monthly_progress, 100)
    milestone_message = "🎉 Monthly revenue target reached!" if monthly_progress >= 100 else None

    # --- Example categories (can be replaced with real categories) ---
    categories = [p['name'] for p in top_products]  # simple placeholder
    filter_date = ""  # default empty
    filter_category = ""  # default empty

    conn.close()

    return render_template(
        "progress.html",
        top_products=top_products,
        weekly_sales=weekly_sales,
        low_stock_products=low_stock,
        current_revenue=current_revenue,
        target_revenue=target_revenue,
        monthly_progress=monthly_progress,
        milestone_message=milestone_message,
        filter_date=filter_date,
        categories=categories,
        filter_category=filter_category
    )

# -----------------------------
# Developer Page
# -----------------------------
@app.route('/developer')
def developer():
    return render_template("developer.html")

# -----------------------------
# Run
# -----------------------------
if __name__=="__main__":
    app.run(debug=True)
