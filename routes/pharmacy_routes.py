from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, Response
import MySQLdb.cursors
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import qrcode
from io import BytesIO
import base64
from uuid import uuid4
from datetime import datetime, timedelta
import json
import secrets
from mail import send_otp_email  # Import the function from mail.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

pharmacy_bp = Blueprint('pharmacy', __name__)

db = None

UPI_GATEWAY_API_KEY = "1a2c85dc-b447-45f6-bc2b-3b607edef0ba"
UPI_GATEWAY_CREATE_ORDER_URL = "https://api.ekqr.in/api/create_order"
UPI_GATEWAY_CHECK_STATUS_URL = "https://api.ekqr.in/api/check_order_status"

def init_pharmacy(mysql):
    global db
    db = mysql
    return pharmacy_bp

def verify_signature(public_key_pem, data, signature):
    try:
        if not public_key_pem or not data or not signature:
            print("Missing required inputs for signature verification")
            return False
        
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        signature_bytes = base64.b64decode(signature.strip())
        
        public_key.verify(
            signature_bytes,
            data.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Signature verification successful")
        return True
    
    except ValueError as ve:
        print(f"Signature verification failed - ValueError: {str(ve)}")
        return False
    except Exception as e:
        print(f"Signature verification failed - Exception: {str(e)}")
        return False

@pharmacy_bp.route('/pharmacy', methods=['GET'])
def pharmacy():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))
    
    if 'loggedin' not in session:
        flash("Please log in to access pharmacy.", 'warning')
        return redirect(url_for('auth.login'))
    
    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        cursor.execute("""
            SELECT p.prescription_id, p.dosage, p.duration, p.instructions, p.status,
                   m.name as medicine_name, m.brand, m.price,
                   d.name as doctor_name
            FROM prescriptions p
            JOIN medicines m ON p.medicine_id = m.medicine_id
            JOIN doctors d ON p.doctor_id = d.doctor_id
            WHERE p.patient_id = %s
            ORDER BY p.prescribed_date DESC
        """, (session['patient_id'],))
        prescriptions = cursor.fetchall()
        
        cursor.execute("SELECT pharmacy_id, name, address FROM pharmacies WHERE is_active = 1")
        pharmacies = cursor.fetchall()
        
        return render_template('pharmacy.html',
                             prescriptions=prescriptions,
                             pharmacies=pharmacies)
    
    finally:
        if cursor:
            cursor.close()

@pharmacy_bp.route('/create_pharmacy_order', methods=['POST'])
def create_pharmacy_order():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))
    
    if 'loggedin' not in session:
        flash("Please log in to place an order.", 'warning')
        return redirect(url_for('auth.login'))
    
    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        prescription_id = request.form.get('prescription_id')
        pharmacy_id = request.form.get('pharmacy_id')
        
        if not prescription_id or not pharmacy_id:
            flash('Please select a prescription and pharmacy', 'danger')
            return redirect(url_for('pharmacy.pharmacy'))
        
        cursor.execute("""
            SELECT p.*, m.price, m.name as medicine_name, d.public_key, d.doctor_id
            FROM prescriptions p
            JOIN medicines m ON p.medicine_id = m.medicine_id
            JOIN doctors d ON p.doctor_id = d.doctor_id
            WHERE p.prescription_id = %s AND p.patient_id = %s AND p.status = 'Pending'
        """, (prescription_id, session['patient_id']))
        prescription = cursor.fetchone()
        
        if not prescription:
            flash('Invalid or unavailable prescription', 'danger')
            return redirect(url_for('pharmacy.pharmacy'))
        
        instructions = prescription['instructions'] if prescription['instructions'] is not None else 'None'
        appointment_id = prescription['appointment_id'] if prescription['appointment_id'] is not None else 'None'
        prescription_message = f"{prescription['doctor_id']}|{session['patient_id']}|{appointment_id}|{prescription['medicine_id']}|{prescription['dosage']}|{prescription['duration']}|{instructions}"
        print(f"Prescription message to verify: {prescription_message}")
        print(f"Signature from DB: {prescription['signature']}")
        print(f"Public key from DB: {prescription['public_key']}")
        
        if not verify_signature(prescription['public_key'], prescription_message, prescription['signature']):
            flash('Prescription signature verification failed', 'danger')
            return redirect(url_for('pharmacy.pharmacy'))
        
        cursor.execute("""
            SELECT stock_quantity 
            FROM pharmacy_inventory 
            WHERE pharmacy_id = %s AND medicine_id = %s
        """, (pharmacy_id, prescription['medicine_id']))
        inventory = cursor.fetchone()
        
        if not inventory or inventory['stock_quantity'] <= 0:
            flash('Medicine out of stock at selected pharmacy', 'warning')
            return redirect(url_for('pharmacy.pharmacy'))
        
        amount = str(prescription['price'])
        client_txn_id = str(uuid4()).replace('-', '')[:10]
        txn_date = datetime.now().strftime('%d-%m-%Y')
        
        session['pending_pharmacy_order'] = {
            'prescription_id': prescription_id,
            'pharmacy_id': pharmacy_id,
            'patient_id': session['patient_id'],
            'amount': amount,
            'client_txn_id': client_txn_id,
            'txn_date': txn_date,
            'medicine_id': prescription['medicine_id'],
            'payment_initiated': datetime.now().timestamp()
        }
        
        redirect_url = "https://monkfish-engaging-kiwi.ngrok-free.app/pharmacy"
        payload = {
            "key": UPI_GATEWAY_API_KEY,
            "client_txn_id": client_txn_id,
            "amount": amount,
            "p_info": f"Medicine: {prescription['medicine_name']}",
            "customer_name": session['name'],
            "customer_email": "patient@example.com",
            "customer_mobile": "9876543210",
            "redirect_url": redirect_url,
            "udf1": "", "udf2": "", "udf3": ""
        }
        
        headers = {"Content-Type": "application/json"}
        try:
            response = requests.post(UPI_GATEWAY_CREATE_ORDER_URL, json=payload, headers=headers)
            result = response.json()
            print(f"Payment initiation response: {result}")
            
            if result.get("status") and "data" in result:
                payment_url = result["data"]["payment_url"]
                qr = qrcode.make(payment_url)
                buffer = BytesIO()
                qr.save(buffer, format="PNG")
                qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
                
                return render_template('pharmacy.html',
                                     prescriptions=[prescription],
                                     pharmacies=[],
                                     show_payment=True,
                                     amount=amount,
                                     payment_url=payment_url,
                                     qr_code=qr_code,
                                     client_txn_id=client_txn_id)
            else:
                flash(f"Payment initiation failed: {result.get('msg', 'Unknown error')}", "danger")
        
        except Exception as e:
            flash(f"Payment gateway error: {str(e)}", "danger")
        
        return redirect(url_for('pharmacy.pharmacy'))
    
    finally:
        if cursor:
            cursor.close()

@pharmacy_bp.route('/check_pharmacy_payment', methods=['POST'])
def check_pharmacy_payment():
    if db is None:
        return jsonify({'status': 'ERROR', 'message': 'Database connection not initialized'}), 500
    
    data = request.get_json()
    client_txn_id = data.get('client_txn_id')
    
    if not client_txn_id or 'pending_pharmacy_order' not in session or session['pending_pharmacy_order']['client_txn_id'] != client_txn_id:
        return jsonify({'status': 'INVALID', 'message': 'No matching transaction found'}), 400
    
    cursor = None
    try:
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        
        order = session['pending_pharmacy_order']
        status_payload = {
            "key": UPI_GATEWAY_API_KEY,
            "client_txn_id": client_txn_id,
            "txn_date": order['txn_date']
        }
        
        response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
        result = response.json()
        print(f"Payment status response: {result}")
        
        if result.get("status"):
            payment_status = result["data"].get("status", "").lower()
            
            if payment_status == "success":
                cursor.execute("SELECT * FROM pharmacy_orders WHERE prescription_id = %s", 
                             (order['prescription_id'],))
                existing = cursor.fetchone()
                
                if not existing:
                    cursor.execute("""
                        INSERT INTO pharmacy_orders (prescription_id, pharmacy_id, patient_id, total_amount, delivery_address, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (order['prescription_id'],
                          order['pharmacy_id'],
                          order['patient_id'],
                          order['amount'],
                          session.get('address', 'Default Address'),
                          'Pending'))
                    
                    cursor.execute("""
                        UPDATE prescriptions 
                        SET status = 'Verified'
                        WHERE prescription_id = %s
                    """, (order['prescription_id'],))
                    
                    cursor.execute("""
                        UPDATE pharmacy_inventory 
                        SET stock_quantity = stock_quantity - 1 
                        WHERE pharmacy_id = %s AND medicine_id = %s
                    """, (order['pharmacy_id'], order['medicine_id']))
                    
                    db.connection.commit()
                    print(f"Order created: {order}")
                
                session.pop('pending_pharmacy_order', None)
                flash("Order placed successfully!", "success")
            
            elif payment_status == "failed":
                session.pop('pending_pharmacy_order', None)
                flash("Payment failed. Please try again.", "danger")
            
            return jsonify({
                'status': payment_status.upper(),
                'message': result["data"].get("msg", "")
            })
        
        return jsonify({'status': 'UNKNOWN', 'message': 'Could not determine payment status'})
    
    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500
    
    finally:
        if cursor:
            cursor.close()

@pharmacy_bp.route('/pharmacy_login', methods=['GET', 'POST'])
def pharmacy_login():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.home'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM pharmacies WHERE email = %s", (email,))
        pharmacy = cursor.fetchone()
        cursor.close()
        
        if pharmacy and check_password_hash(pharmacy['password'], password):
            session['pharmacy_loggedin'] = True
            session['pharmacy_id'] = pharmacy['pharmacy_id']
            session['pharmacy_name'] = pharmacy['name']
            flash('Login successful!', 'success')
            return redirect(url_for('pharmacy.pharmacy_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('pharmacy_login.html')

@pharmacy_bp.route('/pharmacy_register', methods=['GET', 'POST'])
def pharmacy_register():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.home'))
    
    if request.method == 'POST':
        name = request.form['name']
        license_number = request.form['license_number']
        address = request.form['address']
        phone = request.form['phone']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM pharmacies WHERE email = %s OR phone = %s OR license_number = %s", 
                      (email, phone, license_number))
        existing = cursor.fetchone()
        
        if existing:
            flash('Email, phone, or license number already exists', 'danger')
        else:
            cursor.execute("""
                INSERT INTO pharmacies (name, license_number, address, phone, email, password, is_active)
                VALUES (%s, %s, %s, %s, %s, %s, 1)
            """, (name, license_number, address, phone, email, password))
            db.connection.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('pharmacy.pharmacy_login'))
        
        cursor.close()
    
    return render_template('pharmacy_register.html')

@pharmacy_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.home'))
    
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        email = request.form['email']
        
        cursor.execute('SELECT * FROM pharmacies WHERE email = %s', (email,))
        pharmacy = cursor.fetchone()
        
        if pharmacy:
            reset_token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=1)
            
            cursor.execute("""
                UPDATE pharmacies 
                SET reset_token = %s, token_expiry = %s 
                WHERE email = %s
            """, (reset_token, expiry, email))
            db.connection.commit()
            
            reset_link = url_for('pharmacy.reset_password', token=reset_token, _external=True)
            email_body = f"To reset your password, click this link: {reset_link}\nValid for 1 hour."
            
            if send_otp_email(email, email_body):
                flash('Password reset link sent to your email.', 'success')
            else:
                flash('Failed to send reset email. Please try again.', 'danger')
        else:
            flash('Email not found in our records.', 'danger')
        cursor.close()
        return redirect(url_for('pharmacy.pharmacy_login'))
        
    cursor.close()
    return render_template('pharmacy_login.html')

@pharmacy_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.home'))
    
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT * FROM pharmacies 
        WHERE reset_token = %s AND token_expiry > %s
    """, (token, datetime.now()))
    pharmacy = cursor.fetchone()
    
    if not pharmacy:
        flash('Invalid or expired reset link.', 'danger')
        cursor.close()
        return redirect(url_for('pharmacy.pharmacy_login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password_phrm.html', token=token)
            
        hashed_password = generate_password_hash(password)
        cursor.execute("""
            UPDATE pharmacies 
            SET password = %s, reset_token = NULL, token_expiry = NULL 
            WHERE reset_token = %s
        """, (hashed_password, token))
        db.connection.commit()
        flash('Password reset successfully.', 'success')
        cursor.close()
        return redirect(url_for('pharmacy.pharmacy_login'))
    
    cursor.close()
    return render_template('reset_password_phrm.html', token=token)

@pharmacy_bp.route('/pharmacy_dashboard', methods=['GET', 'POST'])
def pharmacy_dashboard():
    if db is None or 'pharmacy_loggedin' not in session:
        flash("Please login to access the pharmacy dashboard.", "warning")
        return redirect(url_for('pharmacy.pharmacy_login'))
    
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_new_medicine':
            name = request.form.get('name')
            brand = request.form.get('brand')
            try:
                price = float(request.form.get('price'))
                stock_quantity = int(request.form.get('stock_quantity'))
            except (ValueError, TypeError):
                flash("Invalid price or stock quantity.", "danger")
                return redirect(url_for('pharmacy.pharmacy_dashboard'))
            
            cursor.execute("SELECT medicine_id FROM medicines WHERE name = %s AND brand = %s", (name, brand))
            medicine = cursor.fetchone()
            if not medicine:
                cursor.execute("INSERT INTO medicines (name, brand, price) VALUES (%s, %s, %s)", (name, brand, price))
                medicine_id = cursor.lastrowid
            else:
                medicine_id = medicine['medicine_id']
            cursor.execute("""
                INSERT INTO pharmacy_inventory (pharmacy_id, medicine_id, stock_quantity)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE stock_quantity = stock_quantity + %s
            """, (session['pharmacy_id'], medicine_id, stock_quantity, stock_quantity))
            db.connection.commit()
            flash("Medicine added successfully!", "success")
        
        elif action == 'update_order_status':
            order_id = request.form.get('order_id')
            status = request.form.get('status', '').strip()
            valid_statuses = ['Pending', 'Filled', 'Cancelled', 'Delivered', 'Verified']
            
            if status not in valid_statuses:
                flash("Invalid status selected.", "danger")
                return redirect(url_for('pharmacy.pharmacy_dashboard'))
            try:
                cursor.execute("UPDATE pharmacy_orders SET status = %s WHERE pharmacy_order_id = %s AND pharmacy_id = %s",
                              (status, order_id, session['pharmacy_id']))
                db.connection.commit()
                flash("Order status updated!", "success")
            except MySQLdb.DataError as e:
                db.connection.rollback()
                flash("Error updating status. Please contact support.", "danger")
                print(f"Failed to update status: {status} - Error: {str(e)}")
        
        elif action == 'verify_prescription':
            prescription_id = request.form.get('prescription_id')
            try:
                cursor.execute("UPDATE pharmacy_orders SET status = 'Verified' WHERE prescription_id = %s AND pharmacy_id = %s",
                              (prescription_id, session['pharmacy_id']))
                db.connection.commit()
                flash("Prescription verified!", "success")
            except MySQLdb.DataError as e:
                db.connection.rollback()
                flash("Error verifying prescription. Please contact support.", "danger")
                print(f"Failed to verify prescription - Error: {str(e)}")
        
        return redirect(url_for('pharmacy.pharmacy_dashboard'))
    
    cursor.execute("SELECT * FROM pharmacies WHERE pharmacy_id = %s", (session['pharmacy_id'],))
    pharmacy = cursor.fetchone()

    cursor.execute("""
        SELECT pi.*, m.name, m.brand, m.price
        FROM pharmacy_inventory pi
        JOIN medicines m ON pi.medicine_id = m.medicine_id
        WHERE pi.pharmacy_id = %s
    """, (session['pharmacy_id'],))
    inventory = cursor.fetchall()
    
    cursor.execute("""
        SELECT po.pharmacy_order_id, po.total_amount, po.status, po.order_date,
           pt.name as patient_name, pt.address as patient_address,
           pr.prescription_id, pr.medicine_id, pr.dosage, pr.duration,
           m.name as medicine_name, d.name as doctor_name
    FROM pharmacy_orders po
    LEFT JOIN prescriptions pr ON po.prescription_id = pr.prescription_id
    LEFT JOIN patients pt ON po.patient_id = pt.patient_id
    LEFT JOIN medicines m ON pr.medicine_id = m.medicine_id
    LEFT JOIN doctors d ON pr.doctor_id = d.doctor_id
    WHERE po.pharmacy_id = %s
    ORDER BY po.order_date DESC
    """, (session['pharmacy_id'],))
    orders = cursor.fetchall()
    
    cursor.execute("SELECT medicine_id, name, brand FROM medicines")
    medicines = cursor.fetchall()

    cursor.execute("SELECT SUM(stock_quantity) as total_stock FROM pharmacy_inventory WHERE pharmacy_id = %s", (session['pharmacy_id'],))
    total_stock = cursor.fetchone()['total_stock'] or 0
    cursor.execute("SELECT COUNT(*) as total_items FROM pharmacy_inventory WHERE pharmacy_id = %s", (session['pharmacy_id'],))
    total_items = cursor.fetchone()['total_items'] or 1
    stock_availability = min(100, max(0, round((total_stock / (total_items * 100)) * 100)))

    cursor.execute("""
        SELECT DATE_FORMAT(order_date, '%%b') as month, SUM(total_amount) as sales
        FROM pharmacy_orders
        WHERE pharmacy_id = %s AND order_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY DATE_FORMAT(order_date, '%%b'), MONTH(order_date)
        ORDER BY MONTH(order_date)
    """, (session['pharmacy_id'],))
    monthly_sales = cursor.fetchall()
    monthly_sales_labels = [row['month'] for row in monthly_sales]
    monthly_sales_data = [float(row['sales'] or 0) for row in monthly_sales]
    if not monthly_sales_labels:
        monthly_sales_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        monthly_sales_data = [0] * 12

    cursor.execute("""
        SELECT WEEK(order_date) as week, COUNT(*) as order_count
        FROM pharmacy_orders
        WHERE pharmacy_id = %s AND order_date >= DATE_SUB(CURDATE(), INTERVAL 4 WEEK)
        GROUP BY WEEK(order_date)
        ORDER BY week
    """, (session['pharmacy_id'],))
    order_trends = cursor.fetchall()
    order_trends_labels = [f"Week {row['week'] % 52}" for row in order_trends]
    order_trends_data = [row['order_count'] for row in order_trends]
    if not order_trends_labels:
        order_trends_labels = ['Week 1', 'Week 2', 'Week 3', 'Week 4']
        order_trends_data = [0] * 4

    cursor.execute("""
        SELECT status, SUM(total_amount) as revenue
        FROM pharmacy_orders
        WHERE pharmacy_id = %s AND order_date >= DATE_SUB(CURDATE(), INTERVAL 5 MONTH)
        GROUP BY status
    """, (session['pharmacy_id'],))
    revenue_data = cursor.fetchall()
    revenue_streams_labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May']
    revenue_streams_pending = [0] * 5
    revenue_streams_verified = [0] * 5
    revenue_streams_delivered = [0] * 5
    for i in range(min(5, len(revenue_data))):
        if revenue_data[i]['status'] == 'Pending':
            revenue_streams_pending[i] = float(revenue_data[i]['revenue'] or 0)
        elif revenue_data[i]['status'] == 'Verified':
            revenue_streams_verified[i] = float(revenue_data[i]['revenue'] or 0)
        elif revenue_data[i]['status'] == 'Delivered':
            revenue_streams_delivered[i] = float(revenue_data[i]['revenue'] or 0)

    cursor.execute("""
        SELECT m.name, SUM(po.total_amount) as total_sold
        FROM pharmacy_orders po
        JOIN prescriptions pr ON po.prescription_id = pr.prescription_id
        JOIN medicines m ON pr.medicine_id = m.medicine_id
        WHERE po.pharmacy_id = %s
        GROUP BY m.name
        ORDER BY total_sold DESC
        LIMIT 3
    """, (session['pharmacy_id'],))
    medicine_categories = cursor.fetchall()
    medicine_categories_labels = [row['name'] for row in medicine_categories]
    medicine_categories_data = [float(row['total_sold'] or 0) for row in medicine_categories]
    if not medicine_categories_labels:
        medicine_categories_labels = ['Painkillers', 'Antibiotics', 'Vitamins']
        medicine_categories_data = [0, 0, 0]

    cursor.execute("SELECT COUNT(*) as total_orders FROM pharmacy_orders WHERE pharmacy_id = %s", (session['pharmacy_id'],))
    total_orders = cursor.fetchone()['total_orders'] or 1
    cursor.execute("SELECT COUNT(*) as delivered_orders FROM pharmacy_orders WHERE pharmacy_id = %s AND status = 'Delivered'", 
                   (session['pharmacy_id'],))
    delivered_orders = cursor.fetchone()['delivered_orders'] or 0
    fulfillment_rate = round((delivered_orders / total_orders) * 100)

    cursor.close()
    
    return render_template('pharmacy_dashboard.html',
                         pharmacy=pharmacy,
                         inventory=inventory,
                         orders=orders,
                         medicines=medicines,
                         stock_availability=stock_availability,
                         monthly_sales_labels=monthly_sales_labels,
                         monthly_sales_data=monthly_sales_data,
                         order_trends_labels=order_trends_labels,
                         order_trends_data=order_trends_data,
                         revenue_streams_labels=revenue_streams_labels,
                         revenue_streams_pending=revenue_streams_pending,
                         revenue_streams_verified=revenue_streams_verified,
                         revenue_streams_delivered=revenue_streams_delivered,
                         medicine_categories_labels=medicine_categories_labels,
                         medicine_categories_data=medicine_categories_data,
                         fulfillment_rate=fulfillment_rate)

@pharmacy_bp.route('/pharmacy_logout')
def pharmacy_logout():
    session.pop('pharmacy_loggedin', None)
    session.pop('pharmacy_id', None)
    session.pop('pharmacy_name', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('pharmacy.pharmacy_login'))

@pharmacy_bp.route('/generate_prescription_pdf/<prescription_id>')
def generate_prescription_pdf(prescription_id):
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))
    
    if 'loggedin' not in session:
        flash("Please login to generate prescription PDF.", "warning")
        return redirect(url_for('auth.login'))
    
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    
    try:
        cursor.execute("""
            SELECT p.prescription_id, p.medicine_id, p.dosage, p.duration, p.instructions, p.prescribed_date,
                   p.appointment_id, m.name as medicine_name, m.brand, m.price,
                   d.name as doctor_name, d.doctor_id, d.public_key, p.signature,
                   pt.name as patient_name, pt.phone,
                   ph.name as pharmacy_name, ph.address
            FROM prescriptions p
            JOIN medicines m ON p.medicine_id = m.medicine_id
            JOIN doctors d ON p.doctor_id = d.doctor_id
            JOIN patients pt ON p.patient_id = pt.patient_id
            LEFT JOIN pharmacy_orders po ON p.prescription_id = po.prescription_id
            LEFT JOIN pharmacies ph ON po.pharmacy_id = ph.pharmacy_id
            WHERE p.prescription_id = %s AND p.patient_id = %s
        """, (prescription_id, session['patient_id']))
        prescription = cursor.fetchone()
        
        if not prescription:
            flash("Prescription not found or you don't have access", "danger")
            return redirect(url_for('patient.dashboard'))
        
        instructions = prescription['instructions'] if prescription['instructions'] is not None else 'None'
        appointment_id = prescription['appointment_id'] if prescription['appointment_id'] is not None else 'None'
        prescription_message = f"{prescription['doctor_id']}|{session['patient_id']}|{appointment_id}|{prescription['medicine_id']}|{prescription['dosage']}|{prescription['duration']}|{instructions}"
        print(f"PDF - Prescription message to verify: {prescription_message}")
        print(f"PDF - Signature from DB: {prescription['signature']}")
        print(f"PDF - Public key from DB: {prescription['public_key']}")
        
        if not verify_signature(prescription['public_key'], prescription_message, prescription['signature']):
            flash("Prescription signature verification failed", "danger")
            return redirect(url_for('patient.dashboard'))
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=inch, bottomMargin=inch)
        styles = getSampleStyleSheet()
        elements = []

        header_style = styles['Heading1']
        header_style.alignment = 1
        header_style.textColor = colors.white
        elements.append(Paragraph("INVOICE", header_style))
        elements.append(Paragraph(f"{prescription['pharmacy_name'] or 'Pharmacy'}", 
                                styles['Normal'].clone('SubHeader', alignment=1, textColor=colors.white)))
        elements.append(Spacer(1, 12))

        invoice_details_data = [
            ["To:", "Invoice Details:"],
            [prescription['patient_name'], f"Invoice No: #{prescription['prescription_id']}"],
            [prescription['phone'], f"Date: {prescription['prescribed_date'].strftime('%d/%m/%Y')}"],
            ["", f"Patient ID: {session['patient_id']}"],
        ]
        invoice_table = Table(invoice_details_data, colWidths=[3*inch, 3*inch])
        invoice_table.setStyle([
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ])
        elements.append(invoice_table)
        elements.append(Spacer(1, 20))

        items_data = [["Item Description", "Unit Price", "Qty", "Total"]]
        amount = float(prescription['price'])
        description = f"{prescription['medicine_name']} ({prescription['brand']}) - {prescription['dosage']} for {prescription['duration']}"
        if prescription['instructions']:
            description += f" - Instructions: {prescription['instructions']}"
        description += f" - Prescribed by: {prescription['doctor_name']}"
        
        items_data.append([description, f"Rs.{amount:.2f}", "1", f"Rs.{amount:.2f}"])
        
        items_table = Table(items_data, colWidths=[3.5*inch, 1*inch, 0.5*inch, 1*inch])
        items_table.setStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0d1b57')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (1, 1), (-1, -1), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f4f6fb')),
        ])
        elements.append(items_table)
        elements.append(Spacer(1, 20))

        tax_rate = amount * 0.05
        shipping = 50
        grand_total = amount + tax_rate + shipping
        
        total_data = [
            ["Sub-total:", f"Rs.{amount:.2f}"],
            ["Tax Rate (5%):", f"Rs.{tax_rate:.2f}"],
            ["Shipping:", f"Rs.{shipping:.2f}"],
            ["Total:", f"Rs.{grand_total:.2f}"],
        ]
        total_table = Table(total_data, colWidths=[5*inch, 1*inch])
        total_table.setStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
            ('FONTNAME', (0, 3), (-1, 3), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ])
        elements.append(total_table)
        elements.append(Spacer(1, 20))

        footer_style = styles['Normal']
        footer_style.alignment = 1
        footer_style.fontSize = 10
        elements.append(Paragraph("<b>Payment Method:</b>", footer_style))
        elements.append(Paragraph("Account # 1234 5678 910", footer_style))
        elements.append(Paragraph("A/C Healthcare System", footer_style))
        elements.append(Paragraph("Bank Details: Health Bank", footer_style))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("For inquiries, contact:", footer_style))
        elements.append(Paragraph("Email: info@healthcare.com | Call: +91 98765 43210", footer_style))
        elements.append(Paragraph("Website: www.healthcare.com", footer_style))

        def add_background(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.HexColor('#0d1b57'))
            canvas.rect(0, doc.height + doc.bottomMargin, doc.width + doc.leftMargin + doc.rightMargin, 
                       doc.topMargin + 0.5*inch, fill=1)
            canvas.setFillColor(colors.HexColor('#f4f6fb'))
            canvas.rect(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, fill=1)
            canvas.restoreState()

        doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)
        pdf = buffer.getvalue()
        buffer.close()
        
        return Response(
            pdf,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment;filename=prescription_{prescription_id}.pdf'}
        )
    
    finally:
        cursor.close()