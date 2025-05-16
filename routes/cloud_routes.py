from flask import Blueprint, jsonify, render_template, request, redirect, url_for, session, flash, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import pyotp
import qrcode
from io import BytesIO
import base64
import plotly.graph_objects as go
from config import AES_SECRET_KEY
from mail import send_activation_email
from utils.encryption import AESEncryption
import json
from datetime import datetime, timedelta
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging
from pymongo import MongoClient
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)
import secrets
import hashlib
import time
from PIL import Image  # Added for logo embedding

logger = logging.getLogger(__name__)

cloud_bp = Blueprint('cloud', __name__)

db = None
mongo_client = None
mongo_db = None
CLOUD_TOTP_SECRET = "JBSWY3DPEHPK3PXP"
aes = AESEncryption(AES_SECRET_KEY)
BACKUP_AES_KEY = bytes.fromhex('644763a252ff93d03e4c0f8cdec880f439c4c571d57fa229b3f45b0715aacb5e')
MONGO_URI = "mongodb+srv://hemanth42079:w09aOMeW5nAccwQ2@cluster0.cnduffa.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
QR_CODE_SECRET = "your-secure-qr-secret-key"  # Replace with a secure key in production

# WebAuthn configuration
RP_ID = "localhost"  # Update to your domain in production
RP_NAME = "YourApp Cloud Server"
ORIGIN = "http://localhost:5000"  # Update to HTTPS domain in production

# Path to logo file
LOGO_PATH = os.path.join('static', 'logo.png')

def init_cloud(mysql):
    global db, mongo_client, mongo_db
    db = mysql
    mongo_client = MongoClient(MONGO_URI)
    mongo_db = mongo_client['backup']
    return cloud_bp

# Helper function to generate QR code with logo
def generate_qr_with_logo(qr_uri):
    try:
        # Create QR code with high error correction
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction (~30%)
            box_size=10,
            border=4,
        )
        qr.add_data(qr_uri)
        qr.make(fit=True)

        # Generate QR code image
        qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGBA')

        # Load logo
        if not os.path.exists(LOGO_PATH):
            logger.warning(f"Logo file not found at {LOGO_PATH}. Generating QR code without logo.")
            buffer = BytesIO()
            qr_img.save(buffer, format="PNG")
            return base64.b64encode(buffer.getvalue()).decode('utf-8')

        logo = Image.open(LOGO_PATH).convert('RGBA')

        # Calculate logo size (20% of QR code size)
        qr_width, qr_height = qr_img.size
        logo_size = int(min(qr_width, qr_height) * 0.2)  # 20% of QR code size
        logo = logo.resize((logo_size, logo_size), Image.LANCZOS)

        # Calculate position to center logo
        logo_position = (
            (qr_width - logo_size) // 2,
            (qr_height - logo_size) // 2
        )

        # Paste logo onto QR code
        qr_img.paste(logo, logo_position, logo)  # Use logo's alpha channel as mask

        # Save to buffer
        buffer = BytesIO()
        qr_img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
        return qr_code
    except Exception as e:
        logger.error(f"Error generating QR code with logo: {str(e)}")
        # Fallback to generating QR code without logo
        qr = qrcode.make(qr_uri)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode('utf-8')

# Helper function to fetch common data
def fetch_common_data(cursor):
    cursor.execute("SELECT id, patient_id, name, email, phone, address, is_activated FROM patients")
    patients = cursor.fetchall()
    cursor.execute("SELECT doctor_id, name, email, phone, specialization, is_activated FROM doctors")
    doctors = cursor.fetchall()
    cursor.execute("""
        SELECT dr.id, dr.doctor_id, dr.patient_id, dr.status, dr.decryption_key,
               d.name as doctor_name, p.name as patient_name
        FROM doctor_requests dr
        JOIN doctors d ON dr.doctor_id = d.doctor_id
        JOIN patients p ON dr.patient_id = p.patient_id
    """)
    doctor_requests = cursor.fetchall()
    cursor.execute("""
        SELECT dp.doctor_id, dp.patient_id, d.name as doctor_name, p.name as patient_name
        FROM doctor_patient dp
        JOIN doctors d ON dp.doctor_id = d.doctor_id
        JOIN patients p ON dp.patient_id = p.patient_id
        WHERE dp.status = 'active'
    """)
    assignments = cursor.fetchall()
    cursor.execute("""
        SELECT DISTINCT mr.id, mr.patient_id, mr.encrypted_data, mr.updated_time
        FROM medical_records mr
        ORDER BY mr.updated_time DESC
    """)
    medical_records = cursor.fetchall()
    encrypted_records = []
    for record in medical_records:
        if record['encrypted_data']:
            record_bytes = record['encrypted_data'] if isinstance(record['encrypted_data'], bytes) else record['encrypted_data'].encode('utf-8')
            record['encrypted_data'] = base64.b64encode(record_bytes).decode('utf-8')
        encrypted_records.append(record)
    return patients, doctors, doctor_requests, assignments, encrypted_records

def generate_graphs(cursor):
    cursor.execute('SELECT COUNT(*) as patient_count FROM patients')
    patient_count = cursor.fetchone()['patient_count']
    cursor.execute('SELECT COUNT(*) as doctor_count FROM doctors')
    doctor_count = cursor.fetchone()['doctor_count']
    pie_fig = go.Figure(data=[go.Pie(labels=['Patients', 'Doctors'], values=[patient_count, doctor_count], 
                                     hole=0.3, marker_colors=['#9333ea', '#3b82f6'], textinfo='label+percent', textposition='inside')])
    pie_fig.update_layout(title_text="Patients vs Doctors Distribution", paper_bgcolor='rgba(0,0,0,0)', 
                          plot_bgcolor='rgba(0,0,0,0)', font_color='white')
    pie_graph = pie_fig.to_html(full_html=False)

    cursor.execute('SELECT DATE(updated_time) as date, COUNT(*) as count FROM medical_records GROUP BY DATE(updated_time)')
    records_data = cursor.fetchall()
    dates = [row['date'] for row in records_data]
    counts = [row['count'] for row in records_data]
    bar_fig = go.Figure(data=[go.Bar(x=dates, y=counts, marker_color='#9333ea', text=counts, textposition='auto')])
    bar_fig.update_layout(title_text="Medical Records Creation Over Time", xaxis_title="Date", yaxis_title="Number of Records", 
                          paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
    bar_graph = bar_fig.to_html(full_html=False)

    cursor.execute('SELECT updated_time, encrypted_data FROM medical_records WHERE patient_id = %s', 
                   (session.get('patient_id', 'default_patient_id'),))
    crypto_data = cursor.fetchall()
    times = [row['updated_time'] for row in crypto_data]
    encryption_times = [len(row['encrypted_data']) * 0.1 for row in crypto_data]
    line_fig = go.Figure(data=[go.Scatter(x=times, y=encryption_times, mode='lines+markers', line_color='#3b82f6', marker=dict(size=8))])
    line_fig.update_layout(title_text="Simulated Cryptographic Operation Times", xaxis_title="Record Creation Time", 
                           yaxis_title="Operation Time (ms)", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
    line_graph = line_fig.to_html(full_html=False)

    cursor.execute('SELECT d.name, COUNT(dp.patient_id) as patient_count FROM doctors d LEFT JOIN doctor_patient dp ON d.doctor_id = dp.doctor_id GROUP BY d.doctor_id, d.name')
    dp_data = cursor.fetchall()
    doctor_names = [row['name'] for row in dp_data]
    patient_counts = [row['patient_count'] for row in dp_data]
    dp_fig = go.Figure(data=[go.Bar(x=doctor_names, y=patient_counts, marker_color='#9333ea', text=patient_counts, textposition='auto')])
    dp_fig.update_layout(title_text="Patients per Doctor", xaxis_title="Doctor Name", yaxis_title="Number of Patients", 
                         paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
    dp_graph = dp_fig.to_html(full_html=False)

    cursor.execute('SELECT DATE(updated_time) as date, COUNT(*) as count FROM medical_records GROUP BY DATE(updated_time) ORDER BY date')
    area_data = cursor.fetchall()
    area_dates = [row['date'] for row in area_data]
    area_counts = [sum(row['count'] for row in area_data[:i+1]) for i in range(len(area_data))]
    area_fig = go.Figure(data=[go.Scatter(x=area_dates, y=area_counts, fill='tozeroy', mode='lines', line_color='#9333ea')])
    area_fig.update_layout(title_text="Cumulative Medical Records Over Time", xaxis_title="Date", yaxis_title="Cumulative Records", 
                           paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
    area_graph = area_fig.to_html(full_html=False)

    cursor.execute("""
        SELECT d.name, 
               COUNT(DISTINCT dp.patient_id) as patient_count, 
               COUNT(a.appointment_id) as appointment_count 
        FROM doctors d 
        LEFT JOIN doctor_patient dp ON d.doctor_id = dp.doctor_id 
        LEFT JOIN appointments a ON d.doctor_id = a.doctor_id 
        GROUP BY d.doctor_id, d.name
    """)
    bubble_data = cursor.fetchall()
    bubble_doctor_names = [row['name'] for row in bubble_data]
    bubble_patient_counts = [row['patient_count'] for row in bubble_data]
    bubble_appointment_counts = [row['appointment_count'] for row in bubble_data]
    bubble_fig = go.Figure(data=[go.Scatter(
        x=bubble_patient_counts, 
        y=bubble_appointment_counts, 
        text=bubble_doctor_names, 
        mode='markers', 
        marker=dict(size=[count * 10 for count in bubble_appointment_counts], color='#3b82f6', opacity=0.7)
    )])
    bubble_fig.update_layout(title_text="Doctors: Patients vs Appointments (Bubble Size = Appointments)", 
                             xaxis_title="Number of Patients", yaxis_title="Number of Appointments", 
                             paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
    bubble_graph = bubble_fig.to_html(full_html=False)

    # New Transaction History Line Graph
    cursor.execute("""
        SELECT DATE(created_at) as date, status, COUNT(*) as count 
        FROM transactions 
        GROUP BY DATE(created_at), status 
        ORDER BY date
    """)
    transaction_data = cursor.fetchall()
    dates = sorted(set(row['date'] for row in transaction_data))
    failed_counts = [0] * len(dates)
    pending_counts = [0] * len(dates)
    success_counts = [0] * len(dates)
    
    for row in transaction_data:
        date_index = dates.index(row['date'])
        if row['status'] == 'FAILED':
            failed_counts[date_index] = row['count']
        elif row['status'] == 'PENDING':
            pending_counts[date_index] = row['count']
        elif row['status'] == 'SUCCESS':
            success_counts[date_index] = row['count']

    transaction_fig = go.Figure()
    transaction_fig.add_trace(go.Scatter(
        x=dates, y=failed_counts, mode='lines+markers', name='Failed',
        line_color='#ef4444', marker=dict(size=8)
    ))
    transaction_fig.add_trace(go.Scatter(
        x=dates, y=pending_counts, mode='lines+markers', name='Pending',
        line_color='#f59e0b', marker=dict(size=8)
    ))
    transaction_fig.add_trace(go.Scatter(
        x=dates, y=success_counts, mode='lines+markers', name='Success',
        line_color='#22c55e', marker=dict(size=8)
    ))
    transaction_fig.update_layout(
        title_text="Transaction History by Status",
        xaxis_title="Date",
        yaxis_title="Number of Transactions",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='white',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5)
    )
    transaction_graph = transaction_fig.to_html(full_html=False)

    return pie_graph, bar_graph, line_graph, dp_graph, area_graph, bubble_graph, transaction_graph

# Encryption and decryption functions
def encrypt_backup(content):
    logger.debug("Encrypting backup")
    cipher = AES.new(BACKUP_AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(content.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def decrypt_backup(iv, ciphertext):
    logger.debug("Entering decrypt_backup function")
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(BACKUP_AES_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return f"Decryption failed: {str(e)}"

def decrypt_backup_new(iv, ciphertext):
    logger.debug("Entering decrypt_backup_new function")
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(BACKUP_AES_KEY, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        decrypted_text = pt.decode('utf-8')
        logger.debug("Decryption successful")
        return decrypted_text
    except Exception as e:
        error_msg = f"Decryption failed: {str(e)}"
        logger.error(error_msg)
        raise Exception(error_msg)

# Generate secure QR code token
def generate_qr_token(user_id, user_type):
    timestamp = int(time.time())
    token_data = f"{user_id}:{user_type}:{timestamp}:{QR_CODE_SECRET}"
    token_hash = hashlib.sha256(token_data.encode()).hexdigest()
    token = f"{user_id}:{user_type}:{timestamp}:{token_hash}"
    return token

# Validate QR code token
def validate_qr_token(token):
    try:
        user_id, user_type, timestamp, token_hash = token.split(':')
        timestamp = int(timestamp)
        # Check if token is within 2 minutes
        if abs(time.time() - timestamp) > 120:
            return False, None, None
        # Verify token integrity
        expected_data = f"{user_id}:{user_type}:{timestamp}:{QR_CODE_SECRET}"
        expected_hash = hashlib.sha256(expected_data.encode()).hexdigest()
        if token_hash != expected_hash:
            return False, None, None
        return True, user_id, user_type
    except Exception as e:
        logger.error(f"QR token validation error: {str(e)}")
        return False, None, None

# Payments Route for Setting Fees
@cloud_bp.route('/payments', methods=['GET', 'POST'])
def payments():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if request.method == 'POST':
            online_fee = request.form.get('online_fee')
            offline_fee = request.form.get('offline_fee')
            if not online_fee or not offline_fee:
                flash('Both online and offline fees are required.', 'danger')
                return redirect(url_for('cloud.payments'))

            try:
                online_fee = float(online_fee)
                offline_fee = float(offline_fee)
                if online_fee < 0 or offline_fee < 0:
                    flash('Fees cannot be negative.', 'danger')
                    return redirect(url_for('cloud.payments'))

                # Update or insert online fee
                cursor.execute("""
                    INSERT INTO payment_settings (appointment_type, fee)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE fee = %s, updated_at = CURRENT_TIMESTAMP
                """, ('online', online_fee, online_fee))

                # Update or insert offline fee
                cursor.execute("""
                    INSERT INTO payment_settings (appointment_type, fee)
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE fee = %s, updated_at = CURRENT_TIMESTAMP
                """, ('offline', offline_fee, offline_fee))

                db.connection.commit()
                flash('Payment fees updated successfully.', 'success')
            except ValueError:
                flash('Invalid fee amount. Please enter valid numbers.', 'danger')
            except Exception as e:
                db.connection.rollback()
                flash(f'Error updating fees: {str(e)}', 'danger')

            return redirect(url_for('cloud.payments'))

        # Fetch current fees
        cursor.execute("SELECT appointment_type, fee FROM payment_settings")
        fees = cursor.fetchall()
        fee_dict = {row['appointment_type']: row['fee'] for row in fees}

        return render_template('payments.html', fees=fee_dict)

    finally:
        cursor.close()

# Transaction History Route
@cloud_bp.route('/transaction_history', methods=['GET'])
def transaction_history():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("""
            SELECT t.*, p.name AS patient_name
            FROM transactions t
            JOIN patients p ON t.patient_id = p.patient_id
            ORDER BY t.created_at DESC
        """)
        transactions = cursor.fetchall()
        return render_template('transaction_history.html', transactions=transactions)

    finally:
        cursor.close()

# Routes
@cloud_bp.route('/index')
def index():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))
    return render_template('index.html')

@cloud_bp.route('/patients', methods=['GET', 'POST'])
def patients():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("SELECT id, patient_id, name, email, phone, address, is_activated, profile_photo FROM patients")
        patients = cursor.fetchall()

        # Add QR code token to each patient
        for patient in patients:
            token = generate_qr_token(patient['patient_id'], 'patient')
            qr_uri = url_for('cloud.qr_login', token=token, _external=True)
            patient['qr_code'] = generate_qr_with_logo(qr_uri)

        if request.method == 'POST':
            action = request.form.get('action')
            entity = request.form.get('entity')
            if entity == 'patient':
                patient_id = request.form.get('patient_id')
                if not patient_id:
                    flash("Patient ID is required.", "danger")
                    return redirect(url_for('cloud.patients'))

                if action == 'update':
                    name = request.form.get('name')
                    email = request.form.get('email')
                    phone = request.form.get('phone')
                    address = request.form.get('address')
                    try:
                        cursor.execute("""
                            UPDATE patients 
                            SET name = %s, email = %s, phone = %s, address = %s 
                            WHERE patient_id = %s
                        """, (name, email, phone, address, patient_id))
                        db.connection.commit()
                        flash(f"Patient {patient_id} updated successfully.", "success")
                    except Exception as e:
                        db.connection.rollback()
                        flash(f"Error updating patient: {str(e)}", "danger")

                elif action == 'delete':
                    try:
                        cursor.execute("DELETE FROM medical_records WHERE patient_id = %s", (patient_id,))
                        cursor.execute("DELETE FROM doctor_requests WHERE patient_id = %s", (patient_id,))
                        cursor.execute("DELETE FROM doctor_patient WHERE patient_id = %s", (patient_id,))
                        cursor.execute("DELETE FROM appointments WHERE patient_id = %s", (patient_id,))
                        cursor.execute("DELETE FROM patients WHERE patient_id = %s", (patient_id,))
                        db.connection.commit()
                        flash(f"Patient {patient_id} deleted successfully.", "danger")
                    except MySQLdb.IntegrityError as e:
                        db.connection.rollback()
                        flash(f"Error deleting patient due to database constraints: {str(e)}", "danger")
                    except Exception as e:
                        db.connection.rollback()
                        flash(f"Unexpected error deleting patient: {str(e)}", "danger")

            return redirect(url_for('cloud.patients'))

        return render_template('patients_list.html', patients=patients)

    finally:
        cursor.close()

@cloud_bp.route('/doctors', methods=['GET', 'POST'])
def doctors():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT doctor_id, name, email, phone, specialization, is_activated, profile_photo FROM doctors")
    doctors = cursor.fetchall()

    # Add QR code token to each doctor
    for doctor in doctors:
        token = generate_qr_token(doctor['doctor_id'], 'doctor')
        qr_uri = url_for('cloud.qr_login', token=token, _external=True)
        doctor['qr_code'] = generate_qr_with_logo(qr_uri)

    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')
        if entity == 'doctor':
            doctor_id = request.form.get('doctor_id')
            if not doctor_id:
                flash("Doctor ID is required.", "danger")
                return redirect(url_for('cloud.doctors'))

            if action == 'update':
                name = request.form.get('name')
                email = request.form.get('email')
                phone = request.form.get('phone')
                specialization = request.form.get('specialization')
                cursor.execute("""
                    UPDATE doctors
                    SET name = %s, email = %s, phone = %s, specialization = %s
                    WHERE doctor_id = %s
                """, (name, email, phone, specialization, doctor_id))
                db.connection.commit()
                flash(f"Doctor {doctor_id} updated successfully.", "success")

            elif action == 'delete':
                try:
                    cursor.execute("DELETE FROM doctor_patient WHERE doctor_id = %s", (doctor_id,))
                    cursor.execute("DELETE FROM doctors WHERE doctor_id = %s", (doctor_id,))
                    db.connection.commit()
                    flash(f"Doctor {doctor_id} and associated patient assignments deleted successfully.", "danger")
                except MySQLdb.IntegrityError as e:
                    db.connection.rollback()
                    flash(f"Error deleting doctor: {str(e)}", "danger")
                except Exception as e:
                    db.connection.rollback()
                    flash(f"Unexpected error: {str(e)}", "danger")

        cursor.close()
        return redirect(url_for('cloud.doctors'))

    cursor.close()
    return render_template('doctors_list.html', doctors=doctors)

@cloud_bp.route('/generate_qr_code/<user_type>/<user_id>')
def generate_qr_code(user_type, user_id):
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        return jsonify({'error': 'Unauthorized'}), 401

    if user_type not in ['patient', 'doctor']:
        return jsonify({'error': 'Invalid user type'}), 400

    token = generate_qr_token(user_id, user_type)
    qr_uri = url_for('cloud.qr_login', token=token, _external=True)
    qr_code = generate_qr_with_logo(qr_uri)
    return jsonify({'qr_code': qr_code})

@cloud_bp.route('/qr_login/<token>')
def qr_login(token):
    is_valid, user_id, user_type = validate_qr_token(token)
    if not is_valid:
        flash('Invalid or expired QR code.', 'danger')
        return redirect(url_for('auth.login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)

    if user_type == 'patient':
        cursor.execute("SELECT id, patient_id, name, email, is_activated FROM patients WHERE patient_id = %s", (user_id,))
        patient = cursor.fetchone()
        if patient and patient['is_activated']:
            session['loggedin'] = True
            session['id'] = patient['id']
            session['patient_id'] = patient['patient_id']
            session['name'] = patient['name']
            session['role'] = 'patient'
            cursor.close()
            flash('Login successful via QR code!', 'success')
            return redirect(url_for('patient.dashboard'))
        else:
            cursor.close()
            flash('Patient not found or account not activated.', 'danger')
            return redirect(url_for('auth.login'))

    elif user_type == 'doctor':
        cursor.execute("SELECT doctor_id, name, email, is_activated FROM doctors WHERE doctor_id = %s", (user_id,))
        doctor = cursor.fetchone()
        if doctor and doctor['is_activated']:
            session['doctor_id'] = doctor['doctor_id']
            cursor.close()
            flash(f"Welcome Dr. {doctor['name']}!", 'success')
            return redirect(url_for('doctor.doctor_dashboard'))
        else:
            cursor.close()
            flash('Doctor not found or account not activated.', 'danger')
            return redirect(url_for('doctor.doctor_login'))

    else:
        cursor.close()
        flash('Invalid user type.', 'danger')
        return redirect(url_for('auth.login'))

@cloud_bp.route('/doctors_activation', methods=['GET', 'POST'])
def doctors_activation():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT doctor_id, name, email, phone, specialization, is_activated FROM doctors")
    doctors = cursor.fetchall()

    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')
        if entity == 'doctor' and action in ['activate', 'deactivate']:
            doctor_id = request.form.get('doctor_id')
            activation_status = '1' if action == 'activate' else '0'
            cursor.execute("""
                UPDATE doctors 
                SET is_activated = %s 
                WHERE doctor_id = %s
            """, (activation_status, doctor_id))
            db.connection.commit()
            
            cursor.execute("SELECT email, name FROM doctors WHERE doctor_id = %s", (doctor_id,))
            doctor = cursor.fetchone()
            send_activation_email(doctor['email'], doctor['name'], 'Doctor', action == 'activate')
            flash(f"Doctor {doctor_id} has been {'activated' if activation_status == '1' else 'deactivated'}.", "info")
            cursor.close()
            return redirect(url_for('cloud.doctors_activation'))

    cursor.close()
    return render_template('doctors_activation.html', doctors=doctors)

@cloud_bp.route('/patients_activation', methods=['GET', 'POST'])
def patients_activation():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT id, patient_id, name, email, phone, address, is_activated FROM patients")
    patients = cursor.fetchall()

    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')
        if entity == 'patient' and action in ['activate', 'deactivate']:
            patient_id = request.form.get('patient_id')
            activation_status = '1' if action == 'activate' else '0'
            cursor.execute("""
                UPDATE patients 
                SET is_activated = %s 
                WHERE patient_id = %s
            """, (activation_status, patient_id))
            db.connection.commit()
            
            cursor.execute("SELECT email, name FROM patients WHERE patient_id = %s", (patient_id,))
            patient = cursor.fetchone()
            send_activation_email(patient['email'], patient['name'], 'Patient', action == 'activate')
            flash(f"Patient {patient_id} has been {'activated' if activation_status == '1' else 'deactivated'}.", "info")
            cursor.close()
            return redirect(url_for('cloud.patients_activation'))

    cursor.close()
    return render_template('patients_activation.html', patients=patients)

@cloud_bp.route('/files', methods=['GET', 'POST'])
def files():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    encrypted_records = []
    decrypted_data = {}
    cursor.execute("""
        SELECT DISTINCT mr.id, mr.patient_id, mr.encrypted_data, mr.updated_time
        FROM medical_records mr
        ORDER BY mr.updated_time DESC
    """)
    medical_records = cursor.fetchall()
    for record in medical_records:
        if record['encrypted_data']:
            record_bytes = record['encrypted_data'] if isinstance(record['encrypted_data'], bytes) else record['encrypted_data'].encode('utf-8')
            record['encrypted_data'] = base64.b64encode(record_bytes).decode('utf-8')
        encrypted_records.append(record)

    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')
        if action == 'decrypt' and entity == 'medical_records':
            encrypted_key = request.form.get('encrypted_key')
            user_keys = [record['encrypted_data'] for record in encrypted_records]
            if encrypted_key not in user_keys:
                flash("Unauthorized attempt.", 'danger')
            else:
                try:
                    decrypted_text = aes.decrypt(base64.b64decode(encrypted_key))
                    decrypted_values = decrypted_text.split('|')
                    if len(decrypted_values) == 5:
                        blood_group, blood_pressure, body_temp, pulse_rate, medications = decrypted_values
                        decrypted_data = {
                            'Blood Group': blood_group,
                            'Blood Pressure': blood_pressure,
                            'Body Temperature': body_temp,
                            'Pulse Rate': pulse_rate,
                            'Previous Medications': medications,
                            'encrypted_key': encrypted_key
                        }
                        flash("Record decrypted successfully.", "success")
                    else:
                        flash("Decryption failed: Invalid data format", 'danger')
                except Exception as e:
                    flash(f"Decryption failed: {str(e)}", 'danger')
    cursor.close()
    return render_template('files.html', encrypted_records=encrypted_records, decrypted_data=decrypted_data)

@cloud_bp.route('/assign_doctors', methods=['GET', 'POST'])
def assign_doctors():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    patients, doctors, _, assignments, _ = fetch_common_data(cursor)

    if request.method == 'POST':
        action = request.form.get('action')
        entity = request.form.get('entity')
        if entity == 'assignment' and action == 'assign':
            patient_id = request.form.get('patient_id')
            doctor_id = request.form.get('doctor_id')
            if not patient_id or not doctor_id:
                flash("Both Patient ID and Doctor ID are required.", "danger")
                return redirect(url_for('cloud.assign_doctors'))
            cursor.execute("""
                INSERT INTO doctor_patient (doctor_id, patient_id, status)
                VALUES (%s, %s, 'active')
                ON DUPLICATE KEY UPDATE status = 'active'
            """, (doctor_id, patient_id))
            db.connection.commit()
            flash(f"Doctor {doctor_id} assigned to Patient {patient_id}", "success")
            cursor.close()
            return redirect(url_for('cloud.assign_doctors'))

    cursor.close()
    return render_template('assign_doctors.html', patients=patients, doctors=doctors, assignments=assignments)

@cloud_bp.route('/doctor_request', methods=['GET', 'POST'])
def doctor_request():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    _, _, doctor_requests, _, _ = fetch_common_data(cursor)

    if request.method == 'POST':
        entity = request.form.get('entity')
        action = request.form.get('action')
        if entity == 'doctor_request':
            request_id = request.form.get('request_id')
            if not request_id:
                flash("Request ID is required.", "danger")
                return redirect(url_for('cloud.doctor_request'))

            if action == 'accept':
                cursor.execute("""
                    SELECT encrypted_data 
                    FROM medical_records 
                    WHERE patient_id = (SELECT patient_id FROM doctor_requests WHERE id = %s)
                    LIMIT 1
                """, (request_id,))
                record = cursor.fetchone()
                if record and record['encrypted_data']:
                    encrypted_data_str = record['encrypted_data'] if isinstance(record['encrypted_data'], str) else record['encrypted_data'].decode('utf-8')
                    encrypted_data_base64 = base64.b64encode(encrypted_data_str.encode('utf-8')).decode('utf-8')
                    cursor.execute("""
                        UPDATE doctor_requests 
                        SET status = 'accepted', decryption_key = %s 
                        WHERE id = %s
                    """, (encrypted_data_base64, request_id))
                    db.connection.commit()
                    flash(f"Request {request_id} accepted. Decryption key assigned.", "success")
                else:
                    flash("No encrypted data found for this patient.", "danger")

            elif action == 'reject':
                cursor.execute("""
                    UPDATE doctor_requests 
                    SET status = 'rejected', decryption_key = NULL 
                    WHERE id = %s
                """, (request_id,))
                db.connection.commit()
                flash(f"Request {request_id} rejected.", "info")
            cursor.close()
            return redirect(url_for('cloud.doctor_request'))

    cursor.close()
    return render_template('doctor_request.html', doctor_requests=doctor_requests)

@cloud_bp.route('/graph')
def graph():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    pie_graph, bar_graph, line_graph, dp_graph, area_graph, bubble_graph, transaction_graph = generate_graphs(cursor)
    cursor.close()
    return render_template('graph.html', 
                          pie_graph=pie_graph, 
                          bar_graph=bar_graph, 
                          line_graph=line_graph, 
                          dp_graph=dp_graph, 
                          area_graph=area_graph, 
                          bubble_graph=bubble_graph,
                          transaction_graph=transaction_graph)

@cloud_bp.route('/cloud_login', methods=['GET', 'POST'])
def cloud_login():
    if 'cloud_loggedin' in session and session['cloud_loggedin']:
        return redirect(url_for('cloud.index'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    totp = pyotp.TOTP(CLOUD_TOTP_SECRET)
    qr_uri = totp.provisioning_uri(name="Cloud Server Admin", issuer_name="YourApp")
    qr_code = generate_qr_with_logo(qr_uri)  # Updated to use logo

    if request.method == 'POST':
        auth_type = request.form.get('auth_type')

        if auth_type == 'webauthn':
            credential_data = request.form.get('credential')
            if not credential_data:
                flash('No credential provided.', 'danger')
                return redirect(url_for('cloud.cloud_login'))

            try:
                credential = json.loads(credential_data)
                cursor.execute(
                    "SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = %s",
                    (session.get('user_id', 'admin'),)
                )
                stored_credential = cursor.fetchone()
                if not stored_credential:
                    flash('No registered credential found.', 'danger')
                    return redirect(url_for('cloud.cloud_login'))

                authentication_verification = webauthn.verify_authentication_response(
                    credential=credential,
                    expected_challenge=base64.b64decode(session.get('webauthn_challenge')),
                    expected_rp_id=RP_ID,
                    expected_origin=ORIGIN,
                    credential_public_key=base64.b64decode(stored_credential['public_key']),
                    credential_current_sign_count=stored_credential['sign_count'],
                    require_user_verification=True,
                )

                cursor.execute(
                    "UPDATE webauthn_credentials SET sign_count = %s WHERE user_id = %s",
                    (authentication_verification.new_sign_count, session.get('user_id', 'admin'))
                )
                db.connection.commit()

                session['cloud_loggedin'] = True
                flash('Login successful with biometric authentication.', 'success')
                return redirect(url_for('cloud.index'))
            except Exception as e:
                logger.error(f"WebAuthn authentication failed: {str(e)}")
                flash(f"Authentication failed: {str(e)}", 'danger')
                return redirect(url_for('cloud.cloud_login'))

        elif auth_type == 'totp':
            otp = request.form.get('otp')
            if not otp or len(otp) != 6 or not otp.isdigit():
                flash('Invalid OTP.', 'danger')
                return redirect(url_for('cloud.cloud_login'))

            if totp.verify(otp):
                session['cloud_loggedin'] = True
                session['user_id'] = 'admin'
                flash('Login successful with OTP.', 'success')
                return redirect(url_for('cloud.index'))
            else:
                flash('Invalid OTP.', 'danger')
                return redirect(url_for('cloud.cloud_login'))

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED
    )
    session['webauthn_challenge'] = base64.b64encode(options.challenge).decode('utf-8')

    cursor.close()
    return render_template(
        'cloud_login.html',
        qr_code=qr_code,
        webauthn_options=json.dumps({
            'publicKey': {
                'challenge': session['webauthn_challenge'],
                'rpId': RP_ID,
                'allowCredentials': [],
                'userVerification': 'required',
                'timeout': 60000,
            }
        })
    )

@cloud_bp.route('/register_webauthn', methods=['GET', 'POST'])
def register_webauthn():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        logger.error('User not logged in for WebAuthn registration')
        flash('Please log in with OTP first.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    if 'user_id' not in session:
        logger.error('No user_id in session')
        flash('Session error: No user ID found.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        credential_data = request.form.get('credential')
        if not credential_data:
            logger.error('No credential provided in WebAuthn registration request')
            flash('No credential provided.', 'danger')
            return redirect(url_for('cloud.register_webauthn'))

        try:
            logger.debug('Received WebAuthn credential: %s', credential_data)
            credential = json.loads(credential_data)
            logger.debug('Parsed credential: %s', credential)
            if not session.get('webauthn_challenge'):
                logger.error('No WebAuthn challenge in session')
                flash('Session error: No challenge found.', 'danger')
                return redirect(url_for('cloud.register_webauthn'))

            registration_verification = webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=base64.b64decode(session['webauthn_challenge']),
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                require_user_verification=True,
            )
            logger.debug('Registration verification: %s', registration_verification)

            cursor.execute(
                "SELECT credential_id FROM webauthn_credentials WHERE user_id = %s",
                (session['user_id'],)
            )
            existing_credential = cursor.fetchone()
            if existing_credential:
                logger.warning('Existing credential found for user_id: %s. Deleting old credential.', session['user_id'])
                cursor.execute(
                    "DELETE FROM webauthn_credentials WHERE user_id = %s",
                    (session['user_id'],)
                )
                db.connection.commit()

            cursor.execute(
                """
                INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    session['user_id'],
                    base64.b64encode(registration_verification.credential_id).decode('utf-8'),
                    base64.b64encode(registration_verification.credential_public_key).decode('utf-8'),
                    registration_verification.sign_count,
                )
            )
            db.connection.commit()
            logger.info('WebAuthn credential registered for user_id: %s', session['user_id'])

            flash('Biometric credential registered successfully.', 'success')
            return redirect(url_for('cloud.index'))
        except Exception as e:
            logger.error('WebAuthn registration failed: %s', str(e), exc_info=True)
            flash(f'Registration failed: {str(e)}', 'danger')
            return redirect(url_for('cloud.register_webauthn'))

    user_id = session['user_id']
    user_name = "Cloud Admin"
    logger.debug('Generating registration options for user_id: %s', user_id)
    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id.encode('utf-8'),
        user_name=user_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
            authenticator_attachment="platform",
        ),
    )
    session['webauthn_challenge'] = base64.b64encode(options.challenge).decode('utf-8')
    logger.debug('Generated WebAuthn challenge: %s', session['webauthn_challenge'])

    cursor.close()
    return render_template(
        'register_webauthn.html',
        webauthn_options=json.dumps({
            'publicKey': {
                'challenge': session['webauthn_challenge'],
                'rp': {'name': RP_NAME, 'id': RP_ID},
                'user': {
                    'id': base64.b64encode(user_id.encode('utf-8')).decode('utf-8'),
                    'name': user_name,
                    'displayName': user_name,
                },
                'pubKeyCredParams': [
                    {'type': 'public-key', 'alg': -7},
                    {'type': 'public-key', 'alg': -257},
                ],
                'authenticatorSelection': {
                    'userVerification': 'required',
                    'authenticatorAttachment': 'platform',
                },
                'timeout': 60000,
            }
        })
    )

@cloud_bp.route('/backup_patient/<patient_id>')
def backup_patient(patient_id):
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access this feature.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
    patient = cursor.fetchone()
    
    if not patient:
        flash('Patient not found.', 'danger')
        cursor.close()
        return redirect(url_for('cloud.patients'))

    cursor.execute("SELECT * FROM medical_records WHERE patient_id = %s", (patient_id,))
    medical_records = cursor.fetchall()
    cursor.execute("""
        SELECT dp.*, d.name as doctor_name 
        FROM doctor_patient dp 
        JOIN doctors d ON dp.doctor_id = d.doctor_id 
        WHERE dp.patient_id = %s
    """, (patient_id,))
    doctor_assignments = cursor.fetchall()
    cursor.execute("""
        SELECT a.*, d.name as doctor_name 
        FROM appointments a 
        JOIN doctors d ON a.doctor_id = d.doctor_id 
        WHERE a.patient_id = %s
    """, (patient_id,))
    appointments = cursor.fetchall()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_content = f"Patient Backup - {patient_id} - {timestamp}\n\n"
    backup_content += "Basic Information:\n" + json.dumps(patient, default=str, indent=2) + "\n\n"
    backup_content += "Medical Records:\n" + json.dumps(medical_records, default=str, indent=2) + "\n\n"
    backup_content += "Doctor Assignments:\n" + json.dumps(doctor_assignments, default=str, indent=2) + "\n\n"
    backup_content += "Appointments:\n" + json.dumps(appointments, default=str, indent=2) + "\n"

    iv, encrypted_content = encrypt_backup(backup_content)
    backup_dir = os.path.join(os.getcwd(), 'backups', 'patients')
    os.makedirs(backup_dir, exist_ok=True)
    filename = f"{patient_id}backup{timestamp}.enc"
    filepath = os.path.join(backup_dir, filename)
    
    enc_file_content = f"IV:{iv}\nCT:{encrypted_content}"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(enc_file_content)
    
    try:
        backup_collection = mongo_db['backup']
        backup_doc = {
            'filename': filename,
            'type': 'patient',
            'patient_id': patient_id,
            'timestamp': timestamp,
            'content': enc_file_content,
            'created_at': datetime.utcnow()
        }
        backup_collection.insert_one(backup_doc)
        logger.debug(f"Backup for patient {patient_id} uploaded to MongoDB")
    except Exception as e:
        logger.error(f"Failed to upload backup to MongoDB: {str(e)}")
        flash(f"Backup created locally but failed to upload to database: {str(e)}", 'danger')

    cursor.close()
    flash(f'Encrypted backup created successfully: {filename}', 'success')
    return redirect(url_for('cloud.patients'))

@cloud_bp.route('/backup_doctor/<doctor_id>')
def backup_doctor(doctor_id):
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access this feature.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM doctors WHERE doctor_id = %s", (doctor_id,))
    doctor = cursor.fetchone()
    
    if not doctor:
        flash('Doctor not found.', 'danger')
        cursor.close()
        return redirect(url_for('cloud.doctors'))

    cursor.execute("""
        SELECT dp.*, p.name as patient_name 
        FROM doctor_patient dp 
        JOIN patients p ON dp.patient_id = p.patient_id 
        WHERE dp.doctor_id = %s
    """, (doctor_id,))
    patient_assignments = cursor.fetchall()
    cursor.execute("""
        SELECT a.*, p.name as patient_name 
        FROM appointments a 
        JOIN patients p ON a.patient_id = p.patient_id 
        WHERE a.doctor_id = %s
    """, (doctor_id,))
    appointments = cursor.fetchall()
    cursor.execute("SELECT * FROM doctor_requests WHERE doctor_id = %s", (doctor_id,))
    requests = cursor.fetchall()

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_content = f"Doctor Backup - {doctor_id} - {timestamp}\n\n"
    backup_content += "Basic Information:\n" + json.dumps(doctor, default=str, indent=2) + "\n\n"
    backup_content += "Patient Assignments:\n" + json.dumps(patient_assignments, default=str, indent=2) + "\n\n"
    backup_content += "Appointments:\n" + json.dumps(appointments, default=str, indent=2) + "\n\n"
    backup_content += "Doctor Requests:\n" + json.dumps(requests, default=str, indent=2) + "\n"

    iv, encrypted_content = encrypt_backup(backup_content)
    backup_dir = os.path.join(os.getcwd(), 'backups', 'doctors')
    os.makedirs(backup_dir, exist_ok=True)
    filename = f"{doctor_id}backup{timestamp}.enc"
    filepath = os.path.join(backup_dir, filename)
    
    enc_file_content = f"IV:{iv}\nCT:{encrypted_content}"
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(enc_file_content)
    
    try:
        backup_collection = mongo_db['backup']
        backup_doc = {
            'filename': filename,
            'type': 'doctor',
            'doctor_id': doctor_id,
            'timestamp': timestamp,
            'content': enc_file_content,
            'created_at': datetime.utcnow()
        }
        backup_collection.insert_one(backup_doc)
        logger.debug(f"Backup for doctor {doctor_id} uploaded to MongoDB")
    except Exception as e:
        logger.error(f"Failed to upload backup to MongoDB: {str(e)}")
        flash(f"Backup created locally but failed to upload to database: {str(e)}", 'danger')

    cursor.close()
    flash(f'Encrypted backup created successfully: {filename}', 'success')
    return redirect(url_for('cloud.doctors'))

@cloud_bp.route('/multi_module', methods=['POST'])
def multi_module():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        action = request.form.get('action')
        entity = request.form.get('entity')
        action_type = request.form.get('action_type')  # 'bulk' for all patients/doctors

        if action not in ['activate', 'deactivate'] or entity not in ['patient', 'doctor'] or action_type != 'bulk':
            flash('Invalid action, entity, or action type.', 'danger')
            return redirect(request.referrer or url_for('cloud.payments'))

        table = 'patients' if entity == 'patient' else 'doctors'
        session_time = '1970-01-01 00:00:00' if action == 'activate' else None

        # Update all records
        cursor.execute(f"UPDATE {table} SET session_start_time = %s", (session_time,))
        db.connection.commit()
        flash(f"Multiple login for all {entity}s {'activated' if action == 'activate' else 'deactivated'} successfully.", 'success')

    except Exception as e:
        db.connection.rollback()
        flash(f"Error: {str(e)}", 'danger')
    finally:
        cursor.close()

    return redirect(request.referrer or url_for('cloud.payments'))
@cloud_bp.route('/decrypt_backup', methods=['GET', 'POST'])
def decrypt_backup():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access this feature.', 'danger')
        return redirect(url_for('cloud.cloud_login'))

    decrypted_content = None
    filename = None
    
    if request.method == 'POST':
        if 'backup_file' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(url_for('cloud.decrypt_backup'))
        
        file = request.files['backup_file']
        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('cloud.decrypt_backup'))
        
        if file and file.filename.endswith('.enc'):
            try:
                content = file.read().decode('utf-8')
                iv_line, ct_line = content.split('\n', 1)
                iv = iv_line.replace('IV:', '')
                ct = ct_line.replace('CT:', '')
                decrypted_content = decrypt_backup_new(iv, ct)
                filename = file.filename.rsplit('.', 1)[0] + '_decrypted.txt'
                flash('File decrypted successfully.', 'success')
            except Exception as e:
                flash(str(e), 'danger')
                logger.error(f"Route error: {str(e)}")
                decrypted_content = None

    return render_template('decrypt_backup.html', decrypted_content=decrypted_content, filename=filename)

@cloud_bp.route('/download_decrypted', methods=['POST'])
def download_decrypted():
    if 'cloud_loggedin' not in session or not session['cloud_loggedin']:
        flash('Please log in to access this feature.', 'danger')
        return redirect(url_for('cloud.decrypt_backup'))

    content = request.form.get('content')
    filename = request.form.get('filename')
    
    if not content or not filename:
        flash('No content to download.', 'danger')
        return redirect(url_for('cloud.decrypt_backup'))

    response = make_response(content)
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'text/plain'
    return response