from flask import Blueprint, render_template, request, redirect, url_for, session, flash, Response
from flask_mysqldb import MySQL
from config import AES_SECRET_KEY
from utils.encryption import AESEncryption
import MySQLdb.cursors
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from io import BytesIO
from datetime import datetime
import requests
import logging
from time import sleep

patient_bp = Blueprint('patient', __name__)

mysql = MySQL()
aes = AESEncryption(AES_SECRET_KEY)

logger = logging.getLogger(__name__)

# Helper function to fetch public IP and geolocation data
def fetch_geolocation(ip_address=None):
    max_retries = 3
    retry_delay = 2  # seconds
    
    try:
        if not ip_address:
            ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
            logger.debug(f"Client IP from headers: {ip_address}")
            
            if not ip_address or ip_address in ('127.0.0.1', '::1'):
                logger.warning(f"Invalid client IP: {ip_address}. Falling back to ifconfig.me")
                for attempt in range(max_retries):
                    try:
                        ip_response = requests.get("https://ifconfig.me", timeout=5)
                        logger.debug(f"ifconfig.me response (attempt {attempt + 1}): {ip_response.status_code}, {ip_response.text}")
                        if ip_response.status_code == 200:
                            ip_address = ip_response.text.strip()
                            break
                        else:
                            logger.warning(f"ifconfig.me failed with status {ip_response.status_code}")
                            if attempt < max_retries - 1:
                                sleep(retry_delay)
                                continue
                            raise ValueError(f"ifconfig.me failed after {max_retries} attempts")
                    except Exception as e:
                        logger.error(f"ifconfig.me error (attempt {attempt + 1}): {str(e)}")
                        if attempt < max_retries - 1:
                            sleep(retry_delay)
                            continue
                        raise ValueError("Failed to fetch IP from ifconfig.me")
            logger.debug(f"Using IP address: {ip_address}")

        for attempt in range(max_retries):
            try:
                geo_response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=5)
                logger.debug(f"ipapi.co response for IP {ip_address} (attempt {attempt + 1}): {geo_response.status_code}, {geo_response.text}")
                
                if geo_response.status_code == 200:
                    data = geo_response.json()
                    if 'latitude' in data and 'longitude' in data and not data.get('error'):
                        return {
                            'ip_address': ip_address,
                            'latitude': data.get('latitude'),
                            'longitude': data.get('longitude'),
                            'city': data.get('city') or 'Unknown',
                            'region': data.get('region') or 'Unknown',
                            'country': data.get('country_name') or 'Unknown'
                        }
                    else:
                        logger.error(f"Invalid ipapi.co response for IP {ip_address}: {data}")
                        raise ValueError("No valid geolocation data")
                elif geo_response.status_code == 429:
                    logger.warning(f"ipapi.co rate limit exceeded for IP {ip_address}")
                    if attempt < max_retries - 1:
                        sleep(retry_delay)
                        continue
                    raise ValueError("ipapi.co rate limit exceeded")
                else:
                    logger.error(f"ipapi.co failed with status {geo_response.status_code}: {geo_response.text}")
                    raise ValueError(f"ipapi.co request failed with status {geo_response.status_code}")
            except Exception as e:
                logger.error(f"ipapi.co error for IP {ip_address} (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    sleep(retry_delay)
                    continue
                raise ValueError(f"Failed to fetch geolocation data from ipapi.co: {str(e)}")
        
        raise ValueError("Failed to fetch geolocation data after retries")
    
    except Exception as e:
        logger.error(f"Error fetching geolocation for IP {ip_address or 'unknown'}: {str(e)}")
        raise ValueError(f"Failed to fetch geolocation data: {str(e)}")

# Helper function to store geolocation data
def store_user_location(user_id, ip_address=None):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        try:
            geolocation = fetch_geolocation(ip_address)
            logger.debug(f"Storing location for user {user_id} with IP {geolocation['ip_address']}")
            
            cursor.execute("""
                INSERT INTO secure_patient_db.user_locations (user_id, ip_address, latitude, longitude, city, region, country, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                user_id,
                geolocation['ip_address'],
                geolocation['latitude'],
                geolocation['longitude'],
                geolocation['city'],
                geolocation['region'],
                geolocation['country']
            ))
            mysql.connection.commit()
            logger.debug(f"Stored geolocation for user {user_id} with IP {geolocation['ip_address']}")
        except ValueError as e:
            logger.warning(f"Geolocation fetch failed for user {user_id}: {str(e)}. Storing fallback location.")
            # Store a fallback record with IP and placeholder values
            fallback_ip = ip_address or request.headers.get('X-Forwarded-For', request.remote_addr)
            cursor.execute("""
                INSERT INTO secure_patient_db.user_locations (user_id, ip_address, latitude, longitude, city, region, country, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                user_id,
                fallback_ip,
                None,  # latitude
                None,  # longitude
                'Unknown',
                'Unknown',
                'Unknown'
            ))
            mysql.connection.commit()
            logger.debug(f"Stored fallback location for user {user_id} with IP {fallback_ip}")
    except Exception as e:
        logger.error(f"Error storing user location for user {user_id}: {str(e)}")
        mysql.connection.rollback()
        # Do not raise exception to prevent dashboard crash
    finally:
        cursor.close()

def validate_session_token(user_type):
    if user_type not in ['patient', 'doctor']:
        return False
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if user_type == 'patient':
            cursor.execute("SELECT session_token FROM patients WHERE patient_id = %s", (session.get('patient_id'),))
        else:
            cursor.execute("SELECT session_token FROM doctors WHERE doctor_id = %s", (session.get('doctor_id'),))
        
        user = cursor.fetchone()
        if not user or user['session_token'] != session.get('session_token'):
            session.clear()
            flash('Session invalid or expired. Please log in again.', 'danger')
            return False
        return True
    finally:
        cursor.close()

def verify_signature(public_key_pem, data, signature):
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    try:
        public_key.verify(
            base64.b64decode(signature),
            data.encode('utf-8'),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        return False

@patient_bp.route('/upload_photo', methods=['POST'])
def upload_photo():
    if 'loggedin' not in session or not validate_session_token('patient'):
        flash('Please login to upload a photo.', 'warning')
        return redirect(url_for('auth.login'))
    
    profile_photo = request.files.get('profile_photo')
    if not profile_photo or not profile_photo.filename:
        flash('No file selected.', 'danger')
        return redirect(url_for('patient.dashboard'))
    
    if profile_photo.mimetype not in ['image/jpeg', 'image/png']:
        flash('Only JPEG or PNG photos are allowed.', 'danger')
        return redirect(url_for('patient.dashboard'))
    
    photo_data = profile_photo.read()
    if len(photo_data) > 2 * 1024 * 1024:
        flash('Photo size must be under 2MB.', 'danger')
        return redirect(url_for('patient.dashboard'))
    
    cursor = mysql.connection.cursor()
    cursor.execute("""
        UPDATE patients SET profile_photo = %s WHERE patient_id = %s
    """, (photo_data, session['patient_id']))
    mysql.connection.commit()
    cursor.close()
    
    flash('Profile photo uploaded successfully.', 'success')
    return redirect(url_for('patient.dashboard'))

@patient_bp.route('/dashboard')
def dashboard():
    if 'loggedin' not in session or not validate_session_token('patient'):
        return redirect(url_for('auth.login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM patients WHERE patient_id = %s', (session['patient_id'],))
    patient = cursor.fetchone()

    cursor.execute("""
        SELECT pr.prescription_id, pr.medicine_id, m.name AS medicine_name,
               pr.dosage, pr.duration, pr.status AS prescription_status,
               d.name AS doctor_name,
               po.pharmacy_order_id, po.total_amount, po.status AS order_status,
               ph.name AS pharmacy_name
        FROM prescriptions pr
        JOIN medicines m ON pr.medicine_id = m.medicine_id
        JOIN doctors d ON pr.doctor_id = d.doctor_id
        LEFT JOIN pharmacy_orders po ON pr.prescription_id = po.prescription_id
        LEFT JOIN pharmacies ph ON po.pharmacy_id = ph.pharmacy_id
        WHERE pr.patient_id = %s
        ORDER BY pr.prescribed_date DESC
    """, (session['patient_id'],))
    prescriptions = cursor.fetchall()

    cursor.execute("""
        SELECT a.appointment_id, a.appointment_date, a.status, 
               d.name AS doctor_name, d.specialization
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.doctor_id
        WHERE a.patient_id = %s
        ORDER BY a.appointment_date DESC
        LIMIT 5
    """, (session['patient_id'],))
    appointments = cursor.fetchall()

    # Store user location, but don't crash on failure
    store_user_location(session['patient_id'])

    cursor.close()
    return render_template('dashboard.html', 
                         patient=patient, 
                         prescriptions=prescriptions,
                         appointments=appointments)

@patient_bp.route('/logout')
def logout():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    if 'patient_id' in session:
        cursor.execute("UPDATE patients SET session_token = NULL WHERE patient_id = %s", (session['patient_id'],))
        mysql.connection.commit()
    cursor.close()
    
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('auth.login'))

@patient_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'loggedin' not in session or not validate_session_token('patient'):
        flash('Please login to upload medical data.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        blood_group = request.form['blood_group']
        blood_pressure = request.form['blood_pressure']
        body_temp = request.form['body_temp']
        pulse_rate = request.form['pulse_rate']
        medications = request.form['medications']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (session['patient_id'],))
        patient = cursor.fetchone()

        if not patient:
            flash('Patient not found.', 'danger')
            return redirect(url_for('patient.upload'))

        data = f"{blood_group}|{blood_pressure}|{body_temp}|{pulse_rate}|{medications}"
        encrypted_data = aes.encrypt(data)

        cursor.execute("""
            INSERT INTO medical_records (patient_id, encrypted_data)
            VALUES (%s, %s)
        """, (patient['patient_id'], encrypted_data))
        mysql.connection.commit()
        cursor.close()

        flash('Medical data uploaded and encrypted successfully.', 'success')
        return redirect(url_for('patient.dashboard'))

    return render_template('upload_data.html')

@patient_bp.route('/decrypt_key', methods=['GET', 'POST'])
def decrypt_key():
    if 'loggedin' not in session or not validate_session_token('patient'):
        flash('Please login to view medical data.', 'warning')
        return redirect(url_for('auth.login'))

    encrypted_keys = []
    decrypted_data = {}
    edit_mode = False

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('''
        SELECT id, patient_id, encrypted_data, updated_time
        FROM medical_records
        WHERE patient_id = %s
    ''', (session['patient_id'],))
    records = cursor.fetchall()
    cursor.close()

    for record in records:
        if record['encrypted_data']:
            if isinstance(record['encrypted_data'], str):
                record_bytes = record['encrypted_data'].encode('utf-8')
            else:
                record_bytes = record['encrypted_data']
            record['encrypted_data'] = base64.b64encode(record_bytes).decode('utf-8')
        encrypted_keys.append(record)

    if request.method == 'POST':
        action = request.form.get('action')
        encrypted_key = request.form.get('encrypted_key')

        user_keys = [record['encrypted_data'] for record in encrypted_keys]
        if encrypted_key not in user_keys:
            flash("Unauthorized attempt.", 'danger')
            return redirect(url_for('patient.decrypt_key'))

        if action == 'decrypt' or action == 'edit':
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
                    edit_mode = (action == 'edit')
                else:
                    flash("Decryption failed: Invalid data format", 'danger')

            except Exception as e:
                flash(f"Decryption failed: {str(e)}", 'danger')

        elif action == 'update':
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                blood_group = request.form.get('blood_group')
                blood_pressure = request.form.get('blood_pressure')
                body_temp = request.form.get('body_temp')
                pulse_rate = request.form.get('pulse_rate')
                medications = request.form.get('previous_medications')

                new_data = f"{blood_group}|{blood_pressure}|{body_temp}|{pulse_rate}|{medications}"
                new_encrypted_data = aes.encrypt(new_data)

                cursor.execute('''
                    UPDATE medical_records 
                    SET encrypted_data = %s, updated_time = NOW()
                    WHERE patient_id = %s AND encrypted_data = %s
                ''', (new_encrypted_data, session['patient_id'], base64.b64decode(encrypted_key)))
                
                mysql.connection.commit()
                cursor.close()
                flash("Record updated successfully", 'success')
                return redirect(url_for('patient.decrypt_key'))

            except Exception as e:
                flash(f"Update failed: {str(e)}", 'danger')

        elif action == 'delete':
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('''
                    DELETE FROM medical_records 
                    WHERE patient_id = %s AND encrypted_data = %s
                ''', (session['patient_id'], base64.b64decode(encrypted_key)))
                
                mysql.connection.commit()
                cursor.close()
                flash("Record deleted successfully", 'success')
                return redirect(url_for('patient.decrypt_key'))

            except Exception as e:
                flash(f"Delete failed: {str(e)}", 'danger')

    return render_template('decrypt_form.html', 
                         encrypted_keys=encrypted_keys, 
                         decrypted_data=decrypted_data,
                         edit_mode=edit_mode)

@patient_bp.route('/verify_doctor', methods=['GET', 'POST'])
def verify_doctor():
    if 'loggedin' not in session or not validate_session_token('patient'):
        flash('Please login to verify doctor.', 'warning')
        return redirect(url_for('auth.login'))

    verification_result = None
    show_popup = False

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        patient_id = session['patient_id']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT dp.signature, d.public_key, d.name, d.doctor_id
            FROM doctor_patient dp
            JOIN doctors d ON dp.doctor_id = d.doctor_id
            WHERE dp.doctor_id = %s AND dp.patient_id = %s AND dp.status = 'active'
        """, (doctor_id, patient_id))
        result = cursor.fetchone()
        cursor.close()

        if result:
            assignment_message = f"Assign {result['doctor_id']} to {patient_id}"
            is_valid = verify_signature(result['public_key'], assignment_message, result['signature'])
            verification_result = f"Dr. {result['name']} verified successfully." if is_valid else "Doctor verification failed. Signature mismatch."
            show_popup = True
        else:
            verification_result = "No active assignment found for this doctor."
            show_popup = True

    return render_template('verify_doctor.html', 
                         verification_result=verification_result,
                         show_popup=show_popup)

@patient_bp.route('/medical_history_pdf')
def medical_history_pdf():
    if 'loggedin' not in session or not validate_session_token('patient'):
        flash('Please login to generate medical history.', 'warning')
        return redirect(url_for('auth.login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute('SELECT name, phone, email FROM patients WHERE patient_id = %s', 
                  (session['patient_id'],))
    patient = cursor.fetchone()
    
    cursor.execute("""
        SELECT encrypted_data, updated_time
        FROM medical_records
        WHERE patient_id = %s
        ORDER BY updated_time DESC
    """, (session['patient_id'],))
    encrypted_records = cursor.fetchall()
    
    decrypted_records = []
    for record in encrypted_records:
        try:
            if record['encrypted_data']:
                if isinstance(record['encrypted_data'], str):
                    encrypted_bytes = base64.b64decode(record['encrypted_data'])
                else:
                    encrypted_bytes = record['encrypted_data']
                decrypted_text = aes.decrypt(encrypted_bytes)
                blood_group, blood_pressure, body_temp, pulse_rate, medications = decrypted_text.split('|')
                decrypted_records.append({
                    'updated_time': record['updated_time'],
                    'description': f"Medical Record - BG: {blood_group}, BP: {blood_pressure}, Temp: {body_temp}, Pulse: {pulse_rate}, Meds: {medications}",
                    'price': 0
                })
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            continue
    
    cursor.execute("""
        SELECT pr.prescription_id, pr.medicine_id, pr.prescribed_date, m.name AS medicine_name, 
               pr.dosage, pr.duration, d.name AS doctor_name, d.doctor_id, d.public_key, 
               pr.signature, po.total_amount, ph.name AS pharmacy_name
        FROM prescriptions pr
        JOIN medicines m ON pr.medicine_id = m.medicine_id
        JOIN doctors d ON pr.doctor_id = d.doctor_id
        LEFT JOIN pharmacy_orders po ON pr.prescription_id = po.prescription_id
        LEFT JOIN pharmacies ph ON po.pharmacy_id = ph.pharmacy_id
        WHERE pr.patient_id = %s
        ORDER BY pr.prescribed_date DESC
    """, (session['patient_id'],))
    prescriptions = cursor.fetchall()
    
    cursor.close()

    verified_prescriptions = []
    for pr in prescriptions:
        prescription_message = f"{pr['doctor_id']}|{session['patient_id']}|{pr['medicine_id']}|{pr['dosage']}|{pr['duration']}|{pr.get('instructions', 'None')}"
        if verify_signature(pr['public_key'], prescription_message, pr['signature']):
            verified_prescriptions.append(pr)

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=inch, rightMargin=inch, topMargin=inch, bottomMargin=inch)
    styles = getSampleStyleSheet()
    elements = []

    header_style = styles['Heading1']
    header_style.alignment = 1
    header_style.textColor = colors.white
    elements.append(Paragraph("INVOICE", header_style))
    elements.append(Paragraph("Healthcare System", styles['Normal'].clone('SubHeader', alignment=1, textColor=colors.white)))
    elements.append(Spacer(1, 12))

    invoice_details_data = [
        ["To:", "Invoice Details:"],
        [patient['name'], f"Invoice No: #{session['patient_id']}{datetime.now().strftime('%Y%m%d')}"],
        [patient['phone'], f"Date: {datetime.now().strftime('%d/%m/%Y')}"],
        [patient['email'], f"Patient ID: {session['patient_id']}"],
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
    total_amount = 0
    
    for record in decrypted_records:
        items_data.append([record['description'], f"₹{record['price']:.2f}", "1", f"₹{record['price']:.2f}"])
        total_amount += record['price']

    for pr in verified_prescriptions:
        amount = float(pr['total_amount'] or 0)
        description = f"Prescription #{pr['prescription_id']} - {pr['medicine_name']} ({pr['dosage']} for {pr['duration']}) by {pr['doctor_name']}"
        if pr['pharmacy_name']:
            description += f" from {pr['pharmacy_name']}"
        items_data.append([description, f"₹{amount:.2f}", "1", f"₹{amount:.2f}"])
        total_amount += amount

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

    tax_rate = total_amount * 0.05
    shipping = 50
    grand_total = total_amount + tax_rate + shipping
    
    total_data = [
        ["Sub-total:", f"Rs.{total_amount:.2f}"],
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
        headers={'Content-Disposition': f'attachment;filename=medical_receipt_{session["patient_id"]}.pdf'}
    )