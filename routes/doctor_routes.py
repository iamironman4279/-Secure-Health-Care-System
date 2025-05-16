from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from config import AES_SECRET_KEY
from utils.encryption import AESEncryption
import MySQLdb.cursors
import base64
from uuid import uuid4
import secrets
import pyotp
from mail import send_otp_email
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import json
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import requests
from time import sleep

doctor_bp = Blueprint('doctor', __name__)

mysql = MySQL()
aes = AESEncryption(AES_SECRET_KEY)

# Setup logging
logger = logging.getLogger(__name__)

# Helper functions for digital signatures
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_pem, public_pem

def sign_data(private_key_pem, data):
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

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
    except Exception:
        return False

# Helper function to ensure session_token and session_start_time columns exist
def ensure_session_columns():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Check and add session_token
        cursor.execute("SHOW COLUMNS FROM doctors LIKE 'session_token'")
        if not cursor.fetchone():
            logger.warning("session_token column missing in doctors table. Attempting to add.")
            cursor.execute("ALTER TABLE doctors ADD COLUMN session_token VARCHAR(64) DEFAULT NULL")
            mysql.connection.commit()
            logger.info("Successfully added session_token column to doctors table")
        else:
            logger.debug("session_token column already exists")

        # Check and add session_start_time
        cursor.execute("SHOW COLUMNS FROM doctors LIKE 'session_start_time'")
        if not cursor.fetchone():
            logger.warning("session_start_time column missing in doctors table. Attempting to add.")
            cursor.execute("ALTER TABLE doctors ADD COLUMN session_start_time DATETIME DEFAULT NULL")
            mysql.connection.commit()
            logger.info("Successfully added session_start_time column to doctors table")
        else:
            logger.debug("session_start_time column already exists")
    except MySQLdb.Error as e:
        logger.error(f"Error ensuring session columns: {str(e)}")
        raise
    finally:
        cursor.close()

# Helper function to generate session token
def generate_session_token():
    return secrets.token_urlsafe(32)

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
                raise ValueError("Failed to fetch geolocation data from ipapi.co")
        
        raise ValueError("Failed to fetch geolocation data after retries")
    
    except Exception as e:
        logger.error(f"Error fetching geolocation for IP {ip_address or 'unknown'}: {str(e)}")
        raise

# Helper function to store geolocation data
def store_user_location(user_id, ip_address=None):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
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
    except Exception as e:
        logger.error(f"Error storing user location for user {user_id}: {str(e)}")
        mysql.connection.rollback()
    finally:
        cursor.close()

# Helper function to validate session token
def validate_session_token(user_type='doctor'):
    if user_type != 'doctor':
        logger.warning(f"Invalid user_type for session validation: {user_type}")
        return False
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("SELECT session_token, session_start_time FROM doctors WHERE doctor_id = %s", (session.get('doctor_id'),))
        user = cursor.fetchone()
        if not user:
            logger.warning(f"No doctor found for ID: {session.get('doctor_id')}")
            session.clear()
            flash('Session invalid or expired. Please log in again.', 'danger')
            return False
        if user['session_token'] != session.get('session_token'):
            logger.info(f"Session token mismatch for doctor ID: {session.get('doctor_id')}")
            session.clear()
            flash('Your account was logged in from another device. Please log in again.', 'warning')
            return False
        # Check session expiration
        if user['session_start_time']:
            expiry_time = user['session_start_time'] + timedelta(minutes=15)
            if datetime.now() > expiry_time:
                logger.info(f"Session expired for doctor ID: {session.get('doctor_id')}")
                cursor.execute("UPDATE doctors SET session_token = NULL, session_start_time = NULL WHERE doctor_id = %s", (session.get('doctor_id'),))
                mysql.connection.commit()
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return False
        return True
    except Exception as e:
        logger.error(f"Error validating session token: {str(e)}")
        session.clear()
        flash('An error occurred validating your session. Please log in again.', 'danger')
        return False
    finally:
        cursor.close()

@doctor_bp.route('/validate_session', methods=['GET'])
def validate_session():
    if 'loggedin' not in session or not session.get('session_token'):
        return jsonify({'valid': False, 'message': 'No active session.'}), 401
    
    if validate_session_token('doctor'):
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False, 'message': session.get('flash_message', 'Session invalid.')}), 401

@doctor_bp.route('/register_doctor', methods=['GET', 'POST'])
def register_doctor():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            if 'otp' not in request.form:
                # Form submission
                name = request.form['name']
                email = request.form['email']
                phone = request.form['phone']
                specialization = request.form['specialization']
                password = request.form['password']
                profile_photo = request.files.get('profile_photo')
                logger.debug(f"Doctor registration attempt for email: {email}")

                photo_data = None
                if profile_photo and profile_photo.filename:
                    if profile_photo.mimetype in ['image/jpeg', 'image/png']:
                        photo_data = profile_photo.read()
                        if len(photo_data) > 2 * 1024 * 1024:  # 2MB limit
                            flash("Photo size must be under 2MB.", 'danger')
                            return render_template('register_doctor.html')
                    else:
                        flash("Only JPEG or PNG photos are allowed.", 'danger')
                        return render_template('register_doctor.html')
                
                # Check for existing email or phone
                cursor.execute("SELECT * FROM doctors WHERE email = %s OR phone = %s", (email, phone))
                if cursor.fetchone():
                    flash('Email or phone already registered.', 'danger')
                    return render_template('register_doctor.html')
                
                # Generate unique doctor ID
                while True:
                    random_number = secrets.randbelow(10**6)
                    doctor_id = f"DD{str(random_number).zfill(6)}"
                    cursor.execute("SELECT * FROM doctors WHERE doctor_id = %s", (doctor_id,))
                    if not cursor.fetchone():
                        break
                
                # Generate key pair and OTP
                private_key, public_key = generate_key_pair()
                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret, interval=600)
                otp = totp.now()
                
                # Hash password
                hashed_password = generate_password_hash(password)
                
                # Store data in temp_registrations
                doctor_data = {
                    'doctor_id': doctor_id,
                    'name': name,
                    'email': email,
                    'phone': phone,
                    'specialization': specialization,
                    'password': hashed_password,
                    'private_key': private_key,
                    'public_key': public_key,
                    'profile_photo': base64.b64encode(photo_data).decode('utf-8') if photo_data else None
                }
                cursor.execute("""
                    INSERT INTO temp_registrations (type, data, otp_secret, expires_at)
                    VALUES (%s, %s, %s, %s)
                """, ('doctor', json.dumps(doctor_data), secret, datetime.now() + timedelta(minutes=30)))
                mysql.connection.commit()
                
                if send_otp_email(email, otp):
                    session.permanent = True
                    session['temp_registration_id'] = cursor.lastrowid
                    flash("OTP sent to your email. Please verify.", 'info')
                    return render_template('verify_otp.html', email=email)
                else:
                    flash("Failed to send OTP. Please try again.", 'danger')
                    return redirect(url_for('doctor.register_doctor'))
            else:
                # OTP verification
                otp_input = request.form['otp']
                temp_id = session.get('temp_registration_id')
                
                if not temp_id:
                    flash("Session expired. Please register again.", 'danger')
                    return redirect(url_for('doctor.register_doctor'))
                
                cursor.execute("""
                    SELECT * FROM temp_registrations 
                    WHERE id = %s AND type = 'doctor' AND expires_at > %s
                """, (temp_id, datetime.now()))
                temp_data = cursor.fetchone()
                
                if not temp_data:
                    flash("Session expired or invalid OTP. Please register again.", 'danger')
                    session.pop('temp_registration_id', None)
                    return redirect(url_for('doctor.register_doctor'))
                
                totp = pyotp.TOTP(temp_data['otp_secret'], interval=600)
                if totp.verify(otp_input, valid_window=1):
                    doctor_data = json.loads(temp_data['data'])
                    profile_photo = base64.b64decode(doctor_data['profile_photo']) if doctor_data['profile_photo'] else None
                    cursor.execute("""
                        INSERT INTO doctors (doctor_id, name, email, phone, specialization, profile_photo, password, is_activated, private_key, public_key, session_token, session_start_time)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL)
                    """, (doctor_data['doctor_id'], doctor_data['name'], doctor_data['email'],
                          doctor_data['phone'], doctor_data['specialization'], profile_photo,
                          doctor_data['password'], '0', doctor_data['private_key'], doctor_data['public_key']))
                    cursor.execute("DELETE FROM temp_registrations WHERE id = %s", (temp_data['id'],))
                    mysql.connection.commit()
                    flash(f"Doctor {doctor_data['name']} registered successfully with ID {doctor_data['doctor_id']}. Awaiting cloud activation.", 'success')
                    session.pop('temp_registration_id', None)
                else:
                    flash("Invalid OTP. Please try again.", 'danger')
                    return render_template('verify_otp.html', email=json.loads(temp_data['data'])['email'])
                return redirect(url_for('doctor.register_doctor'))
        return render_template('register_doctor.html')
    
    except Exception as e:
        logger.error(f"Error in register_doctor route: {str(e)}", exc_info=True)
        flash("An error occurred during registration. Please try again.", 'danger')
        return redirect(url_for('doctor.register_doctor'))
    finally:
        if cursor:
            cursor.close()

@doctor_bp.route('/resend_otp', methods=['POST'])
def resend_otp():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        email = request.form.get('email')
        cursor.execute("""
            SELECT * FROM temp_registrations 
            WHERE type = 'doctor' AND JSON_EXTRACT(data, '$.email') = %s AND expires_at > %s
        """, (email, datetime.now()))
        temp_data = cursor.fetchone()
        
        if temp_data:
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret, interval=600)
            otp = totp.now()
            cursor.execute("""
                UPDATE temp_registrations 
                SET otp_secret = %s, expires_at = %s 
                WHERE id = %s
            """, (secret, datetime.now() + timedelta(minutes=30), temp_data['id']))
            mysql.connection.commit()
            if send_otp_email(email, otp):
                session.permanent = True
                session['temp_registration_id'] = temp_data['id']
                flash("A new OTP has been sent to your email.", 'info')
            else:
                flash("Failed to resend OTP. Please try again.", 'danger')
        else:
            flash("Session expired. Please register again.", 'danger')
            return redirect(url_for('doctor.register_doctor'))
        
        return render_template('verify_otp.html', email=email)
    
    except Exception as e:
        logger.error(f"Error in resend_otp route: {str(e)}", exc_info=True)
        flash("An error occurred while resending OTP. Please try again.", 'danger')
        return redirect(url_for('doctor.register_doctor'))
    finally:
        if cursor:
            cursor.close()

@doctor_bp.route('/doctor_login', methods=['GET', 'POST'])
def doctor_login():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            logger.debug(f"Doctor login attempt for email: {email}")

            if not email or not password:
                flash('Email and password are required.', 'danger')
                logger.warning("Login attempt with missing email or password")
                return render_template('doctor_login.html')

            # Check database connectivity
            try:
                cursor.execute('SELECT 1')
                cursor.fetchall()
                logger.debug("Database connectivity check passed")
            except MySQLdb.OperationalError as e:
                logger.error(f"Database connection error during login: {str(e)}")
                flash('Unable to connect to the database. Please try again later.', 'danger')
                return render_template('doctor_login.html')

            # Ensure session columns exist
            try:
                ensure_session_columns()
            except MySQLdb.Error as e:
                logger.error(f"Failed to ensure session columns: {str(e)}")
                flash('Server configuration error. Please contact support.', 'danger')
                return render_template('doctor_login.html')

            # Fetch doctor
            cursor.execute('SELECT * FROM doctors WHERE email = %s', (email,))
            doctor = cursor.fetchone()
            logger.debug(f"Doctor fetch result: {doctor is not None}")

            if not doctor:
                flash('Email not found.', 'danger')
                logger.warning(f"Login attempt with non-existent email: {email}")
                return render_template('doctor_login.html')

            if not check_password_hash(doctor['password'], password):
                flash('Incorrect password.', 'danger')
                logger.warning(f"Login attempt with incorrect password for email: {email}")
                return render_template('doctor_login.html')

            if not doctor['is_activated']:
                flash('Account not activated by cloud server.', 'warning')
                logger.warning(f"Login attempt with unactivated account: {email}")
                return render_template('doctor_login.html')

            # Check for existing active session
            if doctor['session_token'] and doctor['session_start_time']:
                expiry_time = doctor['session_start_time'] + timedelta(minutes=15)
                if datetime.now() < expiry_time:
                    logger.info(f"Active session detected for {email}. Login rejected.")
                    flash('This account is already logged in on another device. Please log out or wait for the session to expire (15 minutes).', 'danger')
                    return render_template('doctor_login.html')
                else:
                    # Clear expired session
                    logger.info(f"Clearing expired session for {email}")
                    cursor.execute("""
                        UPDATE doctors 
                        SET session_token = NULL, session_start_time = NULL 
                        WHERE id = %s
                    """, (doctor['id'],))
                    mysql.connection.commit()

            # Generate and store new session token and start time
            session_token = generate_session_token()
            session_start_time = datetime.now()
            try:
                cursor.execute("""
                    UPDATE doctors 
                    SET session_token = %s, session_start_time = %s 
                    WHERE id = %s
                """, (session_token, session_start_time, doctor['id']))
                mysql.connection.commit()
                logger.debug(f"Session token and start time updated for {email}")
            except MySQLdb.Error as e:
                logger.error(f"Database error updating session token for {email}: {str(e)}")
                flash('Database error updating session. Please try again.', 'danger')
                return render_template('doctor_login.html')

            # Set session variables
            session.permanent = True
            session['loggedin'] = True
            session['doctor_id'] = doctor['doctor_id']
            session['name'] = doctor['name']
            session['role'] = 'doctor'
            session['session_token'] = session_token
            logger.debug(f"Session variables set for {email}")

            # Store user location (non-blocking)
            try:
                store_user_location(doctor['doctor_id'])
            except Exception as e:
                logger.error(f"Non-critical error storing geolocation for {doctor['doctor_id']}: {str(e)}")
                flash('Login successful, but failed to record location.', 'warning')

            logger.info(f"Successful login for {email} (Doctor ID: {doctor['doctor_id']})")
            flash(f"Welcome Dr. {doctor['name']}!", 'success')
            return redirect(url_for('doctor.doctor_dashboard'))
        
        return render_template('doctor_login.html')
    
    except MySQLdb.Error as e:
        logger.error(f"MySQL error in doctor_login route: {str(e)}", exc_info=True)
        flash(f"Database error during login: {str(e)}. Please try again.", 'danger')
        return redirect(url_for('doctor.doctor_login'))
    except Exception as e:
        logger.error(f"Unexpected error in doctor_login route: {str(e)}", exc_info=True)
        flash(f"Unexpected error during login: {str(e)}. Please try again.", 'danger')
        return redirect(url_for('doctor.doctor_login'))
    
    finally:
        if cursor:
            cursor.close()

@doctor_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    if request.method == 'POST':
        email = request.form['email']
        cursor.execute('SELECT * FROM doctors WHERE email = %s', (email,))
        doctor = cursor.fetchone()
        if doctor:
            reset_token = secrets.token_urlsafe(32)
            expiry = datetime.now() + timedelta(hours=1)
            cursor.execute("""
                UPDATE doctors 
                SET reset_token = %s, token_expiry = %s 
                WHERE email = %s
            """, (reset_token, expiry, email))
            mysql.connection.commit()
            reset_link = url_for('doctor.reset_password', token=reset_token, _external=True)
            email_body = f"To reset your password, click this link: {reset_link}\nValid for 1 hour."
            if send_otp_email(email, email_body):
                flash('Password reset link sent to your email.', 'success')
            else:
                flash('Failed to send reset email. Please try again.', 'danger')
        else:
            flash('Email not found in our records.', 'danger')
        cursor.close()
        return redirect(url_for('doctor.doctor_login'))
    cursor.close()
    return render_template('doctor_login.html')

@doctor_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT * FROM doctors 
            WHERE reset_token = %s AND token_expiry > %s
        """, (token, datetime.now()))
        doctor = cursor.fetchone()
        if not doctor:
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('doctor.doctor_login'))
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('reset_password_doc.html', token=token)
            hashed_password = generate_password_hash(password)
            cursor.execute("""
                UPDATE doctors 
                SET password = %s, reset_token = NULL, token_expiry = NULL, session_token = NULL, session_start_time = NULL
                WHERE reset_token = %s
            """, (hashed_password, token))
            mysql.connection.commit()
            flash('Password reset successfully.', 'success')
            return redirect(url_for('doctor.doctor_login'))
        return render_template('reset_password_doc.html', token=token)
    
    except Exception as e:
        logger.error(f"Error in reset_password route: {str(e)}", exc_info=True)
        flash("An error occurred during password reset. Please try again.", 'danger')
        return redirect(url_for('doctor.doctor_login'))
    finally:
        if cursor:
            cursor.close()

@doctor_bp.route('/doctor_logout')
def doctor_logout():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if 'doctor_id' in session:
            cursor.execute("UPDATE doctors SET session_token = NULL, session_start_time = NULL WHERE doctor_id = %s", (session['doctor_id'],))
            mysql.connection.commit()
        session.clear()
        flash("You have been logged out.", 'info')
        return redirect(url_for('doctor.doctor_login'))
    
    except Exception as e:
        logger.error(f"Error in doctor_logout route: {str(e)}", exc_info=True)
        flash("An error occurred during logout. Please try again.", 'danger')
        return redirect(url_for('doctor.doctor_login'))
    finally:
        if cursor:
            cursor.close()

@doctor_bp.route('/upload_photo_doc', methods=['POST'])
def upload_photo_doc():
    if 'doctor_id' not in session:
        flash("Please log in first.", 'warning')
        return redirect(url_for('doctor.doctor_login'))
    
    if not validate_session_token():
        return redirect(url_for('doctor.doctor_login'))
    
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        doctor_id = session['doctor_id']
        
        if 'profile_photo' not in request.files:
            flash("No photo selected.", 'danger')
            return redirect(url_for('doctor.doctor_dashboard'))
        
        photo = request.files['profile_photo']
        if photo.filename == '':
            flash("No photo selected.", 'danger')
            return redirect(url_for('doctor.doctor_dashboard'))
        
        if photo and photo.mimetype in ['image/jpeg', 'image/png']:
            photo_data = photo.read()
            if len(photo_data) > 2 * 1024 * 1024:  # 2MB limit
                flash("Photo size must be under 2MB.", 'danger')
                return redirect(url_for('doctor.doctor_dashboard'))
            
            cursor.execute("""
                UPDATE doctors 
                SET profile_photo = %s 
                WHERE doctor_id = %s
            """, (photo_data, doctor_id))
            mysql.connection.commit()
            flash("Profile photo uploaded successfully!", 'success')
        else:
            flash("Only JPEG or PNG photos are allowed.", 'danger')
        
        return redirect(url_for('doctor.doctor_dashboard'))
    
    except Exception as e:
        logger.error(f"Error in upload_photo route: {str(e)}", exc_info=True)
        flash("An error occurred while uploading photo. Please try again.", 'danger')
        return redirect(url_for('doctor.doctor_dashboard'))
    finally:
        if cursor:
            cursor.close()

@doctor_bp.route('/doctor_dashboard', methods=['GET', 'POST'])
def doctor_dashboard():
    if 'doctor_id' not in session:
        flash("Please log in first.", 'warning')
        return redirect(url_for('doctor.doctor_login'))
    
    if not validate_session_token():
        return redirect(url_for('doctor.doctor_login'))
    
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        doctor_id = session['doctor_id']
        decrypted_report = None
        search_results = None

        if request.method == 'POST':
            action = request.form.get('action')

            if 'appointment_id' in request.form and action in ['Accept', 'Reject']:
                appointment_id = request.form['appointment_id']
                if action == 'Accept':
                    unique_url = str(uuid4()).replace('-', '')[:40]
                    cursor.execute("""
                        UPDATE appointments 
                        SET status = 'Confirmed', video_call_url = %s 
                        WHERE appointment_id = %s
                    """, (unique_url, appointment_id))
                elif action == 'Reject':
                    cursor.execute("""
                        UPDATE appointments 
                        SET status = 'Cancelled' 
                        WHERE appointment_id = %s
                    """, (appointment_id,))
                mysql.connection.commit()
                flash(f"Appointment {action}ed successfully!", "success")

            elif action == 'request_access':
                patient_id = request.form.get('patient_id')
                if patient_id:
                    cursor.execute("""
                        INSERT INTO doctor_requests (doctor_id, patient_id, status)
                        VALUES (%s, %s, 'pending')
                    """, (doctor_id, patient_id))
                    mysql.connection.commit()
                    flash(f"Data access request for patient {patient_id} submitted successfully!", "success")
                else:
                    flash("Please select a patient to request access.", "danger")

            elif action == 'view_report':
                decryption_key = request.form.get('decryption_key')
                if decryption_key:
                    cursor.execute("""
                        SELECT dr.patient_id, p.name AS patient_name, mr.encrypted_data,
                               mr.blood_group, mr.blood_pressure, mr.body_temp, 
                               mr.pulse_rate, mr.previous_medications, mr.updated_time
                        FROM doctor_requests dr
                        JOIN patients p ON dr.patient_id = p.patient_id
                        LEFT JOIN medical_records mr ON dr.patient_id = mr.patient_id
                        WHERE dr.doctor_id = %s AND dr.decryption_key = %s AND dr.status = 'accepted'
                    """, (doctor_id, decryption_key))
                    report = cursor.fetchone()

                    if report and report['encrypted_data']:
                        try:
                            decrypted_text = aes.decrypt(report['encrypted_data'])
                            decrypted_values = decrypted_text.split('|')
                            if len(decrypted_values) >= 4:
                                blood_group, blood_pressure, body_temp, pulse_rate = decrypted_values[:4]
                                decrypted_report = {
                                    'patient_name': report['patient_name'],
                                    'patient_id': report['patient_id'],
                                    'blood_group': blood_group,
                                    'blood_pressure': blood_pressure,
                                    'body_temp': body_temp,
                                    'pulse_rate': pulse_rate,
                                    'previous_medications': report['previous_medications'],
                                    'updated_time': report['updated_time'],
                                    'encrypted_data': report['encrypted_data']
                                }
                                flash("Report decrypted successfully!", "success")
                            else:
                                flash("Decryption failed: Invalid data format", "danger")
                        except Exception as e:
                            flash(f"Decryption failed: {str(e)}", "danger")
                    elif report:
                        flash("No encrypted data available, showing plain text fields.", "info")
                        decrypted_report = {
                            'patient_name': report['patient_name'],
                            'patient_id': report['patient_id'],
                            'blood_group': report['blood_group'],
                            'blood_pressure': report['blood_pressure'],
                            'body_temp': report['body_temp'],
                            'pulse_rate': report['pulse_rate'],
                            'previous_medications': report['previous_medications'],
                            'updated_time': report['updated_time'],
                            'encrypted_data': 'N/A'
                        }
                    else:
                        flash("Invalid or unauthorized decryption key.", "danger")

            elif action == 'assign_doctor':
                patient_id = request.form.get('patient_id')
                if patient_id:
                    cursor.execute("SELECT private_key FROM doctors WHERE doctor_id = %s", (doctor_id,))
                    doctor = cursor.fetchone()
                    assignment_message = f"Assign {doctor_id} to {patient_id}"
                    signature = sign_data(doctor['private_key'], assignment_message)
                    cursor.execute("""
                        INSERT INTO doctor_patient (doctor_id, patient_id, status, signature)
                        VALUES (%s, %s, 'active', %s)
                        ON DUPLICATE KEY UPDATE status = 'active', signature = %s
                    """, (doctor_id, patient_id, signature, signature))
                    mysql.connection.commit()
                    flash(f"Assigned to patient {patient_id} with digital signature.", "success")

            elif action == 'create_prescription':
                patient_id = request.form.get('patient_id')
                medicine_id = request.form.get('medicine_id')
                dosage = request.form.get('dosage')
                duration = request.form.get('duration')
                instructions = request.form.get('instructions')
                appointment_id = request.form.get('appointment_id') or None

                if not all([patient_id, medicine_id, dosage, duration]):
                    flash("All fields (Patient, Medicine, Dosage, Duration) are required.", "danger")
                else:
                    cursor.execute("SELECT private_key FROM doctors WHERE doctor_id = %s", (doctor_id,))
                    doctor = cursor.fetchone()
                    prescription_message = f"{doctor_id}|{patient_id}|{appointment_id or 'None'}|{medicine_id}|{dosage}|{duration}|{instructions or 'None'}"
                    signature = sign_data(doctor['private_key'], prescription_message)
                    cursor.execute("""
                        INSERT INTO prescriptions (appointment_id, doctor_id, patient_id, medicine_id, dosage, duration, instructions, signature, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'Pending')
                    """, (appointment_id, doctor_id, patient_id, medicine_id, dosage, duration, instructions, signature))
                    mysql.connection.commit()
                    flash("Prescription created successfully with digital signature!", "success")

            elif action == 'search_patients':
                patient_id = request.form.get('patient_id', '').strip()
                name = request.form.get('name', '').strip()
                contact = request.form.get('contact', '').strip()
                dob = request.form.get('dob', '').strip()
                blood_group = request.form.get('blood_group', '').strip()
                blood_pressure = request.form.get('blood_pressure', '').strip()
                body_temp = request.form.get('body_temp', '').strip()
                pulse_rate = request.form.get('pulse_rate', '').strip()

                all_fields = [patient_id, name, contact, dob, blood_group, blood_pressure, body_temp, pulse_rate]
                if not any(all_fields):
                    flash("Please provide at least one search criterion.", "danger")
                else:
                    query = """
                        SELECT DISTINCT p.patient_id, p.name, p.dob, p.phone AS contact,
                                       mr.encrypted_data, mr.previous_medications, mr.updated_time
                        FROM patients p
                        LEFT JOIN medical_records mr ON p.patient_id = mr.patient_id
                        LEFT JOIN appointments a ON p.patient_id = a.patient_id
                        LEFT JOIN doctor_requests dr ON p.patient_id = dr.patient_id AND dr.status = 'accepted'
                        WHERE a.doctor_id = %s OR dr.doctor_id = %s OR (a.doctor_id IS NULL AND dr.doctor_id IS NULL)
                    """
                    params = [doctor_id, doctor_id]
                    conditions = []

                    if patient_id:
                        conditions.append("LOWER(p.patient_id) LIKE %s")
                        params.append(f"%{patient_id.lower()}%")
                    if name:
                        conditions.append("LOWER(p.name) LIKE %s")
                        params.append(f"%{name.lower()}%")
                    if contact:
                        conditions.append("LOWER(p.phone) LIKE %s")
                        params.append(f"%{contact.lower()}%")
                    if dob:
                        conditions.append("p.dob = %s")
                        params.append(dob)

                    if conditions:
                        query += " AND (" + " OR ".join(conditions) + ")"

                    cursor.execute(query, params)
                    results = cursor.fetchall()

                    if not results:
                        flash("No patients found in the system.", "warning")
                    else:
                        search_results = []
                        medical_search = any([blood_group, blood_pressure, body_temp, pulse_rate])

                        for result in results:
                            blood_group_result = blood_pressure_result = body_temp_result = pulse_rate_result = 'N/A'
                            medications_result = result['previous_medications'] if result['previous_medications'] else 'N/A'
                            decryption_failed = False

                            if medical_search and result['encrypted_data']:
                                try:
                                    decrypted_text = aes.decrypt(result['encrypted_data'])
                                    decrypted_values = decrypted_text.split('|')
                                    if len(decrypted_values) >= 5:
                                        blood_group_result = decrypted_values[0]
                                        blood_pressure_result = decrypted_values[1]
                                        body_temp_result = decrypted_values[2]
                                        pulse_rate_result = decrypted_values[3]
                                        medications_result = decrypted_values[4]
                                    else:
                                        decryption_failed = True
                                        flash(f"Invalid medical data format for patient {result['patient_id']}.", "warning")
                                except Exception as e:
                                    decryption_failed = True
                                    flash(f"Decryption failed for patient {result['patient_id']}: {str(e)}", "warning")

                            matches = []
                            if patient_id and patient_id.lower() in result['patient_id'].lower():
                                matches.append(f"Patient ID: {patient_id}")
                            if name and name.lower() in result['name'].lower():
                                matches.append(f"Name: {name}")
                            if contact and contact.lower() in result['contact'].lower():
                                matches.append(f"Contact: {contact}")
                            if dob and dob == result['dob']:
                                matches.append(f"DOB: {dob}")
                            if blood_group and not decryption_failed and blood_group.lower() == blood_group_result.lower():
                                matches.append(f"Blood Group: {blood_group}")
                            if blood_pressure and not decryption_failed and blood_pressure == blood_pressure_result:
                                matches.append(f"Blood Pressure: {blood_pressure}")
                            if body_temp and not decryption_failed and body_temp == body_temp_result:
                                matches.append(f"Body Temperature: {body_temp}")
                            if pulse_rate and not decryption_failed and pulse_rate == pulse_rate_result:
                                matches.append(f"Pulse Rate: {pulse_rate}")

                            if matches:
                                search_results.append({
                                    'patient_id': result['patient_id'],
                                    'name': result['name'],
                                    'contact': result['contact'],
                                    'dob': result['dob'],
                                    'blood_group': blood_group_result,
                                    'blood_pressure': blood_pressure_result,
                                    'body_temp': body_temp_result,
                                    'pulse_rate': pulse_rate_result,
                                    'previous_medications': medications_result,
                                    'updated_time': result['updated_time'],
                                    'matched_fields': matches
                                })

                        if search_results:
                            flash(f"Found {len(search_results)} matching patient(s).", "success")
                        else:
                            flash("No patients matched the search criteria.", "info")

            elif action == 'share_patient':
                patient_id = request.form.get('patient_id')
                to_doctor_id = request.form.get('to_doctor_id')
                if patient_id and to_doctor_id:
                    if to_doctor_id == doctor_id:
                        flash("You cannot share a patient with yourself.", "danger")
                    else:
                        cursor.execute("SELECT private_key FROM doctors WHERE doctor_id = %s", (doctor_id,))
                        doctor = cursor.fetchone()
                        share_message = f"Share {patient_id} from {doctor_id} to {to_doctor_id}"
                        signature = sign_data(doctor['private_key'], share_message)
                        cursor.execute("""
                            INSERT INTO doctor_patient_shares (from_doctor_id, to_doctor_id, patient_id, status, signature)
                            VALUES (%s, %s, %s, 'pending', %s)
                            ON DUPLICATE KEY UPDATE status = 'pending', signature = %s
                        """, (doctor_id, to_doctor_id, patient_id, signature, signature))
                        mysql.connection.commit()
                        flash(f"Patient {patient_id} shared with doctor {to_doctor_id} successfully. Awaiting approval.", "success")
                else:
                    flash("Please select both a patient and a doctor to share with.", "danger")

            elif action in ['accept_share', 'reject_share']:
                share_id = request.form.get('share_id')
                if share_id:
                    new_status = 'accepted' if action == 'accept_share' else 'rejected'
                    cursor.execute("""
                        UPDATE doctor_patient_shares 
                        SET status = %s 
                        WHERE id = %s AND to_doctor_id = %s AND status = 'pending'
                    """, (new_status, share_id, doctor_id))
                    if cursor.rowcount > 0:
                        mysql.connection.commit()
                        flash(f"Share request {'accepted' if new_status == 'accepted' else 'rejected'} successfully!", "success")
                        if new_status == 'accepted':
                            cursor.execute("""
                                SELECT patient_id FROM doctor_patient_shares WHERE id = %s
                            """, (share_id,))
                            patient_id = cursor.fetchone()['patient_id']
                            cursor.execute("""
                                INSERT INTO doctor_requests (doctor_id, patient_id, status)
                                VALUES (%s, %s, 'accepted')
                                ON DUPLICATE KEY UPDATE status = 'accepted'
                            """, (doctor_id, patient_id))
                            mysql.connection.commit()
                    else:
                        flash("Invalid or already processed share request.", "danger")

        # Fetch doctor info with photo
        cursor.execute("SELECT doctor_id, name, email, phone, specialization, profile_photo FROM doctors WHERE doctor_id = %s", (doctor_id,))
        doctor = cursor.fetchone()
        if doctor and doctor['profile_photo']:
            doctor['profile_photo'] = base64.b64encode(doctor['profile_photo']).decode('utf-8')

        # Fetch patients
        cursor.execute("""
            SELECT DISTINCT p.patient_id, p.name, p.dob, p.phone AS contact
            FROM patients p
            JOIN appointments a ON p.patient_id = a.patient_id
            WHERE a.doctor_id = %s
        """, (doctor_id,))
        patients = cursor.fetchall()

        # Fetch appointments
        cursor.execute("""
            SELECT a.*, p.name AS patient_name 
            FROM appointments a
            JOIN patients p ON a.patient_id = p.patient_id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_date ASC
        """, (doctor_id,))
        appointments = cursor.fetchall()

        # Fetch all patients for selection
        cursor.execute("SELECT patient_id, name FROM patients")
        all_patients = cursor.fetchall()

        # Fetch all doctors for sharing
        cursor.execute("SELECT doctor_id, name FROM doctors WHERE doctor_id != %s", (doctor_id,))
        all_doctors = cursor.fetchall()

        # Fetch doctor requests
        cursor.execute("""
            SELECT DISTINCT dr.patient_id, dr.status, dr.decryption_key, p.name as patient_name
            FROM doctor_requests dr
            JOIN patients p ON dr.patient_id = p.patient_id
            WHERE dr.doctor_id = %s
        """, (doctor_id,))
        requests = cursor.fetchall()

        # Fetch prescriptions
        cursor.execute("""
            SELECT pr.prescription_id, pr.patient_id, pr.medicine_id, m.name AS medicine_name,
                   pr.dosage, pr.duration, pr.status AS prescription_status,
                   po.pharmacy_order_id, po.total_amount, po.status AS order_status,
                   ph.name AS pharmacy_name
            FROM prescriptions pr
            JOIN medicines m ON pr.medicine_id = m.medicine_id
            LEFT JOIN pharmacy_orders po ON pr.prescription_id = po.prescription_id
            LEFT JOIN pharmacies ph ON po.pharmacy_id = ph.pharmacy_id
            WHERE pr.doctor_id = %s
            ORDER BY pr.prescribed_date DESC
        """, (doctor_id,))
        prescriptions = cursor.fetchall()

        # Fetch medicines
        cursor.execute("SELECT medicine_id, name, brand FROM medicines")
        medicines = cursor.fetchall()

        # Fetch shared patients
        cursor.execute("""
            SELECT dps.from_doctor_id, d.name AS from_doctor_name, dps.patient_id, p.name AS patient_name
            FROM doctor_patient_shares dps
            JOIN doctors d ON dps.from_doctor_id = d.doctor_id
            JOIN patients p ON dps.patient_id = p.patient_id
            WHERE dps.to_doctor_id = %s AND dps.status = 'accepted'
        """, (doctor_id,))
        shared_patients = cursor.fetchall()

        # Fetch pending share requests
        cursor.execute("""
            SELECT dps.id, dps.from_doctor_id, d.name AS from_doctor_name, dps.patient_id, p.name AS patient_name
            FROM doctor_patient_shares dps
            JOIN doctors d ON dps.from_doctor_id = d.doctor_id
            JOIN patients p ON dps.patient_id = p.patient_id
            WHERE dps.to_doctor_id = %s AND dps.status = 'pending'
        """, (doctor_id,))
        pending_shares = cursor.fetchall()

        return render_template('doctor_dashboard.html', 
                             doctor=doctor, 
                             patients=patients, 
                             appointments=appointments,
                             all_patients=all_patients,
                             all_doctors=all_doctors,
                             requests=requests, 
                             report=decrypted_report,
                             prescriptions=prescriptions,
                             medicines=medicines,
                             search_results=search_results,
                             shared_patients=shared_patients,
                             pending_shares=pending_shares)
    
    except Exception as e:
        logger.error(f"Error in doctor_dashboard route: {str(e)}", exc_info=True)
        flash("An error occurred while loading the dashboard. Please try again.", 'danger')
        return redirect(url_for('doctor.doctor_login'))
    finally:
        if cursor:
            cursor.close()