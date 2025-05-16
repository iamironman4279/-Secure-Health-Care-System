from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import random
import pyotp
from mail import send_otp_email
from datetime import datetime, timedelta
import secrets
import json
import base64
import logging
import requests
from time import sleep

auth_bp = Blueprint('auth', __name__)

mysql = MySQL()

logger = logging.getLogger(__name__)

# Utility Functions
def generate_patient_id():
    return f"PID{random.randint(100000, 999999)}"

def generate_reset_token():
    return secrets.token_urlsafe(32)

def generate_session_token():
    return secrets.token_urlsafe(32)

# Helper function to ensure session_start_time column exists
def ensure_session_start_time_column():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("SHOW COLUMNS FROM patients LIKE 'session_start_time'")
        if not cursor.fetchone():
            logger.warning("session_start_time column missing in patients table. Attempting to add.")
            try:
                cursor.execute("ALTER TABLE patients ADD COLUMN session_start_time DATETIME DEFAULT NULL")
                mysql.connection.commit()
                logger.info("Successfully added session_start_time column to patients table")
            except MySQLdb.Error as e:
                logger.error(f"Failed to add session_start_time column: {str(e)}")
                raise
        else:
            logger.debug("session_start_time column already exists")
    except MySQLdb.Error as e:
        logger.error(f"Error checking session_start_time column: {str(e)}")
        raise
    finally:
        cursor.close()

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

# Route to reprocess geolocation data for existing IPs
@auth_bp.route('/reprocess_geolocation', methods=['GET', 'POST'])
def reprocess_geolocation():
    if 'loggedin' not in session or session.get('role') != 'admin' or not validate_session_token('patient'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('auth.login'))
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("SELECT id, user_id, ip_address FROM secure_patient_db.user_locations")
        records = cursor.fetchall()
        logger.debug(f"Found {len(records)} records in user_locations to reprocess")
        
        updated = 0
        failed = 0
        for record in records:
            try:
                geolocation = fetch_geolocation(record['ip_address'])
                logger.debug(f"Reprocessed geolocation for IP {record['ip_address']}: {geolocation}")
                
                cursor.execute("""
                    UPDATE secure_patient_db.user_locations
                    SET latitude = %s, longitude = %s, city = %s, region = %s, country = %s, timestamp = NOW()
                    WHERE id = %s
                """, (
                    geolocation['latitude'],
                    geolocation['longitude'],
                    geolocation['city'],
                    geolocation['region'],
                    geolocation['country'],
                    record['id']
                ))
                mysql.connection.commit()
                updated += 1
                logger.debug(f"Updated record {record['id']} for user {record['user_id']} with IP {record['ip_address']}")
            except Exception as e:
                logger.error(f"Failed to reprocess geolocation for IP {record['ip_address']}, record {record['id']}: {str(e)}")
                failed += 1
                continue
        
        flash(f"Reprocessed {len(records)} records: {updated} updated, {failed} failed.", 'info')
        return redirect(url_for('auth.home'))
    
    except Exception as e:
        logger.error(f"Error in reprocess_geolocation: {str(e)}")
        flash("An error occurred while reprocessing geolocation data.", 'danger')
        return redirect(url_for('auth.home'))
    finally:
        cursor.close()

# Helper function to validate session token
def validate_session_token(user_type):
    logger.debug(f"Validating session for user_type: {user_type}, patient_id: {session.get('patient_id')}")
    if user_type not in ['patient', 'doctor']:
        logger.warning(f"Invalid user_type for session validation: {user_type}")
        return False
    
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if user_type == 'patient':
            cursor.execute("SELECT session_token, session_start_time FROM patients WHERE patient_id = %s", (session.get('patient_id'),))
        else:
            cursor.execute("SELECT session_token, session_start_time FROM doctors WHERE doctor_id = %s", (session.get('doctor_id'),))
        
        user = cursor.fetchone()
        if not user:
            logger.warning(f"No user found for {user_type} ID: {session.get('patient_id') or session.get('doctor_id')}")
            session.clear()
            flash('Session invalid or expired. Please log in again.', 'danger')
            return False
        if user['session_token'] != session.get('session_token'):
            logger.info(f"Session token mismatch for {user_type} ID: {session.get('patient_id') or session.get('doctor_id')}")
            session.clear()
            flash('Your account was logged in from another device. Please log in again.', 'warning')
            return False
        if user['session_start_time']:
            expiry_time = user['session_start_time'] + timedelta(minutes=15)
            if datetime.now() > expiry_time:
                logger.info(f"Session expired for {user_type} ID: {session.get('patient_id') or session.get('doctor_id')}")
                cursor.execute(f"UPDATE {'patients' if user_type == 'patient' else 'doctors'} SET session_token = NULL, session_start_time = NULL WHERE {'patient_id' if user_type == 'patient' else 'doctor_id'} = %s", (session.get('patient_id') or session.get('doctor_id'),))
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

# Route to validate session (for client-side polling)
@auth_bp.route('/validate_session', methods=['GET'])
def validate_session():
    if 'loggedin' not in session or not session.get('session_token'):
        return jsonify({'valid': False, 'message': 'No active session.'}), 401
    
    if validate_session_token('patient'):
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False, 'message': session.get('flash_message', 'Session invalid.')}), 401

@auth_bp.route('/')
def home():
    return render_template('main.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            if 'otp' in request.form:
                otp_input = request.form['otp']
                temp_id = session.get('temp_registration_id')
                
                if not temp_id:
                    flash("Session expired. Please register again.", 'danger')
                    cursor.close()
                    return redirect(url_for('auth.register'))
                
                cursor.execute("""
                    SELECT * FROM temp_registrations 
                    WHERE id = %s AND type = 'patient' AND expires_at > %s
                """, (temp_id, datetime.now()))
                temp_data = cursor.fetchone()
                
                if not temp_data:
                    flash("Session expired or invalid OTP. Please register again.", 'danger')
                    session.pop('temp_registration_id', None)
                    cursor.close()
                    return redirect(url_for('auth.register'))
                
                totp = pyotp.TOTP(temp_data['otp_secret'], interval=600)
                if totp.verify(otp_input, valid_window=1):
                    patient_data = json.loads(temp_data['data'])
                    profile_photo = base64.b64decode(patient_data['profile_photo']) if patient_data['profile_photo'] else None
                    cursor.execute("""
                        INSERT INTO patients (patient_id, name, phone, email, dob, password, address, profile_photo, is_activated, totp_secret, session_token, session_start_time)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL)
                    """, (patient_data['patient_id'], patient_data['name'], patient_data['phone'],
                          patient_data['email'], patient_data['dob'], patient_data['password'],
                          patient_data['address'], profile_photo, 0, temp_data['otp_secret']))
                    cursor.execute("DELETE FROM temp_registrations WHERE id = %s", (temp_data['id'],))
                    mysql.connection.commit()
                    
                    store_user_location(patient_data['patient_id'])
                    
                    flash(f"Registration successful. Your Patient ID is {patient_data['patient_id']}. Await activation.", 'success')
                    session.pop('temp_registration_id', None)
                    cursor.close()
                    return redirect(url_for('auth.login'))
                else:
                    flash("Invalid OTP. Please try again.", 'danger')
                    cursor.close()
                    return render_template('verify_otp.html', email=json.loads(temp_data['data'])['email'])
            
            name = request.form['name']
            phone = request.form['phone']
            email = request.form['email']
            dob = request.form['dob']
            password = request.form['password']
            address = request.form['address']
            profile_photo = request.files.get('profile_photo')
            
            photo_data = None
            if profile_photo and profile_photo.filename:
                if profile_photo.mimetype in ['image/jpeg', 'image/png']:
                    photo_data = profile_photo.read()
                    if len(photo_data) > 2 * 1024 * 1024:
                        flash("Photo size must be under 2MB.", 'danger')
                        cursor.close()
                        return render_template('register.html')
                else:
                    flash("Only JPEG or PNG photos are allowed.", 'danger')
                    cursor.close()
                    return render_template('register.html')

            cursor.execute("SELECT * FROM patients WHERE email = %s OR phone = %s", (email, phone))
            existing_user = cursor.fetchone()
            
            if existing_user:
                flash('User with this email or phone number already exists.', 'danger')
                cursor.close()
                return redirect(url_for('auth.register'))
            
            while True:
                patient_id = generate_patient_id()
                cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
                if not cursor.fetchone():
                    break

            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret, interval=600)
            otp = totp.now()
            
            hashed_password = generate_password_hash(password)
            patient_data = {
                'patient_id': patient_id,
                'name': name,
                'phone': phone,
                'email': email,
                'dob': dob,
                'password': hashed_password,
                'address': address,
                'profile_photo': base64.b64encode(photo_data).decode('utf-8') if photo_data else None
            }
            
            cursor.execute("""
                INSERT INTO temp_registrations (type, data, otp_secret, expires_at)
                VALUES (%s, %s, %s, %s)
            """, ('patient', json.dumps(patient_data), secret, datetime.now() + timedelta(minutes=30)))
            mysql.connection.commit()
            
            if send_otp_email(email, otp):
                session.permanent = True
                session['temp_registration_id'] = cursor.lastrowid
                flash('OTP has been sent to your email.', 'info')
                cursor.close()
                return render_template('verify_otp.html', email=email)
            else:
                flash('Failed to send OTP. Please try again.', 'danger')
                cursor.close()
                return redirect(url_for('auth.register'))
        
        cursor.close()
        return render_template('register.html')
    
    except Exception as e:
        logger.error(f"Error in register route: {str(e)}", exc_info=True)
        flash("An error occurred during registration. Please try again.", 'danger')
        if 'cursor' in locals():
            cursor.close()
        return redirect(url_for('auth.register'))

@auth_bp.route('/resend_otp', methods=['POST'])
def resend_otp():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        email = request.form.get('email')
        cursor.execute("""
            SELECT * FROM temp_registrations 
            WHERE type = 'patient' AND JSON_EXTRACT(data, '$.email') = %s AND expires_at > %s
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
            cursor.close()
            return redirect(url_for('auth.register'))
        
        cursor.close()
        return render_template('verify_otp.html', email=email)
    
    except Exception as e:
        logger.error(f"Error in resend_otp route: {str(e)}", exc_info=True)
        flash("An error occurred while resending OTP. Please try again.", 'danger')
        if 'cursor' in locals():
            cursor.close()
        return redirect(url_for('auth.register'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    cursor = None
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')
            logger.debug(f"Login attempt for email: {email}")

            if not email or not password:
                flash('Email and password are required.', 'danger')
                logger.warning("Login attempt with missing email or password")
                return render_template('login.html')

            # Check database connectivity
            try:
                cursor.execute('SELECT 1')
                cursor.fetchall()
                logger.debug("Database connectivity check passed")
            except MySQLdb.OperationalError as e:
                logger.error(f"Database connection error during login: {str(e)}")
                flash('Unable to connect to the database. Please try again later.', 'danger')
                return render_template('login.html')

            # Ensure session_start_time column exists
            try:
                ensure_session_start_time_column()
            except MySQLdb.Error as e:
                logger.error(f"Failed to ensure session_start_time column: {str(e)}")
                flash('Server configuration error. Please contact support.', 'danger')
                return render_template('login.html')

            # Fetch user
            cursor.execute('SELECT * FROM patients WHERE email = %s', (email,))
            account = cursor.fetchone()
            logger.debug(f"User fetch result: {account is not None}")

            if not account:
                flash('Email not found.', 'danger')
                logger.warning(f"Login attempt with non-existent email: {email}")
                return render_template('login.html')

            if not check_password_hash(account['password'], password):
                flash('Incorrect password.', 'danger')
                logger.warning(f"Login attempt with incorrect password for email: {email}")
                return render_template('login.html')

            if not account['is_activated']:
                flash('Account not activated by cloud server.', 'warning')
                logger.warning(f"Login attempt with unactivated account: {email}")
                return render_template('login.html')

            # Check for existing active session
            if account['session_token'] and account['session_start_time']:
                expiry_time = account['session_start_time'] + timedelta(minutes=15)
                if datetime.now() < expiry_time:
                    logger.info(f"Active session detected for {email}. Login rejected.")
                    flash('This account is already logged in on another device. Please log out or wait for the session to expire (15 minutes).', 'danger')
                    return render_template('login.html')
                else:
                    # Clear expired session
                    logger.info(f"Clearing expired session for {email}")
                    cursor.execute("""
                        UPDATE patients 
                        SET session_token = NULL, session_start_time = NULL 
                        WHERE id = %s
                    """, (account['id'],))
                    mysql.connection.commit()

            # Generate and store new session token and start time
            session_token = generate_session_token()
            session_start_time = datetime.now()
            try:
                cursor.execute("""
                    UPDATE patients 
                    SET session_token = %s, session_start_time = %s 
                    WHERE id = %s
                """, (session_token, session_start_time, account['id']))
                mysql.connection.commit()
                logger.debug(f"Session token and start time updated for {email}")
            except MySQLdb.Error as e:
                logger.error(f"Database error updating session token for {email}: {str(e)}")
                flash('Database error updating session. Please try again.', 'danger')
                return render_template('login.html')

            # Set session variables
            session.permanent = True
            session['loggedin'] = True
            session['id'] = account['id']
            session['patient_id'] = account['patient_id']
            session['name'] = account['name']
            session['role'] = 'patient'
            session['session_token'] = session_token
            logger.debug(f"Session variables set for {email}")

            # Store user location (non-blocking)
            try:
                store_user_location(account['patient_id'])
            except Exception as e:
                logger.error(f"Non-critical error storing geolocation for {account['patient_id']}: {str(e)}")
                flash('Login successful, but failed to record location.', 'warning')

            logger.info(f"Successful login for {email} (Patient ID: {account['patient_id']})")
            flash('Login successful!', 'success')
            return redirect(url_for('patient.dashboard'))
        
        return render_template('login.html')
    
    except Exception as e:
        logger.error(f"Unexpected error in login route: {str(e)}", exc_info=True)
        flash(f"Unexpected error during login: {str(e)}. Please try again.", 'danger')
        return render_template('error.html', error=str(e))  # Render error page to avoid loop
    
    finally:
        if cursor:
            cursor.close()

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if request.method == 'POST':
            email = request.form['email']
            
            cursor.execute('SELECT * FROM patients WHERE email = %s', (email,))
            account = cursor.fetchone()
            
            if account:
                reset_token = generate_reset_token()
                expiry = datetime.now() + timedelta(hours=1)
                
                cursor.execute("""
                    UPDATE patients 
                    SET reset_token = %s, token_expiry = %s 
                    WHERE email = %s
                """, (reset_token, expiry, email))
                mysql.connection.commit()
                
                reset_link = url_for('auth.auth_reset_password', token=reset_token, _external=True)
                email_body = f"To reset your password, click this link: {reset_link}\nValid for 1 hour."
                
                if send_otp_email(email, email_body):
                    flash('Password reset link sent to your email.', 'success')
                else:
                    flash('Failed to send reset email. Please try again.', 'danger')
            else:
                flash('Email not found in our records.', 'danger')
            cursor.close()
            return redirect(url_for('auth.login'))  # Redirect to login after processing
            
        cursor.close()
        return render_template('forgot_password.html')
    
    except Exception as e:
        logger.error(f"Error in forgot_password route: {str(e)}", exc_info=True)
        flash("An error occurred during password reset. Please try again.", 'danger')
        if 'cursor' in locals():
            cursor.close()
        return redirect(url_for('auth.login'))

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'], endpoint='auth_reset_password')
def reset_password(token):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""
            SELECT * FROM patients 
            WHERE reset_token = %s AND token_expiry > %s
        """, (token, datetime.now()))
        account = cursor.fetchone()
        
        if not account:
            flash('Invalid or expired reset link.', 'danger')
            cursor.close()
            return redirect(url_for('auth.login'))

        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                cursor.close()
                return render_template('reset_password.html', token=token)
                
            hashed_password = generate_password_hash(password)
            cursor.execute("""
                UPDATE patients 
                SET password = %s, reset_token = NULL, token_expiry = NULL, session_token = NULL, session_start_time = NULL
                WHERE reset_token = %s
            """, (hashed_password, token))
            mysql.connection.commit()
            flash('Password reset successfully.', 'success')
            cursor.close()
            return redirect(url_for('auth.login'))
        
        cursor.close()
        return render_template('reset_password.html', token=token)
    
    except Exception as e:
        logger.error(f"Error in reset_password route: {str(e)}", exc_info=True)
        flash("An error occurred during password reset. Please try again.", 'danger')
        if 'cursor' in locals():
            cursor.close()
        return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
def logout():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if 'patient_id' in session:
            cursor.execute("UPDATE patients SET session_token = NULL, session_start_time = NULL WHERE patient_id = %s", (session['patient_id'],))
            mysql.connection.commit()
        cursor.close()
        
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('auth.home'))
    except Exception as e:
        logger.error(f"Error in logout route: {str(e)}", exc_info=True)
        flash("An error occurred during logout. Please try again.", 'danger')
        return redirect(url_for('auth.home'))