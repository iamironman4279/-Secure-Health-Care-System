from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
import MySQLdb.cursors
import requests
import qrcode
from io import BytesIO
import base64
from uuid import uuid4
from datetime import datetime, timedelta
import json

appointment_bp = Blueprint('appointment', __name__)

# Global variable to store dependency
db = None
UPI_GATEWAY_API_KEY = "1a2c85dc-b447-45f6-bc2b-3b607edef0ba"
UPI_GATEWAY_CREATE_ORDER_URL = "https://api.ekqr.in/api/create_order"
UPI_GATEWAY_CHECK_STATUS_URL = "https://api.ekqr.in/api/check_order_status"

def init_appointment(mysql):
    global db
    db = mysql
    return appointment_bp

# Helper function to check if appointment exists
def appointment_exists(cursor, transaction_id):
    cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", (transaction_id,))
    return cursor.fetchone() is not None

# Helper function to get appointment fee
def get_appointment_fee(cursor, appointment_type):
    cursor.execute("""
        SELECT fee 
        FROM payment_settings 
        WHERE appointment_type = %s 
        ORDER BY updated_at DESC, id DESC 
        LIMIT 1
    """, (appointment_type,))
    result = cursor.fetchone()
    return str(result['fee']) if result else "2"  # Default to 2 if not set

# Appointments Route
@appointment_bp.route('/appointments', methods=['GET', 'POST'])
def appointments():
    if db is None:
        flash("Database connection not initialized.", "danger")
        return redirect(url_for('auth.login'))

    if 'loggedin' not in session:
        flash("Please log in to book an appointment.", 'warning')
        return redirect(url_for('auth.login'))

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if request.method == 'POST':
            if 'doctor_id' not in request.form or 'appointment_type' not in request.form:
                flash("Please select a doctor, appointment type, and fill all fields.", "danger")
                return redirect(url_for('appointment.appointments'))

            patient_id = session['patient_id']
            doctor_id = request.form['doctor_id']
            appointment_date = request.form['appointment_date']
            appointment_time = request.form['appointment_time']
            reason = request.form['reason']
            appointment_type = request.form['appointment_type']
            amount = get_appointment_fee(cursor, appointment_type)
            client_txn_id = str(uuid4()).replace('-', '')[:10]
            txn_date = datetime.now().strftime('%d-%m-%Y')
            unique_url = str(uuid4()).replace('-', '')[:40]

            # Check if the doctor is available
            cursor.execute("SELECT unavailable_until FROM doctors WHERE doctor_id = %s", (doctor_id,))
            doctor = cursor.fetchone()
            if doctor and doctor['unavailable_until'] and doctor['unavailable_until'] > datetime.now():
                flash(f"Dr. {doctor_id} is currently unavailable. Please try again later or select another doctor.", "danger")
                return redirect(url_for('appointment.appointments'))

            # Store pending appointment in session
            session['pending_appointment'] = {
                'patient_id': patient_id,
                'doctor_id': doctor_id,
                'appointment_date': appointment_date,
                'appointment_time': appointment_time,
                'reason': reason,
                'appointment_type': appointment_type,
                'unique_url': unique_url,
                'amount': amount,
                'client_txn_id': client_txn_id,
                'txn_date': txn_date,
                'payment_initiated': datetime.now().timestamp()
            }

            # Store transaction in transactions table
            cursor.execute("""
                INSERT INTO transactions (client_txn_id, patient_id, amount, status, appointment_type)
                VALUES (%s, %s, %s, %s, %s)
            """, (client_txn_id, patient_id, amount, 'PENDING', appointment_type))
            db.connection.commit()

            redirect_url = "http://127.0.0.1:5000/appointments"
            payload = {
                "key": UPI_GATEWAY_API_KEY,
                "client_txn_id": client_txn_id,
                "amount": amount,
                "p_info": f"Doctor Appointment ({appointment_type.capitalize()})",
                "customer_name": session['name'],
                "customer_email": "patient@example.com",
                "customer_mobile": "9876543210",
                "redirect_url": redirect_url,
                "udf1": "", "udf2": "", "udf3": ""
            }
            headers = {"Content-Type": "application/json"}
            response = requests.post(UPI_GATEWAY_CREATE_ORDER_URL, json=payload, headers=headers)
            result = response.json()

            if result.get("status") and "data" in result:
                payment_url = result["data"]["payment_url"]
                qr = qrcode.make(payment_url)
                buffer = BytesIO()
                qr.save(buffer, format="PNG")
                qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

                # Fetch available doctors (excluding unavailable ones)
                cursor.execute("""
                    SELECT * FROM doctors 
                    WHERE unavailable_until IS NULL OR unavailable_until <= %s
                """, (datetime.now(),))
                doctors = cursor.fetchall()
                cursor.execute("""
                    SELECT a.*, d.name AS doctor_name 
                    FROM appointments a 
                    JOIN doctors d ON a.doctor_id = d.doctor_id 
                    WHERE a.patient_id = %s 
                    ORDER BY a.appointment_date ASC
                """, (patient_id,))
                patient_appointments = cursor.fetchall()

                return render_template('appointments.html', doctors=doctors, appointments=patient_appointments,
                                       show_payment=True, amount=amount, payment_url=payment_url,
                                       qr_code=qr_code, client_txn_id=client_txn_id, appointment_type=appointment_type)
            else:
                flash(f"Payment initiation failed: {result.get('msg', 'Unknown error')}", "danger")
                cursor.execute("UPDATE transactions SET status = 'FAILED' WHERE client_txn_id = %s", (client_txn_id,))
                db.connection.commit()
                return redirect(url_for('appointment.appointments'))

        # Check for pending appointment and verify payment status
        if 'pending_appointment' in session:
            appt = session['pending_appointment']
            client_txn_id = appt['client_txn_id']
            txn_date = appt['txn_date']

            status_payload = {
                "key": UPI_GATEWAY_API_KEY,
                "client_txn_id": client_txn_id,
                "txn_date": txn_date
            }
            status_response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
            status_result = status_response.json()

            if status_result.get("status") and status_result["data"].get("status") == "SUCCESS":
                if not appointment_exists(cursor, client_txn_id):
                    cursor.execute("""
                        INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                            appointment_time, reason, status, video_call_url, transaction_id, appointment_type)
                        VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s, %s)
                    """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                          appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id, appt['appointment_type']))
                    # Set doctor as unavailable for 10 minutes
                    cursor.execute("""
                        UPDATE doctors 
                        SET unavailable_until = %s 
                        WHERE doctor_id = %s
                    """, (datetime.now() + timedelta(minutes=10), appt['doctor_id']))
                    cursor.execute("UPDATE transactions SET status = 'SUCCESS' WHERE client_txn_id = %s", (client_txn_id,))
                    db.connection.commit()
                session.pop('pending_appointment', None)
                flash("Appointment booked successfully! Awaiting doctor approval.", "success")
            elif status_result["data"].get("status") == "FAILED":
                cursor.execute("UPDATE transactions SET status = 'FAILED' WHERE client_txn_id = %s", (client_txn_id,))
                db.connection.commit()
                flash("Payment failed. Please try again.", "danger")
                session.pop('pending_appointment', None)

        # Fetch available doctors (excluding unavailable ones)
        cursor.execute("""
            SELECT * FROM doctors 
            WHERE unavailable_until IS NULL OR unavailable_until <= %s
        """, (datetime.now(),))
        doctors = cursor.fetchall()
        cursor.execute("""
            SELECT a.*, d.name AS doctor_name 
            FROM appointments a 
            JOIN doctors d ON a.doctor_id = d.doctor_id 
            WHERE a.patient_id = %s 
            ORDER BY a.appointment_date ASC
        """, (session['patient_id'],))
        patient_appointments = cursor.fetchall()
        # Fetch the latest fees
        cursor.execute("""
            SELECT appointment_type, fee 
            FROM payment_settings 
            WHERE id IN (
                SELECT MAX(id) 
                FROM payment_settings 
                GROUP BY appointment_type
            )
        """)
        payment_settings = cursor.fetchall()
        fees = {row['appointment_type']: row['fee'] for row in payment_settings}

        return render_template('appointments.html', doctors=doctors, appointments=patient_appointments,
                               show_payment=False, fees=fees)

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('appointment.appointments'))
    finally:
        cursor.close()

# Webhook Route
@appointment_bp.route('/webhook', methods=['POST'])
def webhook():
    if db is None:
        print("Database connection not initialized for webhook.")
        return "Server error", 500

    data = request.get_json() or request.form.to_dict()
    if not data or 'client_txn_id' not in data:
        print("Webhook data missing or no client_txn_id:", data)
        return "Invalid data", 400

    client_txn_id = data['client_txn_id']
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        if data.get('status') == "success":
            cursor.execute("SELECT * FROM appointments WHERE transaction_id = %s", (client_txn_id,))
            if not cursor.fetchone():
                if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
                    appt = session['pending_appointment']
                    cursor.execute("""
                        INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                            appointment_time, reason, status, video_call_url, transaction_id, appointment_type)
                        VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s, %s)
                    """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                          appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id, appt['appointment_type']))
                    # Set doctor as unavailable for 10 minutes
                    cursor.execute("""
                        UPDATE doctors 
                        SET unavailable_until = %s 
                        WHERE doctor_id = %s
                    """, (datetime.now() + timedelta(minutes=10), appt['doctor_id']))
                    cursor.execute("UPDATE transactions SET status = 'SUCCESS' WHERE client_txn_id = %s", (client_txn_id,))
                    db.connection.commit()
                    session.pop('pending_appointment', None)
            return "Webhook processed", 200
        elif data.get('status') == "failure":
            cursor.execute("UPDATE transactions SET status = 'FAILED' WHERE client_txn_id = %s", (client_txn_id,))
            db.connection.commit()
            if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
                session.pop('pending_appointment', None)
            return "Webhook processed (payment failed)", 200
        return "Webhook received, no action taken", 200

    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return "Webhook error", 500
    finally:
        cursor.close()

@appointment_bp.route('/check_payment_status', methods=['POST'])
def check_payment_status():
    if db is None:
        return jsonify({'status': 'ERROR', 'message': 'Database connection not initialized'}), 500

    data = request.get_json()
    client_txn_id = data.get('client_txn_id')
    if not client_txn_id:
        return jsonify({'status': 'INVALID', 'message': 'No transaction ID provided'}), 400

    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Check if appointment already exists
        if appointment_exists(cursor, client_txn_id):
            cursor.execute("UPDATE transactions SET status = 'SUCCESS' WHERE client_txn_id = %s", (client_txn_id,))
            db.connection.commit()
            return jsonify({'status': 'SUCCESS', 'message': 'Appointment already booked'}), 200

        # If no appointment exists, check payment status
        if 'pending_appointment' in session and session['pending_appointment']['client_txn_id'] == client_txn_id:
            appt = session['pending_appointment']
            status_payload = {
                "key": UPI_GATEWAY_API_KEY,
                "client_txn_id": client_txn_id,
                "txn_date": appt['txn_date']
            }
            response = requests.post(UPI_GATEWAY_CHECK_STATUS_URL, json=status_payload, headers={"Content-Type": "application/json"})
            result = response.json()

            if result.get("status") and result["data"].get("status", "").lower() == "success":
                cursor.execute("""
                    INSERT INTO appointments (patient_id, doctor_id, appointment_date, 
                        appointment_time, reason, status, video_call_url, transaction_id, appointment_type)
                    VALUES (%s, %s, %s, %s, %s, 'Pending', %s, %s, %s)
                """, (appt['patient_id'], appt['doctor_id'], appt['appointment_date'],
                      appt['appointment_time'], appt['reason'], appt['unique_url'], client_txn_id, appt['appointment_type']))
                # Set doctor as unavailable for 10 minutes
                cursor.execute("""
                    UPDATE doctors 
                    SET unavailable_until = %s 
                    WHERE doctor_id = %s
                """, (datetime.now() + timedelta(minutes=10), appt['doctor_id']))
                cursor.execute("UPDATE transactions SET status = 'SUCCESS' WHERE client_txn_id = %s", (client_txn_id,))
                db.connection.commit()
                session.pop('pending_appointment', None)
                return jsonify({'status': 'SUCCESS', 'message': 'Payment successful'}), 200
            elif result["data"].get("status", "").lower() == "failed":
                cursor.execute("UPDATE transactions SET status = 'FAILED' WHERE client_txn_id = %s", (client_txn_id,))
                db.connection.commit()
                session.pop('pending_appointment', None)
                return jsonify({'status': 'FAILED', 'message': 'Payment failed'}), 200
            return jsonify({'status': 'PENDING', 'message': 'Payment still pending'}), 200

        return jsonify({'status': 'INVALID', 'message': 'No matching transaction found'}), 400

    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500
    finally:
        cursor.close()

@appointment_bp.route('/cleanup_doctors', methods=['GET'])
def cleanup_doctors():
    cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("""
            UPDATE doctors 
            SET unavailable_until = NULL 
            WHERE unavailable_until <= %s
        """, (datetime.now(),))
        db.connection.commit()
        return jsonify({'status': 'SUCCESS', 'message': 'Doctor availability cleaned up'}), 200
    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)}), 500
    finally:
        cursor.close()

