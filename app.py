from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_mail import Mail  # Add Flask-Mail
from werkzeug.security import generate_password_hash, check_password_hash
from utils.encryption import AESEncryption, RSAEncryption, DSASignature
from config import DB_CONFIG, AES_SECRET_KEY
import MySQLdb.cursors
import base64
import base64
# In app.py, add this import
from routes.pharmacy_routes import init_pharmacy
import random
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from io import BytesIO
import secrets
import pyotp
import qrcode
import requests
import json
from uuid import uuid4
from datetime import datetime

# Import Blueprints
from routes.auth_routes import auth_bp
from routes.patient_routes import patient_bp
from routes.doctor_routes import doctor_bp
from routes.cloud_routes import cloud_bp, init_cloud
from routes.appointment_routes import appointment_bp, init_appointment
from routes.video_routes import init_video, video_bp
from mail import init_mail  # Import init_mail from mail.py

# ... (previous imports remain unchanged)
import base64
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from utils.encryption import AESEncryption, RSAEncryption, DSASignature
from config import DB_CONFIG, AES_SECRET_KEY
import MySQLdb.cursors
import base64  # Already imported, no need to duplicate
from routes.pharmacy_routes import init_pharmacy
import random
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from io import BytesIO
import secrets
import pyotp
import qrcode
import requests
import json
from uuid import uuid4
from datetime import datetime

# Import Blueprints
from routes.auth_routes import auth_bp
from routes.patient_routes import patient_bp
from routes.doctor_routes import doctor_bp
from routes.cloud_routes import cloud_bp, init_cloud
from routes.appointment_routes import appointment_bp, init_appointment
from routes.video_routes import init_video, video_bp
from mail import init_mail

app = Flask(__name__)
app.secret_key = '5e8e565836ec4ab43a22afe1d316f35f87bf7eeab2d0b80d862d31d6321b976e'
app.permanent_session_lifetime = 3600  # Sessions last 1 hour

# Define the b64encode filter
def b64encode_filter(data):
    if data is None:
        return ''
    return base64.b64encode(data).decode('utf-8')

# Register the filter with Jinja2
app.jinja_env.filters['b64encode'] = b64encode_filter

# ---------------- UPI Gateway Constants ---------------- #
UPI_GATEWAY_API_KEY = "eb8414ec-1f13-4c8f-b713-ae55fbc94a97"
UPI_GATEWAY_CREATE_ORDER_URL = "https://api.ekqr.in/api/create_order"
UPI_GATEWAY_CHECK_STATUS_URL = "https://api.ekqr.in/api/check_order_status"

# ---------------- MySQL Configuration ---------------- #
app.config['MYSQL_HOST'] = DB_CONFIG['host']
app.config['MYSQL_USER'] = DB_CONFIG['user']
app.config['MYSQL_PASSWORD'] = DB_CONFIG['password']
app.config['MYSQL_DB'] = DB_CONFIG['database']

# ---------------- Mail Configuration ---------------- #
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'hemanth42079@gmail.com'
app.config['MAIL_PASSWORD'] = 'spxiqpqiuhaoixbk'
app.config['MAIL_DEFAULT_SENDER'] = 'hemanth42079@gmail.com'

mysql = MySQL(app)
mail = Mail(app)  # Initialize Flask-Mail

# ---------------- Initialize Encryption ---------------- #
aes = AESEncryption(AES_SECRET_KEY)
rsa = RSAEncryption()
dsa = DSASignature()

# Register Blueprints
app.register_blueprint(init_pharmacy(mysql))
app.register_blueprint(auth_bp)
app.register_blueprint(patient_bp)
app.register_blueprint(doctor_bp)
app.register_blueprint(init_cloud(mysql))
app.register_blueprint(init_appointment(mysql))
app.register_blueprint(init_video(mysql))

init_mail(app)

# ------------------- Error Handler ------------------- #
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)