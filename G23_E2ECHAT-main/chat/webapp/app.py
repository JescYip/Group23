# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import auth_utils
import yaml
import requests

app = Flask(__name__)

SITE_KEY = '6LfzpbYpAAAAADLYATqajR2ahg9_vrU3rAngsUXF'
SECRET_KEY = '6LfzpbYpAAAAAKkPqANq8ziX3ln8rH6EC9W2GhoZ'
VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'

# Configure rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)
# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF prevention


# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text, message_type, message_status, created_at FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})


@app.route('/read_message', methods=['GET'])
def mark_read_messages():
        if 'user_id' not in session:
            abort(403)

        message_id = request.args.get('message_id', type=int)
        
        cur = mysql.connection.cursor()
        value = 'READ'
        query = """UPDATE messages SET message_status=%s WHERE message_id=%s"""
        cur.execute(query, (value, message_id,))
        mysql.connection.commit()


        cur.close()
        return jsonify({'message': f'Message marked as read successfully{message_id}'})


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(
    "5/5minutes",
    deduct_when=lambda response: response.status_code == 401
)
def login():
    error = None
    if request.method == 'POST':
        captcha_response = request.form.get('g-recaptcha-response')
        secret_key = SECRET_KEY
        data = {
            'secret': secret_key,
            'response': captcha_response
        }
        result = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data).json()
        if result['success']:
            userDetails = request.form
            username = userDetails['username']
            password = userDetails['password']
            cur = mysql.connection.cursor()
            cur.execute("SELECT user_id, password FROM users WHERE username=%s", (username,))
            account = cur.fetchone()
            cur.close()
            if not account:
                return render_template('login.html', error='Invalid credentials'), 401
            
            hashed_password = account[1]
            verdict = auth_utils.verify_pwd(password, hashed_password)
            if not verdict:
                return render_template('login.html', error='Invalid credentials'), 401

            session['username'] = username
            session['user_id'] = account[0]
            return redirect(url_for('submit_otp'))
        else:
            flash('Invalid reCAPTCHA. Try again', 'danger')


    return render_template('login.html', error=error)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']
    message_type = request.json['message_type']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text, message_type, 'UNREAD')
    
    return jsonify({'status': 'success', 'message': 'Message sent successfully'}), 200

def save_message(sender, receiver, message, message_type='msg', message_status='UNREAD'):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text, message_type, message_status) VALUES (%s, %s, %s, %s, %s)", (sender, receiver, message, message_type, message_status,))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET','POST'])
def signup():
    error = None
    if request.method == 'POST':
        # Implement account creation logic
        userDetails = request.form
        username = userDetails['username']
        password = userDetails['password']

        account = get_user_by_username(username)
        if account:
            return render_template('/signup.html', error='Username already exist')

        isvalid = auth_utils.validate_pwd(password)
        if not isvalid:
            return render_template('/signup.html', error='Password posses some vulnerability')

        hashed_pwd = auth_utils.hash_pwd(password)
        user_id, shared_secret = create_user(username, hashed_pwd)

        session['user_id'] = user_id

        return redirect(url_for('activate_otp', secret=shared_secret, username=username))

    # For GET method
    return render_template('/signup.html', error=error)

def create_user(username, password):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password,))
    user_id = cur.lastrowid

    # 2FA initialization
    shared_secret = auth_utils.generate_otp_secret()
    cur.execute("INSERT INTO otps (user_id, shared_secret, otp_status) VALUES (%s, %s, %s)", (user_id, shared_secret, 'TEMPORARY'))
    
    mysql.connection.commit()
    cur.close()

    return user_id, shared_secret

def get_user_by_username(username):
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, password FROM users WHERE username=%s", (username,))
    account = cur.fetchone()
    cur.close()
    if account:
        return {'user_id': account[0], 'username': account[1], 'password': account[2]}
    return None

@app.route('/submit_otp', methods=['GET', 'POST'])
def submit_otp():
    if 'user_id' not in session:
        abort(403)
    user_id = session['user_id']
    if request.method == 'POST':
        details = request.form
        otp_entry = get_OTP_by_user_id(user_id)
        if not otp_entry:
            abort(403)
        if otp_entry['otp_status'] != 'PERMANENT':
            abort(403)

        shared_secret = otp_entry['shared_secret']
        last_counter = otp_entry['last_counter']

        submitted_otp = details['otp']
        isvalid = auth_utils.verify_otp(shared_secret, submitted_otp, last_counter)
        if not isvalid:
            abort(401)
        accepted_otp_counter = auth_utils.get_accepted_otp_counter(shared_secret, submitted_otp)
        update_user_last_otp(user_id, submitted_otp, accepted_otp_counter)
        session['user_status'] = 'AUTHENTICATED'
        return redirect(url_for('index'))
    
    return render_template('submit_otp.html')

@app.route('/activate_otp', methods=['POST', 'GET'])
def activate_otp():
    error = None
    if 'user_id' not in session:
        abort(403)
    user_id = session['user_id']
    if request.method == 'POST':
        otp_entry = get_OTP_by_user_id(user_id)
        if not otp_entry:
            abort(403)
        shared_secret = otp_entry['shared_secret']
        details = request.form
        submitted_otp = details['otp']
        isvalid = auth_utils.verify_new_otp(shared_secret, submitted_otp)
        if isvalid:
            update_otp_status(user_id, 'PERMANENT')
            accepted_otp_counter = auth_utils.get_accepted_otp_counter(shared_secret, submitted_otp)
            update_user_last_otp(user_id, submitted_otp, accepted_otp_counter)
            session['user_status'] = 'AUTHENTICATED'
            return redirect(url_for('index'))
        else:
            error= 'Invalid'

    return render_template('/activate_otp.html', error=error)

def get_OTP_by_user_id(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, shared_secret, otp_status, last_otp, last_counter FROM otps WHERE user_id=%s", (user_id,))
    otp = cur.fetchone()
    cur.close()
    if otp:
        return {
            'user_id': otp[0], 
            'shared_secret': otp[1], 
            'otp_status': otp[2],
            'last_otp': otp[3],
            'last_counter': int(otp[4]) if otp[4] else None
        }
    return None

# def create_otp_entry(user_id, shared_secret):
#     cur = mysql.connection.cursor()
#     cur.execute("INSERT INTO otps (user_id, shared_secret, otp_status) VALUES (%s, %s, %s)", (user_id, shared_secret, 'TEMPORARY'))
#     mysql.connection.commit()
#     cur.close()

def update_otp_status(user_id, status='PERMANENT'):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE otps SET otp_status=%s WHERE user_id=%s", (status, user_id,))
    mysql.connection.commit()
    cur.close()

def update_user_last_otp(user_id, last_otp, last_counter):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE otps SET last_otp=%s, last_counter=%s WHERE user_id=%s", (last_otp, last_counter, user_id,))
    mysql.connection.commit()
    cur.close()

if __name__ == '__main__':
    app.run(debug=True)

