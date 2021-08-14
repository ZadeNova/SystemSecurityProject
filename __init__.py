import datetime
from datetime import timedelta
import json
import random
import shelve
import string
import uuid
from random import randint  ###### email otp ####
import logging

from twilio.rest import Client
from chatterbot import ChatBot
from chatterbot.trainers import ListTrainer
from chatterbot.trainers import ChatterBotCorpusTrainer

from google.auth._default import default, load_credentials_from_file
import bcrypt
import pyotp
import requests
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, flash, json, after_this_request, session, abort
# New things added by Zade

from flask_session import Session
# End of new items

from flask_mail import Mail, Message
# SQL stuff
###line 43 , 44 for hong ji only , the others just # this 2 line
# import pymysql
# pymysql.install_as_MySQLdb()
#### line 43 , 44 for hong ji only , the others just # this 2 line  as hong ji pc have bug cant use the sql
# lol
import MySQLdb.cursors
from flask_mysqldb import MySQL
from flask_uploads import UploadSet, configure_uploads, IMAGES
from itsdangerous import SignatureExpired, URLSafeTimedSerializer

import CreatingSupplier
import Feedback as F
import Food
import Inventory
import OrderCreation
import User
from CancelOrderForm import CancelOrder
from CreateSupplierForm import SupplierForm
from DeliveryForm import DeliveryFormConfirm
from FeedbackForms import CreateFeedbackForm
from Food import Food
# HJ imports
from Forms import CreateUserForm
from InventoryForm import AddInventoryForm
from NewFoodForm import CreateFoodForm
from OrderForm import OrderInventory
from UpdateUserAccount import UpdateUserForm
from dineinForm import CreateDineInForm
from dineinuser import dineinuser
from loginform import CreateLoginUserForm
from mang_dinine_form import MangDineInForm
from managetable import mangetable1
from managetableform import Createmangetable
from mang_dinine_form import MangDineInForm
from updateOrder import Orderupdate
from updateSupplier import updateSupplierForm
from viewupdateforms import CreateUpdateFeedbackForm
from flask_mail import Mail, Message
from random import randint
import requests
from random import randint  ###### email otp ####
from UpdateUserAccount import UpdateUserForm
import json
# SQL stuff
###line 43 , 44 for hong ji only , the others just # this 2 line
# import pymysql
# pymysql.install_as_MySQLdb()
#### line 43 , 44 for hong ji only , the others just # this 2 line  as hong ji pc have bug cant use the sql
# lol
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import bcrypt
from cryptography.fernet import Fernet
import jwt
from itsdangerous import URLSafeSerializer, SignatureExpired, URLSafeTimedSerializer
## google login ##
import os
import pathlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

import sys
import logging
## google login end ###
# Form imports


app = Flask(__name__)
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)
app.config['SECRET_KEY'] = 'Project'
### google login key###
__all__ = ["default", "load_credentials_from_file"]

# Set default logging handler to avoid "No handler found" warnings.
logging.getLogger(__name__).addHandler(logging.NullHandler())
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
GOOGLE_CLIENT_ID = "936577677720-jgdpckeedh3lt1otgf92ecp88lqpvc1o.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="https://flaskprojectsystemsec.herokuapp.com/callback"
)


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return render_template('error401.html')  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/googleLog")
def googlelog():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        return render_template('error500.html')  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    session["Username"] = id_info.get("name")
    session['2fa_status'] = 'Pass'
    session['google'] = True
    username = session["Username"]
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
    account = cursor.fetchone()
    # If account exists show error and validation checks(do this at the form for this function)
    if account:
        cursor.execute("SELECT * FROM Authentication_Table WHERE Account_ID = %(ID)s", {'ID': account['ID']})
        account1 = cursor.fetchone()
        key = account['SymmetricKey']
        fkey = Fernet(key)
        decryptedaddress_Binary = fkey.decrypt(account['Address'].encode())
        decryptedPhoneNo_Binary = fkey.decrypt(account['Phone_Number'].encode())
        decryptedNRIC_Binary = fkey.decrypt(account['NRIC'].encode())
        decryptedaddress = decryptedaddress_Binary.decode('utf8')
        decryptedNRIC = decryptedNRIC_Binary.decode('utf-8')
        decryptedPhoneNo = decryptedPhoneNo_Binary.decode('utf-8')
        session['loggedin'] = True
        session['ID'] = account['ID']
        session["Username"] = username
        session['2fa_status'] = 'Nil'
        session['role'] = account['role']
        session['email'] = account['Email']
        session['NRIC'] = decryptedNRIC
        session['Address'] = decryptedaddress
        session['Phone_No'] = decryptedPhoneNo
        session['Email_Vulnerabilities'] = account['Email_Vulnerabilities']
        session['Account_Login_Notification'] = account['Account_Login_Notification']
        session["Attempts_Notification"] = account1['Attempts_Notification']
        print(session["Account_Login_Notification"])
        if account['password_update_time'] + datetime.timedelta(days=365) <= datetime.datetime.now().replace(
                microsecond=0):
            return redirect(url_for('Resetpassword', UUID=account['UUID']))
        elif account['Account_Status'] == "Pending":
            print("This account is unactivated")
            flash("This Account has not been activated. Please go to your email to activate the account.")
        elif account['Account_Status'] == "Banned":
            print("This account is banned")
            flash("This Account has been banned")
        elif account['Account_Status'] == "Disabled":
            print("Disabled")
            flash("Account has been disabled, please contact the helpdesk for further assistance")
        elif account['Account_Status'] == "Deleted":
            print("Deleted")
            flash("Account has been deleted, please contact the helpdesk for further assistance")
        elif account['Account_Status'] == "Force":
            print("Force")
            flash("Please reset your password, your password has been compromised ")
            return redirect(url_for('Resetpassword', UUID=account['UUID']))
        else:
            cursor.execute("""INSERT INTO userlogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
            mysql.connection.commit()

            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account1 = cursor.fetchone()
            cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""",
                           (session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))

            mysql.connection.commit()
            cursor.execute(
                """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
                [session['ID']])
            login_ID = cursor.fetchone()

            cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""", (session['ID'], login_ID['Log_in_ID']))
            mysql.connection.commit()
            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account1 = cursor.fetchone()
            if account1['Text_Message_Status'] == True or account1['Authenticator_Status'] == True or account1[
                'Push_Base_Status'] == True or account1['Backup_Code_Status'] == True or account1[
                'Sms_Message_Status'] == True:
                session['2fa_status'] = 'Fail'
                return render_template("2fa.html", status_text=account1['Text_Message_Status'],
                                       status_auth=account1['Authenticator_Status'],
                                       status_psuh=account1['Push_Base_Status'],
                                       status_back=account1['Backup_Code_Status'],
                                       status_sms=account1['Sms_Message_Status'])
            else:
                cursor.execute(
                    'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
                    [session['ID']])
                logininfo = cursor.fetchone()

                if account['Password'] == '0':
                    return redirect("Forcepassword")
                else:
                    if session["Account_Login_Notification"] == 1:  # If True send email
                        msg = Message("Login Notification", recipients=[account['Email']])
                        Username = account['Username']
                        IP = logininfo['Log_In_IP_Address']
                        Date = logininfo['Account_Log_In_Time']
                        msg.html = render_template('Login_Notification_Email.html', Username=Username, Date=Date, IP=IP)
                        mail.send(msg)
                        return redirect("/homepage")
                    else:
                        if account['Password'] == '0':
                            return redirect("Forcepassword")
                        else:
                            return redirect('/homepage')
    else:
        salt = bcrypt.gensalt(rounds=16)
        username = id_info.get("name")
        session['ID'] = id_info.get("name")
        NRIC = id_info.get("name") + 'Nric'
        DOB = False
        gender = False
        password = '0'
        print(password)
        phone_no ='phn'
        email = id_info.get("email")
        security_questions_1 = False
        answer_1 = False
        security_questions_2 = False
        answer_2 = False
        address = id_info.get("name") + 'address'
        role = 'Guest'
        Account_Login_Notification = 0
        print(username)
        print(email)
        print(DOB)
        now = datetime.datetime.now()
        account_creation_time = now.strftime("%Y-%m-%d %H:%M:%S")
        password_update_time = now.replace(microsecond=0)
        email_confirm = 0
        UUID = uuid.uuid4().hex
        Account_Status = 'Active'
        # hash_password = bcrypt.hashpw(password.encode(), salt)
        # Symmetric Key encryption
        key = Fernet.generate_key()
        # Loads the key into the crypto API
        fkey = Fernet(key)
        # Encrypt the stuff and convert to bytes by calling f.encrypt
        encryptedaddress = fkey.encrypt(address.encode())
        EncryptedNRIC = fkey.encrypt(NRIC.encode())
        EncryptPhoneNo = fkey.encrypt(phone_no.encode())

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
        account = cursor.fetchone()
        cursor.execute("""SELECT * FROM accounts WHERE Email = %(email)s""", {'email': email})
        account12 = cursor.fetchone()
        if account12:
            flash('Email already exists! Try another Email !')
            return redirect("/login")

        else:
            cursor.execute(
                "INSERT INTO accounts VALUES (NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                , (username, EncryptedNRIC, DOB, password, gender, EncryptPhoneNo, email, security_questions_1,
                   security_questions_2, answer_1, answer_2, encryptedaddress, role, account_creation_time,
                   email_confirm, key, UUID, Account_Status, password_update_time, Account_Login_Notification, 0, 0, 25))
            mysql.connection.commit()
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
            account12 = cursor.fetchone()
            session['ID'] = account12['ID']
            session["Username"] = username
            cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""",
                           (session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))

            mysql.connection.commit()
            cursor.execute(
                """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
                [session['ID']])
            login_ID = cursor.fetchone()
            cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""", (session['ID'], login_ID['Log_in_ID']))
            mysql.connection.commit()
            msg = 'You have successfully registered! '
            print("working")
            print('inserting authentication table')
            Text_Message_Status = False
            Authenticator_Status = False
            Authenticator_Key = 0
            Push_Base_Status = False
            Backup_Code_Status = False
            Backup_Code_Key = 0
            Backup_Code_No_Of_Use = 0
            Sms_Message_Status = False
            AttemptsNotification = False
            # cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            cursor.execute("""SELECT ID FROM accounts WHERE Username = %(username)s""", {'username': username})
            account = cursor.fetchone()

            Account_ID = account['ID']
            print(Account_ID, 'account id  ')
            cursor.execute("INSERT INTO authentication_table VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                           , (Account_ID, Text_Message_Status, Authenticator_Status, Authenticator_Key,
                              Push_Base_Status, Backup_Code_Status, Backup_Code_Key, Backup_Code_No_Of_Use,
                              Sms_Message_Status, AttemptsNotification))
            mysql.connection.commit()
            cursor.execute("""SELECT ID FROM accounts WHERE Username = %(username)s""", {'username': username})
            account = cursor.fetchone()

            session['loggedin'] = True
            session['ID'] = account['ID']
            session["Username"] = id_info.get("name")
            session['2fa_status'] = 'Nil'
            session['role'] = 'Guest'
            session['email'] = email
            session['Email_Vulnerabilities'] = account12['Email_Vulnerabilities']  # Zadeadd this line
            session['Account_Login_Notification'] = account12['Account_Login_Notification']
            session["Attempts_Notification"] = AttemptsNotification
            print(session["Account_Login_Notification"])
            cursor.execute("""INSERT INTO userlogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
            mysql.connection.commit()

            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account1 = cursor.fetchone()
            cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""",
                           (session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))

            mysql.connection.commit()
            cursor.execute(
                """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
                [session['ID']])
            login_ID = cursor.fetchone()
            cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""", (session['ID'], login_ID['Log_in_ID']))
            mysql.connection.commit()
            cursor.execute(
                'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
                [session['ID']])
            logininfo = cursor.fetchone()
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
            account = cursor.fetchone()

            if account['Password'] == '0':
                return redirect("Forcepassword")
            else:
                if account["Account_Login_Notification"] == 1:
                    msg = Message("Login Notification", recipients=[account['Email']])
                    Username = account['Username']
                    IP = logininfo['Log_In_IP_Address']
                    Date = logininfo['Account_Log_In_Time']
                    msg.html = render_template('Login_Notification_Email.html', Username=Username, Date=Date, IP=IP)
                    mail.send(msg)
                    return redirect("/homepage")
                else:
                    if account['Password'] == '0':
                        return redirect("Forcepassword")
                    else:
                        return redirect("/homepage")


@app.route('/Forcepassword', methods=['GET', 'POST'])
def Forcepassword():
    username = session['Username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
    account = cursor.fetchone()
    captcha_response = request.form.get('g-recaptcha-response')
    if request.method == 'POST' and 'password' in request.form and 'confirm password' in request.form:
        if is_human(captcha_response):
            password = request.form['password']
            confirm_password = request.form['confirm password']
            if password != confirm_password:
                flash("Your Password isn't the same as your confirm password. Please Try Again..")
                return render_template('ForcePassword.html',
                                       sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
            else:
                now = datetime.datetime.now().replace(microsecond=0)
                sql = "UPDATE accounts SET password_update_time = %s WHERE username = %s "
                value = (now, username)
                print(value)
                cursor.execute(sql, value)
                salt = bcrypt.gensalt(rounds=16)
                hash_password = bcrypt.hashpw(password.encode(), salt)
                sql2 = "UPDATE accounts SET Password = %s WHERE username = %s "
                value2 = (hash_password, username)
                cursor.execute(sql2, value2)
                mysql.connection.commit()
                return redirect(url_for('homepage'))
        else:
            flash('Sorry ! Please Check Im not a robot.')
            return render_template('ForcePassword.html',
                                   sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
    return render_template('ForcePassword.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")


## google login key end ###


##Flask - session stuff # FURTHER TESTING IS REQUIRED
# app.config['SESSION_TYPE'] = 'redis'
# app.config['SESSION_PERMANENT'] = False
# app.config['SESSION_USE_SIGNER'] = True
# app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6379')
# server_session = Session(app)

# End of flask-session

app.static_folder = 'static'


@app.route('/chatbot')
def chatbot():
    return render_template('chatbot.html')


@app.route("/get")
def get_bot_response():
    userText = request.args.get('msg')
    print(userText)
    chatbot = ChatBot(
        'CoronaBot',
        storage_adapter='chatterbot.storage.SQLStorageAdapter',
        logic_adapters=[
            'chatterbot.logic.MathematicalEvaluation',
            'chatterbot.logic.TimeLogicAdapter',
            'chatterbot.logic.BestMatch',
            {
                'import_path': 'chatterbot.logic.BestMatch',
                'default_response': 'I am sorry, but I do not understand. I am still learning.',
                'maximum_similarity_threshold': 0.90
            }
        ],
        database_uri='sqlite:///database.sqlite3'
    )

    # Training With Own Questions

    trainer = ListTrainer(chatbot)

    training_data_quesans = open('training_data/ques_ans.txt').read().splitlines()
    training_data_personal = open('training_data/personal_ques.txt').read().splitlines()

    training_data = training_data_quesans + training_data_personal

    trainer.train(training_data)

    # Training With Corpus

    trainer_corpus = ChatterBotCorpusTrainer(chatbot)

    trainer_corpus.train(
        'chatterbot.corpus.english'
    )

    return str(chatbot.get_response(userText))


# Flask-Mail and app.config stuff
# These are default values dont anyhow change
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEBUG'] = True
app.config['MAIL_USERNAME'] = 'Projectsec6@gmail.com'
app.config['MAIL_PASSWORD'] = 'newtestproject'
app.config['MAIL_DEFAULT_SENDER'] = 'Projectsec6@gmail.com'
app.config['MAIL_MAX_EMAILS'] = None
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False
# app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=1)
s = URLSafeTimedSerializer('SecretKey?')
mail = Mail(app)

# Database connection MYSQL
try:
    app.config['MYSQL_HOST'] = 'us-cdbr-east-04.cleardb.com'
    app.config['MYSQL_USER'] = 'b5353b83482c7f'
    app.config[
        'MYSQL_PASSWORD'] = '48b8b0c9'  # change this line to our own sql password , thank you vry not much xd
    app.config['MYSQL_DB'] = 'heroku_6230660f02e0b5c'
except:
    print("MYSQL root is not found?")


mysql = MySQL(app)
app.config['UPLOADED_IMAGES_DEST'] = 'uploads/FoodImages'
images = UploadSet('images', IMAGES)
configure_uploads(app, images)

### hong ji recapcha ##
app.config['SECRET_KEY'] = 'cairocoders-ednalan'


def is_human(captcha_response):
    """ Validating recaptcha response from google server
        Returns True captcha test passed for submitted form else returns False.
    """
    secret = "6LeQDi8bAAAAAIkB8_0hu3rvBirsTLkS4D6t4ztA"
    payload = {'response': captcha_response, 'secret': secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']


# Start of Testing Area

# Hong ji this email shit is yours
# @app.route('/EmailTest')
# def sendemail():
#    msg = Message("Hello there!", recipients=['limojo8042@awinceo.com'])
#    mail.send(msg)
#    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
#    account = cursor.fetchone()
#    return render_template("AuditLog.html", account=account,role=account['role'])

# @socketio.on("Disconnect")
# def disconnecttt():
#    print('hello')
#    pass
#

# Just dont touch anything plz
# def sessionchecker():
#    try:
#        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#        #cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': session['Username']})
#        #account = cursor.fetchone()
#
#        if not(session):
#            #Record into database that user log out
#            cursor.execute("""INSERT INTO UserActions VALUES (NULL,%s,%s) """,(session['ID'],"Logout"))
#            cursor.execute("""INSERT INTO account_log_out VALUES (NULL,%s,%s) """,(session['ID'],datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
#            mysql.connection.commit()
#            sqlcode = """UPDATE account_log_ins INNER JOIN account_log_out ON account_log_ins.Account_ID =
#            account_log_out.Account_ID SET account_log_ins.Log_Out_ID = account_log_out.Log_Out_ID WHERE
#            account_log_ins.Account_ID = %s AND account_log_ins.Log_Out_ID IS NULL AND account_log_out.Log_Out_ID = (SELECT max(account_log_out.Log_Out_ID) from account_log_out where account_log_out.Account_ID = %s)"""
#            values = (session['ID'],session['ID'])
#            cursor.execute(sqlcode,values)
#            mysql.connection.commit()
#            print(session)
#            session.clear()
#            print(session)
#            print("Log out complete sir!")
#        else:
#            print("User is not logged in")
#    except:
#        return render_template("error404.html")
# def pls():
#    print("Hello there motherfucker!")
#
# def executeplz():
#
#    print("The function here has been executed")
#
# @socketio.event('connect')
# def what():
#    print("Connected!")
#
#
# @socketio.on('message')
# def handlemessage(msg):
#    print(msg['data'])
#    pls()
#
# @socketio.on("Pepe")
# def evento():
#    print("PEPEPEPEPEPEPEPEE")
#
#
# @socketio.on('disconnect')
# def disconnect_details():
#    print("Wait so it disconnected")
#    popsession()


#
# @app.route('/testsocket')
# def testtt():
#    print(session)
#
#    return render_template('testsocketio.html')


# @app.route('/testsocket2')
# def test2():
#    print(session)
#
#    return render_template('testsocketio2.html')

# @app.after_request
# def after_request(response):
#    executeplz()
#    session.clear()
#    return response

# End of Testing Area


## hong ji text message done ??? #####
@app.route('/SmsOtpCheck')
def SmsOtpCheck():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    key = account['SymmetricKey']
    fkey = Fernet(key)
    decryptedPhoneNo_Binary = fkey.decrypt(account['Phone_Number'].encode())
    decryptedPhoneNo = decryptedPhoneNo_Binary.decode('utf-8')
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        if decryptedPhoneNo =='phn':
            return redirect(url_for('Forcephn'))
        else:
            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account_sid = 'AC8e0240f8443f52121cc16bbf1f38a719'
            auth_token = '..'
            ### check ur whatapp for the lasted codoe
            client = Client(account_sid, auth_token)
            print('phn:', decryptedPhoneNo)
            print(type(decryptedPhoneNo))
            #if phn == session['username']+'phn':
                #return redirect(url_for('Forcephn'))

            otp = randint(000000, 999999)  # email otp
            session['otp'] = otp

            k12 = datetime.datetime.now() + timedelta(seconds=60)
            session['otp_create_time'] = k12.strftime("%X")
            message = client.messages.create(
                    messaging_service_sid='MG3153b219b198d00e07da6bfd6b91ed8e',
                    body='This is your OTP : '+ str(otp) +' , please do not share it with other people thanks ',
                    to=decryptedPhoneNo
                )

            print(message.sid)


            return render_template('SmsOtpCheck.html', account=account,role=account['role'],opt=otp,phn=decryptedPhoneNo)
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/Forcephn', methods=['GET', 'POST'])
def Forcephn():
    username = session['Username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
    account = cursor.fetchone()
    captcha_response = request.form.get('g-recaptcha-response')
    if request.method == 'POST' and 'phn' in request.form:
        if is_human(captcha_response):
            phn=request.form['phn']
            phone_no = '+65'+phn
            key = account['SymmetricKey']
            fkey = Fernet(key)
            EncryptPhoneNo = fkey.encrypt(phone_no.encode())
            cursor.execute("UPDATE accounts SET Phone_Number=%s  WHERE Username=%s ", (EncryptPhoneNo, [session['Username']]))
            mysql.connection.commit()
            return redirect(url_for('SmsOtpCheck'))
        else:
            flash('Sorry ! Please Check Im not a robot.')
            return render_template('phn.html',
                                   sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb",account=account)
    return render_template('phn.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb",account=account)


@app.route('/validateSms', methods=['GET', 'POST'])
def validateSms():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        time_pre = session['otp_create_time']
        yy = datetime.datetime.now()
        time_now = yy.strftime("%X")
        user_otp = request.form['otp']
        if session['otp'] == int(user_otp) and time_pre > time_now:
            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account1 = cursor.fetchone()
            print('updating text status')
            cursor.execute("UPDATE  authentication_table SET Sms_Message_Status=True WHERE Account_ID=%s ",
                           [session['ID']])
            mysql.connection.commit()
            print('updated successfully noice ')
            flash('successfully', 'primary')
            return render_template('successful.html', account=account, role=account['role'], what='Sms')
        else:
            if time_pre < time_now:
                flash('Otp expire !', 'danger')
                return render_template('Fail.html', account=account, role=account['role'], what='Sms')
            else:
                flash('Opt incorrect !', 'danger')
            return render_template('Fail.html', account=account, role=account['role'], what='Sms')

    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/SmsOtpdisable')
def SmsOtpdisable():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        if account1['Sms_Message_Status'] == True:
            Sms_Message_Status = False
            cursor.execute(
                "UPDATE authentication_table SET Sms_Message_Status=%s  WHERE Account_ID=%s ",
                (Sms_Message_Status, [session['ID']]))
            mysql.connection.commit()
            flash('Sms Otp message  disable ! ', 'primary')
            return redirect(url_for('Changesettings'))
        else:
            flash('Sms Otp message is not activated ', 'danger')
        return redirect(url_for('Changesettings'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/EmailOtpCheck')
def EmailOtpCheck():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        otp = randint(000000, 999999)  # email otp
        session['otp'] = otp
        k12 = datetime.datetime.now() + timedelta(seconds=60)
        session['otp_create_time'] = k12.strftime("%X")

        account1 = cursor.fetchone()
        email = account['Email']
        msg = Message('This is your OTP', recipients=[email])
        msg.body = 'Your OTP is :\n' + '\t\t\t' + str(otp) + '\nPlease do not show this to anyone ! Thank you :)'
        mail.send(msg)

        return render_template('EmailOtpCheck.html', account=account, role=account['role'], opt=otp)
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/EmailOtpdisable')
def EmailOtpdisable():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        if account1['Text_Message_Status'] == True:
            Text_Message_Status = False
            cursor.execute(
                "UPDATE authentication_table SET Text_Message_Status=%s  WHERE Account_ID=%s ",
                (Text_Message_Status, [session['ID']]))
            mysql.connection.commit()
            flash('Text message  disable ! ', 'primary')
            return redirect(url_for('Changesettings'))
        else:
            flash('Text message is not activated ', 'danger')
        return redirect(url_for('Changesettings'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/validate', methods=['GET', 'POST'])
def validate():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        time_pre = session['otp_create_time']
        yy = datetime.datetime.now()
        time_now = yy.strftime("%X")
        user_otp = request.form['otp']
        if session['otp'] == int(user_otp) and time_pre > time_now:
            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account1 = cursor.fetchone()
            print('updating text status')
            cursor.execute("UPDATE  authentication_table SET Text_Message_Status=True WHERE Account_ID=%s ",
                           [session['ID']])
            mysql.connection.commit()
            print('updated successfully noice ')
            flash('successfully', 'primary')
            return render_template('successful.html', account=account, role=account['role'], what='Email')
        else:
            if time_pre < time_now:
                flash('Otp expire !', 'danger')
                return render_template('Fail.html', account=account, role=account['role'], what='Email')
            else:
                flash('Opt incorrect !', 'danger')
            return render_template('Fail.html', account=account, role=account['role'], what='Email')

    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


### hong ji text message end ####

# 2FA form route
# 2FA page route
@app.route("/Backupcode")
def backupcode():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        role = account['role']
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        if account1['Backup_Code_Status'] == False or account1['Backup_Code_No_Of_Use'] == 1:
            optt = string.ascii_uppercase + string.digits
            tem = random.sample(optt, 8)
            conv = ''.join(tem)
            Backup_Code_Status = True
            Backup_Code_Key = conv
            Backup_Code_No_Of_Use = False
            cursor.execute(
                "UPDATE authentication_table SET Backup_Code_Status=%s , Backup_Code_Key= %s ,Backup_Code_No_Of_Use=%s  WHERE Account_ID=%s ",
                (Backup_Code_Status, Backup_Code_Key, Backup_Code_No_Of_Use, [session['ID']]))
            mysql.connection.commit()
            return render_template("BackupCodeCheck.html", backup=conv, account=account, role=role)
        else:
            conv = account1['Backup_Code_Key']
            return render_template("BackupCodeCheck.html", backup=conv, account=account, role=role)
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route("/Backupcodedisable")
def backupcode_disable():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        role = account['role']
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        if account1['Backup_Code_Status'] == True:
            Backup_Code_Status = False
            Backup_Code_Key = False
            Backup_Code_No_Of_Use = False
            cursor.execute(
                "UPDATE authentication_table SET Backup_Code_Status=%s , Backup_Code_Key= %s ,Backup_Code_No_Of_Use=%s  WHERE Account_ID=%s ",
                (Backup_Code_Status, Backup_Code_Key, Backup_Code_No_Of_Use, [session['ID']]))
            mysql.connection.commit()
            flash('Backup Code   disable ! ', 'primary')
            return redirect(url_for('Changesettings'))
        else:
            flash('Backup Code is not activated ', 'danger')
        return redirect(url_for('Changesettings'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


### 2fa login ##
@app.route('/2fa', methods=['GET', 'POST'])
def two_fa():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
    account1 = cursor.fetchone()

    return render_template("2fa.html", status_text=account1['Text_Message_Status'],
                           status_auth=account1['Authenticator_Status'], status_psuh=account1['Push_Base_Status'],
                           status_back=account1['Backup_Code_Status'], status_sms=account1['Sms_Message_Status'])


@app.route('/twofaemail', methods=['GET', 'POST'])
def two_fa_email():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    if request.method == 'POST':
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        otp = randint(000000, 999999)  # email otp
        session['otp'] = otp
        k12 = datetime.datetime.now() + timedelta(seconds=60)
        session['otp_create_time'] = k12.strftime("%X")

        if account1['Text_Message_Status'] == True:
            email = account['Email']
            msg = Message('This is your OTP', recipients=[email])
            msg.body = 'Your OTP is :\n' + '\t\t\t' + str(otp) + '\nPlease do not show this to anyone ! Thank you :)'
            mail.send(msg)
            return render_template('2fa_email_check.html', account=account, role=account['role'])
        else:
            flash('You havent active this function yet choose other 2 factor authentication method', 'danger')
            return redirect(url_for("two_fa_email"))
    else:
        return redirect(url_for("two_fa"))


@app.route('/twofaemailcheck', methods=['GET', 'POST'])
def two_fa_email_check():
    user_otp = request.form['otp']
    time_pre = session['otp_create_time']
    yy = datetime.datetime.now()
    time_now = yy.strftime("%X")
    if session['otp'] == int(user_otp) and time_pre > time_now:
        session['2fa_status'] = 'Pass'

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""INSERT INTO userlogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
        mysql.connection.commit()
        cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""", (
            session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
        mysql.connection.commit()
        cursor.execute(
            """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
            [session['ID']])
        login_ID = cursor.fetchone()
        cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""",
                       (session['ID'], login_ID['Log_in_ID']))
        mysql.connection.commit()

        cursor.execute(
            'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
            [session['ID']])
        logininfo = cursor.fetchone()
        if session["Account_Login_Notification"] == 1:  # If login notif true

            msg = Message("Login Notification", recipients=[session['email']])
            Username = session['Username']
            IP = logininfo['Log_In_IP_Address']
            Date = logininfo['Account_Log_In_Time']
            msg.html = render_template('Login_Notification_Email.html', Username=Username, Date=Date, IP=IP)
            mail.send(msg)
            return redirect(url_for("homepage"))
        else:
            return redirect(url_for("homepage"))
    else:
        if time_pre < time_now:
            flash('Opt expired !', 'danger')
            return redirect(url_for("two_fa_email"))
        else:
            flash('Incorrect Otp , please try again !', 'danger')
        return redirect(url_for("two_fa_email"))


@app.route('/twofasms', methods=['GET', 'POST'])
def two_fa_sms():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    if request.method == 'POST':
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        otp = randint(000000, 999999)  # email otp
        session['otp'] = otp
        k12 = datetime.datetime.now() + timedelta(seconds=60)
        session['otp_create_time'] = k12.strftime("%X")

        if account1['Sms_Message_Status'] == True:
            account_sid = 'AC8e0240f8443f52121cc16bbf1f38a719'
            auth_token = '..' ## check your whatapp for the latest code
            client = Client(account_sid, auth_token)
            phn = session['Phone_No']
            message = client.messages.create(
                messaging_service_sid='MG3153b219b198d00e07da6bfd6b91ed8e',
                body='This is your OTP : ' + str(otp) + ' , please do not share it with other people thanks ',
                to=phn
            )
            print(message.sid)
            return render_template('2fa_email_check.html', account=account, role=account['role'])
        else:
            flash('You havent active this function yet choose other 2 factor authentication method', 'danger')
            return redirect(url_for("two_fa_sms"))
    else:
        return redirect(url_for("two_fa"))


@app.route('/twofasmscheck', methods=['GET', 'POST'])
def two_fa_sms_check():
    user_otp = request.form['otp']
    time_pre = session['otp_create_time']
    yy = datetime.datetime.now()
    time_now = yy.strftime("%X")
    if session['otp'] == int(user_otp) and time_pre > time_now:
        session['2fa_status'] = 'Pass'

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""INSERT INTO userlogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
        mysql.connection.commit()
        cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""", (
            session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
        mysql.connection.commit()
        cursor.execute(
            """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
            [session['ID']])
        login_ID = cursor.fetchone()
        cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""",
                       (session['ID'], login_ID['Log_in_ID']))
        mysql.connection.commit()

        cursor.execute(
            'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
            [session['ID']])
        logininfo = cursor.fetchone()
        if session["Account_Login_Notification"] == 1:  # If login notif true

            msg = Message("Login Notification", recipients=[session['email']])
            Username = session['Username']
            IP = logininfo['Log_In_IP_Address']
            Date = logininfo['Account_Log_In_Time']
            msg.html = render_template('Login_Notification_Email.html', Username=Username, Date=Date, IP=IP)
            mail.send(msg)
            return redirect(url_for("homepage"))
        else:
            return redirect(url_for("homepage"))
    else:
        if time_pre < time_now:
            flash('Opt expired !', 'danger')
            return redirect(url_for("two_fa_email"))
        else:
            flash('Incorrect Otp , please try again !', 'danger')
        return redirect(url_for("two_fa_sms"))


@app.route('/twofabackupcode', methods=['GET', 'POST'])
def two_fa_backupcode():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    if request.method == 'POST':
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        if account1['Backup_Code_Status'] == True and account1['Backup_Code_No_Of_Use'] == False:
            return render_template('2fa_backupcode_check.html')
        else:
            flash('You havent active this function yet choose other 2 factor authentication method', 'danger')
            return redirect(url_for("two_fa"))
    else:
        return redirect(url_for("two_fa"))


# This is the checking.
@app.route('/twofabackupcodecheck', methods=['GET', 'POST'])
def two_fa_backupcode_check():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
    account1 = cursor.fetchone()
    conv = account1['Backup_Code_Key']
    user_otp = request.form['backupcode']
    if conv == user_otp and account1['Backup_Code_No_Of_Use'] == False:
        session['2fa_status'] = 'Pass'
        Backup_Code_Status = False
        Backup_Code_Key = False
        Backup_Code_No_Of_Use = False
        cursor.execute(
            "UPDATE authentication_table SET Backup_Code_Status=%s , Backup_Code_Key= %s ,Backup_Code_No_Of_Use=%s  WHERE Account_ID=%s ",
            (Backup_Code_Status, Backup_Code_Key, Backup_Code_No_Of_Use, [session['ID']]))
        mysql.connection.commit()
        cursor.execute("""INSERT INTO UserLogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
        mysql.connection.commit()
        cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""", (
            session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
        mysql.connection.commit()
        cursor.execute(
            """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
            [session['ID']])
        login_ID = cursor.fetchone()
        cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""",
                       (session['ID'], login_ID['Log_in_ID']))
        mysql.connection.commit()
        cursor.execute(
            'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
            [session['ID']])
        logininfo = cursor.fetchone()
        if session["Account_Login_Notification"] == 1:  # If login notif true
            msg = Message("Login Notification", recipients=[session['email']])
            Username = session['Username']
            IP = logininfo['Log_In_IP_Address']
            Date = logininfo['Account_Log_In_Time']
            msg.html = render_template('Login_Notification_Email.html', Username=Username, Date=Date, IP=IP)
            mail.send(msg)
            return redirect(url_for("homepage"))
        else:
            return redirect(url_for("homepage"))
    else:
        flash('Incorrect Opt ,please check again !')
        return redirect(url_for("two_fa"))


@app.route('/twofaauthen', methods=['GET', 'POST'])
def two_fa_authen():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    if request.method == 'POST':
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        if account1['Authenticator_Status'] == True:

            return render_template('2fa_authenticator_check.html')
        else:
            flash('You havent active this function yet choose other 2 factor authentication method', 'danger')
            return redirect(url_for("two_fa"))
    else:
        return redirect(url_for("two_fa"))


@app.route('/twofaauthencheck', methods=['GET', 'POST'])
def two_fa_authen_check():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
    account = cursor.fetchone()
    cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
    account1 = cursor.fetchone()
    otp = int(request.form.get("otp1"))
    secret = account1['Authenticator_Key']
    if pyotp.TOTP(secret).verify(otp):
        session['2fa_status'] = 'Pass'
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("""INSERT INTO UserLogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
        mysql.connection.commit()
        cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""", (
            session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
        mysql.connection.commit()
        cursor.execute(
            """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
            [session['ID']])
        login_ID = cursor.fetchone()
        cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""",
                       (session['ID'], login_ID['Log_in_ID']))
        mysql.connection.commit()

        msg = Message("Login Notification", recipients=[account['Email']])
        Username = account['Username']
        cursor.execute(
            'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
            [session['ID']])
        logininfo = cursor.fetchone()
        if session["Account_Login_Notification"] == 1:  # If login notif true
            msg = Message("Login Notification", recipients=[account['Email']])
            Username = account['Username']
            IP = logininfo['Log_In_IP_Address']
            Date = logininfo['Account_Log_In_Time']
            msg.html = render_template('Login_Notification_Email.html', Username=Username, Date=Date, IP=IP)
            mail.send(msg)
            return redirect(url_for("homepage"))
        else:
            return redirect(url_for("homepage"))
    else:
        # inform users if OTP is invalid
        flash("You have supplied an invalid 2FA token!", "danger")
        return redirect(url_for("two_fa"))


### end of 2fa login ###
@app.route("/login/2fadisable/")
def login_2fa_disable():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        role = account['role']
        if account1['Authenticator_Status'] == True:
            Authenticator_Key = False
            Authenticator_Status = False
            cursor.execute(
                "UPDATE authentication_table SET Authenticator_Status=%s , Authenticator_Key=%s  WHERE Account_ID=%s ",
                (Authenticator_Status, Authenticator_Key, [session['ID']]))
            mysql.connection.commit()
            flash('Authenticator App  disable ! ', 'primary')
            return redirect(url_for('Changesettings'))
        else:
            flash('Authenticator App is not activated ', 'danger')
            return redirect(url_for('Changesettings'))

    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route("/login/2fa/")
def login_2fa():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        role = account['role']
        if account1['Authenticator_Status'] == False or account1['Authenticator_Key'] == 0:
            # generating random secret key for authentication
            secret = pyotp.random_base32()
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                "alice@google.com",
                issuer_name="Secure App")
            print(totp_uri)
            return render_template("login_2fa.html", secret=secret, account=account, role=role)
        else:
            secret = account1["Authenticator_Key"]
            return render_template("login_2fa.html", secret=secret, account=account, role=role)
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route("/login/2fa/", methods=["POST"])
def login_2fa_form():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        # getting secret key used by user
        secret = request.form.get("secret")
        # getting OTP provided by user
        otp = int(request.form.get("otp"))

        # verifying submitted OTP with PyOTP
        if pyotp.TOTP(secret).verify(otp):
            # inform users if OTP is valid
            flash("The TOTP 2FA token is valid", "success")
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            account = cursor.fetchone()
            role = account['role']
            cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
            account1 = cursor.fetchone()
            Authenticator_Status = True
            Authenticator_Key = secret
            cursor.execute(
                "UPDATE authentication_table SET Authenticator_Status=%s , Authenticator_Key= %s   WHERE Account_ID=%s ",
                (Authenticator_Status, Authenticator_Key, [session['ID']]))
            mysql.connection.commit()

            return render_template("login_2fa.html", secret=secret, account=account, role=role)
        else:
            # inform users if OTP is invalid
            flash("You have supplied an invalid 2FA token!", "danger")
            return redirect(url_for("login_2fa"))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


# email test
@app.route('/userprofile')
def Userprofile():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        print(session)
        print(session['loggedin'])
        if 'loggedin' in session:
            # We need all the account info for the user so we can display it on the profile page
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            account = cursor.fetchone()
            key = account['SymmetricKey']
            fkey = Fernet(key)
            decryptedaddress_Binary = fkey.decrypt(account['Address'].encode())
            decryptedPhoneNo_Binary = fkey.decrypt(account['Phone_Number'].encode())
            decryptedNRIC_Binary = fkey.decrypt(account['NRIC'].encode())
            decryptedaddress = decryptedaddress_Binary.decode('utf8')
            decryptedNRIC = decryptedNRIC_Binary.decode('utf-8')
            decryptedPhoneNo = decryptedPhoneNo_Binary.decode('utf-8')
            session['ID'] = account['ID']
            session['Username'] = account['Username']
            session['email'] = account['Email']
            session['NRIC'] = decryptedNRIC
            session['Address'] = decryptedaddress
            session['Phone_No'] = decryptedPhoneNo
            session['2fa_status'] = 'Nil'
            session['role'] = account['role']
            # Show the profile page with account info
            return render_template('userprofile.html', account=account, email=session['email'], NRIC=session['NRIC'],
                                   address=session['Address'], phone_no=session['Phone_No'])
            # User is not loggedin redirect to login page
        return redirect(url_for('login'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


# @app.route('/ipaddchecker', methods=['GET', 'POST'])
# def ipchecker():
#    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#    cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
#    account = cursor.fetchone()
#    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
#    data = ipapi.location(ip=ip, output='json')
#    return render_template('ipaddresscheck.html',data=data,account=account,role=account['role'])


@app.route('/deleteaccount', methods=['GET', 'POST'])
def deleteaccount():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        flash('I want to delete my account')
        return render_template("accountdelete.html", account=account, role=account['role'])
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/deleteaccountcheck', methods=['POST'])
def deleteaccoutcheck():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        user_int = request.form['user_int']
        if user_int == 'I want to delete my account':
            try:
                username = account['Username']
                Account_Status = 'Disable'
                cursor.execute(
                    "UPDATE accounts SET Account_Status=%s   WHERE Account_ID=%s ",
                    (Account_Status, [session['ID']]))
                mysql.connection.commit()
                print(cursor.rowcount, "record(s) deleted")
                session.clear()
                return redirect(url_for('login'))
            except:
                return redirect(url_for('deleteaccountcheck'))
        else:
            msg = 'Wrong input , please follow word by word , including spacing , and capital !'
            flash('I want to delete my account')
            # return redirect(url_for('deleteaccount',msg=msg))
            return render_template("accountdelete.html", account=account, msg=msg)
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/Settings', methods=['GET', 'POST'])
def Changesettings():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        global dataforemailupdate, IDUpdate
        formupdateuser = UpdateUserForm(request.form)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()
        role = account['role']
        key = account['SymmetricKey']
        fkey = Fernet(key)
        decryptedaddress_Binary = fkey.decrypt(account['Address'].encode())
        decryptedPhoneNo_Binary = fkey.decrypt(account['Phone_Number'].encode())
        decryptedNRIC_Binary = fkey.decrypt(account['NRIC'].encode())
        decryptedaddress = decryptedaddress_Binary.decode('utf8')
        decryptedNRIC = decryptedNRIC_Binary.decode('utf-8')
        decryptedPhoneNo = decryptedPhoneNo_Binary.decode('utf-8')
        if request.method == 'POST' and (formupdateuser.Username.data != account['Username'] or
                                         formupdateuser.NRIC.data != decryptedNRIC or formupdateuser.DOB.data !=
                                         account['Date_of_Birth'] or
                                         formupdateuser.Gender.data != account[
                                             'Gender'] or formupdateuser.Phone_Number.data != decryptedPhoneNo or
                                         formupdateuser.Email.data != account[
                                             'Email'] or formupdateuser.Security_Questions_1.data != account[
                                             'Security_Question_1'] or
                                         formupdateuser.Security_Questions_2.data != account[
                                             'Security_Question_2'] or formupdateuser.Answers_1.data != account[
                                             'Answer_1'] or
                                         formupdateuser.Answers_2.data != account[
                                             'Answer_2'] or formupdateuser.Address.data != decryptedaddress):

            IDUpdate = session['ID']
            cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            account = cursor.fetchone()
            counter, Updated = 0, 1

            cursor.execute("""INSERT INTO UserUpdateTime (Account_ID) VALUES (%s) """, [session['ID']])

            if formupdateuser.Username.data != account['Username']:
                cursor.execute("UPDATE accounts SET Username=%s  WHERE id=%s ",
                               (formupdateuser.Username.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Username = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""",[Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.NRIC.data != decryptedNRIC:
                EncryptedNRIC = fkey.encrypt(formupdateuser.NRIC.data.encode())
                cursor.execute("UPDATE accounts SET NRIC=%s  WHERE id=%s ", (EncryptedNRIC, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET NRIC = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.DOB.data != account['Date_of_Birth']:
                cursor.execute("UPDATE accounts SET Date_of_Birth=%s  WHERE id=%s ",
                               (formupdateuser.DOB.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Date_Of_Birth = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Gender.data != account['Gender']:
                cursor.execute("UPDATE accounts SET Gender=%s  WHERE id=%s ",
                               (formupdateuser.Gender.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Gender = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Phone_Number.data != decryptedPhoneNo:
                new='+65'+formupdateuser.Phone_Number.data
                EncryptPhoneNo = fkey.encrypt(new.encode())
                cursor.execute("UPDATE accounts SET Phone_Number=%s  WHERE id=%s ", (EncryptPhoneNo, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Phone_Number = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                session['Phone_No']=new
                counter += 1
            if formupdateuser.Email.data != account['Email']:
                cursor.execute("UPDATE accounts SET Email=%s  WHERE id=%s ",
                               (formupdateuser.Email.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Email = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Security_Questions_1.data != account['Security_Question_1']:
                cursor.execute("UPDATE accounts SET Security_Question_1=%s  WHERE id=%s ",
                               (formupdateuser.Security_Questions_1.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Security_Question_1 = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Security_Questions_2.data != account['Security_Question_2']:
                cursor.execute("UPDATE accounts SET Security_Question_2=%s  WHERE id=%s ",
                               (formupdateuser.Security_Questions_2.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Security_Question_2 = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Answers_1.data != account['Answer_1']:
                cursor.execute("UPDATE accounts SET Answer_1=%s  WHERE id=%s ",
                               (formupdateuser.Answers_1.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Answer_1 = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Answers_2.data != account['Answer_2']:
                cursor.execute("UPDATE accounts SET Answer_2=%s  WHERE id=%s ",
                               (formupdateuser.Answers_2.data, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Answer_2 = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if formupdateuser.Address.data != decryptedaddress:
                encryptedaddress = fkey.encrypt(formupdateuser.Address.data.encode())
                cursor.execute("UPDATE accounts SET Address=%s  WHERE id=%s ", (encryptedaddress, [session['ID']]))
                # cursor.execute("""UPDATE UserUpdateTime SET Address = %s WHERE Account_ID = %s AND ID = (SELECT Max(ID))""", [Updated,session['ID']])
                mysql.connection.commit()
                counter += 1
            if counter > 0:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("""SELECT distinct Log_In_IP_Address FROM account_log_ins WHERE Account_ID = %s""",
                               [session['ID']])
                cursor.execute(
                    """UPDATE UserUpdateTime SET UpdatedEvent = 'Update' WHERE Account_ID = %s ORDER BY ID DESC Limit 1;""",
                    [session['ID']])
                cursor.execute(
                    """UPDATE UserUpdateTime SET Date_and_Time = current_timestamp() WHERE Account_ID = %s ORDER BY ID DESC Limit 1; """,
                    [session['ID']])
                cursor.execute(
                    """UPDATE UserUpdateTime SET Ip_Address = %s WHERE Account_ID = %s ORDER BY ID DESC Limit 1""",
                    [request.remote_addr, session['ID']])
                mysql.connection.commit()
                account1 = cursor.fetchone()
                counter = str(counter)
                msg = Message("Update of Account", recipients=account['Email'].split())
                msg.html = render_template('UpdateEmail.html', counter=str(counter), Ipaddress=request.remote_addr)
                mail.send(msg)
                flash(
                    "You have just updated {} item/s in your account. An email has been send out as a notification.".format(
                        counter), 'category1')

            return redirect(url_for('Changesettings'))
        else:
            formupdateuser.Username.data = account['Username']
            formupdateuser.NRIC.data = decryptedNRIC
            formupdateuser.DOB.data = account['Date_of_Birth']
            formupdateuser.Gender.data = account['Gender']
            formupdateuser.Phone_Number.data = decryptedPhoneNo
            formupdateuser.Email.data = account['Email']
            formupdateuser.Security_Questions_1.data = account['Security_Question_1']
            formupdateuser.Security_Questions_2.data = account['Security_Question_2']
            formupdateuser.Answers_1.data = account['Answer_1']
            formupdateuser.Answers_2.data = account['Answer_2']
            formupdateuser.Address.data = decryptedaddress

        return render_template('Settings.html', account=account, form=formupdateuser, ip=ip, role=role,
                               status_text=account1['Text_Message_Status'],
                               status_auth=account1['Authenticator_Status'], status_psuh=account1['Push_Base_Status'],
                               status_back=account1['Backup_Code_Status'], status_sms=account1['Sms_Message_Status'], status_Attempts=account1['Attempts_Notification'])
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/Settings_changepassword', methods=['GET', 'POST'])
def Settings_changepassword():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        hashandsalt = account['Password']
        UUID = account['UUID']
        if request.method == 'POST':
            Old_password = request.form['Old_password']
            New_password = request.form['New_password']
            Confirm_password = request.form['Confirm_password']

            if bcrypt.checkpw(Old_password.encode(), hashandsalt.encode()):
                if New_password == Old_password:
                    flash('Please use a different password', 'category2')
                    return redirect(url_for("Changesettings"))
                elif New_password == Confirm_password:
                    salt = bcrypt.gensalt(rounds=16)
                    hash_password = bcrypt.hashpw(New_password.encode(), salt)
                    sql = "UPDATE accounts SET Password = %s WHERE UUID = %s "
                    value = (hash_password, UUID)
                    cursor.execute(sql, value)
                    cursor.execute(
                        """INSERT INTO UserUpdateTime VALUES (NULL, %s, %s, %s, %s) """, [session['ID'], 'UpdatePassword', request.remote_addr, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                    mysql.connection.commit()
                    counter = 1
                    email = Message("Update of Account", recipients=account['Email'].split())
                    email.html = render_template('UpdateEmail.html', counter=str(counter), Ipaddress=request.remote_addr)
                    mail.send(email)

                    flash('Password have been updated', 'category2')
                    return redirect(url_for("Changesettings"))
                else:
                    flash('New password is not the same as Confirm password', 'category2')
                    return redirect(url_for("Changesettings"))
            else:
                flash('Old password is not the same as Current password', 'category2')
                return redirect(url_for("Changesettings"))
        else:
            return redirect(url_for("Changesettings"))

    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


# @app.route('/confirm_email_afterupdate/<token>')
# def confirm_email_update(token):
#    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
#
#        try:
#            print(dataforemailupdate,IDUpdate)
#            print(session)
#            data = dataforemailupdate
#            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#            cursor.execute('SELECT * FROM accounts WHERE id = %(ID)s', {'ID':IDUpdate})
#            account = cursor.fetchone()
#            print(account)
#            email = s.loads(token, salt='Email-confirm', max_age=180)
#
#            sql = "UPDATE accounts SET Username = %s,NRIC = %s,Date_of_Birth = %s,Gender = %s , Phone_Number = %s , Email = %s , Security_Question_1 = %s, Security_Question_2 = %s,Answer_1 = %s,Answer_2 = %s,Address = %s"
#            value = (data['Username'], data['NRIC'], data['DOB'], data['Gender'], data['Phone_Number'], data['Email'], data['Security_Questions_1'], data['Security_Questions_2'], data['Answers_1'], data['Answers_2'], data['Address'])
#            cursor.execute(sql, value)
#            mysql.connection.commit()
#            return redirect(url_for('Managerprofile'))
#        except SignatureExpired:
#            return 'Token is expired'
#    else:
#        flash('Please complete your 2FA !', 'danger')
#        return redirect(url_for("two_fa"))
#
#
@app.route('/managerprofile')
def Managerprofile():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        if 'loggedin' in session:
            # We need all the account info for the user so we can display it on the profile page
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            account = cursor.fetchone()
            print(account)
            print(account['Security_Question_1'])
            print(account['Security_Question_2'])
            print(account['Answer_1'])
            print(account['Answer_2'])
            if account is None:
                # Account does not exist.
                return False
            # Show the profile page with account info
            return render_template('AdminProfile.html', account=account, email=session['email'], NRIC=session['NRIC'],
                                   address=session['Address'], phone_no=session['Phone_No'])
            # User is not loggedin redirect to login page
        return redirect(url_for('login'))

    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


# Edit this - Zadesqlstuff

def get_location(ip_address):
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':

        try:
            response = requests.get("http://ip-api.com/json/{}".format(ip_address))
            js = response.json()
            country = js
            return country
        except Exception as e:
            return "Unknown"
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/EmailLoginNotification', methods=['GET', 'POST'])
def LoginNotification():
    T, F = 1, 0
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE ID = %s AND Username = %s""", [session['ID'], session['Username']])
    account = cursor.fetchone()

    if session["Account_Login_Notification"] == 0:  # This means u on account login notification.
        cursor.execute("""UPDATE accounts SET Account_Login_Notification = %s WHERE ID = %s """, [T, session['ID']])
        session["Account_Login_Notification"] = 1
        mysql.connection.commit()
        print(session)
        print('True')
        return redirect(url_for('Changesettings'))
    else:
        cursor.execute("""UPDATE accounts SET Account_Login_Notification = %s WHERE ID = %s """, [F, session['ID']])
        mysql.connection.commit()
        session["Account_Login_Notification"] = 0
        print(session)
        print('False ')
        return redirect(url_for('Changesettings'))


@app.route('/AttemptsLoginNotification', methods=['GET', 'POST'])
def AttemptsNotification():
    T, F = 1, 0
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE ID = %s AND Username = %s""", [session['ID'], session['Username']])
    account = cursor.fetchone()
    cursor.execute("SELECT * FROM Authentication_Table WHERE Account_ID = %(ID)s", {'ID': account['ID']})
    # Fetch one record and return result
    account1 = cursor.fetchone()

    if account1["Attempts_Notification"] == 0:
        cursor.execute("""UPDATE Authentication_Table SET Attempts_Notification = %s WHERE Account_ID = %s """, [T, account['ID']])
        session["Attempts_Notification"] = 1
        mysql.connection.commit()
        print(session)
        print('True')
        return redirect(url_for('Changesettings'))
    else:
        cursor.execute("""UPDATE Authentication_Table SET Attempts_Notification = %s WHERE Account_ID = %s """, [F, account['ID']])
        mysql.connection.commit()
        session["Attempts_Notification"] = 0
        print(session)
        print('False ')
        return redirect(url_for('Changesettings'))
# sadge

@app.route('/IPmap')
def Ipmap():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        if session['role'] == 'Admin':
            ip_address = request.remote_addr
            # ip_address =
            country = get_location(ip_address)
            print(country)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            account = cursor.fetchone()
            return render_template("IPmap.html", account=account, country=country)
        else:
            return redirect(url_for('Userprofile'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


# Zade Security Notification

def SecurityAlgo():
    # Write down conditions for when to notify user if security threshold exceeds some amount.
    return 'dew it'





@app.route('/dashboard/24hour', methods=['GET', 'POST'])
def dashboardday():
    print(session)
    session['DashboardTime'] = "24Hour"
    return redirect(url_for('ViewDashboard'))


@app.route('/dashboard/1hour', methods=['GET', 'POST'])
def dashboardhour():
    print(session)
    session['DashboardTime'] = "1Hour"
    return redirect(url_for('ViewDashboard'))




@app.route('/dashboard')
def ViewDashboard():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        if session['role'] == 'Admin':

            print(session)
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
            account = cursor.fetchone()
            cursor.execute("""SELECT DISTINCT Acc.ID , Acc.Username , ALI.Account_Log_In_Time AS TimeOfActivity ,ALI.Log_In_IP_Address AS IP_Address , UL.LoginType AS EventType FROM account_log_ins ALI INNER JOIN accounts AS Acc ON Acc.ID = ALI.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ALI.Account_ID WHERE UL.LoginType = 'Login'
                            UNION SELECT * FROM (SELECT Distinct ACO.Account_ID,ACC.Username,ACO.Log_Out_Time,ACO.Log_Out_IP_Address,UL.LoginType FROM account_log_out ACO 
                            INNER JOIN accounts AS ACC ON ACC.ID = ACO.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ACO.Account_ID WHERE UL.LoginType = 'Logout') AS TABLE2 
                            UNION SELECT * FROM (SELECT Account_ID,accounts.Username,Date_and_Time,Ip_Address,UpdatedEvent FROM userupdatetime UUT INNER JOIN accounts ON accounts.ID = UUT.Account_ID) AS TABLE3
                            UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"AttemptedLogin" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                            WHERE Attempted_Log_Ins < 3  ) AS TABLE4
                            UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"LoginFailure" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                            WHERE Attempted_Log_Ins >= 3  ) AS TABLE5
                            ORDER BY TimeOfActivity;""")

            AuditInfo = cursor.fetchall()
            cursor.execute("""SELECT * FROM accounts""")
            allusers = cursor.fetchall()
            cursor.execute("""Select COUNT(Attempted_Log_Ins) AS TotalAttemptedLogins from accountattemptedlogins;""")
            Attemptedlogincount = cursor.fetchone()
            cursor.execute("""SELECT COUNT(ID) As Totalusers from accounts;""")


            No = cursor.fetchone()
            cursor.execute("""SELECT COUNT(ID) as Counter1hour FROM (
                            SELECT DISTINCT Acc.ID , Acc.Username , ALI.Account_Log_In_Time AS TimeOfActivity ,ALI.Log_In_IP_Address AS IP_Address , UL.LoginType AS EventType FROM account_log_ins ALI INNER JOIN accounts AS Acc ON Acc.ID = ALI.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ALI.Account_ID WHERE UL.LoginType = 'Login'
                            UNION SELECT * FROM (SELECT Distinct ACO.Account_ID,ACC.Username,ACO.Log_Out_Time,ACO.Log_Out_IP_Address,UL.LoginType FROM account_log_out ACO 
                            INNER JOIN accounts AS ACC ON ACC.ID = ACO.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ACO.Account_ID WHERE UL.LoginType = 'Logout') AS TABLE2 
                            UNION SELECT * FROM (SELECT Account_ID,accounts.Username,Date_and_Time,Ip_Address,UpdatedEvent FROM userupdatetime UUT INNER JOIN accounts ON accounts.ID = UUT.Account_ID) AS TABLE3
                            UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"AttemptedLogin" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                            WHERE Attempted_Log_Ins < 3  ) AS TABLE4
                            UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"LoginFailure" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                            WHERE Attempted_Log_Ins >= 3  ) AS TABLE5
                            ORDER BY TimeOfActivity) AS CombinedTable WHERE TimeOfActivity > now() - interval 1 HOUR;""")
            eventcount1hr = cursor.fetchone()
            cursor.execute("""SELECT COUNT(ID) as Counter24hour FROM (
                            SELECT DISTINCT Acc.ID , Acc.Username , ALI.Account_Log_In_Time AS TimeOfActivity ,ALI.Log_In_IP_Address AS IP_Address , UL.LoginType AS EventType FROM account_log_ins ALI INNER JOIN accounts AS Acc ON Acc.ID = ALI.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ALI.Account_ID WHERE UL.LoginType = 'Login'
                            UNION SELECT * FROM (SELECT Distinct ACO.Account_ID,ACC.Username,ACO.Log_Out_Time,ACO.Log_Out_IP_Address,UL.LoginType FROM account_log_out ACO 
                            INNER JOIN accounts AS ACC ON ACC.ID = ACO.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ACO.Account_ID WHERE UL.LoginType = 'Logout') AS TABLE2 
                            UNION SELECT * FROM (SELECT Account_ID,accounts.Username,Date_and_Time,Ip_Address,UpdatedEvent FROM userupdatetime UUT INNER JOIN accounts ON accounts.ID = UUT.Account_ID) AS TABLE3
                            UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"AttemptedLogin" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                            WHERE Attempted_Log_Ins < 3  ) AS TABLE4
                            UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"LoginFailure" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                            WHERE Attempted_Log_Ins >= 3  ) AS TABLE5
                            ORDER BY TimeOfActivity) AS CombinedTable WHERE TimeOfActivity > now() - interval 24 HOUR;""")
            eventcount24hr = cursor.fetchone()















            Userlist = []
            UserEvent = {}
            UserAttemptedLoginCount = {}
            EventCount = {}
            EventLoginFailCount = Attemptedlogincount['TotalAttemptedLogins']
            NumberOfUsers = No['Totalusers']


            print(AuditInfo)

            for i in allusers:
                print(i)
                Userlist.append(i['Username'])

            for user in Userlist:
                counter = 0
                for i in AuditInfo:
                    if user == i['Username'] and (
                            i['EventType'] == "AttemptedLogin" or i['EventType'] == 'LoginFailure'):
                        counter += 1
                UserAttemptedLoginCount[user] = counter

            for user in Userlist:
                Eventcounter = 0
                for i in AuditInfo:
                    if user == i['Username']:
                        Eventcounter += 1

                EventCount[user] = Eventcounter

            Userlist = list(set(Userlist))

            print(Userlist)
            print(EventCount)
            # Statistics
            # Calculate average attempt login failure per user
            # All attempted and login failure / Total Logins.
            # Add up everything then divide by total users.
            AvgLoginFailuresUsers = round(EventLoginFailCount/NumberOfUsers,2)
            AvgEventCountUser = round(sum([ EventCount[x] for x in EventCount])/NumberOfUsers,2)
            print(AvgLoginFailuresUsers)
            AvgEvents24hr = round((eventcount24hr['Counter24hour']/NumberOfUsers),2)
            AvgEvent1hr = round((eventcount1hr['Counter1hour']/NumberOfUsers),2)


            # User Events

            # User attempted log ins per user

            return render_template('dashboard.html', account=account, UserAttemptedLoginCount=UserAttemptedLoginCount,
                                   EventCount=EventCount, EventLoginFailCount=EventLoginFailCount
                                   ,AvgLoginFailuresUsers = AvgLoginFailuresUsers ,
                                   AvgEventCountUser = AvgEventCountUser ,sess=session,AvgEvent1hr = AvgEvent1hr, AvgEvents24hr = AvgEvents24hr)
        else:
            return redirect(url_for('Userprofile'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/AuditLog')
def Audit():
    # Security Logs (Event log basically)
    # Log user login failure   (Also try to detect if there huge amounts of login failures across all users)
    # Warning
    # Error Messages
    # Alert Thresholds
    # Admin should be able to see if user change email/password/update settings.
    try:
        if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
            if session['role'] == 'Admin':
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
                account = cursor.fetchone()
                cursor.execute("""SELECT * FROM accounts""")

                cursor.execute("""SELECT DISTINCT Acc.ID , Acc.Username , ALI.Account_Log_In_Time AS TimeOfActivity ,ALI.Log_In_IP_Address AS IP_Address , UL.LoginType AS EventType FROM account_log_ins ALI INNER JOIN accounts AS Acc ON Acc.ID = ALI.Account_ID
                                    INNER JOIN userlogin AS UL ON UL.Account_ID = ALI.Account_ID WHERE UL.LoginType = 'Login'
                                    UNION SELECT * FROM (SELECT Distinct ACO.Account_ID,ACC.Username,ACO.Log_Out_Time,ACO.Log_Out_IP_Address,UL.LoginType FROM account_log_out ACO 
                                    INNER JOIN accounts AS ACC ON ACC.ID = ACO.Account_ID
                                    INNER JOIN userlogin AS UL ON UL.Account_ID = ACO.Account_ID WHERE UL.LoginType = 'Logout') AS TABLE2 
                                    UNION SELECT * FROM (SELECT Account_ID,accounts.Username,Date_and_Time,Ip_Address,UpdatedEvent FROM userupdatetime UUT INNER JOIN accounts ON accounts.ID = UUT.Account_ID) AS TABLE3
                                    UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"AttemptedLogin" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                                    WHERE Attempted_Log_Ins < 3  ) AS TABLE4
                                    UNION SELECT * FROM (SELECT Account_ID,Acco.Username,TimeOfActivity,Ip_Address,"LoginFailure" FROM accountattemptedlogins AS AAL INNER JOIN accounts Acco ON Acco.ID = AAL.Account_ID 
                                    WHERE Attempted_Log_Ins >= 3  ) AS TABLE5
                                    ORDER BY TimeOfActivity DESC; """)

                allaccounts = cursor.fetchall()
                print(allaccounts)
                cursor.execute("""SELECT * FROM accounts""")
                accountlevel = cursor.fetchall()







                return render_template('AuditLog.html', account=account, role=account['role'],
                                       allaccounts=allaccounts)  # labels = labels,values = values)
            else:
                return redirect(url_for('Userprofile'))
        else:
            flash('Please complete your 2FA !', 'danger')
            return redirect(url_for("two_fa"))
    except:
        return render_template('error404.html')


# ZadeStuff

@app.route('/UnbanaccountFunction/<int:ID>', methods=['GET', 'POST'])
def UnBanAccount(ID):
    print("UnBan Account Function")
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""UPDATE accounts SET Account_Status = 'Active' WHERE ID = %s """, [ID])
    mysql.connection.commit()
    return redirect(url_for('ManageAccount'))


@app.route('/BanAccountFunction/<int:ID>', methods=['GET', 'POST'])
def BanAccount(ID):
    print("Ban Account Function")
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""UPDATE accounts SET Account_Status = 'Banned' WHERE ID = %s """, [ID])
    mysql.connection.commit()
    return redirect(url_for('ManageAccount'))


@app.route('/DeleteAccountFunction/<int:ID>', methods=['GET', 'POST'])
def DeleteAccountFunc(ID):
    print("Delete Account")
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""UPDATE accounts SET Account_Status = 'Deleted' WHERE ID = %s """, [ID])
    mysql.connection.commit()
    return redirect(url_for('ManageAccount'))


@app.route('/ForcePasswordAccountFunction/<int:ID>', methods=['GET', 'POST'])
def ForcePasswordChangeAccount(ID):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""UPDATE accounts SET Account_Status = 'Force' WHERE ID = %s """, [ID])
    mysql.connection.commit()
    return redirect(url_for('ManageAccount'))


@app.route("/accountattemptNotify")
def Accountnotifyloginattempts():
    T, F = 1, 0
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE ID = %s AND Username = %s""", [session['ID'], session['Username']])
    account = cursor.fetchone()

    if session["Email_Vulnerabilities"] == 0:  # This means u on account login notification.
        cursor.execute("""UPDATE accounts SET Account_Login_Notification = %s WHERE ID = %s """, [T, session['ID']])
        session["Account_Login_Notification"] = 1
        mysql.connection.commit()
        print(session)
        print('True')
        return redirect(url_for('Changesettings'))
    else:
        cursor.execute("""UPDATE accounts SET Account_Login_Notification = %s WHERE ID = %s """, [F, session['ID']])
        mysql.connection.commit()
        session["Email_Vulnerabilities"] = 0
        print(session)
        print('False ')
        return redirect(url_for('Changesettings'))


@app.route("/EmailAttemptNotification/<int:ID>", methods=['GET', 'POST'])
def EmailUserloginattempt(ID):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""SELECT * FROM accounts WHERE ID = %s """, [ID])
    account = cursor.fetchone()
    print(account)
    msg = Message("Account Vulnerability Concern", recipients=[account['Email']])
    Username = account['Username']
    msg.html = render_template('VulnerabilityEmail1.html', Username=Username)
    mail.send(msg)

    return redirect(url_for('ManageAccount'))


@app.route('/ManageUserAccounts', methods=['GET', 'POST'])
def ManageAccount():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        if session['role'] == "Admin":

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("""SELECT * FROM accounts""")
            account = cursor.fetchone()
            cursor.execute("""SELECT * FROM accounts""")
            allaccounts = cursor.fetchall()

            return render_template('UserAccountManager.html', account=account, allaccounts=allaccounts)
        else:
            return redirect(url_for('Userprofile'))

    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))



@app.route('/ActivityLogUser', methods=['GET', 'POST'])
def UserLogsActivity():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        cursor.execute("""SELECT DISTINCT Acc.ID , Acc.Username , ALI.Account_Log_In_Time AS TimeOfActivity ,ALI.Log_In_IP_Address AS IP_Address , UL.LoginType AS EventType FROM account_log_ins ALI INNER JOIN accounts AS Acc ON Acc.ID = ALI.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ALI.Account_ID WHERE UL.LoginType = 'Login' AND Acc.Username = %s
                            UNION SELECT * FROM (SELECT Distinct ACO.Account_ID,ACC.Username,ACO.Log_Out_Time,ACO.Log_Out_IP_Address,UL.LoginType FROM account_log_out ACO 
                            INNER JOIN accounts AS ACC ON ACC.ID = ACO.Account_ID
                            INNER JOIN userlogin AS UL ON UL.Account_ID = ACO.Account_ID WHERE UL.LoginType = 'Logout' AND ACC.Username = %s) AS TABLE2 
                            UNION SELECT * FROM (SELECT Account_ID,accounts.Username,Date_and_Time,Ip_Address,UpdatedEvent FROM userupdatetime UUT INNER JOIN accounts ON accounts.ID = UUT.Account_ID WHERE accounts.Username = %s) AS TABLE3
                            ORDER BY TimeOfActivity;               """,
                       [session['Username'], session['Username'], session['Username']])

        userloginactivity = cursor.fetchall()
        # Place where progress bar values come in
        cursor.execute("""SELECT * FROM authentication_table WHERE Account_ID = %s """,[session['ID']])
        authenticationmethods = cursor.fetchone()
        TWOFADICT = {}
        Email2FA = authenticationmethods['Text_Message_Status']
        Googleauthen = authenticationmethods['Authenticator_Status']
        BackupCode = authenticationmethods['Backup_Code_Status']
        Phone = authenticationmethods['Sms_Message_Status']

        TWOFADICT['Email2FA'] = Email2FA
        TWOFADICT['Googleauthen'] = Googleauthen
        TWOFADICT['BackupCode'] = BackupCode
        TWOFADICT['Phone'] = Phone

        print(authenticationmethods)
        EmailLoginNotif = account['Account_Login_Notification']
        AttemptedLoginNotification = authenticationmethods['Attempts_Notification']
        Value_of_security = 25  # 25 is default cause everyone got strong password.

        if EmailLoginNotif == 1:
            Value_of_security += 10

        if AttemptedLoginNotification == 1:
            Value_of_security += 15
        counter = 0
        for a in TWOFADICT:
            if TWOFADICT[a] == 1:
                counter += 1

        if counter == 1: # He on one twofa
            Value_of_security += 30




        elif counter > 1: # He on 2 2fa so he go here.
            Value_of_security += 50

        print(Value_of_security)

        print(EmailLoginNotif,AttemptedLoginNotification,counter)



        cursor.execute("""UPDATE accounts SET Security_Level = %s WHERE ID = %s""", [Value_of_security, session['ID']])
        mysql.connection.commit()

        print(userloginactivity)
        return render_template('UserActivityLog.html', account=account, role=account['role'],
                               userloginactivity=userloginactivity , Value_of_security = Value_of_security ,
                               EmailLoginNotif = EmailLoginNotif , AttemptedLoginNotification = AttemptedLoginNotification,
                               Email2FA = Email2FA,Googleauthen = Googleauthen ,BackupCode = BackupCode ,Phone = Phone , counter = counter)


    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/Cantsignin', methods=['GET', 'POST'])
def Cantsignin():
    return render_template("Cant_sign_in.html")


@app.route('/ForgetUsername', methods=['GET', 'POST'])
def ForgottenUsername():
    try:
        if request.method == 'POST' and 'email' in request.form:
            captcha_response = request.form.get('g-recaptcha-response')
            if is_human(captcha_response):
                status = ''
                email = request.form['email']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("SELECT * FROM accounts WHERE Email = %(email)s", {'email': email})
                account = cursor.fetchone()
                print(account)
                if account:
                    msg = Message("Forget Username", recipients=[email])
                    Username = account['Username']
                    msg.html = render_template('forgetusernameemail.html', Username=Username)
                    mail.send(msg)
                    print('sended')
                else:
                    print('It doesnt exit')
                flash(
                    'If your email matches an existing account we will send a password reset email within a few minutes.')
                return render_template('ForgetUsername.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
            else:
                flash('Sorry ! Please Check Im not a robot.')
                return render_template('ForgetUsername.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
        else:
            return render_template('ForgetUsername.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
    except:
        print('error')
        return render_template('error404.html')


@app.route('/ForgetPassword', methods=['GET', 'POST'])
def ForgottenPassword():
    try:
        if request.method == 'POST' and 'email' in request.form:
            captcha_response = request.form.get('g-recaptcha-response')
            if is_human(captcha_response):
                status = ''
                email = request.form['email']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("SELECT * FROM accounts WHERE Email = %(email)s", {'email': email})
                account = cursor.fetchone()
                print(account)
                if account:
                    msg = Message("Forget Password Link", recipients=[email])
                    UUID = account['UUID']
                    msg.html = render_template('forgotpasswordemail.html', UUID=UUID)
                    mail.send(msg)
                    print('sended')
                else:
                    print('It doesnt exit')
                flash(
                    'If your email matches an existing account we will send a password reset email within a few minutes.')
                return render_template('ForgetPassword.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
            else:
                flash('Sorry ! Please Check Im not a robot.')
                return render_template('ForgetPassword.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
        else:
            return render_template('ForgetPassword.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
    except:
        print('error')
        return render_template('error404.html')


@app.route('/Resetpassword/<path:UUID>', methods=['GET', 'POST'])
def Resetpassword(UUID):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE UUID = %(UUID)s", {'UUID': UUID})
    account = cursor.fetchone()
    if account:
        captcha_response = request.form.get('g-recaptcha-response')
        if request.method == 'POST' and 'password' in request.form and 'confirm password' in request.form:
            if is_human(captcha_response):
                password = request.form['password']
                confirm_password = request.form['confirm password']
                if password != confirm_password:
                    flash("Your Password isn't the same as your confirm password. Please Try Again..")
                    return render_template('Resetpassword.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
                else:
                    if account['Account_Status'] == 'Force':
                        sql4 = "UPDATE accounts SET Account_Status = %s WHERE UUID = %s "
                        value4 = ('Active', UUID)
                        cursor.execute(sql4, value4)
                        mysql.connection.commit()
                    now = datetime.datetime.now().replace(microsecond=0)
                    sql = "UPDATE accounts SET password_update_time = %s WHERE UUID = %s "
                    value = (now, UUID)
                    cursor.execute(sql, value)
                    salt = bcrypt.gensalt(rounds=16)
                    hash_password = bcrypt.hashpw(password.encode(), salt)
                    sql2 = "UPDATE accounts SET Password = %s WHERE UUID = %s "
                    value2 = (hash_password, UUID)
                    cursor.execute(sql2, value2)
                    UUID2 = uuid.uuid4().hex
                    sql3 = "UPDATE accounts SET UUID = %s WHERE UUID = %s "
                    value3 = (UUID2, UUID)
                    cursor.execute(sql3, value3)
                    mysql.connection.commit()
                    return redirect(url_for('login'))
            else:
                flash('Sorry ! Please Check Im not a robot.')
                return redirect(url_for('Resetpassword', UUID=UUID))
        return render_template('Resetpassword.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    captcha_response = request.form.get('g-recaptcha-response')

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        if is_human(captcha_response):
            # Process request here
            status = ''
            username = request.form['username']
            password = request.form['password']
            # Check if account exists in MYSQL

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM accounts WHERE username = %(username)s", {'username': username})
            # Fetch one record and return result
            account = cursor.fetchone()
            cursor.execute("SELECT * FROM Authentication_Table WHERE Account_ID = %(ID)s", {'ID': account['ID']})
            # Fetch one record and return result
            account1 = cursor.fetchone()

            if account:

                key = account['SymmetricKey']
                fkey = Fernet(key)
                decryptedaddress_Binary = fkey.decrypt(account['Address'].encode())
                decryptedPhoneNo_Binary = fkey.decrypt(account['Phone_Number'].encode())
                decryptedNRIC_Binary = fkey.decrypt(account['NRIC'].encode())
                decryptedaddress = decryptedaddress_Binary.decode('utf8')
                decryptedNRIC = decryptedNRIC_Binary.decode('utf-8')
                decryptedPhoneNo = decryptedPhoneNo_Binary.decode('utf-8')
                print("All print statements here are testcode")
                print(decryptedaddress)
                print(decryptedNRIC)
                print(decryptedPhoneNo)

                hashandsalt = account['Password']
                # This means that you have logged in
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                print(request.remote_addr)
                print("End of print testcode")
                if bcrypt.checkpw(password.encode(), hashandsalt.encode()):
                    cursor.execute('SELECT * FROM accountattemptedlogins WHERE Account_ID = %(ID)s ORDER BY ID DESC limit 1', {'ID': account['ID']})
                    Time = cursor.fetchone()
                    if Time['TimeOfActivity'] + datetime.timedelta(minutes=30) <= datetime.datetime.now().replace(microsecond=0) and account['Account_Status'] == 'Disabled':
                        sql2 = "UPDATE accounts SET Attempts = %s WHERE username = %s "
                        value2 = (0, account['Username'])
                        cursor.execute(sql2, value2)
                        cursor.execute("UPDATE accounts SET Account_Status = 'Active' WHERE username = %(username)s", {'username': account['Username']})
                        mysql.connection.commit()
                        flash('Your account have been re-enabled, Please key In the information again')
                    # compare the current date and time with the last password update time
                    elif account['password_update_time'] + datetime.timedelta(
                            days=365) <= datetime.datetime.now().replace(microsecond=0):
                        return redirect(url_for('Resetpassword', UUID=account['UUID']))
                    elif account['Account_Status'] == "Pending":
                        print("This account is unactivated")
                        flash("This Account has not been activated. Please go to your email to activate the account.")
                    elif account['Account_Status'] == "Banned":
                        print("This account is banned")
                        flash("This Account has been banned")
                    elif account['Account_Status'] == "Disabled":
                        print("Disabled")
                        flash("Account has been disabled, please contact the helpdesk for further assistance")
                    elif account['Account_Status'] == "Deleted":
                        print("Deleted")
                        flash("Account has been deleted, please contact the helpdesk for further assistance")
                    elif account['Account_Status'] == "Force":
                        print("Force")
                        flash("Please reset your password, your password has been compromised ")
                        return redirect(url_for('Resetpassword', UUID=account['UUID']))
                    else:
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute("UPDATE accounts SET Attempts = 0 WHERE username = %(username)s",
                                       {'username': username})
                        mysql.connection.commit()

                        cursor.execute("""SELECT * FROM Authentication_Table""")
                        session['loggedin'] = True
                        session['ID'] = account['ID']
                        session['Username'] = account['Username']
                        session['email'] = account['Email']
                        session['NRIC'] = decryptedNRIC
                        session['Address'] = decryptedaddress
                        session['Phone_No'] = decryptedPhoneNo
                        session['2fa_status'] = 'Nil'
                        session['role'] = account['role']
                        session['Account_Login_Notification'] = account['Account_Login_Notification']
                        session['Email_Vulnerabilities'] = account['Email_Vulnerabilities']
                        session['Attempts_Notification'] = account1['Attempts_Notification']


                        # Update UserActions table for login!
                        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
                        account1 = cursor.fetchone()

                        if account1['Text_Message_Status'] == True or account1['Authenticator_Status'] == True or \
                                account1['Push_Base_Status'] == True or account1['Backup_Code_Status'] == True or \
                                account1['Sms_Message_Status'] == True:
                            session['2fa_status'] = 'Fail'
                            return render_template("2fa.html", status_text=account1['Text_Message_Status'],
                                                   status_auth=account1['Authenticator_Status'],
                                                   status_psuh=account1['Push_Base_Status'],
                                                   status_back=account1['Backup_Code_Status'],
                                                   status_sms=account1['Sms_Message_Status'])
                        else:

                            cursor.execute("""INSERT INTO userlogin VALUES (NULL,%s,%s) """, (session['ID'], "Login"))
                            mysql.connection.commit()
                            cursor.execute("""INSERT INTO account_log_ins VALUES (NULL,%s,%s,%s,NULL)""", (
                                session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                request.remote_addr))
                            mysql.connection.commit()
                            cursor.execute(
                                """SELECT Log_in_ID FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )""",
                                [session['ID']])
                            login_ID = cursor.fetchone()
                            cursor.execute("""INSERT INTO usersloggedin VALUES (NULL,%s,%s)""",
                                           (session['ID'], login_ID['Log_in_ID']))
                            mysql.connection.commit()
                            cursor.execute(
                                'SELECT * FROM account_log_ins WHERE Account_ID = %s AND Account_Log_In_Time = (SELECT MAX(Account_Log_In_Time) FROM account_log_ins )',
                                [session['ID']])
                            logininfo = cursor.fetchone()
                            if session['Account_Login_Notification'] == 1:  # This means account got login notification.

                                msg = Message("Login Notification", recipients=[account['Email']])
                                Username = account['Username']
                                IP = logininfo['Log_In_IP_Address']
                                Date = logininfo['Account_Log_In_Time']
                                msg.html = render_template('Login_Notification_Email.html', Username=Username,
                                                           Date=Date, IP=IP)
                                mail.send(msg)
                                if account['role'] == 'Admin':
                                    return redirect(url_for('Managerprofile'))
                                else:
                                    return redirect(url_for('Userprofile'))
                            else:  # This means no Login notification
                                if account['role'] == 'Admin':
                                    return redirect(url_for('Managerprofile'))
                                else:
                                    return redirect(url_for('Userprofile'))

                else:  # This else statement executes when password verification fails.
                    msg = 'Incorrect Username/Password'
                    Username = account['Username']
                    if Username == request.form['username']:
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute("SELECT Email,ID,Attempts FROM accounts WHERE username = %(username)s",
                                       {'username': username})
                        Original = cursor.fetchone()
                        Attempts = Original['Attempts']
                        if Attempts == 2:
                            Attempts += 1
                            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            cursor.execute("""INSERT INTO accountattemptedlogins VALUES (NULL,%s,%s,%s,%s)""",
                                           [Original['ID'], Attempts, request.remote_addr, now])
                            mysql.connection.commit()
                            sql2 = "UPDATE accounts SET Attempts = %s WHERE username = %s "
                            value2 = (Attempts, Username)
                            cursor.execute(sql2, value2)

                            cursor.execute("UPDATE accounts SET Account_Status = 'Disabled' WHERE username = %(username)s", {'username': username})
                            mysql.connection.commit()
                            msg = Message("Account Disabled", recipients=[Original['Email']])
                            msg.html = render_template('AccountDisabled.html')
                            mail.send(msg)
                            msg = 'Your Account have been Disabled. please contact the helpdesk'

                        elif Attempts > 2 and Attempts%5 == 0:
                            Attempts += 1
                            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            cursor.execute("""INSERT INTO accountattemptedlogins VALUES (NULL,%s,%s,%s,%s)""", [Original['ID'], Attempts, request.remote_addr, now])
                            mysql.connection.commit()
                            sql2 = "UPDATE accounts SET Attempts = %s WHERE username = %s "
                            value2 = (Attempts, Username)
                            cursor.execute(sql2, value2)
                            mysql.connection.commit()
                            if account1['Attempts_Notification'] == 1:
                                msge = Message("Account Login Attempt", recipients=[Original['Email']])
                                msge.html = render_template('AlertUserEmailAttemptedlogin.html', Date=now, IP=request.remote_addr ,count=Attempts  )
                                mail.send(msge)
                            msg = 'Your Account have already been Disabled. please contact the helpdesk'


                        else:
                            Attempts += 1
                            sql2 = "UPDATE accounts SET Attempts = %s WHERE username = %s "
                            value2 = (Attempts, Username)
                            cursor.execute(sql2, value2)
                            cursor.execute("""INSERT INTO accountattemptedlogins VALUES (NULL,%s,%s,%s,%s)""",[Original['ID'],Attempts,request.remote_addr,datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                            mysql.connection.commit()
                    return render_template('login.html', msg=msg, sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
            else:
                msg = 'Incorrect Username/Password'
                return render_template('login.html', msg=msg, sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")

        else:
            # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."
        flash(status)

    return render_template('login.html', sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")


@app.route('/logout')
def accountlogout():
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': session['Username']})
        # account = cursor.fetchone()
        if session:
            # Record into database that user log out
            cursor.execute("""INSERT INTO UserLogin VALUES (NULL,%s,%s) """, (session['ID'], "Logout"))
            cursor.execute("""INSERT INTO account_log_out VALUES (NULL,%s,%s,%s) """,
                           (session['ID'], datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
            mysql.connection.commit()
            sqlcode = """UPDATE account_log_ins INNER JOIN account_log_out ON account_log_ins.Account_ID = 
            account_log_out.Account_ID SET account_log_ins.Log_Out_ID = account_log_out.Log_Out_ID WHERE 
            account_log_ins.Account_ID = %s AND account_log_ins.Log_Out_ID IS NULL AND account_log_out.Log_Out_ID = (SELECT max(account_log_out.Log_Out_ID) from account_log_out where account_log_out.Account_ID = %s)"""
            values = (session['ID'], session['ID'])
            cursor.execute(sqlcode, values)
            cursor.execute("""DELETE FROM usersloggedin WHERE Account_ID = %s """, [session['ID']])
            mysql.connection.commit()
            print(session)
            session.clear()
            print(session)

            return redirect(url_for('login'))
        else:
            print("Session cant be used by 2 user")
    except:
        return render_template('error404.html')


@app.route('/Createloginuser', methods=['GET', 'POST'])
def create_login_user():
    # Output message if something goes wrong...
    create_login_user_form = CreateLoginUserForm(request.form)
    captcha_response = request.form.get('g-recaptcha-response')
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'Username' in request.form and 'Password' in request.form and 'Email' in request.form and create_login_user_form.validate():
        if 'terms-and-conditions' in request.form:
            if is_human(captcha_response):
                # Process request here
                status = ''

                # Create variables for easy access
                salt = bcrypt.gensalt(rounds=16)

                print("is the form even working")
                print(request.form)
                username = request.form['Username']
                NRIC = request.form['NRIC']
                DOB = request.form['DOB']
                gender = request.form['Gender']
                password = request.form['Password']
                pnh1=request.form['Phone_Number']
                phone_no ='+65'+pnh1
                email = request.form['Email']
                security_questions_1 = request.form['Security_Questions_1']
                answer_1 = request.form['Answers_1']
                security_questions_2 = request.form['Security_Questions_2']
                answer_2 = request.form['Answers_2']
                address = request.form['Address']
                role = 'Guest'
                Account_Login_Notification = 0
                print(DOB)
                now = datetime.datetime.now()
                account_creation_time = now.strftime("%Y-%m-%d %H:%M:%S")
                password_update_time = now.replace(microsecond=0)
                email_confirm = 0
                UUID = uuid.uuid4().hex
                Account_Status = 'Pending'
                hash_password = bcrypt.hashpw(password.encode(), salt)
                # Symmetric Key encryption
                key = Fernet.generate_key()
                # Loads the key into the crypto API
                fkey = Fernet(key)
                # Encrypt the stuff and convert to bytes by calling f.encrypt
                encryptedaddress = fkey.encrypt(address.encode())
                EncryptedNRIC = fkey.encrypt(NRIC.encode())
                EncryptPhoneNo = fkey.encrypt(phone_no.encode())

                # Check if account exists using MySQL
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                print(username, phone_no, NRIC, DOB, gender, email, password, address, role, UUID)
                cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
                account = cursor.fetchone()
                cursor.execute("""SELECT * FROM accounts WHERE Email = %(email)s""", {'email': email})
                account12 = cursor.fetchone()
                # If account exists show error and validation checks(do this at the form for this function)
                if account and account12:
                    msg = 'Both Username and Email already exists, please choose another Username and Email'
                elif account:
                    msg = 'Account already exists!, please choose another Username'
                elif account12:
                    msg = 'Email already exists!, please choose another Email'
                elif not username or not password or not email:
                    print("3")
                    msg = 'Please fill out the form!'
                else:

                    # Account doesnt exists and the form data is valid, now insert new account into accounts table
                    cursor.execute(
                        "INSERT INTO accounts VALUES (NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                        , (username, EncryptedNRIC, DOB, hash_password, gender, EncryptPhoneNo, email,
                           security_questions_1,
                           security_questions_2, answer_1, answer_2, encryptedaddress, role, account_creation_time,
                           email_confirm, key, UUID, Account_Status, password_update_time, Account_Login_Notification,
                           0, 0 ,25))
                    mysql.connection.commit()
                    msg = 'You have successfully registered! '
                    print("working")
                    print('inserting authentication table')
                    Text_Message_Status = False
                    Authenticator_Status = False
                    Authenticator_Key = 0
                    Push_Base_Status = False
                    Backup_Code_Status = False
                    Backup_Code_Key = 0
                    Backup_Code_No_Of_Use = 0
                    Sms_Message_Status = False
                    AttemptsNotification = False
                    # cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
                    cursor.execute("""SELECT ID FROM accounts WHERE Username = %(username)s""", {'username': username})
                    account = cursor.fetchone()
                    Account_ID = account['ID']
                    print(Account_ID, 'account id  ')
                    cursor.execute("INSERT INTO authentication_table VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                                   , (Account_ID, Text_Message_Status, Authenticator_Status, Authenticator_Key,
                                      Push_Base_Status, Backup_Code_Status, Backup_Code_Key, Backup_Code_No_Of_Use,
                                      Sms_Message_Status, AttemptsNotification))
                    mysql.connection.commit()
                    print('insert successfully nocie ')
                    msg = Message("Account Verification Link", recipients=[email])
                    msg.html = render_template('account_verification_email.html', UUID=UUID)
                    mail.send(msg)
                    print('sended')
                    flash('An account verification email have been sent, please verify and activate account')
                    return redirect('login')
            else:
                msg = 'Please check the box "I am not a robot".'
                return render_template('create_login_user_form.html', msg=msg, form=create_login_user_form,
                                       sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
        else:
            msg = 'Please agree on our Terms and Conditions'
            return render_template('create_login_user_form.html', msg=msg, form=create_login_user_form,
                                   sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        print("not working")
        print(request.form)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('create_login_user_form.html', msg=msg, form=create_login_user_form,
                           sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")


@app.route('/Createloginadmin', methods=['GET', 'POST'])
def create_login_admin():
    # Write the code somewhere in this function to record down create admin user event. Log it into audit log?

    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':

        if session['role'] == 'Admin':
            username = session['Username']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            cursor.execute("SELECT * FROM accounts WHERE username = %(username)s",
                           {'username': username})
            # Fetch one record and return result
            account = cursor.fetchone()
            # Output message if something goes wrong...
            create_login_user_form = CreateLoginUserForm(request.form)

            msg = ''
            # Check if "username", "password" and "email" POST requests exist (user submitted form)
            captcha_response = request.form.get('g-recaptcha-response')

            if request.method == 'POST' and 'Username' in request.form and 'Password' in request.form and 'Email' in request.form and create_login_user_form.validate():
                # Create variables for easy access
                if is_human(captcha_response):
                    # Process request here
                    status = ''

                    salt = bcrypt.gensalt(rounds=16)

                    print("is the form even working")
                    print(request.form)
                    username = request.form['Username']
                    NRIC = request.form['NRIC']
                    DOB = request.form['DOB']
                    gender = request.form['Gender']
                    password = request.form['Password']
                    phn1=request.form['Phone_Number']
                    phone_no ='+65'+phn1
                    email = request.form['Email']
                    security_questions_1 = request.form['Security_Questions_1']
                    answer_1 = request.form['Answers_1']
                    security_questions_2 = request.form['Security_Questions_2']
                    answer_2 = request.form['Answers_2']
                    address = request.form['Address']
                    role = 'Admin'
                    Account_Login_Notification = 0
                    now = datetime.datetime.now()
                    account_creation_time = now.strftime("%Y-%m-%d %H:%M:%S")
                    password_update_time = now.replace(microsecond=0)
                    email_confirm = 0
                    UUID = uuid.uuid4().hex
                    Account_Status = 'Active'
                    hash_password = bcrypt.hashpw(password.encode(), salt)
                    # Symmetric Key encryption
                    key = Fernet.generate_key()
                    # Loads the key into the crypto API
                    fkey = Fernet(key)
                    # Encrypt the stuff and convert to bytes by calling f.encrypt
                    encryptedaddress = fkey.encrypt(address.encode())
                    EncryptedNRIC = fkey.encrypt(NRIC.encode())
                    EncryptPhoneNo = fkey.encrypt(phone_no.encode())

                    # Check if account exists using MySQL
                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    print(username, phone_no, NRIC, DOB, gender, email, password, address, role, UUID)
                    cursor.execute("""SELECT * FROM accounts WHERE Username = %(username)s""", {'username': username})
                    account = cursor.fetchone()
                    # If account exists show error and validation checks(do this at the form for this function)
                    if account:
                        msg = 'Account already exists!'
                    elif not username or not password or not email:
                        print("3")
                        msg = 'Please fill out the form!'
                    else:

                        # Account doesnt exists and the form data is valid, now insert new account into accounts table
                        cursor.execute(
                            "INSERT INTO accounts VALUES (NULL,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                            , (username, EncryptedNRIC, DOB, hash_password, gender, EncryptPhoneNo, email,
                               security_questions_1,
                               security_questions_2, answer_1, answer_2, encryptedaddress, role, account_creation_time,
                               email_confirm, key, UUID, Account_Status, password_update_time,
                               Account_Login_Notification, 0, 0 , 25))
                        mysql.connection.commit()
                        msg = 'You have successfully registered! '
                        print("working")
                        print('inserting authentication table')
                        Text_Message_Status = False
                        Authenticator_Status = False
                        Authenticator_Key = 0
                        Push_Base_Status = False
                        Backup_Code_Status = False
                        Backup_Code_Key = 0
                        Backup_Code_No_Of_Use = 0
                        Sms_Message_Status = False
                        AttemptsNotification = False
                        # cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
                        cursor.execute("""SELECT ID FROM accounts WHERE Username = %(username)s""",
                                       {'username': username})
                        account = cursor.fetchone()
                        Account_ID = account['ID']
                        print(Account_ID, 'account id  ')
                        cursor.execute("INSERT INTO authentication_table VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                                       , (Account_ID, Text_Message_Status, Authenticator_Status, Authenticator_Key,
                                          Push_Base_Status, Backup_Code_Status, Backup_Code_Key, Backup_Code_No_Of_Use, Sms_Message_Status, AttemptsNotification))
                        mysql.connection.commit()
                        print('insert successfully nocie ')

                        return redirect('login')
                else:
                    msg = 'Please check the box "I am not a robot".'
                    return render_template('create_login_admin_form.html', msg=msg, form=create_login_user_form,
                                           account=account, sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
            elif request.method == 'POST':
                # Form is empty... (no POST data)
                print("not working")
                print(request.form)
                msg = 'Please fill out the form!'
            # Show registration form with message (if any)
            return render_template('create_login_admin_form.html', msg=msg, form=create_login_user_form,
                                   account=account, sitekey="6LeQDi8bAAAAAGzw5v4-zRTcdNBbDuFsgeU2jEhb")
        else:
            return redirect(url_for('Userprofile'))
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/TermsandConditions')
def TermsAndConditions():
    return render_template('TermsAndConditions.html')


@app.route('/AccountVerification1/<path:UUID>')
def AccountVerification1(UUID):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("UPDATE accounts SET Account_Status = 'Active' WHERE UUID = %(UUID)s", {'UUID': UUID})
    UUID2 = uuid.uuid4().hex
    sql3 = "UPDATE accounts SET UUID = %s WHERE UUID = %s "
    value3 = (UUID2, UUID)
    cursor.execute(sql3, value3)
    mysql.connection.commit()
    flash('Your account have been successfully activated')
    return redirect(url_for("login"))


# End of new stuff
@app.route('/Inventory')
def InventoryPage():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        Inventory_Dict = {}
        Order_Dict = {}
        OngoingOrders_Dict = {}
        InvDataBase = shelve.open('InventoryDB', 'r')
        Inventory_Dict = InvDataBase['Inventory']
        Order_Dict = InvDataBase['Orders']
        OngoingOrders_Dict = InvDataBase['OngoingOrders']
        OngoingOrders_List = []
        Inventory_list = []
        Order_List = []
        for key in Inventory_Dict:
            inventory = Inventory_Dict.get(key)
            Inventory_list.append(inventory)
        for Okey in Order_Dict:
            orders = Order_Dict.get(Okey)
            Order_List.append(orders)
        for i in OngoingOrders_Dict:
            c = OngoingOrders_Dict.get(i)
            OngoingOrders_List.append(c)
        print(OngoingOrders_List)
    except:
        print("hello")

    return render_template('InventoryPage.html', Invcount=len(Inventory_list), Inventory_list=Inventory_list,
                           Order_List=Order_List, Order_Dict=Order_Dict, Inventory_Dict=Inventory_Dict, name=username,
                           role=role, OngoingOrders_List=OngoingOrders_List, OngoingOrders_Dict=OngoingOrders_Dict,
                           )


@app.route('/UpdateInventory/<int:id>', methods=['GET', 'POST'])
def UpdateInventory(id):
    updateInventory = AddInventoryForm(request.form)
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    try:
        if request.method == 'POST':
            Inventory_dict = {}
            db = shelve.open('InventoryDB', 'w')
            Inventory_dict = db['Inventory']

            inventory = Inventory_dict.get(id)
            inventory.set_Name(updateInventory.Name.data)
            inventory.set_Unit_of_Measure(updateInventory.Unit_of_Measure.data)
            inventory.set_Category(updateInventory.Category.data)
            inventory.set_Quantity(updateInventory.Quantity.data)
            inventory.set_Status(updateInventory.Status.data)
            inventory.set_Threshold(updateInventory.Threshold.data)

            db['Inventory'] = Inventory_dict
            db.close()

            return redirect(url_for('InventoryPage'))
        else:
            Inventory_dict = {}
            db = shelve.open('InventoryDB', 'r')
            Inventory_dict = db['Inventory']
            db.close()

            inventory = Inventory_dict.get(id)
            updateInventory.Name.data = inventory.get_Name()
            updateInventory.Unit_of_Measure.data = inventory.get_Unit_of_Measure()
            updateInventory.Quantity.data = inventory.get_Quantity()
            updateInventory.Threshold.data = inventory.get_Threshold()
            updateInventory.Status.data = inventory.get_Status()
            updateInventory.Category.data = inventory.get_Category()
    except:
        return render_template("error404.html")

    return render_template('updateInventory.html', form=updateInventory, name=username, role=role)


@app.route('/InventoryAddition', methods=['GET', 'POST'])
def AddInventory():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        AddingInventory = AddInventoryForm(request.form)

        if request.method == 'POST' and AddingInventory.validate():
            Inventory_Dict = {}
            InvDatabase = shelve.open('InventoryDB', 'c')

            try:
                Inventory_Dict = InvDatabase['Inventory']

                inventory = Inventory.Inventory(AddingInventory.ID.data, AddingInventory.Name.data,
                                                AddingInventory.Unit_of_Measure.data,
                                                AddingInventory.Category.data,
                                                AddingInventory.Threshold.data, AddingInventory.Quantity.data,
                                                AddingInventory.Status.data)
                Inventory_Dict[inventory.get_ID()] = inventory
                InvDatabase["Inventory"] = Inventory_Dict

                InvDatabase.close()
                return redirect(url_for('InventoryPage'))
            except:
                return print("hello")

        return render_template('InventoryAddition.html', form=AddingInventory, name=username, role=role)
    except:
        return render_template('error404.html')


@app.route('/Suppliers', methods=['GET', 'POST'])
def AddSupplier():
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    SupplierCreate = SupplierForm(request.form)

    if request.method == 'POST' and SupplierCreate.validate():
        Supplier_dict = {}
        InvDataBase = shelve.open('InventoryDB', 'c')

        try:
            Supplier_dict = InvDataBase['Supplier']
        except:
            return render_template("error404.html")
        try:
            SupplierObject = CreatingSupplier.Supplier(SupplierCreate.ID.data, SupplierCreate.BusinessName.data,
                                                       SupplierCreate.Handphone.data, SupplierCreate.Address.data,
                                                       SupplierCreate.PostalCode.data, SupplierCreate.Details.data,
                                                       SupplierCreate.Meat.data, SupplierCreate.Fruits.data,
                                                       SupplierCreate.Dairy.data, SupplierCreate.Condiments.data,
                                                       SupplierCreate.Necessities.data)
            Supplier_dict[SupplierObject.get_ID()] = SupplierObject
            print(SupplierObject.get_ID())
            print(SupplierObject.get_Condiments(), SupplierObject.get_Dairy())
            print(SupplierObject.get_Meat(), SupplierObject.get_Necessities(), SupplierObject.get_Fruits())
            print(SupplierObject)
            InvDataBase['Supplier'] = Supplier_dict

            InvDataBase.close()

        except:
            return render_template("error404.html")

        return redirect(url_for('ViewSupplier'))

    return render_template('Suppliers.html', form=SupplierCreate, name=username, role=role)


@app.route('/UpdateSupplier/<int:id>', methods=['GET', 'POST'])
def SuppliersUpdate(id):
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    UpdateSupplierForm = updateSupplierForm(request.form)
    try:
        if request.method == 'POST' and UpdateSupplierForm.validate():
            Supplier_Dict = {}
            InvDataBase = shelve.open('InventoryDB', 'w')
            Supplier_Dict = InvDataBase['Supplier']

            supplier = Supplier_Dict.get(id)
            supplier.set_ID(UpdateSupplierForm.ID.data)
            supplier.set_Address(UpdateSupplierForm.Address.data)
            supplier.set_BusinessName(UpdateSupplierForm.BusinessName.data)
            supplier.set_Details(UpdateSupplierForm.Details.data)
            supplier.set_Handphone(UpdateSupplierForm.Handphone.data)
            supplier.set_PostalCode(UpdateSupplierForm.PostalCode.data)
            supplier.set_Meat(UpdateSupplierForm.Meat.data)
            supplier.set_Condiments(UpdateSupplierForm.Condiments.data)
            supplier.set_Dairy(UpdateSupplierForm.Dairy.data)
            supplier.set_Fruits(UpdateSupplierForm.Fruits.data)
            supplier.set_Necessities(UpdateSupplierForm.Necessities.data)

            InvDataBase['Supplier'] = Supplier_Dict
            InvDataBase.close()

            return redirect(url_for('ViewSupplier'))
        else:
            Supplier_Dict = {}
            InvDataBase = shelve.open('InventoryDB', 'r')
            Supplier_Dict = InvDataBase['Supplier']
            InvDataBase.close()

            supplier = Supplier_Dict.get(id)
            UpdateSupplierForm.ID.data = supplier.get_ID()
            UpdateSupplierForm.Address.data = supplier.get_Address()
            UpdateSupplierForm.BusinessName.data = supplier.get_BusinessName()
            UpdateSupplierForm.Details.data = supplier.get_Details()
            UpdateSupplierForm.Handphone.data = supplier.get_HandPhone()
            UpdateSupplierForm.PostalCode.data = supplier.get_PostalCode()
            UpdateSupplierForm.Meat.data = supplier.get_Meat()
            UpdateSupplierForm.Condiments.data = supplier.get_Condiments()
            UpdateSupplierForm.Dairy.data = supplier.get_Dairy()
            UpdateSupplierForm.Fruits.data = supplier.get_Fruits()
            UpdateSupplierForm.Necessities.data = supplier.get_Necessities()

    except:
        return render_template("error404.html")

    return render_template('UpdateSupplier.html', form=UpdateSupplierForm, name=username, role=role)


@app.route('/ViewSupplier')
def ViewSupplier():
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    try:
        Supplier_Dict = {}
        InvDataBase = shelve.open('InventoryDB', 'r')
        Supplier_Dict = InvDataBase['Supplier']
        InvDataBase.close()

        Supplier_List = []
        for key in Supplier_Dict:
            supplier = Supplier_Dict.get(key)
            Supplier_List.append(supplier)
    except:
        return render_template("error404.html")

    return render_template('ViewSupplier.html', SupplierCount=len(Supplier_List), Supplier_List=Supplier_List,
                           name=username, role=role)


@app.route('/UpdateOrders/<int:id>', methods=['GET', 'POST'])
def UpdateOrders(id):
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    UpdateOrderForm = Orderupdate(request.form)
    InvDataBase = shelve.open('InventoryDB', 'w')

    Supplier_Dict = InvDataBase['Supplier']
    Supplier_List = []
    for key in Supplier_Dict:
        supplier = Supplier_Dict.get(key)
        Supplier_List.append(supplier)
    length = len(Supplier_List)
    start = 0
    supplierchoice_list = []
    for i in Supplier_List:
        supplierchoice = str(i.get_BusinessName())
        supplierchoice_list.append(supplierchoice)

    MeatSupplier = []
    FruitSupplier = []
    DairySupplier = []
    CondimentsSupplier = []
    NecessitiesSupplier = []
    for fu in Supplier_List:
        if fu.get_Meat() == True:
            MeatSupplier.append(fu)
        if fu.get_Fruits() == True:
            FruitSupplier.append(fu)
        if fu.get_Dairy() == True:
            DairySupplier.append(fu)
        if fu.get_Condiments() == True:
            CondimentsSupplier.append(fu)
        if fu.get_Necessities() == True:
            NecessitiesSupplier.append(fu)

    Inventory_Dict = {}
    Inventory_Dict = InvDataBase['Inventory']
    inventory = Inventory_Dict.get(id)

    MeatSupplierChoice = []
    DairySupplierChoice = []
    FruitSupplierChoice = []
    NecessitiesSupplierChoice = []
    CondimentsSupplierChoice = []
    for i in MeatSupplier:
        meatsupplier = i.get_BusinessName()
        MeatSupplierChoice.append(meatsupplier)
    for i in FruitSupplier:
        fruitsupplier = i.get_BusinessName()
        FruitSupplierChoice.append(fruitsupplier)
    for i in DairySupplier:
        dairysupplier = i.get_BusinessName()
        DairySupplierChoice.append(dairysupplier)
    for i in CondimentsSupplier:
        condimentsupplier = i.get_BusinessName()
        CondimentsSupplierChoice.append(condimentsupplier)
    for i in NecessitiesSupplier:
        necessitiessupplier = i.get_BusinessName()
        NecessitiesSupplierChoice.append(necessitiessupplier)

    MeatSupplierLength = len(MeatSupplierChoice)
    FruitSupplierLength = len(FruitSupplierChoice)
    DairySupplierLength = len(DairySupplierChoice)
    CondimentsSupplierLength = len(CondimentsSupplierChoice)
    NecessitiesSupplierLength = len(NecessitiesSupplierChoice)
    if inventory.get_Category() == 'Meat':
        UpdateOrderForm.Supplier.choices = [MeatSupplierChoice[a] for a in range(MeatSupplierLength)]
    elif inventory.get_Category() == 'Fruits':
        UpdateOrderForm.Supplier.choices = [FruitSupplierChoice[a] for a in range(FruitSupplierLength)]
    elif inventory.get_Category() == "Dairy":
        UpdateOrderForm.Supplier.choices = [DairySupplierChoice[a] for a in range(DairySupplierLength)]
    elif inventory.get_Category() == 'Necessities':
        UpdateOrderForm.Supplier.choices = [CondimentsSupplierChoice[a] for a in range(CondimentsSupplierLength)]
    elif inventory.get_Category() == 'Condiments':
        UpdateOrderForm.Supplier.choices = [NecessitiesSupplierChoice[a] for a in range(NecessitiesSupplierLength)]

    try:
        if request.method == 'POST' and UpdateOrderForm.validate():
            Order_dict = {}
            InvDataBase = shelve.open('InventoryDB', 'w')
            Order_dict = InvDataBase['Orders']

            orders = Order_dict.get(id)
            orders.set_Date(UpdateOrderForm.Date.data)
            orders.set_Supplier(UpdateOrderForm.Supplier.data)
            orders.set_Quantity(UpdateOrderForm.Quantity.data)

            InvDataBase['Orders'] = Order_dict
            InvDataBase.close()

            return redirect(url_for('ViewOrders'))
        else:
            Order_dict = {}
            InvDataBase = shelve.open('InventoryDB', 'r')
            Order_dict = InvDataBase['Orders']
            InvDataBase.close()

            orders = Order_dict.get(id)
            UpdateOrderForm.Date.data = orders.get_Date()

            UpdateOrderForm.ExpectedDeliveryDate.data = orders.get_ExpectedDeliveryDate()
            UpdateOrderForm.Quantity.data = orders.get_Quantity()
    except:
        return render_template("error404.html")

    return render_template('UpdateOrders.html', form=UpdateOrderForm, name=username, role=role)


@app.route("/CancelOrder/<int:id>", methods=['GET', 'POST'])
def Cancel_OF_Order(id):
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    OrderCancel = CancelOrder(request.form)
    try:
        Order_Dict = {}
        OngoingOrders = {}
        InvDataBase = shelve.open('InventoryDB', 'w')
        Order_Dict = InvDataBase['Orders']
        OngoingOrders = InvDataBase['OngoingOrders']
        order = Order_Dict.get(id)

        OrderCancel.Quantity.data = order.get_Quantity()
        OrderCancel.Date.data = order.get_Date()
        OrderCancel.ExpectedDeliveryDate.data = order.get_ExpectedDeliveryDate()
        OrderCancel.Supplier.data = order.get_Supplier()

        if request.method == 'POST' and OrderCancel.validate():
            Order_Dict.pop(id)
            OngoingOrders[id] = False

            InvDataBase['Orders'] = Order_Dict
            InvDataBase['OngoingOrders'] = OngoingOrders

            return redirect(url_for('ViewOrders'))
    except:
        return render_template("error404.html")

    return render_template("CancelOrder.html", form=OrderCancel, name=session['username'], role=role)


@app.route('/Orders/<int:id>', methods=['GET', 'POST'])
def OrdersCreate(id):
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    try:
        OrderCreationForm = OrderInventory(request.form)
        Supplier_Dict = {}
        InvDataBase = shelve.open('InventoryDB', 'w')
        Supplier_Dict = InvDataBase['Supplier']
        Supplier_List = []
        for key in Supplier_Dict:
            supplier = Supplier_Dict.get(key)
            Supplier_List.append(supplier)
        length = len(Supplier_List)
        start = 0
        supplierchoice_list = []
        for i in Supplier_List:
            supplierchoice = str(i.get_BusinessName())
            supplierchoice_list.append(supplierchoice)

        MeatSupplier = []
        FruitSupplier = []
        DairySupplier = []
        CondimentsSupplier = []
        NecessitiesSupplier = []
        for fu in Supplier_List:
            if fu.get_Meat() == True:
                MeatSupplier.append(fu)
            if fu.get_Fruits() == True:
                FruitSupplier.append(fu)
            if fu.get_Dairy() == True:
                DairySupplier.append(fu)
            if fu.get_Condiments() == True:
                CondimentsSupplier.append(fu)
            if fu.get_Necessities() == True:
                NecessitiesSupplier.append(fu)

        Inventory_Dict = {}
        Inventory_Dict = InvDataBase['Inventory']
        inventory = Inventory_Dict.get(id)

        MeatSupplierChoice = []
        DairySupplierChoice = []
        FruitSupplierChoice = []
        NecessitiesSupplierChoice = []
        CondimentsSupplierChoice = []
        for i in MeatSupplier:
            meatsupplier = i.get_BusinessName()
            MeatSupplierChoice.append(meatsupplier)
        for i in FruitSupplier:
            fruitsupplier = i.get_BusinessName()
            FruitSupplierChoice.append(fruitsupplier)
        for i in DairySupplier:
            dairysupplier = i.get_BusinessName()
            DairySupplierChoice.append(dairysupplier)
        for i in CondimentsSupplier:
            condimentsupplier = i.get_BusinessName()
            CondimentsSupplierChoice.append(condimentsupplier)
        for i in NecessitiesSupplier:
            necessitiessupplier = i.get_BusinessName()
            NecessitiesSupplierChoice.append(necessitiessupplier)

        MeatSupplierLength = len(MeatSupplierChoice)
        FruitSupplierLength = len(FruitSupplierChoice)
        DairySupplierLength = len(DairySupplierChoice)
        CondimentsSupplierLength = len(CondimentsSupplierChoice)
        NecessitiesSupplierLength = len(NecessitiesSupplierChoice)
        if inventory.get_Category() == 'Meat':
            OrderCreationForm.Supplier.choices = [MeatSupplierChoice[a] for a in range(MeatSupplierLength)]
        elif inventory.get_Category() == 'Fruits':
            OrderCreationForm.Supplier.choices = [FruitSupplierChoice[a] for a in range(FruitSupplierLength)]
        elif inventory.get_Category() == "Dairy":
            OrderCreationForm.Supplier.choices = [DairySupplierChoice[a] for a in range(DairySupplierLength)]
        elif inventory.get_Category() == 'Necessities':
            OrderCreationForm.Supplier.choices = [CondimentsSupplierChoice[a] for a in range(CondimentsSupplierLength)]
        elif inventory.get_Category() == 'Condiments':
            OrderCreationForm.Supplier.choices = [NecessitiesSupplierChoice[a] for a in
                                                  range(NecessitiesSupplierLength)]

        InvDataBase.close()

        if request.method == 'POST' and OrderCreationForm.validate():
            Order_dict = {}
            OrderProgress = {}
            InvDataBase = shelve.open('InventoryDB', 'c')

            try:
                Order_dict = InvDataBase['Orders']
            except:
                return render_template("error404.html")

            Order = OrderCreation.Orders(id, OrderCreationForm.Quantity.data, OrderCreationForm.Date.data,
                                         OrderCreationForm.ExpectedDeliveryDate.data,
                                         OrderCreationForm.Supplier.data)
            print(OrderCreationForm.ExpectedDeliveryDate.data)
            OrderProgress[id] = True
            InvDataBase['OngoingOrders'] = OrderProgress
            Order_dict[Order.get_ID()] = Order
            InvDataBase['Orders'] = Order_dict

            InvDataBase.close()

            return redirect(url_for('InventoryPage'))
    except:
        return render_template("error404.html")

    return render_template('Orders.html', form=OrderCreationForm, name=username, role=role)


@app.route('/ViewOrders')
def ViewOrders():
    users_dict123 = {}
    db = shelve.open('login.db', 'r')
    users_dict123 = db['login']
    db.close()
    users_list1234 = []
    for key in users_dict123:
        user = users_dict123.get(key)
        users_list1234.append(user)
    for users in users_list1234:
        if 'username' in session:
            username = session['username']
            role = users.get_role()
            if username == 'admin':
                role = 'Staff'
            else:
                role = 'Guest'
    try:
        Order_Dict = {}
        InvDataBase = shelve.open('InventoryDB', 'r')
        Order_Dict = InvDataBase['Orders']
        InvDataBase.close()

        Order_List = []
        for key in Order_Dict:
            Order = Order_Dict.get(key)
            Order_List.append(Order)
    except:

        return render_template("error404.html")

    return render_template('ViewOrders.html', OrderCount=len(Order_List), Order_List=Order_List, name=username,
                           role=role)


@app.route("/Deliver/<int:id>", methods=['GET', 'POST'])
def DeliverOrder(id):
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        try:
            ConfirmDelivery = DeliveryFormConfirm(request.form)
            InvDataBase = shelve.open("InventoryDB", 'w')
            Order_Dict = {}
            Inventory_Dict = {}
            OngoingOrders_Dict = {}
            Order_Dict = InvDataBase['Orders']
            Inventory_Dict = InvDataBase['Inventory']
            OngoingOrders_Dict = InvDataBase['OngoingOrders']
            Order_List = []
            Inventory_List = []
            orders = Order_Dict.get(id)
            inventory = Inventory_Dict.get(id)
            Order_List.append(orders)
            Inventory_List.append(inventory)
            print(Order_List[0].get_ID(), Order_List[0].get_Quantity(), Order_List[0].get_Supplier())
            print(Inventory_List)
            ConfirmDelivery.ID.data = Order_List[0].get_ID()
            ConfirmDelivery.Quantity.data = Order_List[0].get_Quantity()
            ConfirmDelivery.Supplier.data = Order_List[0].get_Supplier()
            print(Inventory_List[0].get_Quantity() + Order_List[0].get_Quantity())

            if request.method == 'POST':
                Inventory_List[0].set_Quantity(Inventory_List[0].get_Quantity() + Order_List[0].get_Quantity())
                InvDataBase['Inventory'] = Inventory_Dict
                Order_List[0].set_Quantity(0)

                InvDataBase['Orders'] = Order_Dict
                OngoingOrders_Dict[id] = False

                InvDataBase['OngoingOrders'] = OngoingOrders_Dict

                return redirect(url_for('InventoryPage'))

        except:
            return render_template('error404.html')

        return render_template("Deliver.html", Order_Dict=Order_Dict, Inventory_Dict=Inventory_Dict,
                               Order_List=Order_List,
                               Inventory_List=Inventory_List, form=ConfirmDelivery, name=username, role=role)
    except:
        return render_template('error404.html')


# @app.route('/View')
# def view():
#     try:
#         users_dict123 = {}
#         db = shelve.open('login.db', 'r')
#         users_dict123 = db['login']
#         db.close()
#         users_list1234 = []
#         for key in users_dict123:
#             user = users_dict123.get(key)
#             users_list1234.append(user)
#         for users in users_list1234:
#             if 'username' in session:
#                 username = session['username']
#                 role = users.get_role()
#                 if username == 'admin':
#                     role = 'Staff'
#                 else:
#                     role = 'Guest'
#         InvDataBase = shelve.open("InventoryDB", 'c')
#         Inventory_Dict = {}
#         inventory = Inventory.Inventory(1, "Chicken",
#                                         "Kg",
#                                         "Meat",
#                                         20, 30,
#                                         'Available')
#         Inventory_Dict[inventory.get_ID()] = inventory
#         InvDataBase["Inventory"] = Inventory_Dict
#         Supplier_Dict = {}
#         Order_Dict = {}
#         SupplierObject = CreatingSupplier.Supplier(1, "Singapore Meat Supplier",
#                                                    96441222, "Singapore",
#                                                    700000, "Meat Supplier", True, False, False, False, False)
#         Supplier_Dict[SupplierObject.get_ID()] = SupplierObject
#         InvDataBase['Supplier'] = Supplier_Dict
#         Order_dict = {}
#         Order = OrderCreation.Orders(1, 20, 4 / 2 / 2021,
#                                      "Nova Supplier")
#
#         Order_dict[Order.get_ID()] = Order
#         InvDataBase['Orders'] = Order_dict
#
#         print(inventory)
#
#         return render_template('View.html', name=username, role=role)
#     except:
#         return render_template('error404.html')


# Hong ji's Code


@app.route('/mang_update_dinein/<int:id>/', methods=['GET', 'POST'])
def mang_update_dinein(id):
    try:
        mang_update_dinein = MangDineInForm(request.form)
        tables_dict = {}
        database = shelve.open('mangetablecreate1.db', 'w')
        table_list = []
        tables_dict = database['mangetablecreate1']
        for key in tables_dict:
            table = tables_dict.get(key)
            if table.get_remarks() == 'active':
                table_list.append(table)
        length = len(table_list)
        start = 0
        print(tables_dict)
        print(table_list)
        print(table_list[0].get_table_no())
        print(table_list[0].get_user_id())
        print(table_list[0].get_remarks())
        tablechoice_list = []
        for i in table_list:
            tablechoice = str(i.get_table_no())
            tablechoice_list.append(tablechoice)
        print(tablechoice_list)
        print(tablechoice)
        print(tables_dict)
        print(table_list)
        mang_update_dinein.table_no.choices = [tablechoice_list[a] for a in range(length)]
        if request.method == 'POST' and MangDineInForm:
            users_dict = {}
            db = shelve.open('userdinein.db', 'w')
            users_dict2 = db['userdinein']
            user2 = users_dict2.get(id)
            user2.set_username(mang_update_dinein.username.data)
            user2.set_no_ppl(mang_update_dinein.no_ppl.data)
            user2.set_phone_no(mang_update_dinein.phone_no.data)
            user2.set_table_no(mang_update_dinein.table_no.data)
            user2.set_time(mang_update_dinein.time.data)
            user2.set_status(mang_update_dinein.status.data)
            user2.set_remarks(mang_update_dinein.remarks.data)

            db['userdinein'] = users_dict2
            db.close()
            return redirect(url_for('management_dinein_retretrieve'))
        else:
            tables_dict = {}
            database = shelve.open('mangetablecreate1.db', 'w')
            table_list = []
            tables_dict = database['mangetablecreate1']
            for key in tables_dict:
                table = tables_dict.get(key)
                if table.get_remarks() == 'active':
                    table_list.append(table)
            length = len(table_list)
            start = 0
            print(tables_dict)
            print(table_list)
            print(table_list[0].get_table_no())
            print(table_list[0].get_user_id())
            print(table_list[0].get_remarks())
            tablechoice_list = []
            for i in table_list:
                tablechoice = str(i.get_table_no())
                tablechoice_list.append(tablechoice)
            print(tablechoice_list)
            print(tablechoice)
            print(tables_dict)
            print(table_list)
            mang_update_dinein.table_no.choices = [tablechoice_list[a] for a in range(length)]
            users_dict2 = {}
            db = shelve.open('userdinein.db', 'r')
            try:
                users_dict2 = db['userdinein']
            except:
                print("Error in retrieving Users from userdinein.db.")
            db.close()
            user2 = users_dict2.get(id)
            mang_update_dinein.username.data = user2.get_username()
            mang_update_dinein.no_ppl.data = user2.get_no_ppl()
            mang_update_dinein.table_no.data = user2.get_table_no()
            mang_update_dinein.phone_no.data = user2.get_phone_no()
            mang_update_dinein.time.data = user2.get_time()
            mang_update_dinein.status.data = user2.get_status()
            mang_update_dinein.remarks.data = user2.get_remarks()
            users_dict1 = {}
            db = shelve.open('login.db', 'r')
            try:
                users_dict1 = db['login']
            except:
                print("Error in retrieving Users from login.db.")
            db.close()
            users_list1 = []
            for key in users_dict1:
                user = users_dict1.get(key)
                users_list1.append(user)
            for users in users_list1:
                if 'username' in session:
                    username = session['username']
                    role = users.get_role()
                    if username == 'admin':
                        role = 'Staff'
                    else:
                        role = 'Guest'
            return render_template('mang_update_dinein.html', form=mang_update_dinein, name=session['username'],
                                   role=role)
    except:
        return render_template('error404.html')


@app.route('/homepage')
def homepage():
    if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', [session['ID']])
        account = cursor.fetchone()
        role = account['role']
        cursor.execute('SELECT * FROM authentication_table WHERE Account_ID = %s', [session['ID']])
        account1 = cursor.fetchone()

        if account1['Text_Message_Status'] == True:
            flash('Email otp is activated ', 'primary')
        else:
            flash('Email otp  not activated ', "danger")
        if account1['Sms_Message_Status'] == True:
            flash('Sms otp  is activated ','primary')
        else:
            flash('Sms otp not activated ','danger')
        if account1['Authenticator_Status'] == True:
            flash('Google /Auth Authenticator is activated', 'primary')
        else:
            flash('Google /Auth Authenticator  not activated ', 'danger')
        if account1['Push_Base_Status'] == True:
            flash('Push notification is activated ', 'primary')
        else:
            flash('Push notification  not activated ', 'danger')
        if account1['Backup_Code_Status'] == True:
            flash('Backup code  is activated ', 'primary')
        else:
            flash('Backup code not activated ', 'danger')
        return render_template('homenew.html', account=account, account1=account1, role=role)
    else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))


@app.route('/')  # declarator
# tie to map a web application function to an url
def home():
    print(session)
    # global role
    # users_dict = {}
    # db = shelve.open('login.db', 'r')
    # users_dict = db['login']
    # db.close()
    # users_list = []
    # for key in users_dict:
    #    user = users_dict.get(key)
    #    users_list.append(user)
    # for users in users_list:
    #    if 'username' in session:
    #        username = session['username']
    #        if username == users.get_username():
    #            role = users.get_role()
    #            print(role)
    #        elif username == "admin":
    #            role = "Staff"
    #        elif username == "becca":
    #            role = "Guest"
    #        else:
    #            continue
    #        return render_template('homenew.html', name=username, role=role)
    #    # , nric=users.get_nric(), email=users.get_email(), security_question=users.get_security_questions(), answer=users.get_answer()
    #    else:
    #        return '<p style="text-align:center;">Please log in first.</p>', render_template('home2.html')
    return redirect(url_for('login'))


####end of login code lolllll ############################################################


@app.route('/mangementretrieve')
def mangement_retrieve():
    try:
        users_dict1 = {}
        db = shelve.open('login.db', 'r')
        users_dict1 = db['login']
        db.close()
        users_list1 = []
        for key in users_dict1:
            user = users_dict1.get(key)
            users_list1.append(user)
        for users in users_list1:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
            users_dict = {}
            db = shelve.open('userbooking.db', 'r')
            try:
                users_dict = db['userbooking']
            except:
                print("Error in retrieving Users from userdinein.db.")
            db.close()
            users_list = []
            for key in users_dict:
                user = users_dict.get(key)
                users_list.append(user)

            return render_template('mangementretrieve.html', count=len(users_list), users_list=users_list, role=role,
                                   name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/mangementdinetretrieve')
def management_dinein_retretrieve():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        users_dict = {}
        db = shelve.open('userdinein.db', 'r')
        try:
            users_dict = db['userdinein']
        except:
            print("Error in retrieving Users from userdinein.db.")
        db.close()
        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)
        return render_template('mangementdinetretrieve.html', count=len(users_list), users_list=users_list,
                               name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/create_dinein_user', methods=['GET', 'POST'])
def create_dineinuser():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        create_dineinuser_form = CreateDineInForm(request.form)
        create_dineinuser_form.username.data = session['username']
        z = datetime.datetime.now()
        zy = z.strftime('%d-%m-%Y')
        create_dineinuser_form.time.data = zy
        create_dineinuser_form.status.data = 'waiting'

        users_dict2 = {}
        db = shelve.open('login.db', 'r')
        users_dict2 = db['login']
        db.close()
        users_list1 = []
        for key in users_dict2:
            user = users_dict2.get(key)
            users_list1.append(user)
            if user.get_username() == session['username']:
                print('phone', user.get_phone_no())
                create_dineinuser_form.phone_no.data = user.get_phone_no()
        tables_dict = {}
        database = shelve.open('mangetablecreate1.db', 'w')
        table_list = []
        tables_dict = database['mangetablecreate1']
        for key in tables_dict:
            table = tables_dict.get(key)
            if table.get_remarks() == 'active':
                table_list.append(table)
        length = len(table_list)
        start = 0
        print(tables_dict)
        print(table_list)
        print(table_list[0].get_table_no())
        print(table_list[0].get_user_id())
        print(table_list[0].get_remarks())
        tablechoice_list = []
        for i in table_list:
            tablechoice = str(i.get_table_no())
            tablechoice_list.append(tablechoice)
        print(tablechoice_list)
        print(tablechoice)
        print(tables_dict)
        print(table_list)
        create_dineinuser_form.table_no.choices = [tablechoice_list[a] for a in range(length)]
        if request.method == 'POST' and create_dineinuser_form.validate():
            users_dict2 = {}
            db = shelve.open('userdinein.db', 'c')
            try:
                users_dict2 = db['userdinein']
            except:
                print("Error in retrieving Users from userdinein.db.")

            user2 = dineinuser(create_dineinuser_form.username.data, create_dineinuser_form.phone_no.data,
                               create_dineinuser_form.table_no.data, create_dineinuser_form.remarks.data,
                               create_dineinuser_form.no_ppl.data, create_dineinuser_form.time.data,
                               create_dineinuser_form.status.data)
            users_dict2[user2.get_user_id()] = user2
            db['userdinein'] = users_dict2
            print('status', user2.get_status())
            db.close()
            return redirect(url_for('retrieve_dinein_users'))
        return render_template('create_dinein_user.html', form=create_dineinuser_form, name=session['username'],
                               role=role)
    except:
        return render_template('error404.html')


@app.route('/retrieverdinein')
def retrieve_dinein_users():
    try:
        users_dict = {}
        db = shelve.open('userdinein.db', 'r')
        try:
            users_dict2 = db['userdinein']
        except:
            print("Error in retrieving Users from userdinein.db.")
        db.close()
        users_list = []
        for key in users_dict2:
            user = users_dict2.get(key)
            if user.get_username() == session['username']:
                users_list.append(user)
        users_dict1 = {}
        db = shelve.open('login.db', 'r')
        try:
            users_dict1 = db['login']
        except:
            print("Error in retrieving Users from login.db.")
        db.close()
        users_list1 = []
        for key in users_dict1:
            user = users_dict1.get(key)
            users_list1.append(user)
        for users in users_list1:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'

        return render_template('retrieverdinein.html', count=len(users_list), users_list=users_list,
                               name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/updatedienin/<int:id>/', methods=['GET', 'POST'])
def update_dineuser(id):
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
            y = datetime.datetime.now()
            xy = y.strftime('%d-%m-%Y')

            update_user_form = CreateDineInForm(request.form)
            tables_dict = {}
            database = shelve.open('mangetablecreate1.db', 'w')
            table_list = []
            tables_dict = database['mangetablecreate1']
            for key in tables_dict:
                table = tables_dict.get(key)
                if table.get_remarks() == 'active':
                    table_list.append(table)
            length = len(table_list)
            start = 0
            print(tables_dict)
            print(table_list)
            print(table_list[0].get_table_no())
            print(table_list[0].get_user_id())
            print(table_list[0].get_remarks())
            tablechoice_list = []
            for i in table_list:
                tablechoice = str(i.get_table_no())
                tablechoice_list.append(tablechoice)
            print(tablechoice_list)
            print(tablechoice)
            print(tables_dict)
            print(table_list)
            update_user_form.table_no.choices = [tablechoice_list[a] for a in range(length)]
            if request.method == 'POST' and update_user_form.validate():
                users_dict = {}
                db = shelve.open('userdinein.db', 'w')
                users_dict2 = db['userdinein']
                user2 = users_dict2.get(id)
                user2.set_username(update_user_form.username.data)
                user2.set_no_ppl(update_user_form.no_ppl.data)
                user2.set_phone_no(update_user_form.phone_no.data)
                user2.set_table_no(update_user_form.table_no.data)
                user2.set_time(update_user_form.time.data)
                user2.set_remarks(update_user_form.remarks.data)

                db['userdinein'] = users_dict2
                db.close()
                return redirect(url_for('retrieve_dinein_users'))
            else:
                tables_dict = {}
                database = shelve.open('mangetablecreate1.db', 'w')
                table_list = []
                tables_dict = database['mangetablecreate1']
                for key in tables_dict:
                    table = tables_dict.get(key)
                    if table.get_remarks() == 'active':
                        table_list.append(table)
                length = len(table_list)
                start = 0
                print(tables_dict)
                print(table_list)
                print(table_list[0].get_table_no())
                print(table_list[0].get_user_id())
                print(table_list[0].get_remarks())
                tablechoice_list = []
                for i in table_list:
                    tablechoice = str(i.get_table_no())
                    tablechoice_list.append(tablechoice)
                print(tablechoice_list)
                print(tablechoice)
                print(tables_dict)
                print(table_list)
                update_user_form.table_no.choices = [tablechoice_list[a] for a in range(length)]
                users_dict2 = {}
                db = shelve.open('userdinein.db', 'r')
                try:
                    users_dict2 = db['userdinein']
                except:
                    print("Error in retrieving Users from userdinein.db.")
                db.close()
                user2 = users_dict2.get(id)
                update_user_form.username.data = user2.get_username()
                update_user_form.no_ppl.data = user2.get_no_ppl()
                update_user_form.table_no.data = user2.get_table_no()
                update_user_form.phone_no.data = user2.get_phone_no()
                update_user_form.time.data = user2.get_time()
                update_user_form.remarks.data = user2.get_remarks()
                return render_template('updatedienin.html', form=update_user_form, name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/delete_User/<int:id>', methods=['POST'])
def delete_dine_user(id):
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        users_dict = {}
        db = shelve.open('userdinein.db', 'w')
        users_dict = db['userdinein']
        users_dict.pop(id)
        db['userdinein'] = users_dict
        db.close()
        return redirect(url_for('retrieve_dinein_users'))
    except:
        return render_template('error404.html')


################management table create #############################
@app.route('/mangetablecrete', methods=['GET', 'POST'])
def mangetable_create():
    try:
        mange_table_create = Createmangetable(request.form)
        if request.method == 'POST' and mange_table_create.validate():
            users_dict = {}
            db = shelve.open('mangetablecreate1.db', 'c')
            try:
                users_dict = db['mangetablecreate1']
            except:
                print("Error in retrieving Users from storage.db.")
            mangetable2 = mangetable1(
                mange_table_create.table_no.data, mange_table_create.remarks.data)
            users_dict[mangetable2.get_user_id()] = mangetable2
            db['mangetablecreate1'] = users_dict

            db.close()
            print(mangetable2.get_user_id())
            print(mangetable2.get_table_no())
            return redirect(url_for('retrieve_table'))
        users_dict1 = {}
        db = shelve.open('login.db', 'r')
        users_dict1 = db['login']
        db.close()
        users_list1 = []
        for key in users_dict1:
            user = users_dict1.get(key)
            users_list1.append(user)

        for users in users_list1:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        return render_template('createmangetable.html', form=mange_table_create, name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/mangetableret')
def retrieve_table():
    try:
        users_dict = {}
        db = shelve.open('mangetablecreate1.db', 'r')
        users_dict = db['mangetablecreate1']
        db.close()
        users_dict1 = {}
        db = shelve.open('login.db', 'r')
        users_dict1 = db['login']
        db.close()
        users_list1 = []
        for key in users_dict1:
            user = users_dict1.get(key)
            users_list1.append(user)

        for users in users_list1:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        users_list = []
        for key in users_dict:
            mangetable2 = users_dict.get(key)
            users_list.append(mangetable2)
        return render_template('mangetableretrieve.html', count=len(users_list), users_list=users_list,
                               name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/updatetable/<int:id>/', methods=['GET', 'POST'])
def update_table(id):
    try:
        users_dict1 = {}
        db = shelve.open('login.db', 'r')
        users_dict1 = db['login']
        db.close()
        users_list1 = []
        for key in users_dict1:
            user = users_dict1.get(key)
            users_list1.append(user)
        for users in users_list1:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        mange_table_create = Createmangetable(request.form)
        if request.method == 'POST' and mange_table_create.validate():
            users_dict = {}
            db = shelve.open('mangetablecreate1.db', 'w')
            users_dict = db['mangetablecreate1']
            mangetable2 = users_dict.get(id)
            mangetable2.set_table_no(mange_table_create.table_no.data)
            mangetable2.set_remarks(mange_table_create.remarks.data)
            db['mangetablecreate1'] = users_dict
            db.close()
            return redirect(url_for('retrieve_table'))
        else:
            users_dict = {}
            db = shelve.open('mangetablecreate1.db', 'r')
            users_dict = db['mangetablecreate1']
            db.close()
            mangetable2 = users_dict.get(id)
            mange_table_create.table_no.data = mangetable2.get_table_no()
            mange_table_create.remarks.data = mangetable2.get_remarks()
            tableno = mangetable2.get_table_no()
            return render_template('updatetable.html', form=mange_table_create, table=tableno, name=session['username'],
                                   role=role)
    except:
        return render_template('error404.html')


@app.route('/deletetable/<int:id>', methods=['POST'])
def delete_table(id):
    try:
        users_dict = {}
        db = shelve.open('mangetablecreate1.db', 'w')
        users_dict = db['mangetablecreate1']
        users_dict.pop(id)
        db['mangetablecreate1'] = users_dict
        db.close()
        return redirect(url_for('retrieve_table'))
    except:
        return render_template('error404.html')


################ end of management table create #################
################# check today have how many people #################
@app.route('/check_tdy_ppl')
def check_dine():
    try:
        users_dict = {}
        db = shelve.open('userdinein.db', 'r')
        users_dict = db['userdinein']
        db.close()
        users_dict2 = {}
        db = shelve.open('userbooking.db', 'r')
        users_dict2 = db['userbooking']
        db.close()
        users_list1 = []
        print(users_dict)
        users_list4 = []

        print(users_dict2)
        for key in users_dict:
            user = users_dict.get(key)
            users_list4.append(user)
        users_list2 = []
        for key in users_dict2:
            user = users_dict2.get(key)
            users_list2.append(user)
        users_dict1 = {}
        db = shelve.open('login.db', 'r')
        users_dict1 = db['login']
        db.close()

        users_list3 = []
        for key in users_dict1:
            user = users_dict1.get(key)
            users_list3.append(user)
        print(users_list1)

        for users in users_list1:
            if 'username' in session:
                username = session['username']
                role = ''
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'

        return render_template('check_tdy_ppl.html', count=len(users_list1), count2=len(users_list2),
                               users_list1=users_list1, users_list2=users_list2, name=session['username'],
                               users_list3=users_list3)
    except:
        return render_template('error404.html')


################## end of check today have how many people ###########
################## cher code ################################################
#####      @app.route('/')
##         def home():##
###        return render_template('home.html')#####
@app.route('/book')
def book():
    try:
        return render_template('book.html')
    except:
        return render_template('error404.html')


@app.route('/contactUs')
def contact_us():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        return render_template('contactUs.html', name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/createUser', methods=['GET', 'POST'])
def create_user():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        create_user_form = CreateUserForm(request.form)
        create_user_form.status.data = 'active'
        create_user_form.username.data = session['username']
        users_dict2 = {}
        db = shelve.open('login.db', 'r')
        try:
            users_dict2 = db['login']
        except:
            print("Error in retrieving Users from login.db.")
        db.close()
        users_list1 = []
        for key in users_dict2:
            user = users_dict2.get(key)
            users_list1.append(user)
            if user.get_username() == session['username']:
                print('phone', user.get_phone_no())
                create_user_form.phone_no.data = user.get_phone_no()
        tables_dict = {}
        database = shelve.open('mangetablecreate1.db', 'w')
        table_list = []
        tables_dict = database['mangetablecreate1']
        for key in tables_dict:
            table = tables_dict.get(key)
            if table.get_remarks() == 'active':
                table_list.append(table)
        length = len(table_list)
        start = 0
        print(tables_dict)
        print(table_list)
        print(table_list[0].get_table_no())
        print(table_list[0].get_user_id())
        print(table_list[0].get_remarks())
        tablechoice_list = []
        for i in table_list:
            tablechoice = str(i.get_table_no())
            tablechoice_list.append(tablechoice)
        print(tablechoice_list)
        print(tablechoice)
        print(tables_dict)
        print(table_list)
        create_user_form.table_no.choices = [tablechoice_list[a] for a in range(length)]
        if request.method == 'POST' and create_user_form.validate():
            users_dict = {}
            db = shelve.open('userbooking.db', 'c')
            try:
                users_dict = db['userbooking']
            except:
                print("Error in retrieving Users from storage.db.")
            user = User.book(create_user_form.username.data, create_user_form.date.data, create_user_form.phone_no.data,
                             create_user_form.table_no.data, create_user_form.booking_time.data,
                             create_user_form.remarks.data, create_user_form.no_ppl.data, create_user_form.status.data)
            users_dict[user.get_user_id()] = user
            db['userbooking'] = users_dict
            db.close()
            return redirect(url_for('retrieve_users'))
        return render_template('createUser.html', form=create_user_form, name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/retrieveUsers')
def retrieve_users():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
            users_dict = {}
            db = shelve.open('userbooking.db', 'r')
            try:
                users_dict = db['userbooking']
            except:
                print("Error in retrieving Users from userbooking.db.")
            db.close()
            users_list = []
            for key in users_dict:
                user = users_dict.get(key)
                if user.get_username() == session['username']:
                    users_list.append(user)
            z = datetime.datetime.today()
            zy = z.strftime('%d-%m-%Y')
            print(zy, 'tdy date')

            return render_template('retrieveUsers.html', count=len(users_list), users_list=users_list,
                                   name1=session['username'], date=zy, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/updateUser/<int:id>/', methods=['GET', 'POST'])
def update_user(id):
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        update_user_form = CreateUserForm(request.form)
        tables_dict = {}
        database = shelve.open('mangetablecreate1.db', 'w')
        table_list = []
        tables_dict = database['mangetablecreate1']
        for key in tables_dict:
            table = tables_dict.get(key)
            if table.get_remarks() == 'active':
                table_list.append(table)
        length = len(table_list)
        start = 0
        print(tables_dict)
        print(table_list)
        print(table_list[0].get_table_no())
        print(table_list[0].get_user_id())
        print(table_list[0].get_remarks())
        tablechoice_list = []

        for i in table_list:
            tablechoice = str(i.get_table_no())
            tablechoice_list.append(tablechoice)
        print(tablechoice_list)
        print(tablechoice)
        print(tables_dict)
        print(table_list)
        update_user_form.table_no.choices = [tablechoice_list[a] for a in range(length)]
        if request.method == 'POST' and update_user_form.validate():
            users_dict = {}
            db = shelve.open('userbooking.db', 'w')
            users_dict = db['userbooking']
            user = users_dict.get(id)
            user.set_username(update_user_form.username.data)
            user.set_date(update_user_form.date.data)
            user.set_no_ppl(update_user_form.no_ppl.data)
            user.set_phone_no(update_user_form.phone_no.data)
            user.set_table_no(update_user_form.table_no.data)
            user.set_booking_time(update_user_form.booking_time.data)
            user.set_remarks(update_user_form.remarks.data)
            db['userbooking'] = users_dict
            db.close()
            return redirect(url_for('retrieve_users'))
        else:
            tables_dict = {}
            database = shelve.open('mangetablecreate1.db', 'w')
            table_list = []
            tables_dict = database['mangetablecreate1']
            for key in tables_dict:
                table = tables_dict.get(key)
                if table.get_remarks() == 'active':
                    table_list.append(table)
            length = len(table_list)
            start = 0
            print(tables_dict)
            print(table_list)
            print(table_list[0].get_table_no())
            print(table_list[0].get_user_id())
            print(table_list[0].get_remarks())
            tablechoice_list = []
            for i in table_list:
                tablechoice = str(i.get_table_no())
                tablechoice_list.append(tablechoice)
            print(tablechoice_list)
            print(tablechoice)
            print(tables_dict)
            print(table_list)
            update_user_form.table_no.choices = [tablechoice_list[a] for a in range(length)]
            users_dict = {}
            db = shelve.open('userbooking.db', 'r')
            users_dict = db['userbooking']
            db.close()
            user = users_dict.get(id)
            update_user_form.username.data = user.get_username()
            update_user_form.date.data = user.get_date()
            update_user_form.no_ppl.data = user.get_no_ppl()
            update_user_form.table_no.data = user.get_table_no()
            update_user_form.phone_no.data = user.get_phone_no()
            update_user_form.booking_time.data = user.get_booking_time()
            update_user_form.remarks.data = user.get_remarks()

            return render_template('updateUser.html', form=update_user_form, name=session['username'], role=role)

    except:
        return render_template('error404.html')


@app.route('/deleteUser/<int:id>', methods=['POST'])
def delete_user(id):
    try:
        users_dict = {}
        db = shelve.open('userbooking.db', 'w')
        try:
            users_dict = db['userbooking']
        except:
            print("Error in retrieving Users from userbooking.db.")
        users_dict.pop(id)
        db['userbooking'] = users_dict
        db.close()
        return redirect(url_for('retrieve_users'))
    except:
        return render_template('error404.html')


# Bryan Codes


@app.route('/createFeedbacks', methods=['GET', 'POST'])
def create_feedback():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        create_user_form = CreateFeedbackForm(request.form)
        create_user_form.date.data = datetime.datetime.today()
        if request.method == 'POST' and create_user_form.validate():
            feedbacks_dict = {}
            db = shelve.open('feedback.db', 'c')

            try:
                feedbacks_dict = db['Feedbacks']
            except:
                print("Error in retrieving Feedbacks from storage.db.")

            user = F.Feedback(create_user_form.category.data, create_user_form.rating.data,
                              create_user_form.contact.data, create_user_form.remarks.data, 'Open',
                              create_user_form.date.data)
            feedbacks_dict[user.get_no_of_feedbacks()] = user
            db['Feedbacks'] = feedbacks_dict

            db.close()
            return redirect(url_for('home'))
    except:
        return render_template('error404.html')

    return render_template('createFeedback.html', form=create_user_form, name=session['username'], role=role)


@app.route('/viewFeedbacks')
def view_feedbacks():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        datetime.date.today()
        feedbacks_dict = {}
        feedback_db = shelve.open('feedback.db', 'r')
        feedbacks_dict = feedback_db['Feedbacks']

        feedback_db.close()

        feedbacks_list = []
        for key in feedbacks_dict:
            feedback = feedbacks_dict.get(key)
            if feedback.get_category() == "F":
                feedbacks_list.append(feedback)
            elif feedback.get_category() == "S":
                feedbacks_list.append(feedback)
            elif feedback.get_category() == "H":
                feedbacks_list.append(feedback)
            elif feedback.get_category() == "A":
                feedbacks_list.append(feedback)
            elif feedback.get_category() == "D":
                feedbacks_list.append(feedback)
            else:
                print("Error")

        return render_template('viewFeedbacks.html',
                               count=len(feedbacks_list), feedbacks_list=feedbacks_list, name=session['username'],
                               role=role)

    except:
        return render_template('error404.html')


@app.route('/viewRemarks/')
def view_remarks():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        feedbacks_dict = {}
        db = shelve.open('feedback.db', 'r')
        feedbacks_dict = db['Feedbacks']

        db.close()

        feedbacks_list = []
        for key in feedbacks_dict:
            feedback = feedbacks_dict.get(key)
            feedbacks_list.append(feedback)

        return render_template('viewRemarks.html',
                               count=len(feedbacks_list), feedbacks_list=feedbacks_list, name=session['username'],
                               role=role)

    except:
        return render_template('error404.html')


@app.route('/updateFeedback/<int:id>/', methods=['GET', 'POST'])
def update_feedback(id):
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        update_user_form = CreateUpdateFeedbackForm(request.form)
        if request.method == 'POST' and update_user_form.validate():
            feedbacks_dict = {}
            feedback_db = shelve.open('feedback.db', 'w')
            feedbacks_dict = feedback_db['Feedbacks']

            user = feedbacks_dict.get(id)
            user.set_category(update_user_form.category.data)
            user.set_rating(update_user_form.rating.data)
            user.set_contact(update_user_form.contact.data)
            user.set_remarks(update_user_form.remarks.data)
            user.set_status(update_user_form.status.data)

            feedback_db['Feedbacks'] = feedbacks_dict
            feedback_db.close()

            return redirect(url_for('view_feedbacks'))
        else:
            feedback_dict = {}
            feedback_db = shelve.open('feedback.db', 'r')
            feedback_dict = feedback_db['Feedbacks']
            feedback_db.close()

            user = feedback_dict.get(id)
            update_user_form.category.choices = user.get_category()
            update_user_form.rating.choices = user.get_rating()
            update_user_form.contact.data = user.get_contact()
            update_user_form.remarks.data = user.get_remarks()
            update_user_form.status.data = user.get_status()

            return render_template('updateFeedback.html', form=update_user_form, name=session['username'], role=role)

    except:
        return render_template('error404.html')


# Jolene's codes#


@app.route('/createfood', methods=['GET', 'POST'])
def create_food():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        create_food_form = CreateFoodForm(request.form)
        if request.method == 'POST' and create_food_form.validate():
            food_dict = {}
            fooddatabase = shelve.open('food.db', 'c')

            try:
                food_dict = fooddatabase['Creation']
            except:
                print("Error in retrieving data from food.db.")

            food = Food(create_food_form.name.data, create_food_form.image.data, create_food_form.category.data,
                        create_food_form.status.data, create_food_form.price.data, create_food_form.ingredients.data,
                        create_food_form.extra_remarks.data)
            food_dict[food.get_id()] = food
            fooddatabase['Creation'] = food_dict

            fooddatabase.close()

            return redirect(url_for('retrieve_food'))
        return render_template('createfood.html', form=create_food_form, name=session['username'], role=role)
    except:
        return render_template('error404.html')


@app.route('/customerui')
def customerui():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
        return render_template('customerui.html', count=len(food_list), foods_list=food_list, maindishlist=maindishlist,
                               sidedishlist=sidedishlist, drinklist=drinklist, kidsmeallist=kidsmeallist,
                               promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/managehome')
def managehome():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        return render_template('managehome.html', name=session['username'], role=role)

    except:
        return render_template('error404.html')


@app.route('/retrievefood')
def retrieve_food():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            # if food.get_food_name() == 'Ban Mian':
            food_list.append(food)

        return render_template('retrievefood.html', count=len(food_list), foods_list=food_list, role=role,
                               name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/updateFood/<int:id>', methods=['GET', 'POST'])
def updateFood(id):
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        update_food_form = CreateFoodForm(request.form)
        if request.method == 'POST' and update_food_form.validate():
            food_dict = {}
            db = shelve.open('food.db', 'w')
            food_dict = db['Creation']

            user = food_dict.get(id)
            user.set_food_name(update_food_form.name.data)
            user.set_image(update_food_form.image.data)
            user.set_category(update_food_form.category.data)
            user.set_status(update_food_form.status.data)
            user.set_price(update_food_form.price.data)
            user.set_ingredients(update_food_form.ingredients.data)
            user.set_extra_remarks(update_food_form.extra_remarks.data)

            db['Creation'] = food_dict
            db.close()

            return redirect(url_for('retrieve_food'))
        else:
            food_dict = {}
            db = shelve.open('food.db', 'r')
            food_dict = db['Creation']
            db.close()

            user = food_dict.get(id)
            update_food_form.name.data = user.get_food_name()
            update_food_form.image.data = user.get_image()
            update_food_form.category.data = user.get_category()
            update_food_form.status.data = user.get_status()
            update_food_form.price.data = user.get_price()
            update_food_form.ingredients.data = user.get_ingredients()
            update_food_form.extra_remarks.data = user.get_extra_remarks()

            return render_template('updateFood.html', form=update_food_form, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalbanmian')
def orderfinalbanmian():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
                print(maindishlist)
        return render_template('orderfinalbanmian.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalporridge')
def orderfinalporridge():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
                print(maindishlist)
        return render_template('orderfinalporridge.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalchicken')
def orderfinalchicken():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
                print(maindishlist)
        return render_template('orderfinalchicken.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinaldumpling')
def orderfinaldumpling():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
                print(maindishlist)
        return render_template('orderfinaldumpling.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])

    except:
        return render_template('error404.html')


@app.route('/orderfinalmilktea')
def orderfinalmilktea():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
                print(maindishlist)
        return render_template('orderfinalmilktea.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalrootbeer')
def orderfinalrootbeer():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)
                print(maindishlist)
        return render_template('orderfinalrootbeer.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalkid1')
def orderfinalkid1():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)

        return render_template('orderfinalkid1.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist,
                               sidedishlist=sidedishlist, drinklist=drinklist, kidsmeallist=kidsmeallist,
                               promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalkid2')
def orderfinalkid2():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)

        return render_template('orderfinalkid2.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist,
                               sidedishlist=sidedishlist, drinklist=drinklist, kidsmeallist=kidsmeallist,
                               promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.route('/orderfinalcnyset')
def orderfinalcnyset():
    try:
        users_dict123 = {}
        db = shelve.open('login.db', 'r')
        users_dict123 = db['login']
        db.close()
        users_list1234 = []
        for key in users_dict123:
            user = users_dict123.get(key)
            users_list1234.append(user)
        for users in users_list1234:
            if 'username' in session:
                username = session['username']
                role = users.get_role()
                if username == 'admin':
                    role = 'Staff'
                else:
                    role = 'Guest'
        food_dict = {}
        db = shelve.open('food.db', 'r')
        food_dict = db['Creation']
        db.close()

        food_list = []
        for key in food_dict:
            food = food_dict.get(key)
            food_list.append(food)

        x = 0
        length = len(food_list)
        start = 0
        maindishlist = []
        sidedishlist = []
        drinklist = []
        promolist = []
        kidsmeallist = []
        for food in food_list:
            if food.get_category() == 'Main dishes':
                f = food
                maindishlist.append(f)
            elif food.get_category() == 'Side dishes':
                sd = food
                sidedishlist.append(sd)
            elif food.get_category() == 'Drinks':
                drink = food
                drinklist.append(drink)
            elif food.get_category() == 'On Promos':
                promo = food
                promolist.append(promo)
            elif food.get_category() == 'Kids Meal':
                kidsmeal = food
                kidsmeallist.append(kidsmeal)

        return render_template('orderfinalcnyset.html', count=len(food_list), foods_list=food_list,
                               maindishlist=maindishlist, sidedishlist=sidedishlist, drinklist=drinklist,
                               kidsmeallist=kidsmeallist, promolist=promolist, role=role, name=session['username'])
    except:
        return render_template('error404.html')


@app.errorhandler(500)
def page_not_found(e):
    return render_template('error500.html'), 500


# @app.errorhandler(404)
# def page_not_found(e):
# return render_template('error404.html'), 404
if __name__ == '__main__':
    app.run(debug=True)
