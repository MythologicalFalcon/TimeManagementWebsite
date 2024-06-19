# importing needed libraries
import pyotp
from flask import *
from flask_bootstrap import Bootstrap
import mysql.connector
import cryptography
from cryptography.fernet import Fernet
import smtplib
import random
import urllib
import pandas
from sqlalchemy import create_engine
import sqlite3
import re

name = ""

# configuring flask application
app = Flask(__name__)
app.config["SECRET_KEY"] = "APP_SECRET_KEY"
x =0
secret = ""
Bootstrap(app)


# homepage route
@app.route("/")
def index():
    return render_template("login.html")


# login page route
@app.route("/login/")
def login():
    global name
    name = ""
    return render_template("login.html")


# login form route
@app.route("/login/", methods=["POST"])
def login_form():
    # demo creds
    username = request.form.get("username")
    password = request.form.get("password")
    print(username)
    print(password)
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    quer = "SELECT * from cse563.signup where username='"+username+"'"
    global name
    name = username
    mycursor.execute(quer)
    myresult = mycursor.fetchall()
    
    key = myresult[0][5]
    key = key.encode()
    f = Fernet(key)
    password = f._encrypt_from_parts(password.encode(), 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')

    password = password.decode()
    
    if username == myresult[0][0] and password == (myresult[0][1]):
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()
        emailid = str(myresult[0][2])
        s.login("charansri10@gmail.com", "ioczkmxoslrubkxo")
        emailOTP = random.randint(100000,999999)
        global x
        x = emailOTP
        s.sendmail('&&&&&&',emailid,str(x))
        return redirect(url_for("login_2fa", emailOTP = emailOTP))
    elif username == myresult[0][0] and password == myresult[0][1] :
        return redirect(url_for("login_2fa",  emailOTP = emailOTP))
    else:
        # inform users if creds are invalid
        flash("You have supplied invalid login credentials!", "danger")
        return redirect(url_for("login"))


# 2FA page route
@app.route("/login/2fa/")
def login_2fa():
    # generating random secret key for authentication
    
    emailOTP = request.form.get("emailOTP")
    
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    quer = "SELECT * from cse563.signup where username='"+name+"';"
    mycursor.execute(quer)
    myresult = mycursor.fetchall()
    secret = myresult[0][2]
    return render_template("login_2fa.html")
    return render_template("login_2fa.html", secret=secret, emailOTP = emailOTP )


# 2FA form route
@app.route("/login/2fa/", methods=["POST"])
def login_2fa_form():
    # getting secret key used by user
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    quer = "SELECT * from cse563.signup where username='"+name+"';"
    mycursor.execute(quer)
    myresult = mycursor.fetchall()
    secret = myresult[0][6]
    emailOTP = request.form.get("emailOTP")
    emailOTP = x
    #secret = "VDMJ5BUMRW4NZMH7XA3HOVLWSYA4JBSI"
    # getting OTP provided by user
    otp = int(request.form.get("otp"))
    print("charan")
    print(secret)
    # verifying submitted OTP with PyOTP
    if ((pyotp.TOTP(secret).verify(otp)) or (otp == emailOTP)):
        # inform users if OTP is valid
        #flash("The TOTP 2FA token is valid", "success")
        #return "<h1>Charan Your verification is successful</h1>"
        if(myresult[0][4] == "manager"):
            return redirect(url_for("premanager"))
        else:
            return redirect(url_for("nonothers"))
    else:
        # inform users if OTP is invalid
        flash("You have supplied an invalid 2FA token!", "danger")
        return redirect(url_for("login_2fa"))

@app.route("/signup/")
def signupform():
    return render_template("signup.html")

#signup page
@app.route("/signup/", methods=["POST"])
def signup():
    username = request.form.get("username")
    password = request.form.get("password")
    confirmpassword = request.form.get("confirmpassword")
    email = request.form.get("email")
    fullname = request.form.get("fullname")
    role = request.form.get("role")
    key = fernetkey = Fernet.generate_key().decode()
    secretAuthenticatorKey = "VDMJ5BUMRW4NZMH7XA3HOVLWSYA4JBSI"

    #password encryption using fernet Key
    
    print(username)
    print(password)
    print(confirmpassword)
    print(email)
    print(fullname)
    print(role)
    flag = 0
    if (len(password)<=8):
        flag = -1
        flash("Password Does not meet the requirements")
        return redirect(url_for("signup"))
    elif not re.search("[a-z]", password):
        flag = -1
        flash("Password Does not meet the requirements")
        return redirect(url_for("signup"))
    elif not re.search("[A-Z]", password):
        flag = -1
        flash("Password Does not meet the requirements")
        return redirect(url_for("signup"))
    elif not re.search("[0-9]", password):
        flag = -1
        flash("Password Does not meet the requirements")
        return redirect(url_for("signup"))
    elif not re.search("[_@$]" , password):
        flag = -1
        flash("Password Does not meet the requirements")
        return redirect(url_for("signup"))
    elif re.search("\s" , password):
        flag = -1
        flash("Password Does not meet the requirements")
        return redirect(url_for("signup"))
    else:
        key = key.encode()
        f = Fernet(key)
        password = f._encrypt_from_parts(password.encode(), 0,b'\xbd\xc0,\x16\x87\xd7G\xb5\xe5\xcc\xdb\xf9\x07\xaf\xa0\xfa')
        password = password.decode()
        mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
        mycursor = mydb.cursor()
        val = "'"+username+"','"+password+"','"+email+"','"+fullname+"','"+role+"','"+fernetkey+"','"+secretAuthenticatorKey+"'"
        quer = "INSERT into CSE563.signup values("+val+")";
        print(quer)
        mycursor.execute(quer)
        mydb.commit()
        flash("User created succesfully!")
        return redirect(url_for("login"))


@app.route('/manager/')
def manager():
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM cse563.effort")
    data = mycursor.fetchall()

    # Pass the data to a template and render it to HTML
    return render_template("manager.html", data=data)

@app.route('/manager/', methods=["POST"])
def managerpost():
    forma = request.form.get("exportdata")
    
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM cse563.effort")
    data = mycursor.fetchall()
    if(forma == "csv"):
        df = pandas.DataFrame(data)
        print(df.head())
        df.to_csv (r'exported_data.xlsx', index = False) # place 'r' before the path name
    if(forma == "xls"):
        df = pandas.DataFrame(data)
        df.to_csv (r'exported_data.xlsx', index = False) # place 'r' before the path name

    # Pass the data to a template and render it to HTML
    return render_template("manager.html", data=data)

@app.route("/other/")
def otherform():
    return render_template("other.html")

#signup page
@app.route("/other/", methods=["POST"])
def other():
    user = name
    date = request.form.get("date")
    starttime = request.form.get("starttime")+":00"
    endtime = request.form.get("endtime")+":00"
    hours = request.form.get("hours")
    print(user)
    print(date)
    print(starttime)
    print(endtime)
    print(type(endtime))
    print(hours)
    starthr = int(starttime[0:2])
    endhr = int(endtime[0:2])
    startmin= int(starttime[3:5])
    endmin = int(endtime [3:5])
    if(starthr > endhr):
        flash("CHeck the timings of Hours")
        return redirect(url_for("other"))
    if(starthr == endhr):
        if(endmin < startmin):
            flash("CHeck the timings of Hours")
            return redirect(url_for("other"))
        
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    val = "'"+user+"','"+date+"','"+starttime+"','"+endtime+"','"+hours+"'"
    quer = "INSERT into CSE563.effort values("+val+")";
    print(quer)
    mycursor.execute(quer)
    mydb.commit()
    flash("Hours have been successfully submitted!")
    return redirect(url_for("other"))

@app.route("/nonothers/")
def nonothersform():
    return render_template("nonothers.html")

#signup page
@app.route("/nonothers/", methods=["POST"])
def nonothers():
    user = name
    date = request.form.get("date")
    starttime = request.form.get("starttime")+":00"
    endtime = request.form.get("endtime")+":00"
    hours = request.form.get("hours")
    print(user)
    print(date)
    print(starttime)
    print(endtime)
    print(type(endtime))
    print(hours)
    starthr = starttime[0:2]
    print("*************************************************************************************")
    print(starthr)
    
    endhr = endtime[0:2]
    print(endhr)
    startmin = starttime[3:5]
    print(startmin)
    
    endmin = endtime [3:5]
    print(endmin)
    starthr = int(starthr)
    endhr = int(endhr)
    startmin= int(startmin)
    endmin = int(endmin)
    if(starthr > endhr):
        flash("CHeck the timings of Hours")
        return redirect(url_for("nonothers"))
    if(starthr == endhr):
        if(endmin < startmin):
            flash("CHeck the timings of Hours")
            return redirect(url_for("nonothers"))
    
    mydb = mysql.connector.connect(host="localhost",user="root",password="admin",database = "cse563", auth_plugin='mysql_native_password')
    mycursor = mydb.cursor()
    val = "'"+user+"','"+date+"','"+starttime+"','"+endtime+"','"+hours+"'"
    quer = "INSERT into CSE563.effort values("+val+")";
    print(quer)
    mycursor.execute(quer)
    mydb.commit()
    flash("Hours have been successfully submitted!")
    return redirect(url_for("nonothers"))

@app.route("/premanager/")
def premanagerform():
    return render_template("premanager.html")

#signup page
@app.route("/premanager/", methods=["POST"])
def premanager():
    user = name
    value = request.form.get("role")
    print(value)
    if (value == "add"):
        return redirect(url_for("other"))
    else:
        return redirect(url_for("manager"))


# running flask server
if __name__ == "__main__":
    app.run(debug=True)
