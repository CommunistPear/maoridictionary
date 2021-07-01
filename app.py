from flask import Flask, render_template
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DB_NAME = "dictionary.db"
app = Flask(__name__)

bcrypt = Bcrypt(app)
app.secret_key = "sefofe@#$%**jkvbuseb22BUJBBOPVIUBZPuboiserfbuso@#@##21ashjsrf77755kl%^$##"


@app.route('/login', methods=["GET", "POST"])
def render_login_page():
    if is_logged_in():
        return redirect('/')
    print(request.form)
    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        query = """SELECT id, fname, password FROM customers WHERE email = ?"""
        con = create_connection(DB_NAME)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        con.close()
        # if given the email is not in the database this will raise an error
        # would be better to find out how to see if the query return an empty resultset
        try:
            userid = user_data[0][0]
            firstname = user_data[0][1]
            db_password = user_data[0][2]
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # check if the password is incorrect for that email address

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['userid'] = userid
        session['firstname'] = firstname
        session['cart'] = []
        print(session)
        return redirect('/')

    return render_template('login.html', logged_in=is_logged_in())


def create_connection(db_file):
    # creates connection to database
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)


@app.route('/')
def render_home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run()
