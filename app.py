import urllib.parse
from flask import Flask, render_template, session, redirect, request
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

# DB_NAME = "dictionary.db"
DB_NAME = "C:/Users/17075/OneDrive - Wellington College/Technology/DTS/Y13/" \
          "Maori Dictionary/Maori Dictionary/dictionary.db"
app = Flask(__name__)

bcrypt = Bcrypt(app)
app.secret_key = "sefofe@#$%**jkvbuseb22BUJBBOPVIUBZPuboiserfbuso@#@##21ashjsrf77755kl%^$##"


# creates login page
@app.route("/login", methods=["GET", "POST"])
def render_login_page():
    if is_logged_in():
        return redirect("/")
    print(request.form)
    if request.method == "POST":
        # takes email input and strips it and makes it lowercase so it is consistent in the database.
        email = request.form["email"].strip().lower()
        # removes spaces at the end of the password that may have been inputted accidentally.
        password = request.form["password"].strip()
        # selects the id, first name and password from the Users table where the email has been entered.
        query = """SELECT id, f_name, password FROM users WHERE email = ?"""
        # creates a connection to the database.
        con = create_connection(DB_NAME)
        cur = con.cursor()
        # executes the query.
        cur.execute(query, (email,))
        user_data = cur.fetchall()
        # closes the database.
        con.close()
        # if the given email is not in the database this will raise an error.
        try:
            userid = user_data[0][0]
            firstname = user_data[0][1]
            db_password = user_data[0][2]
        except IndexError:
            return redirect("/login?error=" + urllib.parse.quote("Email invalid or password incorrect"))

        # check if the password is incorrect for that email address
        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + ("/login?error=" + urllib.parse.quote("Email invalid or "
                                                                                     "password incorrect")))

        session["email"] = email
        session["userid"] = userid
        session["firstname"] = firstname
        return redirect("/")

    return render_template('login.html', logged_in=is_logged_in())


# creates a signup page for creating accounts.
@app.route("/signup", methods=["GET", "POST"])
def render_signup_page():
    # checks if the user is logged in.
    if is_logged_in():
        # if the user is logged in, redirects to home page.
        return redirect("/")
    # retrieves information from HTML form about signing up.
    # Strips all inputs and gives names title case and makes email lower case.
    if request.method == "POST":
        print(request.form)
        f_name = request.form.get("f_name").strip().title()
        l_name = request.form.get("l_name").strip().title()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        password2 = request.form.get("password2")
        # checks if the passwords the user inputs matches to ensure they didn't make any mistakes.
        if password != password2:
            return redirect("/signup?error=" + urllib.parse.quote("Passwords don't match"))
        # for extra security, prevents users from having passwords that are fewer than 8 characters long.
        if len(password) < 8:
            return redirect("/signup?error=" + urllib.parse.quote("Password must be 8 characters or more"))
        # hashes password to ensure security.
        hashed_password = bcrypt.generate_password_hash(password)
        # connects to database
        con = create_connection(DB_NAME)
        # inserts users information into database.
        query = "INSERT INTO users (id, f_name, l_name, email, password) " \
                "VALUES(NULL,?,?,?,?)"

        cur = con.cursor()  # You need this line next
        try:
            cur.execute(query, (f_name, l_name, email, hashed_password))  # this line actually executes the query
        # Prevents duplicate emails from being entered.
        except sqlite3.IntegrityError:
            con.close()
            return redirect("/signup?error=" + urllib.parse.quote("Email is already used"))

        # commits new information to the database
        con.commit()
        con.close()
        return redirect("/login")
    # loads HTML for signup page.
    return render_template("signup.html", logged_in=is_logged_in())


# Creates logout page.
@app.route('/logout')
def logout():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect("/?message=" + urllib.parse.quote("See you next time!"))


# function that determines whether a user is logged in or not.
def is_logged_in():
    if session.get("email") is None:
        print("not logged in")
        return False
    else:
        print("logged in")
        return True


# function for creating connection to prevent repeating code.
def create_connection(db_file):
    """create a connection to the sqlite db - maori.db"""
    try:
        connection = sqlite3.connect(db_file)
        print(connection)
        return connection
    except Error as e:
        print(e)

    return None


# function for getting categories from database.
def fetch_categories():
    con = create_connection(DB_NAME)
    print(DB_NAME)
    print(con)
    # sorts by category name.
    query = "SELECT id, category_name FROM category order by category_name"
    cur = con.cursor()
    cur.execute(query)
    categories = cur.fetchall()
    con.close()
    return categories


# Creates home page where the add word and add category forms are located.
@app.route('/', methods=["GET", "POST"])
def render_homepage():
    if request.method == "POST" and is_logged_in():
        if request.form.get("form") == "category":
            category_name = request.form.get("category").strip().lower()
            # prevents categories with names shorter than
            if len(category_name) < 3:
                return redirect("/?error=" + urllib.parse.quote("Name must be at least 3 letters long."))
            else:
                # connect to the database
                con = create_connection(DB_NAME)
                # inserts new category to the database and lets database auto increment handle ID.
                query = "INSERT INTO category (id, category_name) VALUES(NULL, ?)"

                cur = con.cursor()  # You need this line next
                try:
                    cur.execute(query, (category_name,))  # this line actually executes the query
                # Prevents duplicate categories from being added to the database.
                except sqlite3.IntegrityError:
                    con.close()
                    return redirect("/?error=" + urllib.parse.quote("Category already exists"))

                con.commit()
                con.close()
            # urllib.parse.quote allows for messages in the URL that have spaces opposed to plus signs.
            return redirect("/?message=" + urllib.parse.quote("Thank you for creating a category!"))
        # gets information from form on the webpage, strips them of extra characters,
        # makes them lowercase and adds applies them to a variable which is called on by the query.
        if request.form.get('form') == 'word':
            maori_word = request.form.get('maori_word').strip().lower()
            english_word = request.form.get('english_word').strip().lower()
            definition = request.form.get('definition').strip().lower()
            category = request.form.get('category').strip()
            difficulty_level = request.form.get('difficulty_level').strip()
            # validates that the words/definitions are over a certain length and are within required ranges.
            status = validate_words(maori_word, english_word, definition, category, difficulty_level)
            # if validate_words returns blank everything is correct and so connects to the database and inserts.
            if status == "":
                # connect to the database
                con = create_connection(DB_NAME)
                # inserts words and word properties into the words table of the database.
                query = "INSERT INTO words (id, maori, english, category, definition, difficulty_level)" \
                        " VALUES(NULL, ?, ?, ?, ?, ?)"

                cur = con.cursor()  # You need this line next
                try:
                    cur.execute(query, (maori_word, english_word, category, definition,
                                        difficulty_level))  # this line actually executes the query
                    con.commit()
                except:
                    con.close()
                    return redirect("/menu?error=" + urllib.parse.quote("Unknown error"))

                con.close()

            return redirect("/?message=" + urllib.parse.quote("Thank you for adding a word"))

    return render_template('home.'
                           'html', logged_in=is_logged_in(), categories=fetch_categories())


# route for parts of the app concerning the deletion of categories and the lists of words within each category.
@app.route('/categories/<cat_id>', methods=["GET", "POST"])
def render_categories(cat_id):
    con = create_connection(DB_NAME)
    if request.method == "POST" and is_logged_in():
        query = "DELETE FROM category WHERE id = ?"
        cur = con.cursor()
        # deletes all words in a category before deleting the category itself. It does this through the use of a
        # foreign key. This must be turned on before each use.
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute(query, (cat_id,))
        con.commit()
        con.close()
        return redirect("/")
    query = "SELECT id, maori, english, definition, difficulty_level, images FROM words WHERE category=? " \
        # "ORDER BY maori_word ASC"
    cur = con.cursor()
    cur.execute(query, (cat_id,))
    definitions = cur.fetchall()
    con.close()
    return render_template('words.html', definitions=definitions, logged_in=is_logged_in(),
                           categories=fetch_categories())


# route that includes all details with words like difficulty level. It also allows for the removal and editing of words.
@app.route("/word/<word_id>", methods=["GET", "POST"])
def render_detail(word_id):
    con = create_connection(DB_NAME)
    query = "SELECT id, maori, english, definition, difficulty_level, images, category FROM words WHERE id=?"
    cur = con.cursor()
    cur.execute(query, (word_id,))
    definitions = cur.fetchall()
    definition = definitions[0]
    if request.method == "POST" and is_logged_in():
        # if request.form.get is equal to edit it means that someone wishes to edit the word opposed to deleting it.
        # this is important to include as the edit and delete forms are located on the same page and if they are
        # mixed up it could be a disaster.
        if request.form.get('form') == 'edit':
            maori_word = request.form.get('maori_word').strip().lower()
            english_word = request.form.get('english_word').strip().lower()
            definition = request.form.get('definition').strip().lower()
            category = request.form.get('category').strip()
            difficulty_level = request.form.get('difficulty_level').strip()
            # validates words using validate_words function
            status = validate_words(maori_word, english_word, definition, category, difficulty_level)
            # if status supplied by verification function is blank then no errors were found so it continues.
            if status == "":
                # updates the database with new information, overwriting the old information.
                query = "UPDATE words SET maori = ?, english = ?, definition = ?, " \
                        " category = ?, difficulty_level = ? WHERE id = ?"
                cur = con.cursor()
                cur.execute(query, (maori_word, english_word, definition, category,
                                    difficulty_level, word_id))
                con.commit()
            else:
                con.close()
                return redirect(status)
            # closes the connection to the database
            con.close()
            # redirects you to the new location of the word within the database/website.
            return redirect("/word/" + word_id)
        # ensures that the form being submitted is the correct form so you don't edit the form when you wish to
        # delete it
        elif request.form.get('form') == 'delete':
            query = "DELETE FROM words WHERE id = ?"
            cur = con.cursor()
            cur.execute(query, (word_id,))
            con.commit()
            con.close()
            return redirect("/categories/" + str(definition[6]))
    con.close()

    return render_template('detail.html', definition=definition, logged_in=is_logged_in(),
                           categories=fetch_categories())


# function that validates words and provides error codes for the URL if there is a problem.
# urllib.parse.quote allows for spaces to be put into the URL.
# min_length is the minimum length for the words and definition.
# This allows for the minimum length to be changed easily.
def validate_words(maori_word, english_word, definition, category, difficulty_level):
    min_length = 2
    if len(maori_word) < min_length:
        return "/?error=" + urllib.parse.quote("Word name must be at least " + str(min_length) + " letters long.")
    elif len(english_word) < min_length:
        return "/?error=" + urllib.parse.quote("Word name must be at least " + str(min_length) + " letters long.")
    elif len(definition) < min_length:
        return "/?error=" + urllib.parse.quote(
            "definition must be at least " + str(min_length) + " letters long.")
    elif not category.isnumeric():
        # This error can only occur if someone tampers with the HTML so I added a humorous error.
        return "/?error=" + urllib.parse.quote("Get out of my HTML.")
    elif not difficulty_level.isnumeric() and 1 > int(difficulty_level) > 10:
        return "/?error=" + urllib.parse.quote("Difficulty must be between 1 and 10.")

    else:
        return ""


if __name__ == '__main__':
    app.run(debug=True)
