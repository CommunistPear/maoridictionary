from flask import Flask, render_template
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DB_NAME = "dictionary.db"
app = Flask(__name__)


def create_connection(db_file):
    # creates connection to database
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)


# def get_words():
#     con = create_connection(DB_NAME)
#     query = "SELECT id, words" \
#             " FROM Insert ORDER BY * ASC"
#     cur = con.cursor()  # You need this line next
#     cur.execute(query)  # this line actually executes the query
#     class_list = cur.fetchall()  # puts the results into a list usable in python
#    con.close()
#    return class_list


@app.route('/')
def render_home():
    return render_template('home.html')


if __name__ == '__main__':
    app.run()
