from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
import re

app = Flask(__name__)

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ansh*270406",
        database="lostfound"
    )

@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        # Basic college email validation
        if not re.match(r".+@college\.edu$", email):
            error = "Use your college email ID"
            return render_template("login.html", error=error)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE email=%s AND password=%s",
            (email, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            return redirect(url_for("home"))
        else:
            error = "Invalid email or password"

    return render_template("login.html", error=error)

@app.route("/home")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True)
