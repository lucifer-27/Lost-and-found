from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
import re
#hello
app = Flask(__name__, static_folder="static")

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ansh*270406",
        database="LostAndFound"
    )

@app.route("/", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        if not re.match(r".+@college\.edu$", email):
            error = "Use your college email ID"
            return render_template("index.html", error=error)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT role FROM users WHERE email=%s AND password=%s AND role=%s",
            (email, password, role)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            if role == "student":
                return redirect(url_for("student"))
            elif role == "staff":
                return redirect(url_for("staff"))
            elif role == "admin":
                return redirect(url_for("admin"))
        else:
            error = "Invalid email, password, or role"

    return render_template("index.html", error=error)

@app.route("/student")
def student():
    return "<h1>Student Dashboard</h1>"

@app.route("/staff")
def staff():
    return "<h1>Staff Dashboard</h1>"

@app.route("/admin")
def admin():
    return "<h1>Admin Dashboard</h1>"

if __name__ == "__main__":
    app.run(debug=True)
