import psycopg2
import os
from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "clave_insegura")


# -------------------------------------------
# FUNCIÓN PARA OBTENER CONEXIÓN A POSTGRESQL
# -------------------------------------------
def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    return conn


# -------------------------------------------
# RUTA DE REGISTRO
# -------------------------------------------
@app.route("/", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        primer_nombre = request.form.get("primer_nombre")
        segundo_nombre = request.form.get("segundo_nombre")
        primer_apellido = request.form.get("primer_apellido")
        segundo_apellido = request.form.get("segundo_apellido")
        correo = request.form.get("correo")
        contraseña = request.form.get("contraseña")
        contraseña2 = request.form.get("contraseña2")
        fecha_nacimiento = request.form.get("fecha_nacimiento")
        rol = request.form.get("rol")

        # Validaciones
        if not (primer_nombre and primer_apellido and correo and contraseña and contraseña2 and fecha_nacimiento and rol):
            flash("Completa todos los campos obligatorios")
            return redirect("/")

        if contraseña != contraseña2:
            flash("Las contraseñas no coinciden")
            return redirect("/")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verificar si el correo ya existe
        cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
        existente = cursor.fetchone()

        if existente:
            flash("Este correo ya está registrado.")
            cursor.close()
            conn.close()
            return redirect("/iniciosesion")

        # Encriptar contraseña
        hash_pw = generate_password_hash(contraseña)

        # Insertar usuario nuevo
        cursor.execute(
            """
            INSERT INTO usuarios (
                primer_nombre, segundo_nombre, primer_apellido, segundo_apellido,
                correo, contraseña, fecha_nacimiento, rol
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (primer_nombre, segundo_nombre, primer_apellido, segundo_apellido,
            correo, hash_pw, fecha_nacimiento, rol)
        )
        conn.commit()

        cursor.close()
        conn.close()

        flash("Registro exitoso. Inicia sesión.")
        return redirect("/iniciosesion")

    return render_template("registro.html")


# -------------------------------------------
# RUTA DE INICIO DE SESIÓN
# -------------------------------------------
@app.route("/iniciosesion", methods=["GET", "POST"])
def iniciosesion():
    if request.method == "POST":
        correo = request.form.get("correo")
        contraseña = request.form.get("contraseña")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT contraseña, rol FROM usuarios WHERE correo = %s", (correo,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user:
            flash("Correo incorrecto")
            return redirect("/iniciosesion")

        hashed_pw = user[0]
        rol = user[1]

        if not check_password_hash(hashed_pw, contraseña):
            flash("Contraseña incorrecta")
            return redirect("/iniciosesion")

        # Guardar sesión
        session["usuario"] = correo
        session["rol"] = rol

        # 🚀 Redirección inmediata según el rol
        if rol == "Estudiante":
            return redirect("/estudiante")
        elif rol == "Profesor":
            return redirect("/profesor")
        elif rol == "Administrador":
            return redirect("/admin")

    return render_template("iniciosesion.html")


# -------------------------------------------
# RUTAS PARA CADA ROL
# -------------------------------------------
@app.route("/estudiante")
def estudiante():
    if "usuario" not in session or session.get("rol") != "Estudiante":
        return redirect("/iniciosesion")
    return render_template("estudiante.html")


@app.route("/profesor")
def profesor():
    if "usuario" not in session or session.get("rol") != "Profesor":
        return redirect("/iniciosesion")
    return render_template("profesor.html")


@app.route("/admin")
def admin():
    if "usuario" not in session or session.get("rol") != "Administrador":
        return redirect("/iniciosesion")
    return render_template("admin.html")


# -------------------------------------------
# CERRAR SESIÓN
# -------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/iniciosesion")


# -------------------------------------------
# EJECUCIÓN
# -------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
