from flask import Flask, render_template, request, redirect, session, flash

app = Flask(__name__)
app.secret_key = "clave_secreta"
# Almacenamiento en memoria de usuarios registrados (temporal, reinicia al reiniciar app)
users = {}


@app.route("/", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre")
        correo = request.form.get("correo")
        contrasenia = request.form.get("contraseña")
        contrasenia2 = request.form.get("contraseña2")

        # Validaciones básicas
        if not (nombre and correo and contrasenia and contrasenia2):
            flash("Por favor completa todos los campos")
            return redirect("/")

        if contrasenia != contrasenia2:
            flash("Las contraseñas no coinciden")
            return redirect("/")

        if correo in users:
            flash("El correo ya está registrado. Inicia sesión o usa otro correo.")
            return redirect("/iniciosesion")

        # Guardar usuario en memoria y redirigir al inicio de sesión
        users[correo] = {"nombre": nombre, "contraseña": contrasenia}
        flash("Registro exitoso. Por favor inicia sesión.")
        return redirect("/iniciosesion")

    return render_template("registro.html")


@app.route("/iniciosesion", methods=["GET", "POST"])
def iniciosesion():
    if request.method == "POST":
        correo = request.form.get("correo")
        contrasenia = request.form.get("contraseña")

        user = users.get(correo)
        if user and user.get("contraseña") == contrasenia:
            session["usuario"] = correo
            flash("Inicio de sesión exitoso")
            return redirect("/inicio")

        flash("Correo o contraseña incorrectos")
        return redirect("/iniciosesion")

    return render_template("iniciosesion.html")


@app.route("/inicio")
def inicio():
    usuario = session.get("usuario")
    return render_template("inicio.html", usuario=usuario)


@app.route("/logout")
def logout():
    session.pop("usuario", None)
    flash("Sesión cerrada")
    return redirect("/iniciosesion")


if __name__ == "__main__":
    app.run(debug=True)
