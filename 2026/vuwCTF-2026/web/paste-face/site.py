import json
import sandbox
import argon2
import base64
from flask import Flask, render_template, request, abort, session, url_for, redirect, make_response
import requests
import os

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024
app.secret_key = os.environ.get("SESSION_SECRET_KEY", "dev")

hasher = argon2.PasswordHasher()

def wrap_test_results(test_results):
    try:
        app.logger.error(json.dumps(test_results))
        if len(test_results) != len(sandbox.test_sentences):
            return None
    except Exception as e:
        app.logger.error(e)
        return None

    return {sentence: results for sentence, results in zip(sandbox.test_sentences, test_results)}

@app.get("/pastes/<int:id>/")
def get_paste(id: int):
    try:
        paste_info = requests.get(f"http://localhost:9999/pastes/{id}").json()
        name, description, username = paste_info["name"], paste_info.get("description"), paste_info["username"]
        test_results = paste_info.get("test_results")
        test_errors = paste_info.get("test_errors")

        # app.logger.error(f"{test_results=}, {type(test_results)=}")
    except Exception as _:
        abort(404)
    return render_template("paste.html", id=id, name=name, description=description, username=username, test_results=wrap_test_results(test_results), test_errors=test_errors)

@app.get("/pastes/<int:id>/data/")
def get_paste_data(id: int):
    resp = requests.get(f"http://localhost:9999/pastes/{id}/data")
    try:
        out = make_response((resp.iter_content(), resp.status_code, resp.headers))
        return out
    except Exception as _:
        abort(500 if resp.ok else resp.status_code)

@app.post("/pastes/")
def post_paste():
    try:
        name = request.form["name"]
        description = request.form.get("description")
        if "paste.model" in request.files:
            model = request.files["paste.model"].read(1024)
        else:
            model = request.form["model"].encode()
    except Exception as _:
        abort(400)
    sandbox_response = requests.post("http://localhost:9998/test", data=model)
    test_results = None
    try:
        if sandbox_response.ok:
            test_results = sandbox_response.json()
    except Exception as _:
        pass

    db_data = {"name": name, "model": base64.b64encode(model).decode('ascii')}
    if description is not None:
        db_data["description"] = description
    if test_results is not None:
        db_data["test_results"] = test_results
    if not sandbox_response.ok:
        db_data["errors"] = sandbox_response.content.decode()

    db_response = requests.post("http://localhost:9999/pastes/", json=db_data)
    db_id = int(db_response.content.decode())

    return redirect(url_for("get_paste", id=db_id))

@app.get("/users/")
def get_users():
    resp = requests.get("http://localhost:9999/users/")
    if resp.ok:
        return resp.iter_content()
    else:
        abort(resp.status_code)

@app.get("/users/<username>")
def get_user(username: str):
    resp = requests.get(f"http://localhost:9999/users/{username}/pastes")
    pastes = resp.json()
    if not isinstance(pastes, list):
        return 500
    return render_template("user.html", username=username, pastes=pastes)

@app.post("/users/login")
def process_login():
    try:
        user_info = request.form
        username = user_info["username"]
        password = user_info["password"]
    except Exception as _:
        return ({"message": "Failed to authenticate"}, 400)
    resp = requests.get(f"http://localhost:9999/users/{username}/password").json()
    try:
        hasher.verify(resp["password"], password)
    except Exception as _:
        return ({"message": "Failed to authenticate"}, 400)

    session["user"] = username
    return redirect(url_for("index"))

@app.get("/users/login")
def login():
    if "user" in session:
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/users/logout", methods=["GET", "POST"])
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

@app.get("/admin/")
def admin():
    if session.get("user") != "admin":
        return ({"message": "Failed to authorise access to /admin/"}, 400)
    return {"flag": os.environ.get("FLAG", "VuwCTF{XXXXXXXXXXXXXXX}")}

# TODO: (17/03/2019): Add support for registration and password updates
# It's already implemented in the db so it should be pretty easy, just a few requests to the API ^-^
# I think registration should just be a POST request but I'm a bit worried as it stands...

@app.route("/")
def index():
    resp = requests.get("http://localhost:9999/pastes/")
    pastes = resp.json()
    return render_template("index.html", pastes=pastes)

if __name__ == "__main__":
    app.run("0.0.0.0", 9967)
