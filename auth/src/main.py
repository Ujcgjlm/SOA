import os

from flask import Flask, request
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI")
app.config["JWT_SECRET_KEY"] = os.environ.get("SECRET_KEY")

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(240), nullable=False)

    first_name = db.Column(db.String(120), nullable=True)
    last_name = db.Column(db.String(120), nullable=True)
    birth_date = db.Column(db.Date, nullable=True)
    email = db.Column(db.String(120), nullable=True, unique=True)
    phone_number = db.Column(db.String(20), nullable=True, unique=True)

    def check_password(self, password):
        return check_password_hash(self.password, password)


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return {"error": "Data not valid"}, 400

    user = User.query.filter_by(username=username).first()
    if user:
        return {"error": "Username already exists"}, 400

    new_user = User(username=username, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()

    return {"msg": "User created"}, 200


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return {"error": "Data not valid"}, 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return {"error": "Invalid credentials"}, 400

    token = create_access_token(identity=str(user.id))
    return {"token": token}, 200


@app.route("/users/me", methods=["PATCH"])
@jwt_required()
def update():
    current_user_id = get_jwt_identity()

    user = User.query.get(current_user_id)
    if not user:
        return {"error": "User not found"}, 404

    data = request.get_json()

    user.first_name = data.get("first_name", user.first_name)
    user.last_name = data.get("last_name", user.last_name)
    user.birth_date = data.get("birth_date", user.birth_date)
    user.email = data.get("email", user.email)
    user.phone_number = data.get("phone_number", user.phone_number)

    db.session.commit()

    return {"msg": "Details updated"}, 200


if __name__ == "__main__":
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
