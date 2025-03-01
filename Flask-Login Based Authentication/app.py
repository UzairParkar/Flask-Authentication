from flask import Flask, request, jsonify
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user,UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)

db = SQLAlchemy()
login_manager = LoginManager()
ma = Marshmallow()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    _password = db.Column(db.String(120), nullable=False)

    @property
    def password(self):
        raise AttributeError('Cannot View Passord in Plain Text')
    
    @password.setter
    def password(self,password):
        self._password = generate_password_hash(password)
    
    def verify_password(self,password):
        return check_password_hash(self._password,password)
    



class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True

user_schema = UserSchema()
users_schema = UserSchema(many = True)

    



def create_app():
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'ahiddenkey'
    db.init_app(app)
    ma.init_app(app)
    login_manager.init_app(app)
    with app.app_context():
        db.create_all()

    return app



@app.route('/register',methods = ['POST'])
def register():
    data = request.get_json()
    user = User(
        username = data.get('username'),
        email = data.get('email')
    )
    user.password = data.get('password')
    db.session.add(user)
    db.session.commit()
    return jsonify({"Message":'registration successfull'}), 200

@app.route('/g',methods = ['GET'])
def get_users():
    users = User.query.all()
    return jsonify(users_schema.dump(users)),200



@app.route('/login',methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    password = data.get('password')

    if not user or not user.verify_password(password):
        return jsonify({"Message":"Invalid credentials"}), 403
    
    login_user(user)
    return jsonify({"Message":'Logged in successfully'}),200


@app.route('/logout',methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"Message":"LOgged out successfully"}), 200

if __name__ == '__main__':
    create_app()
    app.run(debug=True)

