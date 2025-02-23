from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, validate
from functools import wraps
import jwt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer,primary_key =True)
    name = db.Column(db.String(255),nullable = False)
    age = db.Column(db.Integer,nullable = True)
    username = db.Column(db.String(255),nullable = False)
    _password = db.Column(db.String(255),nullable = False)
    notes = db.relationship('Note',backref = 'user')
    
    @property
    def password(self):
        return AttributeError('Cannot View Password in plain text')
    
    @password.setter
    def set_password(self,password):
        self._password = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self._password,password)
    
class Note(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    content  = db.Column(db.String(255),nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    
class NoteSchema(Schema):
    id = fields.Int(dump_only = True)
    content = fields.Str(required=True)

class Userschema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required = False,validate=validate.Length(min=1))
    age = fields.Int(required = True)
    username = fields.Str(required=True,validate=validate.Length(min=5))
    password = fields.Str(required=True,validate=validate.Length(min=8),load_only=True)


user_schema = Userschema()
users_schema = Userschema(many= True)

note_schema = NoteSchema()
notes_schema = NoteSchema(many=True)

with app.app_context():
    db.create_all()

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers.get('x-access-token')

        if not token:
            return jsonify({"message":'Token is missing.'}), 401

        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
            current_user = User.query.filter_by(id = data['user_id']).first()

            if not current_user:
                return jsonify({"Message": "Invalid token"}), 401

            session['user_id'] = current_user.id
        except jwt.ExpiredSignatureError:
            return jsonify({"Message":"Token has expired"}), 401

        except jwt.InvalidTokenError:
            return jsonify({"Message":"Token is Invalid"}), 403 

        return f(current_user,*args,**kwargs)

    return decorated



@app.route('/signup',methods=['POST'])
def signup():
    data = request.get_json()
    errors = user_schema.validate(data)


    euser = User.query.filter_by(username = data['username']).first()
    if euser:
        return jsonify({'Message':"Choose another Username"}),401

    if errors:
        return jsonify(errors), 400

    new_user = User(
        name = data['name'],
        age = data['age'],
        username = data['username']
    )

    new_user.set_password = data['password']
    db.session.add(new_user)
    db.session.commit()

    return user_schema.dump(new_user), 200


@app.route('/login',methods = ['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get("password")

    if not username or not password:
        return jsonify({"Message":"Username and password are required fields."}), 401

    user = User.query.filter_by(username = data['username']).first()

    if not user:
        return jsonify({"Message":"User not Found"}), 404

    if not user or not user.verify_password(password):
        return jsonify({"Message":"Invalid credentials"}), 401

    

    if user and user.verify_password(password):
        token = jwt.encode({"user_id":user.id, "exp": datetime.utcnow() + timedelta(minutes = 5)},app.config['SECRET_KEY'],algorithm = 'HS256')
        response = {"Message":'Logged in successfully', 'token':token}
        session['user_id'] = user.id

        return jsonify(response),200

@app.route('/dashboard',methods=['GET'])
@token_required
def dashboard(current_user):
    user_notes = Note.query.filter_by(user_id = current_user.id).all()
    notes = notes_schema.dump(user_notes)
    return jsonify({
        "username": current_user.username,
        "notes": notes
    }),200


@app.route('/createanote',methods=['POST'])
@token_required
def createnote(current_user):
    data = request.get_json()
    errors = note_schema.validate(data)
    if errors:
        return jsonify(errors),400


    new_note = Note(
        content=data['content'],
        user_id=current_user.id
    )
    
    db.session.add(new_note)
    db.session.commit()

    return note_schema.dump(new_note), 201


@app.route('/updatenote/<int:note_id>',methods = ['PUT'])
@token_required
def updatenote(current_user,note_id):
    note =  Note.query.filter_by(id = note_id,user_id  = current_user.id).first()

    if not note:
        return jsonify({"Message":"Note Doesnt exist"}), 404

    data = request.get_json()
    errors = note_schema.validate(data)

    if errors:
        return jsonify(errors), 400

    note.content = data['content']
    db.session.commit()

    return note_schema.dump(note), 200


@app.route('/delnote/<int:note_id>',methods =['DELETE'])
@token_required
def deletenote(current_user, note_id):
    note = Note.query.filter_by(id = note_id,user_id  = current_user.id).first()

    if not note:
        return jsonify({"Message":"Note Not found"}), 404


    db.session.delete(note)
    db.session.commit()

    return jsonify({'Message':"Note deleted Successfully"}), 200




@app.route('/logout',methods = ['POST'])
@token_required
def logout(current_user):
    session.pop('user_id', None)
    token = request.headers.get('x-access-token')
    if token:
        token = None

    return jsonify({"Message":"Logged Out succesfully"}), 200












if __name__ == '__main__':
    app.run(debug=True)









