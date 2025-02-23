import jwt
from flask import Flask, request, jsonify, session, make_response
from flask_marshmallow import Marshmallow
from marshmallow import fields, validate, Schema
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] ='asecretkey'

db = SQLAlchemy(app)
ma = Marshmallow(app)

class User(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    username = db.Column(db.String(50),unique = True,nullable = False)
    _password = db.Column(db.String(50),nullable = True)
    notes = db.relationship('Note',backref = 'user',lazy = True)

    @property
    def password(self):
        return AttributeError('Cannot View Password in plain text')
    
    @password.setter
    def password(self,password):
        self._password = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self._password,password)
    

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)



class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True, validate=validate.Length(min=1))
    password = fields.Str(required=True, validate=validate.Length(min=1),load_only=True)



class NoteSchema(Schema):
    id = fields.Int(dump_only=True)
    title = fields.Str(required=True, validate=validate.Length(min=1))
    content = fields.Str(required=True, validate=validate.Length(min=1))
    user_id = fields.Int(required=False)


user_schema = UserSchema()
users_schema = UserSchema(many=True)
note_schema = NoteSchema()
notes_schema = NoteSchema(many = True)


# with app.app_context():
#     db.create_all()

def token_required(f):
    @wraps(f)
    def decorateed(*args,**kwargs):
        token = None
        token = request.cookies.get('current_user')

        if not token:
            return jsonify({"message":"token is missing"}), 401
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'],options=None)
            current_user = User.query.filter_by(id = data['id']).first()


            if not current_user:
                return jsonify({"Message": "Invalid token"}), 401
            

        except jwt.ExpiredSignatureError:
            return ({"Message":"token has expired"}), 401
        
        except Exception as e:
            return jsonify({"Message":str(e)}),401
        
        return f(current_user,*args,**kwargs)
    

    return decorateed

@app.route('/signup',methods=['POST'])
def signup():
    data = request.get_json()
    errors = user_schema.validate(data)
    euser = User.query.filter_by(username = data['username']).first()
    if euser:
        return jsonify({"Message":"Choose another Username"}), 401
    
    if errors:
        return jsonify(errors),400
    
    password  = data['password']
    if len(password) < 8:
        return jsonify({"Message":"Password must be at least 8 characters long"}), 400
    
    if not any(char.islower() for char in password):
        return jsonify({'message': 'Password must contain at least one lowercase letter'}), 400
    
    if not any(char.isupper() for char in password):
        return jsonify({'message': 'Password must contain at least one uppercase letter'}), 400
    
    if not any(char.isdigit() for char in password):
        return jsonify({'message': 'Password must contain at least one number'}), 400
    
    if not any(char in '@#$%^&+=' for char in password):
        return jsonify({'message': 'Password must contain at least one special character @#$%^&+='}), 400
    
    new_user = User(**data)
    new_user.password = data['password']
    db.session.add(new_user)
    db.session.commit()

    return user_schema.dump(new_user),200



@app.route('/login',methods = ['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"Message":'Credentials are required to login'}) ,401
    
    user = User.query.filter_by(username = data['username']).first()
    
    if not user:
        return jsonify({"Message":"User Not Found."}), 404
    
    if not user or not user.verify_password(password):
        return jsonify({"Message":"Invalid Credentials"}), 401
    
    session['user_id'] = user.id
    token = jwt.encode ({'id':user.id,'exp':datetime.utcnow() + timedelta(minutes=5)},app.config['SECRET_KEY'],algorithm='HS256')
    response = make_response(token)
    response.set_cookie(
        'current_user', token, secure= app.config.get("SECURE_COOKIE")
    )
    return response, 200

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.cookies.get('current_user')
    if not token:
        return jsonify({"message":"login first"})
    
    session.pop('user_id',None)
    response  = make_response(jsonify({'message':"Logout Successful"}))
    response.set_cookie('current_user',"",expires=0)
    return response, 200


@app.route('/dashboard',methods = ['GET'])
@token_required
def dashboard(current_user):
    user_details = User.query.get(current_user.id)
    user_notes = Note.query.filter_by(user_id = current_user.id).all()
    notes = notes_schema.dump(user_notes)
    return jsonify({"WELCOME":user_details.username,
                    "Your Notes": notes}), 200


@app.route("/create",methods = ['POST'])
@token_required
def create_note(current_user):
    data = request.get_json()
    errors = note_schema.validate(data)

    if errors:
        return jsonify(errors),400
    
    new_note = Note(
        title = data['title'],
        content = data['content'],
        user_id = current_user.id
    )
    db.session.add(new_note)
    db.session.commit()
    return note_schema.dump(new_note), 201

@app.route('/delete/<int:id>',methods = ['DELETE'])
@token_required
def delete_note(current_user,id):
    note = Note.query.filter_by(id = id,user_id = current_user.id).first()
    if not note:
        return jsonify({"Message":"Note Not Found"}), 404
    db.session.delete(note)
    db.session.commit()

    return jsonify({'message':"Note deleted successfully"}), 200
    
if __name__ == '__main__':
    app.run(debug=True)



        
