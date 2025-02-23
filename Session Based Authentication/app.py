from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow import Schema, fields, validate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=59)

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
    user_id = db.Column(db.Integer,db.ForeignKey('user.id',ondelete="CASCADE"))
    user_note_id = db.Column(db.Integer, nullable=False) 

    
class NoteSchema(Schema):
    content = fields.Str(required=True)
    user_note_id = fields.Int(dump_only=True)

class Userschema(Schema):
    id = fields.Int(dump_only=True)
    name = fields.Str(required = False,validate=validate.Length(min=1))
    age = fields.Int(required = True)
    username = fields.Str(required=True,validate=validate.Length(min=5))
    password = fields.Str(required=True,validate=validate.Length(min=8),load_only=True)
    notes = fields.Nested(NoteSchema,many=True,exclude=('user_id',))


user_schema = Userschema()
users_schema = Userschema(many= True)

note_schema = NoteSchema()
notes_schema = NoteSchema(many=True)

# with app.app_context():
#     db.create_all()

@app.route('/signup',methods=['POST'])
def signup():
    data = request.get_json()
    errors = user_schema.validate(data)

    user = User.query.filter_by(username = data['username']).first()
    if user:
        return jsonify({"Message":"Choose a different Username"}),401
    if errors:
        return jsonify(errors),400
    
    new_user = User(
        name = data['name'],
        age = data['age'],
        username = data['username']
    )



    new_user.set_password = data['password']
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message':"User created Sucessfully"}), 201

@app.route('/login',methods =['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"message":"Could not verify"}),401
            
    user = User.query.filter_by(username = data['username']).first()
    if not user:
        return jsonify({"Message":"User Not found -- Try Signing Up"}),404
    
    if not user or not user.verify_password(password):
        return jsonify({"Message":"Invalid Credentials"}),404
    
    session['user_id'] = user.id

    return jsonify({"Message":'Logged in successfully'}), 200
    
@app.route('/logout',methods=['POST'])
def logout():
    session.pop('user_id',None)
    session.pop('last_activity',None)
    return jsonify({'Message':"Logged out successfully"}),200

@app.route('/dashboard',methods=['GET'])
def dashboard():
    
    if 'user_id' not in session:
        return jsonify({"Message":"Login to access this route"}),401

    
    else:
        notes = Note.query.filter_by(user_id = session['user_id']).all()
        return notes_schema.dump(notes), 200

    


@app.route("/create",methods=['POST'])
def createNote():
    
    if 'user_id' not in session:
        return jsonify({"message":"Login to access this route"}) , 401
    
    user_note_count = Note.query.filter_by(user_id=session['user_id']).count()
    

    ddata = request.get_json()
    ddata['user_id'] = session['user_id']
    ddata['user_note_id'] = user_note_count + 1
    note = Note(**ddata)
    db.session.add(note)
    db.session.commit()
    return note_schema.dump(note), 200



if __name__ == '__main__':
    app.run(debug=True)
