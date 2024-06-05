from db_init import db
import bcrypt


class UserDetails(db.Model):
    __tablename__ = 'user_details'
    id = db.Column(db.Integer, db.Sequence('user_id_seq'), primary_key=True, autoincrement=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(64), nullable=False)

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(128), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_name = db.Column(db.String(256), nullable=False)

    def __init__(self, name, price, image_name):
        self.name = name
        self.price = price
        self.image_name = image_name