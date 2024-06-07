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


class OrderDetails(db.Model):
    __tablename__ = 'order_details'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.Integer, db.ForeignKey('user_details.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    delivery_address = db.Column(db.String(256), nullable=False)
    product_name = db.Column(db.String(128), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    total = db.Column(db.Float, nullable=False)

    def __init__(self, username, product_id, delivery_address, product_name, quantity, price, total):
        self.username = username
        self.product_id = product_id
        self.delivery_address = delivery_address
        self.product_name = product_name
        self.quantity = quantity
        self.price = price
        self.total = total
