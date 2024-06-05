from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from config import config

db = SQLAlchemy()


def create_app(config_mode):
    app = Flask(__name__)
    app.config.from_object(config[config_mode])
    migrate = Migrate(app, db)
    db.init_app(app)

    with app.app_context():
        # Create the database and the table
        db.create_all()

    return app
