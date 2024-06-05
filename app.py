"""
Module docstring: This module provides functionality
for Cellmart wesite developed using flask.
"""
import re
import json
import logging
import os

from datetime import datetime
from flask import Flask, request, redirect, url_for, session
from flask import render_template
from db_init import create_app
from db_init import db
from model import UserDetails, Product

app = create_app(os.getenv("CONFIG_MODE"))

app.secret_key = '12345678'


@app.route('/')
# ‘/’ URL is bound with home() function.
def home():
    """
    Render the home page.

    This function checks whether the user is logged in or not. If the user is logged in,
    it returns the index.html template with the username of the logged-in user.

    Returns:
        A rendered template of 'index.html' with the username if the user is logged in,
        otherwise, the template without the username.
    """
    products = get_all_products()
    # check whether user is logged or not
    if 'user' in session:
        return render_template('index.html', username=session[
            'user']['name'], products=products)  # return index.html with username of logged user

    return render_template('index.html', products=products)

@app.route('/login')
# ‘/login’ URL is bound with login() function.
def login():
    """
    Render the login page.

    Thisfunction chceks whether the user is already logged-in. If user is logged in,
    it redirects them to cart page.If the user arrived at the login page after registration,
    they will see a registration success message.

    Returns:
        A rendered template of 'login.html'. If the user is logged in, it may also redirect
        them to the cart page. If the user arrived after registration,
        they will see a success message.
    """
    # check whether user is logged or not
    if 'username' in session:
        return redirect(url_for('cart'))  # redirect to cart page if user is already logged
    registered = request.args.get('registered')  # get registered url parameter
    error_msg = request.args.get('error_msg')  # get registered url parameter

    #  if user landed to loging page after registraion, user will see a regisration success message
    if registered:
        return render_template('login.html',
                success_message='You have successfully been registered. please login...')
    if error_msg:
        return render_template('login.html',
                error_message=error_msg)
    return render_template('login.html')

@app.route('/register', methods=['GET'])
# ‘/register’ URL is bound with register() function.
def register():
    """
    Render the registrtion page.

    This function checks whether the user is already logged in. If the usr is logged in,
    it redirects them to the cart page. If the user is not logged in, it renders registration
    page where the user can signup for a account.

    Returns:
        A rendered template of 'register.html'. If the user is already logged in,
        it may also redirect
        them to the cart page.
    """
    # check whether user is logged or not
    if 'user' in session:
        return redirect(url_for('home'))  # redirect to cart page if user is already logged
    #  return registration page tp the user if user has no any active sessions
    return render_template('register.html')


@app.route('/register', methods=['POST'])
# ‘/register’ URL is bound with register_action() function.
def register_action():
    """
    Register new user.

    This function receives a POST request with user registration data,
    including name, email, and password. It checks if the provided
    email already exists in the system and, if the password
    meets the complexity requirements. If all checks pass, the user
    details are stored in DB for registration completion.
    If there are any errors, such as duplicate username/email or
    invalid password,a appropriate errr message displayes.

    Returns:
        - If successful, it redirects to login page with a success message.
        - If there are errors in registration request, renders
          registration pagewith appropriate eror messages.
    """
    #  get name, email and password which are submitted by user
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    error_message = None

    # check if passwords do not match
    if password != confirm_password:
        error_message = 'passwords do not match!'

    # check if email is already is registered in the system
    elif is_email_exist(email):
        error_message = 'email already exists!'

    # Check password complexity
    elif not is_valid_password(password):
        error_message = ('Password must be at least 12 characters long and contain at least '
                         '1 uppercase, 1 lowercase, 1 number, and 1 special character')

    # if there is an error in the registration request, return error message
    if error_message is not None:
        return render_template('register.html', error_message=error_message, email=email,
                               name=name)

    # if there is no any errors, Store user details in DB to complte the registration
    user_details = UserDetails(name=name, email=email, role='user')
    user_details.set_password(password)
    db.session.add(user_details)
    db.session.commit()

    # Redirect to login page with success message
    return redirect(url_for('login', registered=True))


# this method check if email already exists
def is_email_exist(email):
    """
    Check if email already exists in DB

    Args:
        email (str):  email address to check for existence in fil.

    Returns:
        bool: True if the email already exists,if not False .
    """
    existing_user = db.session.query(UserDetails).filter_by(email=email).first()
    return existing_user is not None


# this function validates password complexity
def is_valid_password(password):
    """
    Validate password complexity.

    This function checks whether the given password meet required complexity criteria:
    - At least 12 characters long
    - Contains at least 1 lowercase letter
    - Contains at least 1uppercase letter
    - Contains at least 1 digit
    - Contains at least 1 special character

    Args:
        password (str): The password to validate.

    Returns:
        bool: Trueif, the password meets the complexity criteria, False otherwise.
    """
    # validate length
    if len(password) < 12:
        return False
    # check for lowercase charactor
    if not re.search("[a-z]", password):
        return False
    # check for uppercase charactor
    if not re.search("[A-Z]", password):
        return False
    # check for a number
    if not re.search("[0-9]", password):
        return False
    # check for a special charactor
    if not re.search("[!@#$%^&*()_+=]", password):
        return False
    return True
    """
    Checks if email already exist in user_details.txt.

    Args:
        email (str):  email to check for existence.

    Returns:
        bool: True if the email already exists,not False.
    """
    with open('user_details.txt', 'r', encoding='utf-8') as user_details_file:
        for line in user_details_file:
            user, email_db, _ = line.strip().split(',')
            if email_db == email:
                return True
    return False


def get_product_by_id(product_id):
    return db.session.query(Product).get(product_id)


def get_all_products():
    return db.session.query(Product).all()


if __name__ == '__main__':
    app.run()