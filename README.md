# Database-project
# Mobile Market Website Project

This project is a web application for an e-commerce website named Mobile Market, developed using the Flask framework and Postgres Database. The application provides users with functionalities such as user registration, login, viewing and ordering products, and updating passwords. It also includes logging of failed login attempts.

## Features

```
User Registration
Login
Home Page with Product Listings
Checkout
Viewing Order History
Updating Password
User Logout
Logging of Failed Login Attempts
Remember username on login page
```

## Installation and Setup

### Prerequisites

```
Python 3.x
pip (Python package installer)
```

### Create a virtual environment:

```
python3 -m venv venv
source venv/bin/activate   # On Windows, use `venv\Scripts\activate`
```

### Install the required packages:

```
pip install -r requirements.txt
```

### Set up environment variables:

```
CONFIG_MODE=development
DEVELOPMENT_DATABASE_URL='postgresql://postgres:1234@localhost:5432/postgres'
PRODUCTION_DATABASE_URL=
```

### Run the application:

```
Run the application:
```
