# Intranet System

CS 2660 Final Project - A simple login system with different user levels.

## What It Does

This website lets users:
- Create accounts with secure passwords
- Log in securely
- See different options based on their access level
- Admins can manage other users

## Setup

1. Make sure you have Python installed
2. Install Flask: `pip install flask`
3. Run the program: `python app.py`
4. Go to http://127.0.0.1:5000/ in your browser

## How to Use

1. Register a new account
2. Log in with your username and password
3. Different users see different things:
   - Regular users: Only see basic dashboard
   - Managers: Can manage some users
   - Admins: Can control everything

## Important Notes
-  Admin user is generated automatically. The Password is 'CS2660Final!'

## Files

- `app.py`: Main program file
- `database.py`: Handles user data and passwords
- `templates/`: Html files
- `database.db`: Created automatically when you run the program

## Cool Features

- Password security (stores passwords safely)
- Locks accounts after 3 wrong password attempts
- Password requirements (uppercase, lowercase, numbers, etc.)
- Option to generate a strong password
- Admins can change user access levels

## Documentation Referenced
- https://getbootstrap.com/docs/5.3/getting-started/introduction/
- https://flask.palletsprojects.com/en/stable/tutorial/templates/
- https://www.digitalocean.com/community/tutorials/how-to-make-a-web-application-using-flask-in-python-3
- https://docs.python.org/3/library/sqlite3.html
- https://docs.python.org/3/library/hashlib.html


