import sqlite3
import os
import hashlib
import random
import string

#******************************
#Access Levels
ACCESS_LEVEL_ADMIN = "admin"
ACCESS_LEVEL_MANAGER = "manager"
ACCESS_LEVEL_USER = "user"
#******************************






#Database connection generator

def db_generator():
    """
    Initializes the database connection and creates the necessary tables for storing
    user authentication and related data. Ensures that an admin user exists in the
    database to avoid a state where no administrative access is available. This function
    automates the setup of the initial database schema and ensures proper defaults.

    :return: The connection object representing the open database connection.
    :rtype: sqlite3.Connection
    """
    con = sqlite3.connect('database.db')
    con.cursor()
    cur = con.cursor()

    # Create table for users called users -> stores user authentication and other info
    cur.execute('''CREATE TABLE IF NOT EXISTS users ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            access_level TEXT NOT NULL,
            login_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )''')

    # Check if admin user already exists
    cur.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    admin_exists = cur.fetchone()  # Fetch the resulting row

    # If no admin user exists then you won't be able to access the power of the admins! This code creates one if it doesnt exist yet
    if not admin_exists:
        # Use a fixed password for admin instead of generating a random one
        admin_password = 'CS2660Final!'

        # Generate salt and hash the password
        salt = os.urandom(20).hex()
        admin_password_hash = hash_pw(admin_password, salt)

        # Insert admin
        cur.execute(
            "INSERT INTO users (username, password, salt, access_level, login_attempts, locked) VALUES (?, ?, ?, ?, ?, ?)",
            ('admin', admin_password_hash, salt, ACCESS_LEVEL_ADMIN, 0, 0))

        # Print the admin credentials
        print("Created admin user with username: admin")
        print("Admin password: CS2660Final!")

    con.commit()
    print("Database created successfully")
    return con

def hash_pw(plain_text, salt='') -> str:
    """
    Generates a salted SHA-1 hash for the given plain text. If a salt is not
    provided, a random salt is generated. The salt is prepended to the resultant
    hash. This function ensures that the resultant hashed string is unique and
    suitable for secure password storage.

    :param plain_text: The plaintext string that needs to be hashed.
    :type plain_text: str
    :param salt: An optional cryptographic salt to combine with the plaintext.
    :type salt: str, optional
    :return: The salted hash as a string with the salt prepended to the hash.
    :rtype: str
    """
    if not salt:
        salt = os.urandom(20).hex()  # generate a random salt if not provided
    hashable = salt + plain_text  # concatenate salt and plain_text
    hashable = hashable.encode('utf-8')  # convert to bytes
    this_hash = hashlib.sha1(hashable).hexdigest()  # hash w/ SHA-1 and hexdigest

    return salt + this_hash  # prepend hash and return

def add_user(username, password_hash, salt, access_level=ACCESS_LEVEL_USER):
    """
    Insert a new user into the database with the provided username, password hash, salt,
    and access level. If the username already exists, the method will catch the database
    integrity error and return False, without adding the user.

    :param username: The username for the new user.
    :type username: str
    :param password_hash: The hashed password for the new user.
    :type password_hash: str
    :param salt: The salt value used for hashing the password.
    :type salt: str
    :param access_level: The level of access for the user, defaulting to `ACCESS_LEVEL_USER`.
                         This can be adjusted for administrative or guest privileges.
    :type access_level: int
    :return: True if the user was successfully added to the database, False if the username
             already exists.
    :rtype: bool
    """
    #Connect to the database
    con = sqlite3.connect('database.db')
    cur = con.cursor()

    #check to see if username alr exits
    try:
        cur.execute("INSERT INTO users (username, password, salt, access_level) VALUES (?, ?, ?, ?)",
                    (username, password_hash, salt, access_level)
                    )
        con.commit()
        con.close()
        return True
    except sqlite3.IntegrityError:
        print("Username already exists") #TODO:Check if this works in flask
        con.close()
        return False

def get_user_info(username):
    """
    Fetches user information from the database based on the provided username. The function connects to a SQLite
    database, retrieves a single record matching the username, and returns the fetched information as a tuple.

    :param username: The username to search for in the database.
    :type username: str

    :return: The user information as a tuple containing id, username, password, salt, access level,
             login attempts, and locked status"""
    # Connect to the database
    con = sqlite3.connect('database.db')
    cur = con.cursor()

    cur.execute("SELECT id, username, password, salt, access_level, login_attempts, "
                "locked FROM users WHERE username = ?",(username,))

    info = cur.fetchone()
    con.close()

    return info

def update_user_access_level(username, new_access_level):
    """
    Updates the access level of a user in the database. This function connects to the
    database, updates the access level for a given username, commits the change, and
    closes the connection. If the update is successful, it returns a boolean value
    indicating the success of the operation.

    :param username: The username of the user whose"""
    con = sqlite3.connect('database.db')
    cur = con.cursor()

    try:
        cur.execute("UPDATE users SET access_level = ? WHERE username = ?",
                    (new_access_level,username))
        con.commit()
        result = cur.rowcount > 0

    except sqlite3.Error:
        result = False
    finally:
        con.close()

    return result

def permissions(required_lvl, user_lvl):
    """
    Check if a user has sufficient permission level for a required action.

    This function compares the access levels of the user and the required
    access level to determine if the user meets or exceeds the required
    level of permissions.

    :param required_lvl: The access level required to perform the action.
    :type required_lvl: str
    :param user_lvl: The access level currently assigned to the user.
    :type user_lvl: str
    :return: True if the user has sufficient permission, False otherwise.
    :rtype: bool
    """
    levels = {
        ACCESS_LEVEL_USER: 1,
        ACCESS_LEVEL_MANAGER: 2,
        ACCESS_LEVEL_ADMIN: 3
    }

    return levels.get(user_lvl, 0) >= levels.get(required_lvl, 0)

def authenticate_login(username, password):
    """
    Authenticates a user's login credentials by verifying the provided username and
    password against the stored hash and salt in the database. It also manages login
    attempt tracking and locks the account after a predefined number of failed
    login attempts.

    :param username: The username of the user attempting to log in.
    :type username: str
    :param password: The password entered by the user attempting to log in.
    :type password: str
    :return: A tuple where the first value is a boolean indicating success or
        failure, and the second value is a string providing the result message
        or the username on successful authentication.
    :rtype: tuple
    """

    # Get user information
    user_info = get_user_info(username)  # returns a 7-tuple

    # If user doesn't exist
    if not user_info:
        print("Invalid. Try again.")
        return False, "Invalid username or password"

    # Check if account is locked
    if user_info[6] == 1:
        print("Account Locked.")
        return False, "Account is locked due to too many failed attempts"

    # Extract salt and stored password from database
    stored_password = user_info[2]  # password hash
    salt = user_info[3]  # salt

    # Calculate hash using password and salt
    hashed_pw = hash_pw(password, salt)

    # Check if calculated password matches stored password
    if hashed_pw == stored_password:
        # Reset login attempts on successful login
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        cur.execute("UPDATE users SET login_attempts = 0, locked = 0 WHERE username = ?", (username,))
        con.commit()
        con.close()
        return True, username
    else:
        # Increment login attempts
        con = sqlite3.connect('database.db')
        cur = con.cursor()
        login_attempts = user_info[5] + 1
        locked = 1 if login_attempts >= 3 else 0

        cur.execute("UPDATE users SET login_attempts = ?, locked = ? WHERE username = ?",
                   (login_attempts, locked, username))
        con.commit()
        con.close()

        if locked == 1:
            print("Account Locked.")
            return False, "Account locked due to too many failed attempts"
        else:
            return False, "Invalid username or password"

def validate_password(username, password):
    """
    Validates whether the given password meets specific security criteria. The password is checked against"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long. Please try again."
    if len(password) > 25:
        return False, "Password must be at most 25 characters long. Please try again."
    number = any(char.isdigit() for char in password)
    if not number:
        return False, "You need a number! Please try again."
    lowercase = any(c.islower() for c in password)
    if not lowercase:
        return False, "You need a lowercase letter! Please try again."
    uppercase = any(c.isupper() for c in password)
    if not uppercase:
        return False, "You need a uppercase letter! Please try again."
    special = any(not c.isalnum() for c in password)
    if not special:
        return False, "You need a special character! Please try again."
    if username == password:
        return False, "Your password cant be the same as your username."
    else:
        return True, "Password is valid!"

def display_menu(access_level):
    """
    Displays a menu based on the access level provided. The menu options presented
    to the user depend on their access level, allowing only actions they are
    authorized to perform.

    :param access_level: The access level of the user. Determines the menu options
        available to the user.
    :type access_level: int

    :return: None
    """
    print("Available options:")
    print("1. View profile")

    if permissions(ACCESS_LEVEL_MANAGER, access_level):
        print("2. Manage users")

    if permissions(ACCESS_LEVEL_ADMIN, access_level):
        print("3. System settings")
        print("4. View logs")




if __name__ == "__main__":
    db_generator()


