from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import random
import string
from database import db_generator, add_user, authenticate_login, validate_password, hash_pw, get_user_info, \
    update_user_access_level
from database import ACCESS_LEVEL_ADMIN, ACCESS_LEVEL_MANAGER, ACCESS_LEVEL_USER, permissions

app = Flask(__name__)
# Set a static secret key for production use
app.secret_key = os.urandom(20)

# Initialize the database
db_generator()  # This function doesn't return anything, so don't assign it


def generate_strong_password(length=12):
    """
    Generate a strong random password

    Parameters:
    - length: Length of the password (default: 12)

    Returns:
    - A strong random password
    """
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = '!@#$%^&*()'

    # Ensure at least one of each character type
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special)
    ]

    # Add remaining characters
    characters = lowercase + uppercase + digits + special
    for i in range(length - 4):
        password.append(random.choice(characters))

    # Shuffle the password to randomize character order
    random.shuffle(password)
    return ''.join(password)


@app.route('/', methods=['GET'])
def index():
    #Main route that redirects to dashboard if logged in, otherwise to login page
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    #Handle user login with attempt limiting
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Track login attempts
        if 'login_attempts' not in session:
            session['login_attempts'] = 0

        # Check if user is locked out
        if session['login_attempts'] >= 3:
            flash('Account locked. Please contact an administrator.', 'danger')
            return render_template('login.html')

        # Authenticate user
        success, message = authenticate_login(username, password)

        if success:
            # Reset login attempts on successful login
            session.pop('login_attempts', None)

            # Get user info from database
            user_info = get_user_info(username)
            if user_info:
                # user_info is a tuple: (id, username, password_hash, salt, access_level, login_attempts, locked)
                session['username'] = user_info[1]  # username
                session['access_level'] = user_info[4]  # access_level

                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('dashboard'))
        else:
            # Increment login attempts
            session['login_attempts'] += 1
            attempts_left = 3 - session['login_attempts']

            if attempts_left > 0:
                flash(f'Invalid username or password. {attempts_left} attempts remaining.', 'danger')
            else:
                flash('Account locked. Please contact an administrator.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    #Handle user registration with password validation and generation
    if request.method == 'POST':
        username = request.form['username']

        # Check if user wants a generated password
        if 'generate_password' in request.form:
            password = generate_strong_password()
            flash(f'Your generated password is: {password}. Please save it securely!', 'info')
        else:
            password = request.form['password']

        # Validate password - pass both username and password as expected by the function
        is_valid, message = validate_password(username, password)

        if not is_valid:
            flash(message, 'danger')
            return render_template('register.html')

        # Hash password with salt
        salt = os.urandom(20).hex()  # 40 character hex salt
        password_hash = hash_pw(password, salt)

        # Add user to database (lowest access level by default)
        if add_user(username, password_hash, salt, ACCESS_LEVEL_USER):
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists. Please choose another.', 'danger')

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    #Protected dashboard page for authenticated users
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))

    # Get access level for permission checking
    username = session['username']
    access_level = session['access_level']

    # Check permissions for different access levels
    show_manager_options = permissions(ACCESS_LEVEL_MANAGER, access_level)
    show_admin_options = permissions(ACCESS_LEVEL_ADMIN, access_level)

    return render_template('dashboard.html',
                           username=username,
                           access_level=access_level,
                           show_manager_options=show_manager_options,
                           show_admin_options=show_admin_options)


@app.route('/logout')
def logout():
    #Handle user logout by clearing session data
    session.clear()  # Clear all session data, not just username and access_level
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Error handlers for robustness
@app.errorhandler(404)
def page_not_found(e):
    #Handle 404 errors
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    print(f"SERVER ERROR: {e}")
    return render_template('500.html'), 500


@app.errorhandler(Exception)
def handle_exception(e):
    print(f"UNHANDLED EXCEPTION: {str(e)}")
    return render_template('error.html', error=str(e)), 500


@app.route('/manage_users', methods=['GET'])
def manage_users():
    # Check if user is logged in and is an admin
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    # Get current user info from database
    con = db_generator()

    # Add error handling for database connection
    if con is None:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))

    try:
        current_user = con.execute('SELECT * FROM users WHERE username = ?',
                                   (session['username'],)).fetchone()

        if current_user[4] != ACCESS_LEVEL_ADMIN:
            flash('You do not have permission to access this page', 'danger')
            con.close()
            return redirect(url_for('dashboard'))

        # Get all users for admin to manage
        all_users = con.execute('SELECT id, username, access_level FROM users').fetchall()
        con.close()

        users_list = []
        for user in all_users:
            users_list.append({
                'id': user[0],
                'username': user[1],
                'access_level': user[2]
            })

        return render_template('management.html', users=users_list)

    except Exception as e:
        if con:
            con.close()
        flash(f'An error occurred: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/update_access_level', methods=['POST'])
def update_access_level():
    # Check if user is logged in and is an admin
    if 'username' not in session:
        flash('You must be logged in to access this page', 'danger')
        return redirect(url_for('login'))

    # Get current user info from database
    conn = db_generator()
    if conn is None:
        flash('Database connection error', 'danger')
        return redirect(url_for('dashboard'))

    try:
        current_user = conn.execute('SELECT * FROM users WHERE username = ?',
                                    (session['username'],)).fetchone()
        if current_user[4] != ACCESS_LEVEL_ADMIN:
            flash('You do not have permission to perform this action', 'danger')
            conn.close()
            return redirect(url_for('dashboard'))

        # Get form data
        user_id = request.form.get('user_id')
        new_access_level = request.form.get('access_level')

        # Update user access level
        # Convert user_id to username if necessary
        target_user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
        if not target_user:
            flash('User not found', 'danger')
            conn.close()
            return redirect(url_for('manage_users'))

        username = target_user[0]  # Get username from tuple using index

        if update_user_access_level(username, new_access_level):
            flash('Access level updated successfully', 'success')
        else:
            flash('Failed to update access level', 'danger')

        conn.close()
        return redirect(url_for('manage_users'))

    except Exception as e:
        if conn:
            conn.close()
        flash(f'An error occurred: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))















if __name__ == '__main__':
    # Remove debug=True before submitting final version
    app.run(debug=True)