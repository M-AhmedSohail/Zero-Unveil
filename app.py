import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import re
from werkzeug.utils import secure_filename
from utils import predict, predict_multiclass, extract_and_count_opcodes, calculate_byte_entropy,explain_with_lime, model, scaler   # Import necessary functions
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Define the path for the JSON file where user data will be stored
USER_DATA_FILE = 'users.json'
UPLOAD_FOLDER = 'uploads'
STATIC_FOLDER = 'static'
ALLOWED_EXTENSIONS = {'exe'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload and static folders exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(STATIC_FOLDER):
    os.makedirs(STATIC_FOLDER)

# Helper function to validate email
def is_valid_email(email):
    email_regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(email_regex, email)

# Helper function to check allowed files
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to load users from the JSON file
def load_users():
    if not os.path.exists(USER_DATA_FILE):
        return {}  # Return an empty dictionary if the file doesn't exist
    with open(USER_DATA_FILE, 'r') as file:
        return json.load(file)
    
# Function to save users to the JSON file
def save_users(users):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(users, file, indent=4)

# Route for the login page
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    users = load_users()  # Load users from the JSON file

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists and password matches
        if username in users and users[username]['password'] == password:
            session['username'] = username  # Store username in session
            return redirect(url_for('index'))  # Redirect to dashboard
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))  # Redirect back to login page

    return render_template('login.html')

# Route for the dashboard (index page)
@app.route('/dashboard')
def index():
    if 'username' in session:
        username = session['username']
        users = load_users()  # Load users from the JSON file
        
        if username in users:
            user_data = users[username]
            
            # Get the total counts for scanned, benign, and malicious files
            total_scans = user_data.get('total_scans', 0)
            total_benign = user_data.get('total_benign', 0)
            total_malicious = user_data.get('total_malicious', 0)
            
            # Get the last 5 scans for the dashboard
            recent_scans = user_data.get('scans', [])[-5:]

            # Get all scans for the reports section
            all_scans = user_data.get('scans', [])

            return render_template(
                'dashboard.html', 
                username=username, 
                user_data=user_data,
                total_scans=total_scans, 
                total_benign=total_benign, 
                total_malicious=total_malicious, 
                scans=recent_scans,  # For the dashboard (last 5)
                all_scans=all_scans  # For the reports (all scans)
            )
        else:
            flash('User data not found', 'danger')
            return redirect(url_for('login'))

    return redirect(url_for('login'))  # Redirect to login if not logged in

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    users = load_users()  # Load users from the JSON file

    if request.method == 'POST':
        name = request.form['fullname']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirmpassword']

        # Validate email format
        if not is_valid_email(email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('signup'))

        # Ensure username has no spaces
        if ' ' in username:
            flash('Username must not contain spaces.', 'danger')
            return redirect(url_for('signup'))

        # Ensure password is at least 8 characters
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('signup'))

        # Ensure password and confirm password match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))

        # Check if username already exists
        if username in users:
            flash('Username already taken. Please choose another.', 'danger')
            return redirect(url_for('signup'))

        # Save user information to the JSON file
        users[username] = {
            'name': name,
            'email': email,
            'password': password
        }
        save_users(users)  # Save updated users to the JSON file

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))  # Redirect to login page after successful signup

    return render_template('signup.html')

# Route for the forget password page
@app.route('/forget-password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        email = request.form['email']
        # Here you would implement the logic to send a password reset email
        flash(f'Password recovery instructions sent to {email}.', 'info')
        return redirect(url_for('login'))

    return render_template('forgetPassword.html')

# Route to log out
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login'))  # Redirect to login page

# Route to handle file upload and classification
@app.route('/upload', methods=['POST'])
def upload_file():
    users = load_users()  # Load users from the JSON file

    # Check if a file is provided in the POST request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    # Check if a file was selected
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    

    # Check if the file is allowed
    if file and allowed_file(file.filename):
        # Secure and clean the filename
        filename = secure_filename(file.filename)
        # Remove spaces and special characters for a cleaner LIME file name
        base_filename = re.sub(r'[^a-zA-Z0-9]', '_', filename.rsplit('.', 1)[0])
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        try:
            # Call the binary prediction function to classify the file (Malicious/Benign)
            binary_result = predict(file_path)
            category = "N/A"
            lime_explanation_file = None
            explain_text = None
            complete_text = None

            # If the file is classified as malicious, perform multi-class classification
            if binary_result == 'Malicious':
                multiclass_result = predict_multiclass(file_path)
                category = multiclass_result

                # Generate LIME explanation
                features = extract_and_count_opcodes(file_path)
                entropy = calculate_byte_entropy(file_path)[1]
                data_row = list(features.values())
                feature_names = list(features.keys())

                # Ensure the STATIC_FOLDER exists
                if not os.path.exists(STATIC_FOLDER):
                    os.makedirs(STATIC_FOLDER)

                

                expt, compt = explain_with_lime(model, [data_row], data_row, feature_names, scaler)

                # Convert compt (Stream object) to a serializable format
                explain_text = expt
                complete_text = ''.join([chunk.choices[0].delta.content or '' for chunk in compt])  # Stream to string

                print(f"Explanation Text: {expt}")
                print(f"Completion Text: {complete_text}")




            # Store the scan information in the user's record
            username = session.get('username')
            if username and username in users:
                user_data = users[username]

                # Initialize total scans, benign, and malicious if they don't exist
                if 'total_scans' not in user_data:
                    user_data['total_scans'] = 0
                if 'total_benign' not in user_data:
                    user_data['total_benign'] = 0
                if 'total_malicious' not in user_data:
                    user_data['total_malicious'] = 0
                if 'scans' not in user_data:
                    user_data['scans'] = []

                # Update the total scans count
                user_data['total_scans'] += 1

                # Update benign/malicious counts
                if binary_result == 'Benign':
                    user_data['total_benign'] += 1
                else:
                    user_data['total_malicious'] += 1

                # Append the scan details
                user_data['scans'].append({
                    "filename": filename,
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "result": binary_result,
                    "category": category,
                    "lime_explanation": lime_explanation_file
                })

                # Save the updated user data
                save_users(users)

            # Return the binary classification and multi-class details
            return jsonify({
                'binary_result': binary_result,
                'multiclass_result': category,
                'explain_text': explain_text,
                'complete_text': complete_text
                
            }), 200

        except Exception as e:
            print(f"Error during prediction: {e}")
            return jsonify({'error': f"Error during prediction: {e}"}), 500

    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/lime-explanation')
def lime_explanation():
    try:
        # Serve the LIME explanation HTML file from the static folder
        return app.send_static_file('lime_explanation_sample.html')
    except Exception as e:
        print(f"Error loading LIME explanation: {e}")
        return "Error loading LIME explanation", 500
    
@app.route('/update-profile-picture', methods=['POST'])
def update_profile_picture():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    users = load_users()

    if username in users:
        user_data = users[username]

        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture:
                # Save the new profile picture
                filename = secure_filename(profile_picture.filename)
                profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                # Update user's profile picture path
                user_data['profile_picture'] = filename

                # Save updated user data
                save_users(users)
                flash('Profile picture updated successfully!', 'success')
            else:
                flash('No picture selected', 'danger')
    else:
        flash('User not found', 'danger')

    return redirect(url_for('index'))

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    users = load_users()

    if username in users:
        user_data = users[username]

        # Update basic profile information
        user_data['name'] = request.form['fullname']
        user_data['username'] = request.form['username']
        user_data['email'] = request.form['email']

        # Password change section
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if current_password != user_data['password']:
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New password and confirm password do not match', 'danger')
        elif len(new_password) < 8:
            flash('New password must be at least 8 characters long', 'danger')
        else:
            # Update password
            user_data['password'] = new_password
            flash('Profile updated successfully', 'success')

        # Save updated user data
        save_users(users)
    else:
        flash('User not found', 'danger')

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
