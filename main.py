import os

from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_jwt_extended import create_access_token, create_refresh_token,verify_jwt_in_request, get_jwt_identity
from flask_jwt_extended import JWTManager
      
# Instantiate Flask application and set the secret key for JWT
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")
jwt = JWTManager(app)

# Store users in a dictionary
users = {}

# Implementation of token_required Decorator
def token_required(fn):
  @wraps(fn)
  def wrapper(*args, **kwargs):
    try:
      # Verify the JWT token in the request headers
      verify_jwt_in_request()
      # Get username (identity) from JWT token
      username = get_jwt_identity()
      # Get user's name from database
      current_user = users.get(username)

      # Check the existence of user
      if not current_user:
        return api_response(message="User does not exist", status=404)

      # Invoke the original endpoint, passing the information of authenticated user
      return fn(current_user, *args, **kwargs)
    except Exception as e:
      # If there is an error during token validation
      return api_response(message="Token is invalid", status=401)
  return wrapper

# Api response function
def api_response(data=None, message=None, status=200):
  response={
    'success' : 200 <= status < 300,
    'status' : status
  }
  if message:
    response['message'] = message
  
  if data is not None:
    response['data'] = data
  
  return jsonify(response), status

# Register function
@app.route('/register', methods=['POST'])
def register():
  data = request.get_json()
  username = data.get('username')
  password = data.get('password')
  full_name = data.get('full_name')
  email = data.get('email')

  # Check username, password and email
  if not username and not password:
    return jsonify({'error' : 'Missing username or password'}), 400
  if username in users:
    return jsonify({'error' : 'Username already exists'}), 400
  if '@' not in email:
    return jsonify({'error' : 'Invalid email format'}), 400
  if len(password) < 6:
    return jsonify({'error' : 'Password must be at least 6 characters long'}), 400
  if not full_name:
    return jsonify({'error': 'Missing full name'}), 400

  # Encrypt password before storing
  pw_hash = generate_password_hash(password)

  profile = {
    'username' : username,
    'email' : email,
    'full_name' : full_name,
    'profile_picture' : 'default.png',
    'bio' : '',
    'created_at' : int(datetime.now().timestamp())
  }

  users[username] = {'password' :pw_hash, 'profile' : profile}

  return api_response(message="User registered successfully")

# Login function
@app.route('/login', methods=['POST'])
def login():
  data = request.get_json()
  username = data.get('username')
  password = data.get('password')

  # Check the existence of user in the system
  if username not in users:
    return jsonify({'error' : 'Invalid username or password'}), 401
  
  # Check if the entered password matches the encrypted password
  if not check_password_hash(users[username]['password'], password):
    return jsonify({'error' : 'Invalid username of password'}), 401

  # If both username and password are correct, then create an access token and a refresh token
  access_token = create_access_token(identity=username)
  refresh_token = create_refresh_token(identity=username)

  # Return the 'Success' response wither token and user's information
  return api_response(
    message='Login successful',
    data = {
      'access_token' : access_token,
      'refresh_token' : refresh_token,
      'user' : users[username]['profile']
    })
  
# Log out function
@app.route('/logout', methods=['POST'])
def logout():
  return api_response(message="Logout successful")

# View own profile
@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
  # Retrieve profile of current user
  try:
    verify_jwt_in_request()
    username = get_jwt_identity()
    current_user = users.get(username)

    if not current_user:
      return api_response(message='User not found', status=404)
    
    return api_response(data=current_user['profile'])

  except Exception as e:
    return api_response(message=f'Token is invalid: {str(e)}', status=401)


@app.route("/")
def hello_world():
  """Example Hello World route."""
  name = os.environ.get("NAME", "World")
  return f"Hello {name}!"


if __name__ == "__main__":
  app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 3000)))