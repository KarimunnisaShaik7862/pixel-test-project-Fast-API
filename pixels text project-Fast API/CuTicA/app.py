from fastapi import FastAPI, Request, Form, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from pymongo import MongoClient, errors
from bson import ObjectId
import requests
import urllib.parse
import base64
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GoogleRequest
import pickle
import secrets
from typing import Optional
from dotenv import load_dotenv
import os

load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Middleware for handling sessions
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))

# Templates setup
templates = Jinja2Templates(directory="templates")

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# MongoDB Atlas configuration
username = os.getenv('MONGO_USERNAME')
password = os.getenv('MONGO_PASSWORD')

if not username or not password:
    raise ValueError("Environment variables MONGO_USERNAME and MONGO_PASSWORD must be set")

password = urllib.parse.quote(password)
mongo_uri = f"mongodb+srv://{username}:{password}@cluster0.sfffof5.mongodb.net/cutica_db?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(mongo_uri)
db = client.cutica_db

# Define classes_collection globally
classes_collection = db.classes  # Replace 'classes' with your actual collection name

# Function to get current public IP address
def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org")
        return response.text
    except requests.RequestException as e:
        print(f"Error getting public IP: {str(e)}")
        return None

# Function to whitelist IP in MongoDB Atlas access list
def whitelist_ip_in_mongo(ip):
    try:
        atlas_api_key_public = os.getenv('ATLAS_API_KEY_PUBLIC')
        atlas_api_key_private = os.getenv('ATLAS_API_KEY_PRIVATE')
        atlas_group_id = os.getenv('ATLAS_GROUP_ID')

        if not atlas_api_key_public or not atlas_api_key_private or not atlas_group_id:
            raise ValueError("MongoDB Atlas API keys and group ID must be set in environment variables")

        resp = requests.post(
            f"https://cloud.mongodb.com/api/atlas/v1.0/groups/{atlas_group_id}/accessList",
            auth=(atlas_api_key_public, atlas_api_key_private),
            json=[{'ipAddress': ip, 'comment': 'From FastAPI application'}]
        )
        resp.raise_for_status()  # Raise exception for non-2xx responses
        print("MongoDB Atlas accessList request successful")
    except (requests.RequestException, ValueError) as e:
        print(f"Error while whitelisting IP in MongoDB Atlas: {str(e)}")

# Get current public IP and whitelist it in MongoDB Atlas
current_ip = get_public_ip()
if current_ip:
    whitelist_ip_in_mongo(current_ip)

# Google API Client Libraries setup (authentication)
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
creds = None

# Paths for credentials and tokens
current_dir = os.path.dirname(os.path.abspath(__file__))
auth_dir = os.path.join(current_dir, 'auth')
credentials_path = os.path.join(auth_dir, 'credentials.json')
token_path = os.path.join(auth_dir, 'token.pickle')

# Load credentials from token or request new ones if needed
if os.path.exists(token_path):
    with open(token_path, 'rb') as token:
        creds = pickle.load(token)

if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
        creds = flow.run_local_server(port=0)
    with open(token_path, 'wb') as token:
        pickle.dump(creds, token)

# Build Gmail service
service = build('gmail', 'v1', credentials=creds)

# Function to send email using Gmail API
def send_email(to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message = {'raw': raw}
    try:
        message = service.users().messages().send(userId='me', body=message).execute()
        print('Message Id: %s' % message['id'])
        return message
    except Exception as error:
        print(f'An error occurred: {error}')
        return None

# Function to get current username from session
def get_current_username(request: Request):
    return request.session.get('username')

# Define password resets collection globally
password_resets_collection = db["password_resets"]

# Function to send email using Gmail API
def send_email(to, subject, body):
    SCOPES = ['https://www.googleapis.com/auth/gmail.send']
    creds = None
    current_dir = os.path.dirname(os.path.abspath(__file__))
    auth_dir = os.path.join(current_dir, 'auth')
    credentials_path = os.path.join(auth_dir, 'credentials.json')
    token_path = os.path.join(auth_dir, 'token.pickle')

    # Load credentials from token or request new ones if needed
    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)

    # Build Gmail service
    service = build('gmail', 'v1', credentials=creds)

    # Create email message
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    message = {'raw': raw}

    try:
        message = service.users().messages().send(userId='me', body=message).execute()
        print('Message Id: %s' % message['id'])
        return message
    except Exception as error:
        print(f'An error occurred: {error}')
        return None

# Function to get current username from session
def get_current_username(request: Request):
    return request.session.get('username')

# Routes

# Main home route
@app.get("/", response_class=HTMLResponse)
async def main_home(request: Request):
    return templates.TemplateResponse("main_home.html", {"request": request})

@app.route('/get_data', methods=['GET'])
def get_data():
    # Replace with your logic to fetch and return data
    data = {'message': 'Hello, data!'}
    return jsonify(data)

# Login page route
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# Signup page route
@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

# Handle signup POST request
@app.post("/signup", response_class=HTMLResponse)
async def signup_post(request: Request, signUpUsername: str = Form(...), signUpEmail: str = Form(...), signUpPassword: str = Form(...)):
    try:
        existing_user = db.users.find_one({'email': signUpEmail})
        if existing_user:
            return templates.TemplateResponse('signup.html', {'request': request, 'message': 'Email already exists. Please use a different email.'})
        else:
            db.users.insert_one({'username': signUpUsername, 'email': signUpEmail, 'password': signUpPassword})
            return RedirectResponse(url='/login', status_code=status.HTTP_303_SEE_OTHER)
    except errors.PyMongoError as e:
        return templates.TemplateResponse('signup.html', {'request': request, 'message': 'Database error. Please try again later.'})

# Handle login POST request
@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, loginEmail: str = Form(...), loginPassword: str = Form(...)):
    try:
        user = db.users.find_one({'email': loginEmail, 'password': loginPassword})
        if user:
            request.session['user_id'] = str(user['_id'])
            request.session['username'] = user['username']
            return RedirectResponse(url=f"/dashboard/{user['username']}", status_code=status.HTTP_303_SEE_OTHER)
        else:
            return templates.TemplateResponse('login.html', {'request': request, 'message': 'Invalid email or password'})
    except errors.PyMongoError as e:
        return templates.TemplateResponse('login.html', {'request': request, 'message': 'Database error. Please try again later.'})

# Dashboard page route
@app.get("/dashboard/{username}", response_class=HTMLResponse)
async def dashboard(request: Request, username: str):
    try:
        support_members = db.support_members.find()
        return templates.TemplateResponse("dashboard.html", {"request": request, "username": username, "support_members": support_members})
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})

# Support team page route
@app.get("/support_team", response_class=HTMLResponse)
async def support_team(request: Request):
    try:
        support_team_members = db.support_members.find()
        return templates.TemplateResponse("support_team.html", {"request": request, "support_team_members": support_team_members})
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})

# Customers page route
@app.get("/customers", response_class=HTMLResponse)
async def customers_page(request: Request):
    try:
        customers = db.customers.find()
        return templates.TemplateResponse("customers.html", {"request": request, "customers": customers})
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})

# Account page route
@app.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    return templates.TemplateResponse("account.html", {"request": request, "username": request.session.get('username', 'Guest')})

# Notification page route
@app.get("/notification", response_class=HTMLResponse)
async def notification_page(request: Request):
    username = request.session.get('username', 'Guest')
    return templates.TemplateResponse("notification.html", {"request": request, "username": username})

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    if "username" not in request.session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not logged in",
        )
    return templates.TemplateResponse("settings.html", {"request": request})

# Email configuration page route
@app.get("/email_config", response_class=HTMLResponse)
async def email_config(request: Request):
    # Your logic for email configuration page
    return templates.TemplateResponse("email_config.html", {"request": request})

# Classification configuration page route
@app.get("/classification_config")
async def classification_config(request: Request):
    classes = list(classes_collection.find())  # Get classes from MongoDB
    return templates.TemplateResponse("classification_config.html", {"request": request, "classes": classes})

# Routes
@app.get("/add_class")
async def add_class(request: Request):
    return templates.TemplateResponse("add_class.html", {"request": request})

@app.post("/add_class_form")
async def add_class_form(request: Request, name: str = Form(...), description: str = Form(...)):
    try:
        # Insert into MongoDB
        result = classes_collection.insert_one({"name": name, "description": description})
        if result.inserted_id:
            # Fetch all classes after insertion
            classes = list(classes_collection.find())
            return templates.TemplateResponse("classification_config.html", {"request": request, "classes": classes})
        else:
            raise HTTPException(status_code=500, detail="Failed to add class")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/delete_class/{class_id}")
async def delete_class(class_id: str):
    try:
        result = classes_collection.delete_one({"_id": ObjectId(class_id)})
        if result.deleted_count == 1:
            return {"message": "Class deleted successfully"}
        else:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Class not found")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/view_class_details/{class_id}")
async def view_class_details(class_id: str):
    try:
        # Fetch class details from MongoDB
        class_details = classes_collection.find_one({"_id": ObjectId(class_id)})
        if class_details:
            # Fetch examples related to this class from MongoDB (replace with your logic)
            examples = []  # Replace with actual fetching logic
            return templates.TemplateResponse("class_view_details.html", {"class_details": class_details, "examples": examples})
        else:
            raise HTTPException(status_code=404, detail="Class not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/password_change', name='password_change')
def password_change_page(request: Request):
    # Your code to handle the password change page
    return templates.TemplateResponse("password_change.html", {"request": request})

# Change email page
@app.get("/email_change", response_class=HTMLResponse)
async def email_change(request: Request, username: Optional[str] = Depends(get_current_username)):
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Pass the username to the template
    return templates.TemplateResponse("email_change.html", {"request": request, "username": username})

# Help page route
@app.get("/help", response_class=HTMLResponse)
async def help_page(request: Request):
    username = request.session.get('username', 'Guest')
    return templates.TemplateResponse("help.html", {"request": request, "username": username})

# Logout route
@app.get("/logout")
async def logout(request: Request):
    request.session.pop('user_id', None)
    request.session.pop('username', None)
    return RedirectResponse(url="/login")

@app.get("/add_support", name="add_support")
async def add_support(request: Request):
    return templates.TemplateResponse("add_support.html", {"request": request})

@app.post("/new_support_credentials", name="new_support_credentials")
async def new_support_credentials(request: Request, name: str = Form(...), email: str = Form(...), phone: str = Form(...)):
    try:
        db.support_members.insert_one({'name': name, 'email': email, 'phone': phone})
        return RedirectResponse(url="/support_team", status_code=status.HTTP_303_SEE_OTHER)
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})

# Forgot password page route
@app.get("/forgot_password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.post("/forgot_password", response_class=HTMLResponse)
async def send_password_reset_email(request: Request, forgotPasswordEmail: str = Form(...)):
    try:
        user = db.users.find_one({'email': forgotPasswordEmail})
        if not user:
            return templates.TemplateResponse("forgot_password.html", {"request": request, "messages": [("error", "Email not found.")]})

        token = secrets.token_urlsafe(32)
        password_resets_collection.insert_one({'email': forgotPasswordEmail, 'token': token})

        reset_link = f"http://localhost:8000/reset_password/{token}"
        send_email(forgotPasswordEmail, "Password Reset", f"Click the link to reset your password: {reset_link}")

        return templates.TemplateResponse("forgot_password.html", {"request": request, "messages": [("success", "Password reset link sent to your email.")]})
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})
    except Exception as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': str(e)})

# Reset password route
@app.get("/reset_password/{token}", response_class=HTMLResponse)
async def reset_password(token: str, request: Request):
    try:
        password_reset_entry = password_resets_collection.find_one({'token': token})
        if not password_reset_entry:
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})
    except Exception as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': str(e)})

@app.post("/reset_password/{token}", response_class=HTMLResponse)
async def reset_password_post(token: str, request: Request, newPassword: str = Form(...)):
    try:
        password_reset_entry = password_resets_collection.find_one({'token': token})

        if not password_reset_entry:
            return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

        email = password_reset_entry['email']
        db.users.update_one({'email': email}, {'$set': {'password': newPassword}})
        password_resets_collection.delete_one({'token': token})

        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    except errors.PyMongoError as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': 'Database error. Please try again later.'})
    except Exception as e:
        return templates.TemplateResponse('error.html', {'request': request, 'message': str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)