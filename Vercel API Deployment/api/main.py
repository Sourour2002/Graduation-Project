# Necessary imports.
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from supabase import create_client, Client
from dotenv import load_dotenv
import os

# FastAPI documentation formatting and organization. 
tags_metadata = [
    {
        "name": "Authentication",
        "description": "Authentication related endpoints."
    },
    {
        "name": "Users Info Management",
        "description": "Manage users information. CRUD operations. (W.I.P)"
    },
    {
        "name": "Model Interactions",
        "description": "AI Model interactions with different features. (W.I.P)"
    },
]

# Load environment variables from .env file
load_dotenv()

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_API_KEY = os.getenv("SUPABASE_API_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_API_KEY)

# FastAPI configuration and initialization. 
app = FastAPI(openapi_tags=tags_metadata)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

origins = [
    "http://localhost:3000",  # Adjust the port if your frontend/react project runs on a different one.
    "https://yourfrontenddomain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins from the list.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
ALGORITHM = "HS256"

# Pydantic basemodel.
class UserCreate(BaseModel):
    username: str
    password: str

# Helper function to create an access token.
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Helper function to verify the token.
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")

# Helper function to find a user by username.
def get_user_by_username(username: str):
    response = supabase.table("users").select("*").eq("username", username).execute()
    if response.data:
        return response.data[0]
    return None

# Auth endpoint for registering a new user.
@app.post("/auth/register", tags=["Authentication"])
def register_user(user: UserCreate):
    # Check if username is already taken.
    if get_user_by_username(user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash the password and save the user in Supabase.
    hashed_password = pwd_context.hash(user.password)
    response = supabase.table("users").insert({"username": user.username, "hashed_password": hashed_password}).execute()
    if not response:
        raise HTTPException(status_code=500, detail="Failed to register user")
    return {"message": "User registered successfully"}

# Auth endpoint for logging in an existing user.
@app.post("/auth/login", tags=["Authentication"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Create access token.
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Auth endpoint that verifies if a token is valid or not.
@app.get("/auth/verify-token/{token}", tags=["Authentication"])
async def verify_user_token(token: str):
    # Decodes and validates a JWT token.
    verify_token(token)
    return {"details": "Token is valid"}

# Users endpoint that gets the current logged in user's information.
@app.get("/users/info", tags=["Users Info Management"])
def get_user_info(token: str = Depends(oauth2_scheme)):
    # Retrieve user information from Supabase using token details.
    payload = verify_token(token)
    username = payload.get("sub")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user["id"], "username": user["username"]}

# Model endpoint that receives uploaded files.
@app.post("/model/upload", tags=["Model Interactions"])
async def upload_audio(file: UploadFile = File(...)):
    try:
        ##
        #   Model Logic
        ##
        # Storing file for now...
        file_data = await file.read()
        response = supabase.storage.from_("Model-Uploads").upload(file.filename, file_data)
        return JSONResponse(content={"details": "File uploaded successfully", 
                                     "filename": file.filename})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
