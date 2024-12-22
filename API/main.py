# Necessary imports.
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from models import User
from database import SessionLocal, engine
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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

# FastAPI configuration and initialization. 
app = FastAPI(openapi_tags=tags_metadata)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

origins = [
    "http://localhost:3000",  # Adjust the port if your frontend/react project runs on a different one.
    "https://yourfrontenddomain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allows all origins from the list.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite Database Dependency.
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT secret, algorithm and expiration period.
SECRET_KEY = "Uj37vPdD8p$wXkZLr!b94MZzFY&3@TqNxKJ2CQgVH7m^6W#tBp"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Pydantic basemodel.
class UserCreate(BaseModel):
    username: str
    password: str

# Helper function to get user information by username. => Verifying if the username already exists.
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

# Helper function to create/register a new user.
def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    return {
        "details" : "User registered correctly"
    }

# Auth endpoint for registering a new user.
@app.post("/auth/register", tags=["Authentication"])
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(db=db, user=user)

# Helper function to authenticate a user.
def authenticate_user(username: str, password: str, db: Session):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user

# Helper function that creates an access token.
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Auth endpoint for logging in an existing user.
@app.post("/auth/login", tags=["Authentication"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Helper function that helps verify if a token is valid.
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")

# Auth endpoint that verifies if a token is valid or not.
@app.get("/auth/verify-token/{token}", tags=["Authentication"])
async def verify_user_token(token: str):
    verify_token(token=token)
    return {"details": "Token is valid"}

# Users endpoint that gets the current logged in user's information.
@app.get("/users/info", tags=["Users Info Management"])
def get_user_info(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": user.id,
            "username": user.username
        }
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")

# Helper variables for testing the upload endpoint for the AI model.
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Model endpoint that receives uploaded files.
@app.post("/model/upload", tags=["Model Interactions"])
async def upload_audio(file: UploadFile = File(...)):
    try:
        
        ##
        #   Model Logic
        ##
        
        # Storing file for now...
        file_location = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_location, "wb") as f:
            f.write(await file.read())
        return JSONResponse(content={"details": "File uploaded successfully", "filename": file.filename})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
