# Necessary imports.
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import JWTError, jwt

from tensorflow.keras.models import load_model
from nltk.stem import WordNetLemmatizer
import speech_recognition as speech
import tensorflow as tf
import pickle
import nltk

from datetime import datetime, timedelta, timezone
from supabase import create_client, Client
from dotenv import load_dotenv
import numpy as np
import librosa
import random
import json
import os
import io

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
    {
        "name": "Chatbots",
        "description": "Chatbot AI Models for different quran tafsers. (W.I.P)"
    }
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

# Initializing Lemmatizer
lemmatizer = WordNetLemmatizer()

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
ALGORITHM = "HS256"

# Pydantic basemodel.
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class ChatbotPrompt(BaseModel):
    prompt: str

# Quran Recitation Model.
# model = load_model("my_model.h5")
model = load_model("models/model_without_users.h5")

# Chatbot Models.
words_al_saadi = pickle.load(open('models/words_al-Saadi.pkl', 'rb')) 
classes_al_saadi = pickle.load(open('models/classes_al-Saadi.pkl', 'rb'))  
chatbot_model_al_saadi = load_model('models/chatbot_model_al-Saadi.h5')

words_al_muyassar = pickle.load(open('models/words_al-Muyassar.pkl', 'rb')) 
classes_al_muyassar = pickle.load(open('models/classes_al-Muyassar.pkl', 'rb'))  
chatbot_model_al_muyassar = load_model('models/chatbot_model_al-Muyassar.h5')

# Chatbot JSON data.
with open('models/Tafser al-Saadi.json', encoding='utf-8') as f:
    Tafser_al_Saadi = json.load(f)

with open('models/Tafser al-Muyassar.json', encoding='utf-8') as f:
    Tafser_al_Muyassar = json.load(f)

# Loading all quran verses.
with open("quran_verses.json", "r", encoding="utf-8") as file:
    quran_verses = json.load(file)

# Chatbot helper functions.
def clean_up_sentence(sentence):
    sentence_words = nltk.word_tokenize(sentence)
    sentence_words = [lemmatizer.lemmatize(word) for word in sentence_words]
    return sentence_words

def bag_of_words(sentence, words):
    sentence_words = clean_up_sentence(sentence)
    bag = [0] * len(words)
    for w in sentence_words:
        for i, word in enumerate(words):
            if word == w:
                bag[i] = 1
    return np.array(bag)

def predict_class(sentence, words, classes, model):
    bow = bag_of_words(sentence, words)
    res = model.predict(np.array([bow]))[0]
    ERROR_THRESHOLD = 0.25
    results = [[i, r] for i, r in enumerate(res) if r > ERROR_THRESHOLD]
    results.sort(key=lambda x: x[1], reverse=True)
    return_list = [{'sura': classes[r[0]], 'probability': str(r[1])} for r in results]
    return return_list

def get_response(sura_list, sura_json):
    if not sura_list:
        return "Sorry, I don't understand."
    
    aya = sura_list[0]['sura']
    for i in sura_json['sura']:
        if i['aya'] == aya:
            return random.choice(i['responses'])
    return "No matching response found."

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

# Helper function to find a user by email.
def get_user_by_email(email: str):
    response = supabase.table("users").select("*").eq("email", email).execute()
    if response.data:
        return response.data[0]
    return None

# Helper function to find a user by email or username.
def get_user_by_email_or_username(identifier: str):
    response = supabase.table("users").select("*").or_(f"username.eq.{identifier},email.eq.{identifier}").execute()
    if response.data:
        return response.data[0]
    return None

# Auth endpoint for registering a new user.
@app.post("/auth/register", tags=["Authentication"])
def register_user(user: UserCreate):
    # Check if username or email is already taken.
    if get_user_by_username(user.username) or get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Hash the password and save the user in Supabase.
    hashed_password = pwd_context.hash(user.password)
    response = supabase.table("users").insert({
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_password
    }).execute()
    if not response:
        raise HTTPException(status_code=500, detail="Failed to register user")
    
    # Create access token.
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"message": "User registered successfully", "access_token": access_token, "token_type": "bearer"}

# Auth endpoint for logging in an existing user.
@app.post("/auth/login", tags=["Authentication"])
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Find user by username or email.
    user = get_user_by_email_or_username(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username, email, or password",
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
    return {"id": user["id"], "username": user["username"], "email": user["email"]}

# Model endpoint that receives audio file and pass it to the audio AI model returning the results.
@app.post("/model/upload", tags=["Model Interactions"])
async def upload_audio(file: UploadFile = File(...)):
    try:
        file_data = await file.read()
        file_like = io.BytesIO(file_data)
        
        shape0, max_shape1 = 13, 1499, 
        signal, sr =librosa.load(file_like,sr=22050)
        mfcc = librosa.feature.mfcc(y=signal,
                            sr=sr,
                            n_fft=2048,
                            n_mfcc=13,
                            hop_length=512)
        
        arr = np.zeros((shape0, max_shape1))
        mfcc_length = mfcc.shape[1]
        
        if mfcc_length < max_shape1:
            arr[:, :mfcc_length] = mfcc
        else:
            arr = mfcc[:, :max_shape1]

        mfcc = arr.T
        mfcc = mfcc[..., np.newaxis]
        x = mfcc[np.newaxis,...]
        prediction = model.predict(x)
        index = np.argmax(prediction,axis=1)
        index = (index.tolist() if isinstance(index, np.ndarray) else int(index))[0]
        
        recording_transcript = []
        
        file_like.seek(0)
        recognizer = speech.Recognizer()
        with speech.AudioFile(file_like) as source:
            audio = recognizer.record(source)
        
        try:
            transcript = recognizer.recognize_google(audio, language="ar-SA")

            recording_transcript.append(transcript)
            recording_transcript = "".join(recording_transcript).strip().split()
        except speech.UnknownValueError:
            return JSONResponse(content={"error": "Could not understand the audio"}, status_code=500)
        except speech.RequestError as e:
             return JSONResponse(content={"error": f"Google Speech Recognition error: {e}"}, status_code=500)
        
        quran_reference = quran_verses["1"]["arabic2"][index]
        incorrect_words_index_list = []
        
        if len(quran_reference) != len(recording_transcript):
            correction_status = "Incorrect Recitation"
        else:
            if quran_reference == recording_transcript:
                correction_status = "Correct Recitation"
            else:
                set1 = set(quran_reference)
                set2 = set(recording_transcript)
                if set1 == set2:
                    correction_status = "The words are recited correctly, but in different order."
                else:
                    correction_status = "Incorrect Recitation (Words)"
                    for i in range(len(quran_reference)):
                        if quran_reference[i] != recording_transcript[i]:
                            incorrect_words_index_list.append(i + 1)
        
        return JSONResponse(content={
            "surah_number": 1,
            "verse_number": index + 1,
            "correction_status": correction_status,
            "incorrect_words_index_list": incorrect_words_index_list,
            "filename": file.filename})
        
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

# Tafser al-Saadi chatbot interaction endpoint.
@app.post("/chatbot/Tafser-al-Saadi", tags=["Chatbots"])
def chatbot_tafser_al_saadi(chatbot_prompt: ChatbotPrompt):
    try:
        model_output = predict_class(chatbot_prompt.prompt, words_al_saadi, classes_al_saadi, chatbot_model_al_saadi)
        response = get_response(model_output, Tafser_al_Saadi)
        
        return JSONResponse(content={"response": response})

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

# Tafser al-Muyassar chatbot interaction endpoint.
@app.post("/chatbot/Tafser-al-Muyassar", tags=["Chatbots"])
def chatbot_tafser_al_muyassar(chatbot_prompt: ChatbotPrompt):
    try:
        model_output = predict_class(chatbot_prompt.prompt, words_al_muyassar, classes_al_muyassar, chatbot_model_al_muyassar)
        response = get_response(model_output, Tafser_al_Muyassar)
        
        return JSONResponse(content={"response": response})

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
