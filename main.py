from datetime import datetime, timedelta
from typing import Union
import uvicorn
from pymongo import MongoClient

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


SECRET_KEY = "2f9483dd1f5e62a9257802d497e3e68f5ff211fbea68922ece525cd86615b44325c2cd1963d54932c1da39e5998ca30dd7b1182631d7a73fcac4615babe8e8a7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None
    password: str


class Mongo:
    def __init__(self):
        self.client = MongoClient("mongodb+srv://test.mp8koe0.mongodb.net/myFirstDatabase", username="adityasahu4321", password="789456")
        self.db = self.client.test
        self.collection = self.db.users

    def insert(self, data):
        self.collection.insert_one(data).inserted_id

    def find(self, username):
        user = self.collection.find_one({"username": username})
        return user

    def delete(self, username):
        self.collection.find_one_and_delete({"username": username})

    def update(self, data):
        self.collection.find_one_and_update(data)

db = Mongo()

class Oauth:
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


    def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt


    def get_current_user(token: str = Depends(oauth2_scheme)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            token_data = TokenData(username=username)
        except JWTError:
            raise credentials_exception
        user = db.find(username=token_data.username)
        if user is None:
            raise credentials_exception
        return user


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    data =db.find(username)
    print(data)
    if not data:
        return None
    else:
        user_dict=data
        return User(**user_dict)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    print(user)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authanticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = Oauth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user")
async def new_user(user: User):
    current_user={
        user.username: {
            "username"  : user.username,
            "email"     : user.email,
            "full_name" : user.full_name,
            "disabled"  : user.disabled,
            "password"  : get_password_hash(user.password),
        }
    }
    db.insert(current_user)
    return {"status": "ok"}


@app.get("/users/me/", response_model=User)
async def read_user_me(current_user: User = Depends(Oauth.get_current_user)):
    return current_user


uvicorn.run(app=app)
# print(authenticate_user("string", "string"))