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


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$A3/O7LXTMmZ1xrTE51MWMe8xOS0Wxkpz04R3gEzQiITJRrUfoobnW",
        "disabled": False,
    }
}

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


class UserInDB(User):
    hashed_password: str


class Mongo:
    def __init__(self):
        self.client = MongoClient("mongodb+srv://test.mp8koe0.mongodb.net/myFirstDatabase", username="adityasahu4321", password="789456")
        self.db = self.client.test
        self.collection = self.db.test

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


    async def get_current_user(token: str = Depends(oauth2_scheme)):
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            token_data = TokenData(username=username)
        except JWTError:
            raise credentials_exception
        user = get_user(fake_users_db, username=token_data.username)
        if user is None:
            raise credentials_exception
        return user


    async def get_current_active_user(current_user: User = Depends(get_current_user)):
        if current_user.disabled:
            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins = ["*"],
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = Oauth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user")
async def new_user(user: User):
    current_user = {"username"    : user.username,
                    "email"       : user.email,
                    "full_name"   : user.full_name,
                    "disabled"    : user.disabled}
    current_user["password"] = get_password_hash(user.password)
    db.insert(current_user)
    return {"status": "OK"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(Oauth.get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(Oauth.get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


uvicorn.run(app=app)
# print(get_password_hash("789456"))