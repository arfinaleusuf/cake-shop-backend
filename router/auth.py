from fastapi import APIRouter, Depends,HTTPException
from passlib.context import CryptContext
from typing import Annotated, Optional, Literal
from pydantic import BaseModel, Field
from models import Users
from database import SessionLocal
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt
from dotenv import load_dotenv
import os

router = APIRouter()
load_dotenv()

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
OAuth2_bearer = OAuth2PasswordBearer(tokenUrl="login")

SECRET_KEY = os.getenv("MY_SECRET_KEY")
ALGORITHM = "HS256"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class CreateUsers(BaseModel):
    email: str
    username: str
    firstname: str
    lastname: str
    password: str
    role: Literal["admin", "customer"]

db_dependency = Annotated[Session, Depends(get_db)]

def authenticate_user(username, password, db):
        user = db.query(Users).filter(Users.username == username).first()
        if user is None:
            return False
        
        if bcrypt_context.verify(password, user.hash_password):
            return user
        else:
            return False


def create_access_token(username: str, user_id: int, role: str, expires_delta : timedelta):
    encode = {'sub':username, 'id': user_id, 'role': role}
    expires = datetime.now() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: Annotated[str, Depends(OAuth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        if username is None or user_id is None:
            raise HTTPException(status_code=404, detail='User not Found')
        return{'username': username,'id': user_id, 'role': role}
    except:
        raise HTTPException(status_code=404, detail='User not Found')

    
@router.post("/login")
def login_user(db: db_dependency,form_data: Annotated[OAuth2PasswordRequestForm,Depends()]):

    user = authenticate_user(form_data.username,form_data.password,db)
    if not user:
        raise HTTPException(status_code=401,detail="Incorrect username or password")
    token = create_access_token(user.username,user.id,user.role,timedelta(minutes=30))
    return {"access_token": token,"token_type": "bearer"}