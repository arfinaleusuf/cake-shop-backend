from fastapi import APIRouter, Depends,HTTPException
from passlib.context import CryptContext
from typing import Annotated, Optional, Literal
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr
from models import Users, PasswordResetOtp
import random
from database import SessionLocal
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt
from dotenv import load_dotenv
import os
import smtplib
import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

router = APIRouter()
load_dotenv()

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
OAuth2_bearer = OAuth2PasswordBearer(tokenUrl="login")

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

SECRET_KEY = os.getenv("MY_SECRET_KEY")
ALGORITHM = "HS256"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class CreateUsers(BaseModel):
    email: EmailStr
    username: str
    firstname: str
    lastname: str 
    password: str 
    phone_number: str
    img_url: Optional[str] = None
    role: Literal["admin", "customer"] = "customer"

class UpdatePassword(BaseModel):
    current_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class VerifyOtpRequest(BaseModel):
    email: str
    otp: str


class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str

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

user_dependency = Annotated[dict,Depends(get_current_user)]

@router.post('/createuser')
def createuser(db: db_dependency, new_user: CreateUsers):
    user_model = Users(
        email = new_user.email,
        username = new_user.username,
        firstname = new_user.firstname,
        lastname = new_user.lastname,
        hash_password = bcrypt_context.hash(new_user.password),
        is_active = True,
        role = new_user.role,
        phone_number = new_user.phone_number,
        img_url = new_user.img_url
    )
    db.add(user_model)
    db.commit()

    return JSONResponse(status_code=201, content={'messege': 'User added Successfully'})

@router.put("/passwordChange")
def update_password(user: user_dependency,db: db_dependency,update_password: UpdatePassword):
    current_user = db.query(Users).filter(Users.id == user.get("id")).first()

    if current_user is None:
        raise HTTPException(status_code=401,detail="User not found")

    if not bcrypt_context.verify(update_password.current_password,current_user.hash_password):
        raise HTTPException(status_code=401,detail="Wrong password")

    current_user.hash_password = bcrypt_context.hash(update_password.new_password)

    db.commit()

    return {"message": "Password updated successfully"}

def send_email_sync(receiver_email: str, otp: str):
    html_content = f"""
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: auto; padding: 20px;">
        <h2 style="color: #2563eb;">Baking Bliss - Password Reset</h2>
        <p>Hello,</p>
        <p>Your password reset OTP is:</p>
        <h1 style="color: #2563eb; letter-spacing: 6px;">{otp}</h1>
        <p>This OTP will expire in <strong>5 minutes</strong>.</p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <br>
        <p>Thank you,<br><strong>Baking Bliss</strong></p>
    </div>
    """

    message = MIMEMultipart("alternative")
    message["Subject"] = "OTP For Password Reset "
    message["From"] = f"Baking Bliss <{SMTP_EMAIL}>"
    message["To"] = receiver_email

    # HTML বডি সেট করা
    message.attach(MIMEText(html_content, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, receiver_email, message.as_string())
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Email sending failed: {str(e)}"
        )


async def send_otp_email(receiver_email: str, otp: str):
    # smtplib ব্লকিং হওয়ায় ব্যাকগ্রাউন্ড থ্রেডে রান করানো হচ্ছে
    await asyncio.to_thread(send_email_sync, receiver_email, otp)

@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest,db: db_dependency):

    user = db.query(Users).filter(Users.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=404,detail="User not found")

    otp = str(random.randint(100000,999999))

    reset_otp = PasswordResetOtp(
        user_id = user.id,
        otp = bcrypt_context.hash(otp),
        expires_at = datetime.now() + timedelta(minutes=5),
        is_used = False
    )

    await send_otp_email(user.email, otp)

    db.add(reset_otp)

    db.commit()

    return {"message": "OTP sent successfully"}

@router.post("/verify-otp")
def verify_otp(request: VerifyOtpRequest,db: db_dependency):
    user = db.query(Users).filter(Users.email == request.email).first()

    if user is None:
        raise HTTPException(status_code=404,detail="User not found")

    reset_data = (
        db.query(PasswordResetOtp)
        .filter(PasswordResetOtp.user_id == user.id,PasswordResetOtp.is_used == False)
        .order_by(PasswordResetOtp.id.desc()).first()
    )

    if reset_data is None:
        raise HTTPException(status_code=400,detail="OTP not found")

    if reset_data.expires_at < datetime.now():
        raise HTTPException(status_code=400,detail="OTP expired")
    
    if not bcrypt_context.verify(request.otp,reset_data.otp):
        raise HTTPException(status_code=400,detail="Invalid OTP")
    
    return {
        "message": "OTP verified successfully"
    }

@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest,db: db_dependency):
    user = db.query(Users).filter(Users.email == request.email).first()

    if user is None:
        raise HTTPException(status_code=404,detail="User not found")

    reset_data = (
        db.query(PasswordResetOtp)
        .filter(PasswordResetOtp.user_id == user.id,PasswordResetOtp.is_used == False)
        .order_by(PasswordResetOtp.id.desc()).first())

    if reset_data is None:
        raise HTTPException(status_code=400,detail="OTP not found")

    if reset_data.expires_at < datetime.now():
        raise HTTPException(status_code=400,detail="OTP expired")
    
    if not bcrypt_context.verify(request.otp,reset_data.otp):
        raise HTTPException(status_code= 400,detail="Invalid OTP")
    
    user.hash_password = bcrypt_context.hash(request.new_password)
    reset_data.is_used = True

    db.commit()

    return {
        "message": "Password reset successfully"
    }