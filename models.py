from database import Base
from sqlalchemy import Column, String, Integer, Boolean, Float, DateTime, ForeignKey
from datetime import datetime

class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index= True)
    email = Column(String, unique=True)
    img_url = Column(String, nullable=True)
    username = Column(String, unique=True)
    firstname = Column(String)
    lastname = Column(String)
    phone_number = Column(String)
    hash_password = Column(String)
    role = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)

class Products(Base):
    __tablename__= "products"
    id = Column(Integer, index=True, primary_key=True)
    img_url = Column(String, nullable=True)
    title = Column(String)
    description = Column(String)
    price = Column(Integer)
    is_available = Column(Boolean, default=True)


class Orders(Base):
    __tablename__= "orders"

    id = Column(Integer, index=True, primary_key=True)
    product_id = Column(Integer, ForeignKey("products.id"))
    customer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    customer_phone = Column(String) 
    bill = Column(Float)

class PasswordResetOtp(Base):
    __tablename__ = "password_reset_otp"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    otp = Column(String,nullable=False)
    expires_at = Column(DateTime,nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)