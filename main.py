from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Annotated, Optional
import models
from pydantic import BaseModel,Field
from models import Users, Products, Orders, PasswordResetOtp
from database import SessionLocal, engine
from fastapi.responses import JSONResponse
from router import auth
from router.auth import get_current_user
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI()



origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

models.Base.metadata.create_all(bind=engine)
app.include_router(auth.router)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]