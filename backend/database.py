# database.py
# Handles all database connections and ORM setup for the Gmail Organizer backend

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
from datetime import datetime
import os

# Load environment variables from .env (local dev) or Railway (production)
load_dotenv()

# Read the DATABASE_URL from environment
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise Exception("DATABASE_URL is not set. Be sure to add it to your .env file for local development.")

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL, echo=False)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()


# ===========================
# MODELS
# ===========================

class UserToken(Base):
    """
    Stores Gmail OAuth tokens per user.
    Adjust/expand fields later as needed.
    """
    __tablename__ = "user_tokens"

    id = Column(Integer, primary_key=True, index=True)
    # Email address of the Gmail account
    email = Column(String(255), unique=True, index=True, nullable=False)
    # Full serialized credentials as JSON string
    token_json = Column(Text, nullable=False)

    # Optional helper fields
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Optional: if you ever want to support multiple Google accounts per app user,
    # you can later add an "app_user_id" column here.


# ===========================
# DB INITIALIZATION
# ===========================

def init_db():
    """
    Creates all tables in the database.
    Use: python init_db.py
    """
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully.")
