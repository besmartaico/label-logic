# database.py
# Handles all database connections and ORM setup for the Gmail Organizer backend

from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

# Load environment variables from .env (local dev) or Railway (production)
load_dotenv()

# Read the DATABASE_URL from environment
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise Exception("DATABASE_URL is not set. Be sure to add it to your .env file for local development.")

# Create SQLAlchemy engine
# For PostgreSQL, no special connect_args are required
engine = create_engine(DATABASE_URL, echo=False)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()

#############################################
# YOUR MODELS GO HERE
#############################################

# Example model (uncomment and modify once your models are defined)
#
# class User(Base):
#     __tablename__ = "users"
#     id = Column(Integer, primary_key=True, index=True)
#     email = Column(String(255), unique=True, index=True)
#     refresh_token = Column(Text)
#     created_at = Column(DateTime)
#
# Add your actual Label Logic tables here (Rules, Users, Suggestions, etc.)

#############################################
# Initialize database + create all tables
#############################################

def init_db():
    """
    Creates all tables in the database.
    Use: python init_db.py
    """
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully.")
