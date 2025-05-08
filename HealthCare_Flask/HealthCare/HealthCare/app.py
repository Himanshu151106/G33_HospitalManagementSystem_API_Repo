from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from your_model_file import User  # Adjust the import according to your project structure

engine = create_engine('your_database_url')  # Replace with your actual database URL
Session = sessionmaker(bind=engine)
session = Session()

def get_user(user_id):
    return session.get(User, int(user_id))