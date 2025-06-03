from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta, date
import os
import uuid
from pymongo import MongoClient
from jose import JWTError, jwt
from passlib.context import CryptContext
import uvicorn

app = FastAPI()

# Security
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URL)
db = client.habit_tracker

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    id: str
    email: str
    name: str

class Habit(BaseModel):
    name: str
    description: Optional[str] = None
    color: Optional[str] = "#8b5cf6"  # Default purple
    category: Optional[str] = "General"

class HabitUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    color: Optional[str] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None

class DailyRecord(BaseModel):
    habit_id: str
    date: str  # YYYY-MM-DD format
    completed: bool
    notes: Optional[str] = None

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.users.find_one({"id": user_id})
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.get("/")
async def root():
    return {"message": "Habit Tracker API"}

@app.post("/api/auth/register", response_model=Token)
async def register(user: UserRegister):
    # Check if user already exists
    if db.users.find_one({"email": user.email}):
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Create new user
    user_id = str(uuid.uuid4())
    hashed_password = get_password_hash(user.password)
    new_user = {
        "id": user_id,
        "email": user.email,
        "name": user.name,
        "password": hashed_password,
        "created_at": datetime.utcnow()
    }
    
    db.users.insert_one(new_user)
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_id}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=Token)
async def login(user: UserLogin):
    db_user = db.users.find_one({"email": user.email})
    if not db_user or not verify_password(user.password, db_user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": db_user["id"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me", response_model=User)
async def get_me(current_user: dict = Depends(get_current_user)):
    return User(
        id=current_user["id"],
        email=current_user["email"],
        name=current_user["name"]
    )

@app.get("/api/habits")
async def get_habits(current_user: dict = Depends(get_current_user)):
    habits = list(db.habits.find(
        {"user_id": current_user["id"], "is_active": True},
        {"_id": 0}
    ))
    return habits

@app.post("/api/habits")
async def create_habit(habit: Habit, current_user: dict = Depends(get_current_user)):
    habit_id = str(uuid.uuid4())
    habit_dict = habit.dict()
    habit_dict.update({
        "id": habit_id,
        "user_id": current_user["id"],
        "created_at": datetime.utcnow().isoformat(),
        "is_active": True
    })
    
    # Insert the habit (exclude _id field)
    result = db.habits.insert_one(habit_dict)
    
    # Automatically create a daily record for today
    today_date = date.today().strftime("%Y-%m-%d")
    daily_record = {
        "id": str(uuid.uuid4()),
        "user_id": current_user["id"],
        "habit_id": habit_id,
        "date": today_date,
        "completed": False,
        "notes": None,
        "completion_time": None
    }
    
    # Insert today's record for this habit
    db.daily_records.insert_one(daily_record)
    
    # Return the habit without any MongoDB ObjectId
    return {
        "id": habit_id,
        "name": habit_dict["name"],
        "description": habit_dict.get("description"),
        "color": habit_dict["color"],
        "category": habit_dict["category"],
        "user_id": current_user["id"],
        "created_at": habit_dict["created_at"],
        "is_active": True
    }

@app.put("/api/habits/{habit_id}")
async def update_habit(
    habit_id: str, 
    habit_update: HabitUpdate, 
    current_user: dict = Depends(get_current_user)
):
    update_data = {k: v for k, v in habit_update.dict().items() if v is not None}
    
    result = db.habits.update_one(
        {"id": habit_id, "user_id": current_user["id"]},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    return {"message": "Habit updated successfully"}

@app.delete("/api/habits/{habit_id}")
async def delete_habit(habit_id: str, current_user: dict = Depends(get_current_user)):
    result = db.habits.update_one(
        {"id": habit_id, "user_id": current_user["id"]},
        {"$set": {"is_active": False}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    return {"message": "Habit deleted successfully"}

@app.get("/api/records/{record_date}")
async def get_daily_records(record_date: str, current_user: dict = Depends(get_current_user)):
    records = list(db.daily_records.find(
        {"user_id": current_user["id"], "date": record_date},
        {"_id": 0}
    ))
    return records

@app.post("/api/records")
async def update_daily_record(record: DailyRecord, current_user: dict = Depends(get_current_user)):
    # Check if habit belongs to user
    habit = db.habits.find_one({"id": record.habit_id, "user_id": current_user["id"]})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    record_id = str(uuid.uuid4())
    record_dict = record.dict()
    record_dict.update({
        "id": record_id,
        "user_id": current_user["id"],
        "completion_time": datetime.utcnow() if record.completed else None
    })
    
    # Update or insert record
    result = db.daily_records.update_one(
        {"user_id": current_user["id"], "habit_id": record.habit_id, "date": record.date},
        {"$set": record_dict},
        upsert=True
    )
    
    return {"message": "Record updated successfully"}

@app.get("/api/analytics/streak/{habit_id}")
async def get_habit_streak(habit_id: str, current_user: dict = Depends(get_current_user)):
    # Check if habit belongs to user
    habit = db.habits.find_one({"id": habit_id, "user_id": current_user["id"]})
    if not habit:
        raise HTTPException(status_code=404, detail="Habit not found")
    
    # Get all records for this habit, sorted by date descending
    records = list(db.daily_records.find(
        {"user_id": current_user["id"], "habit_id": habit_id},
        {"_id": 0}
    ).sort("date", -1))
    
    current_streak = 0
    longest_streak = 0
    temp_streak = 0
    
    # Calculate streaks
    for record in records:
        if record["completed"]:
            temp_streak += 1
            longest_streak = max(longest_streak, temp_streak)
        else:
            temp_streak = 0
    
    # Current streak calculation (from today backwards)
    today = date.today()
    check_date = today
    
    while True:
        date_str = check_date.strftime("%Y-%m-%d")
        record = next((r for r in records if r["date"] == date_str), None)
        
        if record and record["completed"]:
            current_streak += 1
            check_date = check_date - timedelta(days=1)
        else:
            break
    
    return {
        "current_streak": current_streak,
        "longest_streak": longest_streak,
        "total_completions": sum(1 for r in records if r["completed"]),
        "total_days": len(records)
    }

@app.get("/api/analytics/weekly")
async def get_weekly_analytics(current_user: dict = Depends(get_current_user)):
    # Get last 7 days
    today = date.today()
    week_dates = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
    
    # Get all records for the week
    records = list(db.daily_records.find(
        {
            "user_id": current_user["id"],
            "date": {"$in": week_dates}
        },
        {"_id": 0}
    ))
    
    # Get all user habits
    habits = list(db.habits.find(
        {"user_id": current_user["id"], "is_active": True},
        {"_id": 0}
    ))
    
    # Calculate completion data for each day
    daily_stats = []
    for date_str in week_dates:
        day_records = [r for r in records if r["date"] == date_str]
        completed_count = sum(1 for r in day_records if r["completed"])
        total_habits = len(habits)
        
        daily_stats.append({
            "date": date_str,
            "completed": completed_count,
            "total": total_habits,
            "percentage": (completed_count / total_habits * 100) if total_habits > 0 else 0
        })
    
    return {
        "daily_stats": daily_stats,
        "week_average": sum(day["percentage"] for day in daily_stats) / 7 if daily_stats else 0
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)