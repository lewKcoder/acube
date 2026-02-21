"""
User CRUD API built with FastAPI.
Provides endpoints for creating, retrieving, and deleting users
with JWT authentication and in-memory storage.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
import jwt

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="User CRUD API", version="1.0.0")

# In-memory storage
users_db: dict[str, dict] = {}

# Security
security = HTTPBearer()


# --- Models ---

class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        pattern=r"^[a-zA-Z0-9]+$",
        description="Username must be 3-30 alphanumeric characters",
    )
    email: EmailStr
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Display name between 1 and 100 characters",
    )


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: str


class MessageResponse(BaseModel):
    message: str


class HealthResponse(BaseModel):
    status: str
    timestamp: str


# --- Auth Helpers ---

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token and return payload."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


# --- Endpoints ---

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint - no authentication required."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Users"],
)
async def create_user(
    user: UserCreate,
    token_data: dict = Depends(verify_token),
):
    """Create a new user."""
    # Check for duplicate username
    for existing_user in users_db.values():
        if existing_user["username"] == user.username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )
        if existing_user["email"] == user.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists",
            )

    user_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()

    user_record = {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "created_at": now,
    }

    users_db[user_id] = user_record

    return UserResponse(**user_record)


@app.get("/users/{user_id}", response_model=UserResponse, tags=["Users"])
async def get_user(
    user_id: str,
    token_data: dict = Depends(verify_token),
):
    """Get a user by ID."""
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return UserResponse(**users_db[user_id])


@app.delete(
    "/users/{user_id}",
    response_model=MessageResponse,
    tags=["Users"],
)
async def delete_user(
    user_id: str,
    token_data: dict = Depends(verify_token),
):
    """Delete a user by ID."""
    if user_id not in users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    del users_db[user_id]
    return MessageResponse(message="User deleted successfully")


# --- Token generation endpoint (for testing) ---

@app.post("/auth/token", tags=["Auth"])
async def generate_token():
    """Generate a JWT token for testing purposes."""
    token = create_access_token(data={"sub": "admin", "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
