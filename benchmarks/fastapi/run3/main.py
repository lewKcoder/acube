"""
User CRUD API
FastAPI application with JWT authentication and in-memory storage.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr, field_validator
import jwt

# --- Configuration ---
JWT_SECRET = "super-secret-key-please-change"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 1

# --- App Setup ---
app = FastAPI(
    title="User Management API",
    description="A simple User CRUD API with JWT authentication",
    version="1.0.0",
)

# In-memory database
user_store: dict[str, dict[str, Any]] = {}

security = HTTPBearer()


# --- Custom Exception Handler ---

class APIError(Exception):
    def __init__(self, status_code: int, error: str, message: str):
        self.status_code = status_code
        self.error = error
        self.message = message


@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error,
            "message": exc.message,
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "request_error",
            "message": exc.detail,
        },
    )


# --- Pydantic Models ---

class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        description="Alphanumeric username, 3-30 characters",
    )
    email: EmailStr = Field(..., description="Valid email address")
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Display name, 1-100 characters",
    )

    @field_validator("username")
    @classmethod
    def username_must_be_alphanumeric(cls, v: str) -> str:
        if not v.isalnum():
            raise ValueError("Username must contain only alphanumeric characters")
        return v

    @field_validator("display_name")
    @classmethod
    def display_name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Display name cannot be blank or whitespace only")
        return v


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: str


class DeleteResponse(BaseModel):
    message: str
    deleted_id: str


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str


# --- Auth ---

def decode_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Decode and validate a JWT bearer token."""
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
        if "sub" not in payload:
            raise APIError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error="invalid_token",
                message="Token missing 'sub' claim",
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise APIError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="token_expired",
            message="The provided token has expired",
        )
    except jwt.InvalidTokenError:
        raise APIError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="invalid_token",
            message="The provided token is invalid",
        )


# --- Routes ---

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Health check endpoint. No authentication required."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version="1.0.0",
    )


@app.post(
    "/users",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Users"],
)
async def create_user(
    user_data: UserCreate,
    auth: dict = Depends(decode_jwt),
):
    """
    Create a new user.

    Validates that username and email are unique before creating.
    """
    # Check for duplicate username or email
    for existing in user_store.values():
        if existing["username"].lower() == user_data.username.lower():
            raise APIError(
                status_code=status.HTTP_409_CONFLICT,
                error="duplicate_username",
                message=f"Username '{user_data.username}' is already taken",
            )
        if existing["email"].lower() == user_data.email.lower():
            raise APIError(
                status_code=status.HTTP_409_CONFLICT,
                error="duplicate_email",
                message=f"Email '{user_data.email}' is already registered",
            )

    user_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()

    user_record = {
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "display_name": user_data.display_name,
        "created_at": now,
    }

    user_store[user_id] = user_record

    return UserOut(**user_record)


@app.get("/users/{user_id}", response_model=UserOut, tags=["Users"])
async def get_user(
    user_id: str,
    auth: dict = Depends(decode_jwt),
):
    """Retrieve a user by their ID."""
    if user_id not in user_store:
        raise APIError(
            status_code=status.HTTP_404_NOT_FOUND,
            error="user_not_found",
            message=f"No user found with ID '{user_id}'",
        )
    return UserOut(**user_store[user_id])


@app.delete("/users/{user_id}", response_model=DeleteResponse, tags=["Users"])
async def delete_user(
    user_id: str,
    auth: dict = Depends(decode_jwt),
):
    """Delete a user by their ID."""
    if user_id not in user_store:
        raise APIError(
            status_code=status.HTTP_404_NOT_FOUND,
            error="user_not_found",
            message=f"No user found with ID '{user_id}'",
        )

    del user_store[user_id]

    return DeleteResponse(
        message="User successfully deleted",
        deleted_id=user_id,
    )


# --- Test token endpoint ---

@app.post("/auth/token", tags=["Auth"])
async def get_test_token():
    """Generate a test JWT token for development/testing."""
    payload = {
        "sub": "test-admin",
        "role": "admin",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": TOKEN_EXPIRY_HOURS * 3600,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
