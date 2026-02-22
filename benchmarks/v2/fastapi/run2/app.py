import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"

app = FastAPI(title="User Profile Service")

profiles: dict[str, dict] = {}
username_index: dict[str, str] = {}
email_index: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def decode_token(authorization: str = Header(...)) -> str:
    if not JWT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "JWT_SECRET is not configured"},
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid authorization header format"},
        )

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Token has expired"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Token is invalid"},
        )

    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Token missing sub claim"},
        )
    return sub


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    display_name: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError(
                "username must be 3-30 characters, alphanumeric or underscore"
            )
        return v

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: str) -> str:
        if not (1 <= len(v) <= 100):
            raise ValueError("display_name must be between 1 and 100 characters")
        return v


class UpdateUserRequest(BaseModel):
    display_name: str

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: str) -> str:
        if not (1 <= len(v) <= 100):
            raise ValueError("display_name must be between 1 and 100 characters")
        return v


class FullProfileResponse(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: str


class PublicProfileResponse(BaseModel):
    id: str
    username: str
    display_name: str


class DeletedResponse(BaseModel):
    deleted: bool


class HealthResponse(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_view(record: dict) -> dict:
    return {
        "id": record["id"],
        "username": record["username"],
        "email": record["email"],
        "display_name": record["display_name"],
        "created_at": record["created_at"],
    }


def _public_view(record: dict) -> dict:
    return {
        "id": record["id"],
        "username": record["username"],
        "display_name": record["display_name"],
    }


# ---------------------------------------------------------------------------
# Validation error handler
# ---------------------------------------------------------------------------

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request, exc: RequestValidationError):
    messages = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"] if p != "body")
        messages.append(f"{loc}: {err['msg']}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "Validation failed", "details": messages},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/users", status_code=status.HTTP_201_CREATED, response_model=FullProfileResponse)
async def create_user(body: CreateUserRequest, caller: str = Depends(decode_token)):
    lower_username = body.username.lower()
    lower_email = body.email.lower()

    if lower_username in username_index:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "Username already taken"},
        )

    if lower_email in email_index:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "Email already registered"},
        )

    profile_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "id": profile_id,
        "username": body.username,
        "email": body.email,
        "display_name": body.display_name,
        "owner_id": caller,
        "created_at": now,
    }

    profiles[profile_id] = record
    username_index[lower_username] = profile_id
    email_index[lower_email] = profile_id

    return _full_view(record)


@app.get("/users/{user_id}")
async def get_user(user_id: str, caller: str = Depends(decode_token)):
    record = profiles.get(user_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "User not found"},
        )

    if caller == record["owner_id"]:
        return _full_view(record)
    return _public_view(record)


@app.put("/users/{user_id}", response_model=FullProfileResponse)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    caller: str = Depends(decode_token),
):
    record = profiles.get(user_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "User not found"},
        )

    if caller != record["owner_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Not authorized to update this profile"},
        )

    record["display_name"] = body.display_name
    return _full_view(record)


@app.delete("/users/{user_id}", response_model=DeletedResponse)
async def delete_user(user_id: str, caller: str = Depends(decode_token)):
    record = profiles.get(user_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "User not found"},
        )

    if caller != record["owner_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Not authorized to delete this profile"},
        )

    username_index.pop(record["username"].lower(), None)
    email_index.pop(record["email"].lower(), None)
    del profiles[user_id]

    return {"deleted": True}


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return {"status": "ok"}
