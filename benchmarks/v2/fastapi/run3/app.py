import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, field_validator

app = FastAPI(title="User Profile Service")

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"

profiles: dict[str, dict] = {}
username_index: dict[str, str] = {}
email_index: dict[str, str] = {}

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def decode_token(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Missing or malformed Authorization header"},
        )
    raw_token = authorization[7:]
    try:
        payload = jwt.decode(raw_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": f"Invalid token: {exc}"},
        )
    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Token missing 'sub' claim"},
        )
    return str(sub)


class CreateUserPayload(BaseModel):
    username: str
    email: str
    display_name: str

    @field_validator("username")
    @classmethod
    def check_username(cls, v: str) -> str:
        if not USERNAME_PATTERN.match(v):
            raise ValueError(
                "username must be 3-30 characters, alphanumeric or underscore"
            )
        return v

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        if not EMAIL_PATTERN.match(v):
            raise ValueError("invalid email format")
        return v

    @field_validator("display_name")
    @classmethod
    def check_display_name(cls, v: str) -> str:
        if not (1 <= len(v) <= 100):
            raise ValueError("display_name must be between 1 and 100 characters")
        return v


class UpdateUserPayload(BaseModel):
    display_name: str

    @field_validator("display_name")
    @classmethod
    def check_display_name(cls, v: str) -> str:
        if not (1 <= len(v) <= 100):
            raise ValueError("display_name must be between 1 and 100 characters")
        return v


def full_view(record: dict) -> dict:
    return {
        "id": record["id"],
        "username": record["username"],
        "email": record["email"],
        "display_name": record["display_name"],
        "created_at": record["created_at"],
    }


def public_view(record: dict) -> dict:
    return {
        "id": record["id"],
        "username": record["username"],
        "display_name": record["display_name"],
    }


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    body: CreateUserPayload,
    authorization: Optional[str] = Header(default=None),
):
    caller = decode_token(authorization)

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

    return full_view(record)


@app.get("/users/{user_id}")
def get_user(
    user_id: str,
    authorization: Optional[str] = Header(default=None),
):
    caller = decode_token(authorization)

    record = profiles.get(user_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "User not found"},
        )

    if record["owner_id"] == caller:
        return full_view(record)
    return public_view(record)


@app.put("/users/{user_id}")
def update_user(
    user_id: str,
    body: UpdateUserPayload,
    authorization: Optional[str] = Header(default=None),
):
    caller = decode_token(authorization)

    record = profiles.get(user_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "User not found"},
        )

    if record["owner_id"] != caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Not authorized to modify this profile"},
        )

    record["display_name"] = body.display_name
    return full_view(record)


@app.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    authorization: Optional[str] = Header(default=None),
):
    caller = decode_token(authorization)

    record = profiles.get(user_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "User not found"},
        )

    if record["owner_id"] != caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Not authorized to delete this profile"},
        )

    username_index.pop(record["username"].lower(), None)
    email_index.pop(record["email"].lower(), None)
    del profiles[user_id]

    return {"deleted": True}


from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request, exc: RequestValidationError):
    messages = []
    for err in exc.errors():
        loc = " -> ".join(str(part) for part in err["loc"] if part != "body")
        messages.append(f"{loc}: {err['msg']}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": {"error": "; ".join(messages)}},
    )
