import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator

app = FastAPI(title="User Profile Service")

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"

users_db: dict[str, dict[str, Any]] = {}

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    display_name: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not USERNAME_RE.match(v):
            raise ValueError(
                "username must be 3-30 characters and contain only "
                "alphanumeric characters or underscores"
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


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: str


class PublicUserResponse(BaseModel):
    id: str
    username: str
    display_name: str


class DeleteResponse(BaseModel):
    deleted: bool


class HealthResponse(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def get_current_user_sub(authorization: str = Header(...)) -> str:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
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
    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing sub claim",
        )
    return str(sub)


# ---------------------------------------------------------------------------
# Exception handler for validation errors
# ---------------------------------------------------------------------------

from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Any, exc: RequestValidationError) -> JSONResponse:
    errors = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error["loc"] if loc != "body")
        errors.append({"field": field, "message": error["msg"]})
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "Validation error", "errors": errors},
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    sub: str = Depends(get_current_user_sub),
) -> UserResponse:
    for existing in users_db.values():
        if existing["username"] == body.username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )
        if existing["email"] == body.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists",
            )

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    user = {
        "id": user_id,
        "username": body.username,
        "email": body.email,
        "display_name": body.display_name,
        "owner_id": sub,
        "created_at": now,
    }
    users_db[user_id] = user

    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        display_name=user["display_name"],
        created_at=user["created_at"],
    )


@app.get("/users/{user_id}", response_model=UserResponse | PublicUserResponse)
async def get_user(
    user_id: str,
    sub: str = Depends(get_current_user_sub),
) -> UserResponse | PublicUserResponse:
    user = users_db.get(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user["owner_id"] == sub:
        return UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            display_name=user["display_name"],
            created_at=user["created_at"],
        )

    return PublicUserResponse(
        id=user["id"],
        username=user["username"],
        display_name=user["display_name"],
    )


@app.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    sub: str = Depends(get_current_user_sub),
) -> UserResponse:
    user = users_db.get(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user["owner_id"] != sub:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this profile",
        )

    user["display_name"] = body.display_name

    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        display_name=user["display_name"],
        created_at=user["created_at"],
    )


@app.delete("/users/{user_id}", response_model=DeleteResponse)
async def delete_user(
    user_id: str,
    sub: str = Depends(get_current_user_sub),
) -> DeleteResponse:
    user = users_db.get(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user["owner_id"] != sub:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this profile",
        )

    del users_db[user_id]
    return DeleteResponse(deleted=True)
