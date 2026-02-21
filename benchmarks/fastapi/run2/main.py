"""User CRUD API with FastAPI."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
import jwt

app = FastAPI()

# In-memory user storage
users: dict = {}

# JWT config
SECRET = "secret"
ALGORITHM = "HS256"

security = HTTPBearer()


# Models
class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9]+$")
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=100)


class User(BaseModel):
    id: str
    username: str
    email: str
    display_name: str
    created_at: str


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/users", status_code=201)
def create_user(body: CreateUserRequest, user=Depends(get_current_user)):
    # Check duplicate username
    for u in users.values():
        if u["username"] == body.username:
            raise HTTPException(status_code=400, detail="Username taken")

    uid = str(uuid4())
    record = {
        "id": uid,
        "username": body.username,
        "email": body.email,
        "display_name": body.display_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    users[uid] = record
    return record


@app.get("/users/{user_id}")
def get_user(user_id: str, user=Depends(get_current_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    return users[user_id]


@app.delete("/users/{user_id}")
def delete_user(user_id: str, user=Depends(get_current_user)):
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[user_id]
    return {"message": "User deleted"}


# Helper endpoint to get a token for testing
@app.post("/token")
def login():
    token = jwt.encode(
        {"sub": "testuser", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        SECRET,
        algorithm=ALGORITHM,
    )
    return {"access_token": token}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
