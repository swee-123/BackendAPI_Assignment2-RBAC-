import os
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()  # optional in dev

# ----------------------
# Configuration (env)
# ----------------------
JWT_SECRET = os.getenv("JWT_SECRET", "")  # change in prod
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
# ----------------------

app = FastAPI(title="JWT + RBAC (Argon2) Demo")

# Use Argon2 via passlib. Install passlib[argon2] which brings argon2-cffi.
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# ----------------------
# In-memory "user DB" (demo)
# ----------------------
raw_users = {
    # username: (plain_password, [roles])
    "alice": ("alicepassword", ["user"]),
    "bob": ("bobpassword", ["user", "admin"]),
}

users_db = {}
for username, (plain_pw, roles) in raw_users.items():
    users_db[username] = {
        "username": username,
        "hashed_password": pwd_context.hash(plain_pw),
        "roles": roles,
        "full_name": username.capitalize(),
        "email": f"{username}@example.com",
    }


# ----------------------
# Pydantic schemas
# ----------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: Optional[datetime]


class TokenData(BaseModel):
    username: Optional[str] = None
    roles: List[str] = []


class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = []


# ----------------------
# Helpers: auth, token generation & verification
# ----------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Argon2 supports long passwords; no need to manually truncate.
    """
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = users_db.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(*, data: dict, expires_delta: Optional[timedelta] = None) -> Tuple[str, datetime]:
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt, expire


def decode_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: Optional[str] = payload.get("sub")
        roles = payload.get("roles") or []
        return TokenData(username=username, roles=roles)
    except JWTError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from e


# ----------------------
# Dependencies
# ----------------------
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    token_data = decode_token(token)
    if not token_data.username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    user_entry = users_db.get(token_data.username)
    if not user_entry:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return User(
        username=user_entry["username"],
        full_name=user_entry.get("full_name"),
        email=user_entry.get("email"),
        roles=user_entry.get("roles", []),
    )


def require_role(role: str):
    def dependency(user: User = Depends(get_current_user)):
        if role not in (user.roles or []):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden - missing role")
        return user
    return dependency


# ----------------------
# Routes
# ----------------------
@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Exchange username & password for an access token.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token_payload = {"sub": user["username"], "roles": user.get("roles", [])}
    token, expires_at = create_access_token(data=token_payload)
    return Token(access_token=token, expires_at=expires_at)


@app.get("/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"msg": f"Hello {current_user.username}, you are authenticated.", "roles": current_user.roles}


@app.get("/admin")
async def admin_route(current_user: User = Depends(require_role("admin"))):
    return {"msg": f"Welcome admin {current_user.username}. You may create/manage resources."}


@app.get("/debug/users")
async def list_users():
    # For demo only: shows emails & roles
    return {u: {"roles": users_db[u]["roles"], "email": users_db[u]["email"]} for u in users_db}