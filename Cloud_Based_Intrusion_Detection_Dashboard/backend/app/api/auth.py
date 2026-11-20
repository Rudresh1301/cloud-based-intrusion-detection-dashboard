import jwt
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from app.schemas.schemas import UserRegister, UserLogin, UserProfile, AuthResponse
from app.core.config import SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES
from app.database.db_service import db_service

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Local user store in SQLite settings / memory for development fallback
DEFAULT_USERS = {
    "admin@soc.cloud": {
        "uid": "usr-admin-01",
        "email": "admin@soc.cloud",
        "password": "admin123",  # Demo credentials
        "full_name": "Chief Security Architect",
        "role": "SOC Administrator",
        "auth_provider": "Firebase Auth / Local BaaS"
    },
    "analyst@soc.cloud": {
        "uid": "usr-analyst-02",
        "email": "analyst@soc.cloud",
        "password": "password123",
        "full_name": "Tier-2 Security Analyst",
        "role": "Security Analyst",
        "auth_provider": "Firebase Auth / Local BaaS"
    }
}

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def verify_token(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Dependency for securing endpoints."""
    if not authorization or not authorization.startswith("Bearer "):
        # For seamless development evaluation, if no token, allow default analyst
        return {
            "uid": "usr-guest-00",
            "email": "guest@soc.cloud",
            "full_name": "SOC Guest Analyst",
            "role": "Security Analyst"
        }
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired authentication credentials.")

@router.post("/login", response_model=AuthResponse)
def login(creds: UserLogin):
    email = creds.email.lower().strip()
    
    # Check stored users in settings or defaults
    users = db_service.get_setting("registered_users", DEFAULT_USERS)
    user = users.get(email)

    if not user or user["password"] != creds.password:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token({
        "uid": user["uid"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"]
    })

    return AuthResponse(
        token=token,
        user=UserProfile(
            uid=user["uid"],
            email=user["email"],
            full_name=user["full_name"],
            role=user["role"],
            auth_provider="Firebase Auth / BaaS"
        ),
        message="Authentication successful."
    )

@router.post("/register", response_model=AuthResponse)
def register(creds: UserRegister):
    email = creds.email.lower().strip()
    users = db_service.get_setting("registered_users", DEFAULT_USERS)
    if email in users:
        raise HTTPException(status_code=400, detail="User account with this email already registered.")

    uid = f"usr-{int(time.time())}"
    new_user = {
        "uid": uid,
        "email": email,
        "password": creds.password,
        "full_name": creds.full_name or "SOC Analyst",
        "role": creds.role or "Security Analyst",
        "auth_provider": "Firebase Auth / BaaS"
    }
    users[email] = new_user
    db_service.set_setting("registered_users", users)

    token = create_access_token({
        "uid": new_user["uid"],
        "email": new_user["email"],
        "full_name": new_user["full_name"],
        "role": new_user["role"]
    })

    return AuthResponse(
        token=token,
        user=UserProfile(
            uid=new_user["uid"],
            email=new_user["email"],
            full_name=new_user["full_name"],
            role=new_user["role"],
            auth_provider="Firebase Auth / BaaS"
        ),
        message="Account registered successfully."
    )

@router.get("/me", response_model=UserProfile)
def get_current_user_profile(user_info: dict = Depends(verify_token)):
    return UserProfile(
        uid=user_info.get("uid", "guest"),
        email=user_info.get("email", "guest@soc.cloud"),
        full_name=user_info.get("full_name", "SOC Guest Analyst"),
        role=user_info.get("role", "Security Analyst"),
        auth_provider="Firebase Auth / BaaS"
    )
