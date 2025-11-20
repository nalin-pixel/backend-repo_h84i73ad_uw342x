import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db
from schemas import User as UserSchema, Ticket as TicketSchema, Message as MessageSchema, Session as SessionSchema

app = FastAPI(title="HotHost API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Helpers ----------

def _hash_password(password: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${digest}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, digest = stored_hash.split("$")
    except ValueError:
        return False
    return _hash_password(password, salt) == stored_hash


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------- Auth Models ----------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    token: str
    email: EmailStr
    name: Optional[str]
    role: Literal["user", "support"]


class TicketCreateRequest(BaseModel):
    subject: str
    priority: Literal["low", "medium", "high"] = "medium"


class MessageCreateRequest(BaseModel):
    ticket_id: str
    body: str


# ---------- Startup: ensure support account ----------

SUPPORT_EMAIL = "pepovinea@support.org"
SUPPORT_PASSWORD = "CPtoj123@123"

@app.on_event("startup")
def ensure_support_account():
    if db is None:
        return
    users = db["user"]
    sessions = db["session"]
    tickets = db["ticket"]
    messages = db["message"]
    # Create basic indexes
    users.create_index("email", unique=True)
    sessions.create_index("token", unique=True)
    tickets.create_index("user_id")
    messages.create_index("ticket_id")

    existing = users.find_one({"email": SUPPORT_EMAIL})
    if not existing:
        password_hash = _hash_password(SUPPORT_PASSWORD)
        support_user = UserSchema(email=SUPPORT_EMAIL, password_hash=password_hash, name="Support Agent", role="support")
        doc = support_user.model_dump()
        doc.update({"created_at": _now(), "updated_at": _now()})
        users.insert_one(doc)


# ---------- Auth dependency ----------

def get_current_user(authorization: Optional[str] = Header(None)):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    session = db["session"].find_one({"token": token})
    if not session or session.get("expires_at") < _now():
        raise HTTPException(status_code=401, detail="Session expired")
    user = db["user"].find_one({"_id": session["user_id"]})
    # During creation we store user_id as string; ensure fetch by string id
    if not user:
        user = db["user"].find_one({"_id": session["user_id"]})
    if not user:
        # fallback: try by string field
        user = db["user"].find_one({"_id": session.get("user_id")})
    if not user:
        # alternatively we stored as plain id string in `id`
        user = db["user"].find_one({"id": session.get("user_id")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ---------- Public endpoints ----------

@app.get("/")
def root():
    return {"service": "HotHost API", "status": "ok"}


@app.get("/test")
def test_database():
    resp = {"backend": "running", "database": "not configured"}
    try:
        if db is not None:
            resp["database"] = "connected"
            resp["collections"] = db.list_collection_names()
    except Exception as e:
        resp["database"] = f"error: {str(e)[:80]}"
    return resp


# ---------- Auth endpoints ----------

@app.post("/auth/register", response_model=AuthResponse)
def register(payload: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    users = db["user"]
    if users.find_one({"email": str(payload.email).lower()}):
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = _hash_password(payload.password)
    user_doc = UserSchema(email=str(payload.email).lower(), password_hash=password_hash, name=payload.name, role="user").model_dump()
    user_doc.update({"created_at": _now(), "updated_at": _now()})
    res = users.insert_one(user_doc)
    user_id = str(res.inserted_id)

    token = secrets.token_urlsafe(32)
    session_doc = SessionSchema(user_id=user_id, token=token, expires_at=_now() + timedelta(days=30)).model_dump()
    session_doc.update({"created_at": _now(), "updated_at": _now()})
    db["session"].insert_one(session_doc)

    return AuthResponse(token=token, email=payload.email, name=payload.name, role="user")


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": str(payload.email).lower()})
    if not user or not _verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = secrets.token_urlsafe(32)
    session_doc = SessionSchema(user_id=str(user.get("_id")), token=token, expires_at=_now() + timedelta(days=30)).model_dump()
    session_doc.update({"created_at": _now(), "updated_at": _now()})
    db["session"].insert_one(session_doc)

    return AuthResponse(token=token, email=user["email"], name=user.get("name"), role=user.get("role", "user"))


@app.get("/auth/me")
def me(user=Depends(get_current_user)):
    return {
        "email": user.get("email"),
        "name": user.get("name"),
        "role": user.get("role", "user"),
        "id": str(user.get("_id"))
    }


# ---------- Ticketing endpoints ----------

@app.post("/tickets")
def create_ticket(payload: TicketCreateRequest, user=Depends(get_current_user)):
    ticket = TicketSchema(user_id=str(user.get("_id")), subject=payload.subject, priority=payload.priority)
    doc = ticket.model_dump()
    doc.update({"created_at": _now(), "updated_at": _now()})
    res = db["ticket"].insert_one(doc)
    return {"id": str(res.inserted_id), **doc}


@app.get("/tickets")
def list_tickets(user=Depends(get_current_user)):
    collection = db["ticket"]
    if user.get("role") == "support":
        tickets = list(collection.find({}).sort("created_at", -1))
    else:
        tickets = list(collection.find({"user_id": str(user.get("_id"))}).sort("created_at", -1))
    for t in tickets:
        t["id"] = str(t.pop("_id"))
    return tickets


@app.post("/tickets/{ticket_id}/message")
def post_message(ticket_id: str, payload: MessageCreateRequest, user=Depends(get_current_user)):
    # Validate access
    ticket = db["ticket"].find_one({"_id": None})
    # We stored _id as ObjectId automatically; to keep things simple, we stored custom string ids earlier
    # Since we used default insert_one, _id is ObjectId. We'll allow by comparing string forms.
    t = db["ticket"].find_one({"_id": {"$exists": True}})
    from bson import ObjectId
    try:
        obj_id = ObjectId(ticket_id)
        ticket = db["ticket"].find_one({"_id": obj_id})
    except Exception:
        ticket = db["ticket"].find_one({"_id": ticket_id})

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if user.get("role") != "support" and str(ticket.get("user_id")) != str(user.get("_id")):
        raise HTTPException(status_code=403, detail="Not allowed")

    msg = MessageSchema(ticket_id=str(ticket.get("_id")), user_id=str(user.get("_id")), body=payload.body, from_role=user.get("role", "user")).model_dump()
    msg.update({"created_at": _now(), "updated_at": _now()})
    res = db["message"].insert_one(msg)
    return {"id": str(res.inserted_id), **msg}


@app.get("/tickets/{ticket_id}/messages")
def list_messages(ticket_id: str, user=Depends(get_current_user)):
    from bson import ObjectId
    try:
        obj_id = ObjectId(ticket_id)
        ticket = db["ticket"].find_one({"_id": obj_id})
    except Exception:
        ticket = db["ticket"].find_one({"_id": ticket_id})

    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if user.get("role") != "support" and str(ticket.get("user_id")) != str(user.get("_id")):
        raise HTTPException(status_code=403, detail="Not allowed")

    msgs = list(db["message"].find({"ticket_id": str(ticket.get("_id"))}).sort("created_at", 1))
    for m in msgs:
        m["id"] = str(m.pop("_id"))
    return msgs


@app.post("/tickets/{ticket_id}/status")
def set_ticket_status(ticket_id: str, status: Literal["open", "closed"], user=Depends(get_current_user)):
    if user.get("role") != "support":
        raise HTTPException(status_code=403, detail="Only support can change status")
    from bson import ObjectId
    try:
        obj_id = ObjectId(ticket_id)
        ticket = db["ticket"].find_one({"_id": obj_id})
    except Exception:
        ticket = db["ticket"].find_one({"_id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    db["ticket"].update_one({"_id": ticket["_id"]}, {"$set": {"status": status, "updated_at": _now()}})
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
