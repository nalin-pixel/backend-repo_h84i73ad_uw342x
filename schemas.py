"""
Database Schemas for HotHost.org

Each Pydantic model maps to a MongoDB collection with the model name lowercased.
- User -> user
- Ticket -> ticket
- Message -> message
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import datetime


class User(BaseModel):
    email: EmailStr
    password_hash: str = Field(..., description="SHA256 hash of password with salt")
    name: Optional[str] = None
    role: Literal["user", "support"] = "user"
    avatar: Optional[str] = None


class Ticket(BaseModel):
    user_id: str = Field(..., description="Owner user id as string")
    subject: str
    status: Literal["open", "closed"] = "open"
    priority: Literal["low", "medium", "high"] = "medium"


class Message(BaseModel):
    ticket_id: str
    user_id: str
    body: str
    from_role: Literal["user", "support"] = "user"
    seen: bool = False


class Session(BaseModel):
    user_id: str
    token: str
    expires_at: datetime
