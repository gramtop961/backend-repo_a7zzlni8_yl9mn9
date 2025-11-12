"""
Database Schemas for Lernify Road

Each Pydantic model represents a MongoDB collection. The collection name
is the lowercase of the class name (e.g., User -> "user").
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any

class User(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=15)
    qualification: str = Field(..., description="Student qualification")
    password_hash: str
    salt: str
    domains: List[str] = Field(default_factory=list)
    tokens: List[str] = Field(default_factory=list)

class RoadmapStep(BaseModel):
    domain: str
    index: int
    title: str
    description: str
    video_urls: List[str] = Field(default_factory=list)
    quiz: Dict[str, Any] = Field(default_factory=dict)

class Attempt(BaseModel):
    user_id: str
    domain: str
    step_index: int
    score: int
    total: int

class Resume(BaseModel):
    user_id: str
    summary: str
    skills: List[str]
    education: List[Dict[str, Any]]
    experience: List[Dict[str, Any]]
    projects: List[Dict[str, Any]]
