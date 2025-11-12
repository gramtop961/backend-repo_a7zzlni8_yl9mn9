import os
import secrets
import hashlib
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from database import db, create_document, get_documents

app = FastAPI(title="Lernify Road API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# Utils
# ----------------------

def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return {"hash": dk.hex(), "salt": salt}


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    return hash_password(password, salt)["hash"] == password_hash


def auth_dependency(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization token")
    token = authorization.replace("Bearer ", "").strip()
    user = db["user"].find_one({"tokens": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    user["id"] = str(user.get("_id"))
    return user

# ----------------------
# Data models
# ----------------------

ALLOWED_QUALIFICATIONS = {
    "BCA", "MCA", "BSc CS", "MSc CS", "B.Tech CSE", "BE CSE", "B.Tech IT", "BE IT",
    "Data Science", "AI/ML", "Computer Engineering", "Information Technology"
}

DOMAINS = [
    "Frontend Development",
    "Backend Development",
    "AI/ML"
]

# Simple in-code roadmaps (can be expanded or moved to DB later)
ROADMAP: Dict[str, List[Dict[str, Any]]] = {
    "Frontend Development": [
        {
            "index": 1,
            "title": "HTML & CSS Basics",
            "description": "Learn structure and styling.",
            "videos": [
                "https://www.youtube.com/watch?v=G3e-cpL7ofc",
                "https://www.youtube.com/watch?v=1Rs2ND1ryYc"
            ],
            "quiz": {
                "questions": [
                    {"q": "HTML stands for?", "a": ["HyperText Markup Language", "Hyperlinks and Text Markup Language"], "correct": 0},
                    {"q": "CSS is used for?", "a": ["Styling", "Database"], "correct": 0}
                ]
            }
        },
        {
            "index": 2,
            "title": "JavaScript Fundamentals",
            "description": "Variables, functions, DOM.",
            "videos": ["https://www.youtube.com/watch?v=PkZNo7MFNFg"],
            "quiz": {
                "questions": [
                    {"q": "typeof null is?", "a": ["object", "null"], "correct": 0}
                ]
            }
        },
        {
            "index": 3,
            "title": "React Basics",
            "description": "Components and hooks.",
            "videos": ["https://www.youtube.com/watch?v=bMknfKXIFA8"],
            "quiz": {
                "questions": [
                    {"q": "React is a ...", "a": ["library", "framework"], "correct": 0}
                ]
            }
        }
    ],
    "Backend Development": [
        {
            "index": 1,
            "title": "HTTP & REST",
            "description": "Understand APIs.",
            "videos": ["https://www.youtube.com/watch?v=Q-BpqyOT3a8"],
            "quiz": {
                "questions": [
                    {"q": "HTTP status 200 means?", "a": ["OK", "Not Found"], "correct": 0}
                ]
            }
        },
        {
            "index": 2,
            "title": "Databases",
            "description": "SQL vs NoSQL.",
            "videos": ["https://www.youtube.com/watch?v=ztHopE5Wnpc"],
            "quiz": {
                "questions": [
                    {"q": "MongoDB is ...", "a": ["NoSQL", "SQL"], "correct": 0}
                ]
            }
        }
    ],
    "AI/ML": [
        {
            "index": 1,
            "title": "Python Basics",
            "description": "Syntax and data structures.",
            "videos": ["https://www.youtube.com/watch?v=_uQrJ0TkZlc"],
            "quiz": {
                "questions": [
                    {"q": "Which is a list?", "a": ["[1,2,3]", "(1,2,3)"], "correct": 0}
                ]
            }
        },
        {
            "index": 2,
            "title": "NumPy & Pandas",
            "description": "Data handling.",
            "videos": ["https://www.youtube.com/watch?v=vmEHCJofslg"],
            "quiz": {
                "questions": [
                    {"q": "Pandas primary structure?", "a": ["DataFrame", "Tensor"], "correct": 0}
                ]
            }
        }
    ]
}

# ----------------------
# Schemas
# ----------------------

class RegisterBody(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=15)
    qualification: str
    password: str = Field(..., min_length=6, max_length=128)

class LoginBody(BaseModel):
    email: EmailStr
    password: str

class ChangePasswordBody(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6, max_length=128)

class SubmitAssessmentBody(BaseModel):
    domain: str
    step_index: int
    answers: List[int]

class ResumeBody(BaseModel):
    summary: str
    skills: List[str]
    education: List[Dict[str, Any]]
    experience: List[Dict[str, Any]]
    projects: List[Dict[str, Any]]

# ----------------------
# Auth Routes
# ----------------------

@app.post("/auth/register")
def register(body: RegisterBody):
    if body.qualification not in ALLOWED_QUALIFICATIONS:
        raise HTTPException(status_code=400, detail="Only IT-related student qualifications are allowed")

    existing = db["user"].find_one({"email": body.email.lower()})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    hp = hash_password(body.password)
    user_doc = {
        "first_name": body.first_name.strip(),
        "last_name": body.last_name.strip(),
        "email": body.email.lower(),
        "phone": body.phone.strip(),
        "qualification": body.qualification,
        "password_hash": hp["hash"],
        "salt": hp["salt"],
        "domains": [],
        "tokens": [],
        "progress": {},  # e.g., {"Frontend Development": 1}
    }
    _id = create_document("user", user_doc)
    return {"ok": True, "user_id": _id}

@app.post("/auth/login")
def login(body: LoginBody):
    user = db["user"].find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user.get("salt"), user.get("password_hash")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(24)
    db["user"].update_one({"_id": user["_id"]}, {"$addToSet": {"tokens": token}})
    return {"token": token, "first_name": user.get("first_name"), "last_name": user.get("last_name")}

@app.post("/auth/change-password")
def change_password(body: ChangePasswordBody, user=Depends(auth_dependency)):
    if not verify_password(body.old_password, user.get("salt"), user.get("password_hash")):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    hp = hash_password(body.new_password)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": hp["hash"], "salt": hp["salt"]}})
    return {"ok": True}

# ----------------------
# Core Data Routes
# ----------------------

@app.get("/domains")
def get_domains():
    return {"domains": DOMAINS}

@app.get("/roadmap/{domain}")
def get_roadmap(domain: str, user=Depends(auth_dependency)):
    if domain not in ROADMAP:
        raise HTTPException(status_code=404, detail="Domain not found")
    progress_for_domain = (user.get("progress") or {}).get(domain, 0)
    steps = ROADMAP[domain]
    # Mark locked based on progress
    enriched = []
    for step in steps:
        locked = step["index"] > progress_for_domain + 1
        enriched.append({**step, "locked": locked})
    return {"steps": enriched, "progress": progress_for_domain}

@app.post("/assessment/submit")
def submit_assessment(body: SubmitAssessmentBody, user=Depends(auth_dependency)):
    if body.domain not in ROADMAP:
        raise HTTPException(status_code=404, detail="Domain not found")
    steps = ROADMAP[body.domain]
    step = next((s for s in steps if s["index"] == body.step_index), None)
    if not step:
        raise HTTPException(status_code=404, detail="Step not found")

    current_progress = (user.get("progress") or {}).get(body.domain, 0)
    if body.step_index != current_progress + 1:
        raise HTTPException(status_code=400, detail="You must complete previous step first")

    questions = step["quiz"]["questions"]
    if len(body.answers) != len(questions):
        raise HTTPException(status_code=400, detail="Answer count mismatch")

    score = 0
    for i, q in enumerate(questions):
        if body.answers[i] == q["correct"]:
            score += 1
    total = len(questions)

    # Save attempt
    attempt_doc = {
        "user_id": str(user["_id"]),
        "domain": body.domain,
        "step_index": body.step_index,
        "score": score,
        "total": total,
    }
    create_document("attempt", attempt_doc)

    # Update progress if passed (>= 60%)
    passed = (score / max(total, 1)) >= 0.6
    if passed:
        db["user"].update_one({"_id": user["_id"]}, {"$set": {f"progress.{body.domain}": body.step_index}})

    return {"score": score, "total": total, "passed": passed}

# ----------------------
# Profile & Dashboard
# ----------------------

@app.get("/me")
def get_me(user=Depends(auth_dependency)):
    return {
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "email": user.get("email"),
        "phone": user.get("phone"),
        "qualification": user.get("qualification"),
        "progress": user.get("progress", {}),
    }

class UpdateProfileBody(BaseModel):
    first_name: Optional[str] = Field(None, min_length=2, max_length=50)
    last_name: Optional[str] = Field(None, min_length=2, max_length=50)
    phone: Optional[str] = Field(None, min_length=10, max_length=15)

@app.put("/me")
def update_me(body: UpdateProfileBody, user=Depends(auth_dependency)):
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        db["user"].update_one({"_id": user["_id"]}, {"$set": updates})
    return {"ok": True}

@app.get("/dashboard")
def dashboard(user=Depends(auth_dependency)):
    attempts = list(db["attempt"].find({"user_id": str(user["_id"])}, {"_id": 0}))
    progress = user.get("progress", {})
    # Compute overall progress percentage per domain
    progress_pct = {}
    for domain, steps in ROADMAP.items():
        done = progress.get(domain, 0)
        total = len(steps)
        pct = int((done / max(total, 1)) * 100)
        progress_pct[domain] = pct
    return {"attempts": attempts, "progress": progress_pct}

# ----------------------
# Resume
# ----------------------

@app.post("/resume")
def upsert_resume(body: ResumeBody, user=Depends(auth_dependency)):
    db["resume"].update_one(
        {"user_id": str(user["_id"])},
        {"$set": {
            "user_id": str(user["_id"]),
            "summary": body.summary,
            "skills": body.skills,
            "education": body.education,
            "experience": body.experience,
            "projects": body.projects,
        }},
        upsert=True
    )
    return {"ok": True}

@app.get("/resume")
def get_resume(user=Depends(auth_dependency)):
    data = db["resume"].find_one({"user_id": str(user["_id"])}, {"_id": 0})
    return data or {"summary": "", "skills": [], "education": [], "experience": [], "projects": []}

@app.get("/resume/download")
def download_resume(user=Depends(auth_dependency)):
    data = db["resume"].find_one({"user_id": str(user["_id"])}, {"_id": 0}) or {}
    # Return simple HTML that frontend can render/print to PDF
    skills = ", ".join(data.get("skills", []))
    html = f"""
    <html>
    <head><meta charset='utf-8'><title>Resume</title></head>
    <body style='font-family: Arial, sans-serif; padding: 24px;'>
      <h1 style='margin:0'>{user.get('first_name','')} {user.get('last_name','')}</h1>
      <p style='color:#555;margin:4px 0'>{user.get('email','')} • {user.get('phone','')}</p>
      <h2>Summary</h2>
      <p>{data.get('summary','')}</p>
      <h2>Skills</h2>
      <p>{skills}</p>
      <h2>Education</h2>
      <ul>{''.join([f"<li><strong>{e.get('degree','')}</strong> - {e.get('institution','')} ({e.get('year','')})</li>" for e in data.get('education',[])])}</ul>
      <h2>Experience</h2>
      <ul>{''.join([f"<li><strong>{e.get('role','')}</strong> - {e.get('company','')} ({e.get('duration','')})<br/>{e.get('details','')}</li>" for e in data.get('experience',[])])}</ul>
      <h2>Projects</h2>
      <ul>{''.join([f"<li><strong>{p.get('name','')}</strong>: {p.get('description','')}</li>" for p in data.get('projects',[])])}</ul>
    </body>
    </html>
    """
    return {"html": html}

# ----------------------
# Health
# ----------------------

@app.get("/")
def health():
    return {"ok": True, "message": "Lernify Road backend running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
