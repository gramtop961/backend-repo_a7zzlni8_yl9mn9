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
    "AI/ML",
    "Full-Stack Development",
    "DevOps",
    "Cloud Computing",
    "Data Engineering",
    "Cybersecurity",
    "Mobile Development",
    "UI/UX Design",
    "QA Automation"
]

# ----------------------
# Roadmap generator with assessments after each step + final 20Q assessment
# ----------------------

def standard_20_questions() -> List[Dict[str, Any]]:
    # Consistent 20 multiple-choice questions applicable across domains
    return [
        {"q": "HTTP status 200 means?", "a": ["OK", "Not Found"], "correct": 0},
        {"q": "Which is a NoSQL DB?", "a": ["MongoDB", "PostgreSQL"], "correct": 0},
        {"q": "Git command to commit?", "a": ["git commit", "git push"], "correct": 0},
        {"q": "JSON.parse converts?", "a": ["string->object", "object->string"], "correct": 0},
        {"q": "Array method to transform items?", "a": ["map", "find"], "correct": 0},
        {"q": "Secure protocol for web?", "a": ["HTTPS", "FTP"], "correct": 0},
        {"q": "Container platform?", "a": ["Docker", "Make"], "correct": 0},
        {"q": "Cloud service model with Functions?", "a": ["FaaS", "IaaS"], "correct": 0},
        {"q": "Primary purpose of CI?", "a": ["Automate builds/tests", "Design UI"], "correct": 0},
        {"q": "DataFrame belongs to?", "a": ["Pandas", "NumPy only"], "correct": 0},
        {"q": "Python list literal?", "a": ["[1,2]", "(1,2)"], "correct": 0},
        {"q": "React is a?", "a": ["library", "database"], "correct": 0},
        {"q": "CSS property for spacing outside?", "a": ["margin", "padding"], "correct": 0},
        {"q": "OWASP item relates to?", "a": ["Web security", "Graphic design"], "correct": 0},
        {"q": "Android primary language?", "a": ["Kotlin", "Swift"], "correct": 0},
        {"q": "UX focuses on?", "a": ["Experience", "Networking"], "correct": 0},
        {"q": "e2e tests simulate?", "a": ["User flows", "Static typing"], "correct": 0},
        {"q": "Key in React lists used for?", "a": ["stable identity", "styling"], "correct": 0},
        {"q": "SQL stands for?", "a": ["Structured Query Language", "Simple Query Logic"], "correct": 0},
        {"q": "Version control platform?", "a": ["GitHub", "Figma"], "correct": 0},
    ]

# Base learning steps per domain
BASE_ROADMAP: Dict[str, List[Dict[str, Any]]] = {
    "Frontend Development": [
        {
            "title": "HTML & CSS Basics",
            "description": "Learn structure and styling.",
            "videos": [
                "https://www.youtube.com/watch?v=G3e-cpL7ofc",
                "https://www.youtube.com/watch?v=1Rs2ND1ryYc"
            ],
            "quiz": {"questions": [
                {"q": "HTML stands for?", "a": ["HyperText Markup Language", "Hyperlinks and Text Markup Language"], "correct": 0},
                {"q": "CSS is used for?", "a": ["Styling", "Database"], "correct": 0}
            ]}
        },
        {
            "title": "JavaScript Fundamentals",
            "description": "Variables, functions, DOM.",
            "videos": ["https://www.youtube.com/watch?v=PkZNo7MFNFg"],
            "quiz": {"questions": [
                {"q": "typeof null is?", "a": ["object", "null"], "correct": 0}
            ]}
        },
        {
            "title": "React Basics",
            "description": "Components and hooks.",
            "videos": ["https://www.youtube.com/watch?v=bMknfKXIFA8"],
            "quiz": {"questions": [
                {"q": "React is a ...", "a": ["library", "framework"], "correct": 0}
            ]}
        },
    ],
    "Backend Development": [
        {
            "title": "HTTP & REST",
            "description": "Understand APIs.",
            "videos": ["https://www.youtube.com/watch?v=Q-BpqyOT3a8"],
            "quiz": {"questions": [
                {"q": "HTTP status 200 means?", "a": ["OK", "Not Found"], "correct": 0}
            ]}
        },
        {
            "title": "Databases",
            "description": "SQL vs NoSQL.",
            "videos": ["https://www.youtube.com/watch?v=ztHopE5Wnpc"],
            "quiz": {"questions": [
                {"q": "MongoDB is ...", "a": ["NoSQL", "SQL"], "correct": 0}
            ]}
        }
    ],
    "AI/ML": [
        {
            "title": "Python Basics",
            "description": "Syntax and data structures.",
            "videos": ["https://www.youtube.com/watch?v=_uQrJ0TkZlc"],
            "quiz": {"questions": [
                {"q": "Which is a list?", "a": ["[1,2,3]", "(1,2,3)"], "correct": 0}
            ]}
        },
        {
            "title": "NumPy & Pandas",
            "description": "Data handling.",
            "videos": ["https://www.youtube.com/watch?v=vmEHCJofslg"],
            "quiz": {"questions": [
                {"q": "Pandas primary structure?", "a": ["DataFrame", "Tensor"], "correct": 0}
            ]}
        }
    ],
    "Full-Stack Development": [
        {
            "title": "Frontend + Backend Basics",
            "description": "Understand client-server and rendering.",
            "videos": ["https://www.youtube.com/watch?v=1Rs2ND1ryYc", "https://www.youtube.com/watch?v=Q-BpqyOT3a8"],
            "quiz": {"questions": [
                {"q": "What is REST?", "a": ["Architectural style", "Programming language"], "correct": 0}
            ]}
        },
        {
            "title": "API integration",
            "description": "Connect frontend to backend APIs.",
            "videos": ["https://www.youtube.com/watch?v=9I8NzKj2sYo"],
            "quiz": {"questions": [
                {"q": "HTTP method to create?", "a": ["POST", "GET"], "correct": 0}
            ]}
        }
    ],
    "DevOps": [
        {
            "title": "Version Control",
            "description": "Git and GitHub.",
            "videos": ["https://www.youtube.com/watch?v=Uszj_k0DGsg"],
            "quiz": {"questions": [
                {"q": "Command to commit?", "a": ["git commit", "git push"], "correct": 0}
            ]}
        },
        {
            "title": "CI/CD Basics",
            "description": "Pipelines and deployments.",
            "videos": ["https://www.youtube.com/watch?v=scEDHsr3APg"],
            "quiz": {"questions": [
                {"q": "CI stands for?", "a": ["Continuous Integration", "Code Injection"], "correct": 0}
            ]}
        }
    ],
    "Cloud Computing": [
        {
            "title": "Cloud Fundamentals",
            "description": "IaaS, PaaS, SaaS.",
            "videos": ["https://www.youtube.com/watch?v=3hLmDS179YE"],
            "quiz": {"questions": [
                {"q": "S3 is?", "a": ["Object storage", "Compute service"], "correct": 0}
            ]}
        },
        {
            "title": "Serverless",
            "description": "Functions as a Service.",
            "videos": ["https://www.youtube.com/watch?v=EBSdyoO3goc"],
            "quiz": {"questions": [
                {"q": "AWS Lambda type?", "a": ["FaaS", "IaaS"], "correct": 0}
            ]}
        }
    ],
    "Data Engineering": [
        {
            "title": "ETL Basics",
            "description": "Extract, Transform, Load.",
            "videos": ["https://www.youtube.com/watch?v=fuP4Kva87m8"],
            "quiz": {"questions": [
                {"q": "T in ETL?", "a": ["Transform", "Transfer"], "correct": 0}
            ]}
        },
        {
            "title": "Big Data Systems",
            "description": "Hadoop/Spark overview.",
            "videos": ["https://www.youtube.com/watch?v=7ooZ4S7Ay6Y"],
            "quiz": {"questions": [
                {"q": "Spark is for?", "a": ["Distributed computing", "Web styling"], "correct": 0}
            ]}
        }
    ],
    "Cybersecurity": [
        {
            "title": "Security Basics",
            "description": "CIA triad.",
            "videos": ["https://www.youtube.com/watch?v=inWWhr5tnEA"],
            "quiz": {"questions": [
                {"q": "CIA triad C?", "a": ["Confidentiality", "Computation"], "correct": 0}
            ]}
        },
        {
            "title": "OWASP Top 10",
            "description": "Common web risks.",
            "videos": ["https://www.youtube.com/watch?v=EoaDgUgS6QA"],
            "quiz": {"questions": [
                {"q": "SQLi targets?", "a": ["Databases", "File system"], "correct": 0}
            ]}
        }
    ],
    "Mobile Development": [
        {
            "title": "Mobile Platforms",
            "description": "Android vs iOS.",
            "videos": ["https://www.youtube.com/watch?v=fis26HvvDII"],
            "quiz": {"questions": [
                {"q": "Android language?", "a": ["Kotlin", "Swift"], "correct": 0}
            ]}
        },
        {
            "title": "Cross-platform",
            "description": "React Native overview.",
            "videos": ["https://www.youtube.com/watch?v=0-S5a0eXPoc"],
            "quiz": {"questions": [
                {"q": "React Native uses?", "a": ["JavaScript", "Java only"], "correct": 0}
            ]}
        }
    ],
    "UI/UX Design": [
        {
            "title": "Design Principles",
            "description": "Hierarchy, contrast, spacing.",
            "videos": ["https://www.youtube.com/watch?v=_ZKX3xHka0k"],
            "quiz": {"questions": [
                {"q": "UX focuses on?", "a": ["Experience", "Backend"], "correct": 0}
            ]}
        },
        {
            "title": "Prototyping",
            "description": "Wireframes to hi-fi.",
            "videos": ["https://www.youtube.com/watch?v=hz2L1v8mK8w"],
            "quiz": {"questions": [
                {"q": "Tool for UI design?", "a": ["Figma", "Docker"], "correct": 0}
            ]}
        }
    ],
    "QA Automation": [
        {
            "title": "Testing Fundamentals",
            "description": "Unit, integration, e2e.",
            "videos": ["https://www.youtube.com/watch?v=Eu35xM76kKY"],
            "quiz": {"questions": [
                {"q": "e2e tests simulate?", "a": ["User flows", "Code style"], "correct": 0}
            ]}
        },
        {
            "title": "Automation Tools",
            "description": "Selenium/Cypress basics.",
            "videos": ["https://www.youtube.com/watch?v=7N63cMKOs44"],
            "quiz": {"questions": [
                {"q": "Cypress is for?", "a": ["Web testing", "Image editing"], "correct": 0}
            ]}
        }
    ],
}

# Build full ROADMAP: After each learning step, insert a 20-question assessment, and append a final 20-question assessment
ROADMAP: Dict[str, List[Dict[str, Any]]] = {}
for domain, steps in BASE_ROADMAP.items():
    expanded: List[Dict[str, Any]] = []
    idx = 1
    for s_i, s in enumerate(steps, start=1):
        # Learning step
        expanded.append({
            "index": idx,
            "title": s["title"],
            "description": s.get("description", ""),
            "videos": s.get("videos", []),
            "quiz": s.get("quiz", {"questions": []}),
        })
        idx += 1
        # Post-step assessment
        expanded.append({
            "index": idx,
            "title": f"Assessment after Step {s_i} (20 questions)",
            "description": "Evaluate your understanding of the previous step.",
            "videos": [],
            "quiz": {"questions": standard_20_questions()},
        })
        idx += 1
    # Final comprehensive assessment
    expanded.append({
        "index": idx,
        "title": "Final Assessment (20 questions)",
        "description": "Comprehensive assessment for the domain.",
        "videos": [],
        "quiz": {"questions": standard_20_questions()},
    })
    ROADMAP[domain] = expanded

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
    results: List[bool] = []
    for i, q in enumerate(questions):
        is_correct = body.answers[i] == q["correct"]
        results.append(is_correct)
        if is_correct:
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

    return {"score": score, "total": total, "passed": passed, "results": results}

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
