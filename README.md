VulnBox – Cybersecurity Learning Platform
Overview

VulnBox is an interactive cybersecurity learning platform built with Python Django.
It allows users to explore and practice real-world web vulnerabilities such as SQL Injection and Login Bypass in a safe, controlled environment.
The platform includes secure authentication, user scoring, and a cyberpunk-themed interface for a hands-on learning experience.

Features

User Authentication – Secure signup/login system using Django’s built-in auth

Hacking Challenges – Includes SQL Injection & Login Bypass exercises

User Dashboard – Tracks user progress and scores

Access Restriction – Only logged-in users can access challenges

Dark Cyberpunk UI – Tailwind CSS-based modern hacker design

SQLite / MySQL Support – Easily switch databases

Modular Django Architecture – Organized modules for scalability

Tech Stack
Category	Technology
Backend	Python, Django
Frontend	HTML, CSS, Tailwind CSS, JavaScript
Database	SQLite / MySQL
Authentication	Django’s built-in auth system
Tools	VS Code, Git, GitHub
Project Structure
VULNBOX/
│
├── authapp/              # Handles authentication and user management
├── core/                 # Challenge logic and main views
├── templates/            # HTML templates
├── static/               # CSS, JS, and images
├── db.sqlite3            # Local database
├── manage.py             # Django management script
└── requirements.txt      # Dependencies list

⚙️ Installation & Setup
1️⃣ Clone the repository
git clone https://github.com/alan-j-w/Vulnbox.git
cd Vulnbox

2️⃣ Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate      # (On Windows)
source venv/bin/activate   # (On Mac/Linux)

3️⃣ Install dependencies
pip install -r requirements.txt

4️⃣ Run the development server
python manage.py runserver


Then open your browser and go to 👉 http://127.0.0.1:8000/

Future Enhancements

Add more vulnerabilities

Include Docker support for containerized deployment

👨‍💻 Author

Alan Joy Wilson
🖥️ Python Django Developer | Cybersecurity Enthusiast
🔗 GitHub Profile

⚠️ License

This project currently has no open-source license.
All rights reserved by the author — please contact for collaboration or usage permissions.
