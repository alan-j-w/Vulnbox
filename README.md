# VulnBox: Professional Interactive Cybersecurity Training Platform

**VulnBox** is a high-end, immersive cybersecurity learning environment built with Python and Django. It is designed to provide a secure, hands-on space for mastering web exploitation, vulnerability research, and modern AI security. 

With a glassmorphism "Cyber-Dashboard" aesthetic and an integrated **Gemini AI Assistant**, VulnBox bridges the gap between theoretical knowledge and real-world penetration testing skills.

---

## 🚀 Key Features

*   **🛡️ Multi-Vector Hacking Labs**: Practical modules covering SQLi, XSS, CSRF, NoSQL, and Command Injection.
*   **🤖 VulnBot (Gemini AI)**: A context-aware AI assistant powered by Google's **Gemini 2.5 Flash** to provide hints and explain complex security concepts.
*   **🏆 Gamified Progression**: Real-time scoring system with flag submission and "Lab Mastery" tracking.
*   **☁️ Scalable Media Storage**: Profile picture management fully integrated with **Cloudinary** for production-grade reliability.
*   **🖥️ Cyber-Terminal UI**: A premium, responsive interface featuring animated hexagonal frames, glowing glassmorphism panels, and a pulsing activity timeline.
*   **🔐 Root-Level Security**: Robust authentication and a "Danger Zone" account management system for secure data erasure.

---

## 📚 Curriculum & Vulnerability Coverage

VulnBox categorizes labs into specialized tracks aligned with CEH (Certified Ethical Hacker) standards:

#### 🌐 Web Exploitation (Classic)
*   **SQL Injection**: Bypass authentication and dump databases.
*   **Brute-Force**: Master credential spraying and dictionary attacks.
*   **Command Injection**: Execute OS-level commands through vulnerable inputs.
*   **Post-Exploitation**: Learn how to pivot and escalate after the initial breach.

#### 🧠 Artificial Intelligence Security (Modern)
*   **Prompt Injection**: Trick LLMs into leaking system instructions or secrets.
*   **Data Poisoning**: Understand how corrupted datasets affect model reliability.
*   **Model Theft**: Explore the ethics and techniques of reverse-engineering AI properties.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend** | Python 3.12, Django 5.x |
| **Frontend** | Vanilla JS, Tailwind CSS, Particles.js, Lucide Icons |
| **AI Integration** | Google Gemini API (v1beta/v1) |
| **Media/Storage** | Cloudinary (CDN), SQLite/PostgreSQL |
| **Configuration** | Python-Decouple (Environment Variables) |

---

## ⚙️ Installation & Production Setup

### 1. Prerequisites
- Python 3.10+
- A Cloudinary account for media storage.
- A Google AI Studio API key for VulnBot.

### 2. Environment Configuration
Create a `.env` file in the `vulnbox_project/` directory with the following keys:
```env
# Security
SECRET_KEY=your_django_secret_key
DEBUG=True

# Cloudinary Storage
CLOUDINARY_URL=cloudinary://<api_key>:<api_secret>@<cloud_name>

# Gemini AI Assistant
GEMINI_API_KEY=your_google_gemini_api_key
```

### 3. Quick Start
```bash
# Clone and enter project
git clone https://github.com/alan-j-w/Vulnbox.git
cd Vulnbox/vulnbox_project

# Install dependencies
pip install -r requirements.txt

# Apply migrations
python manage.py makemigrations authapp
python manage.py migrate

# Launch Platform
python manage.py runserver
```

---

## 👨‍💻 Author & Development

*   **Alan Joy Wilson**
*   Full-Stack Django Developer | Cybersecurity Researcher
*   **GitHub**: [alan-j-w](https://github.com/alan-j-w)

---

## ⚠️ Security Disclaimer

VulnBox is strictly for **educational and ethical research purposes**. Never attempt to use the techniques learned here on systems you do not own or have explicit written permission to test. Unauthorized access is illegal and unethical.

---

&copy; 2026 VulnBox Platform. All Rights Reserved. `v1.2-stable`
