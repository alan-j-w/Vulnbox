Vulnbox: An Interactive Cybersecurity Learning Platform

Vulnbox is a hands-on web application built with Python and Django, designed to provide a safe and controlled environment for learning ethical hacking. Users can practice exploiting real-world vulnerabilities, track their progress on a personal dashboard, and earn points in a gamified learning system.

-----

## ✨ Features

  * **Secure User Authentication**: Complete user registration and login system to protect user data and progress.
  * **Personalized User Dashboard**: A central hub for users to view their current score and track completed modules.
  * **Gamified Scoring System**: An engaging points-based system that rewards users for successfully submitting "flags" from challenges.
  * **Hands-On Hacking Labs**: A wide array of interactive modules covering both classic and modern vulnerabilities.
  * **Admin Control Panel**: A full-featured admin dashboard for managing users, courses, and site content.
  * **Modern UI**: A sleek, responsive, cyberpunk-themed interface built with Tailwind CSS.

-----

## 📚 Modules & Vulnerabilities Covered

Vulnbox offers a rich curriculum that covers a wide range of security topics, from foundational web exploits to cutting-edge AI vulnerabilities.

#### Foundational Web Security

  * **SQL Injection (`SQLi`)**: Learn how to manipulate database queries to bypass logins and extract sensitive data.
  * **Brute-Force Attacks**: Practice techniques for systematically guessing credentials to gain unauthorized access.
  * **Command Injection**: Exploit vulnerabilities to execute arbitrary commands on the server's operating system.
  * **Cross-Site Request Forgery (`CSRF`)**: Understand how to trick a user's browser into making unintended requests.
  * **NoSQL Injection**: Explore injection attacks specifically targeting modern NoSQL databases.

#### Advanced & Specialized Topics

  * **Cryptography**: Discover and exploit common flaws in encryption and hashing implementations.
  * **Prompt Injection**: A modern attack targeting Large Language Models (LLMs) to make them bypass their instructions.
  * **Data Poisoning**: Learn how attackers can corrupt the training data of a machine learning model.
  * **Model Theft**: Explore techniques to reverse-engineer and steal proprietary AI models.

-----

## 🛠️ Tech Stack

| Category | Technology & Tools |
| :--- | :--- |
| **Backend** | Python, Django |
| **Frontend**| HTML, CSS, JavaScript, Tailwind CSS |
| **Database**| SQLite (default), PostgreSQL/MySQL compatible |
| **Authentication**| Django's Built-in Authentication System |
| **Development**| Git, GitHub, VS Code |

-----

## ⚙️ Local Installation and Setup

Follow these steps to get a local copy of Vulnbox up and running.

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/alan-j-w/Vulnbox.git
    cd Vulnbox
    ```

2.  **Create and Activate a Virtual Environment**

    ```bash
    # On Windows
    python -m venv venv
    venv\Scripts\activate

    # On macOS / Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Run Migrations and Start the Server**

    ```bash
    python manage.py migrate
    python manage.py runserver
    ```

    The application will now be running at 👉 `http://127.0.0.1:8000/`

-----

## 👨‍💻 Author

  * **Alan Joy Wilson**
  * Python Django Developer | Cybersecurity Enthusiast
  * **GitHub Profile**: [github.com/alan-j-w](https://www.google.com/search?q=https://github.com/alan-j-w)

-----

## ⚠️ License

This project is currently for personal and educational use. All rights are reserved by the author. Please get in touch for collaboration or usage permissions.
