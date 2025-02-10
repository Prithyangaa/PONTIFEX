# Job Application Management System

This is a Job Application Management System built with Flask, SQLAlchemy, Flask-Login, Flask-WTF, and other popular Python libraries. It allows users to manage their job applications, including saving, applying, updating statuses, and withdrawing applications.

## Features

- **User Registration and Authentication**: Users can sign up, log in, and manage their account.
- **Dashboard**: A dashboard to view available job vacancies.
- **Application Management**: Users can apply for jobs, update the status of their applications, and withdraw applications.
- **Email Notifications**: Email notifications are sent for actions like registration or password reset.
- **Job Application Status**: Users can update the status of job applications (Saved, Applied, Offered, Rejected).

## Technologies Used

- **Flask**: A lightweight web framework for Python.
- **Flask-SQLAlchemy**: SQLAlchemy integration for Flask to manage the database.
- **Flask-Login**: User session management and authentication.
- **Flask-WTF**: Web forms handling with validation.
- **Flask-Mail**: Email functionality for sending notifications.
- **WTForms**: For creating web forms and validation in Flask.
- **SQLite**: The database system used for storing job applications and user data.
- **dotenv**: For securely managing environment variables.
- **bcrypt**: For password hashing.

## Installation Instructions

### Prerequisites:

- Python 3.x
- A code editor like **VS Code** (optional but recommended).
- SQLite (which is the default database system, no installation required).

### Setup:

1. **Clone the Repository**:

   - Clone this repository to your local system.

2. **Set Up a Virtual Environment**:

   - Create and activate a virtual environment to isolate your dependencies.
     python3 -m venv venv
     source venv/bin/activate # On Windows: venv\Scripts\activate

3. **Install Dependencies**:

   - Install the required dependencies using pip:
     pip install -r requirements.txt

4. **Database Setup**:

   - The application uses SQLite as the database system. By default, the database file is stored in the instance folder.

5. **Run the Application**:
   - To start the Flask development server:
     python app.py

The application will now be running locally at http://127.0.0.1:5000/.

7. **Accessing the Application**:

Open your browser and go to http://127.0.0.1:5000/ to access the application.

You will be prompted to sign up or log in to start managing your job applications.

The application uses SQLite for database management. SQLite is a serverless, self-contained, and lightweight database system. It is included in Python’s standard library, so there is no need for external installation.

The database file is stored in the instance folder. It is automatically created and populated with data when you first run the application.
