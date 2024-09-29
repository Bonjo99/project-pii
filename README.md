# Pii Detection Web-app Azure
## Introduction
This project is a web application aimed at detecting Personally Identifiable Information (PII) in various types of documents, including PDF and DOCX files. The application utilizes Azure Cognitive Services for text analysis, Flask for the web framework, and Azure Blob Storage for storing and managing documents.

## Features
Document Upload: Users can upload PDF or DOCX files to the application for PII detection.
PII Detection: The application analyzes uploaded documents to identify and redact PII such as names, addresses, and phone numbers.
User Authentication: User authentication is implemented using Google OAuth for secure access to the application.
Secure Password Storage: User passwords are securely hashed using Flask-Bcrypt to ensure data security.
Password Strength Check: Passwords are checked against a defined policy to ensure they meet security standards.
Cloud Storage: Azure Blob Storage is used to store uploaded documents securely.
Text Redaction: PII detected in documents is redacted to protect sensitive information before storing or sharing documents.

## Installation
Clone the repository: git clone https://github.com/your_username/pii-detection-web-app.git
Install dependencies: pip install -r requirements.txt
Set up Azure services (Azure Blob Storage, Azure Text Analytics) and Google OAuth credentials.
Update configuration files with the necessary credentials and endpoints.

## Usage
Run the Flask application: python app.py
Access the application in your web browser at http://localhost:5000
Sign in using your Google account.
Upload documents for PII detection.
View the redacted documents and download them securely.
