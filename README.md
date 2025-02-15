Server deployed on Render
https://assignment4-3-tcuq.onrender.com

Secure Web Application with EJS and MongoDB Atlas

This is a secure and interactive web application built using EJS for templating, MongoDB Atlas for cloud-based database storage, and local authentication techniques. The application allows users to register, log in, and manage their profiles. It also includes features like profile picture upload and session-based authentication.
Features

    User Authentication:

        Registration and login system.

        Password hashing using bcrypt.

        Session-based authentication with express-session.

    Profile Management:

        Users can upload and display a profile picture using multer.

    Database Integration:

        MongoDB Atlas for cloud-based database storage.

        CRUD operations for user data.

    Security:

        Environment variables for sensitive data (e.g., MongoDB URI, session secret).

        Access control: Only logged-in users can access certain pages.

    Deployment:

        Deployed on Render for online access.

Technologies Used

    Frontend: EJS (Embedded JavaScript) for dynamic templates.

    Backend: Node.js, Express.js.

    Database: MongoDB Atlas.

    Authentication: bcrypt for password hashing, express-session for session management.

    File Upload: multer for handling profile picture uploads.

    Environment Management: dotenv for managing environment variables.

Setup Instructions
1. Prerequisites

   Node.js and npm installed on your machine.

   A MongoDB Atlas account and database cluster.

   A Render account for deployment.

2. Clone the Repository
   bash
   Copy

git clone https://github.com/Mahamba-25/Assignment4_3.git
cd Assignment4_3

3. Install Dependencies
   bash
   Copy

npm install

4. Set Up Environment Variables

Create a .env file in the root directory and add the following variables:
Copy

MONGO_URI=mongodb+srv://username:password@cluster0.mongodb.net/dbname
SESSION_SECRET=your-secret-key

    Replace username, password, and dbname with your MongoDB Atlas credentials.

    Replace your-secret-key with a strong secret key for session management.

5. Run the Application Locally
   bash
   Copy

node server.js

The application will be running at:
Copy

http://localhost:3000

Usage
1. Registration

   Navigate to /register.

   Fill out the registration form with a username, email, and password.

   Submit the form to create a new account.

2. Login

   Navigate to /login.

   Enter your username and password to log in.

3. Dashboard

   After logging in, you will be redirected to the dashboard.

   The dashboard displays a welcome message with your username.

4. Profile Picture Upload

   Navigate to the dashboard.

   Use the upload form to upload a profile picture.

   The uploaded picture will be displayed on the dashboard.

5. Logout

   Click the logout link to end your session.


Server deployed on Render
https://assignment4-3-tcuq.onrender.com