# Secure User API

This project is a secure REST API for user management using Node.js, Express.js, PostgreSQL, JWT, HTTPS, CSRF protection, and SQL injection protection.

## Features

- User registration
- User login
- JWT authentication
- Role-based authorization
- HTTPS communication
- CSRF protection
- SQL injection protection using parameterized queries
- CRUD operations for users

## Technologies Used

- Node.js
- Express.js
- PostgreSQL
- bcrypt
- JSON Web Token (JWT)
- dotenv
- helmet
- cors
- HTTPS with self-signed certificate

## API Endpoints

| Method | Endpoint | Description | Authentication | CSRF |
|---|---|---|---|---|
| GET | `/` | API home route | No | No |
| POST | `/auth/register` | Register a new user | No | No |
| POST | `/auth/login` | Login and receive tokens | No | No |
| GET | `/users` | Get all users | Admin only | No |
| GET | `/users/:id` | Get user by ID | Admin or own user | No |
| POST | `/users` | Create a new user | Admin only | Yes |
| PUT | `/users/:id` | Update user | Admin or own user | Yes |
| DELETE | `/users/:id` | Delete user | Admin only | Yes |

## Environment Variables

Create a `.env` file based on `.env.example`.

Example:

```env
PORT=3000

DATABASE_URL=postgresql://postgres:your_password@localhost:5434/secure_api_db

JWT_SECRET=change_this_to_your_secret_key

ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=change_this_admin_password
Install Dependencies
npm install
Run PostgreSQL Database

If using Docker Compose for PostgreSQL:

docker compose up -d
Generate HTTPS Certificate

This project uses a self-signed certificate for HTTPS.

mkdir certs

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost"
Run the API
npm run dev

The API will run at:

https://localhost:3000

If running on a remote server, replace localhost with your server address.

Default Admin Account

The default admin account is created automatically when the application starts.

Email: admin@example.com
Password: admin123

Use the values defined in your .env file.

Testing with Postman

Because this project uses a self-signed HTTPS certificate, disable SSL certificate verification in Postman:

Settings > General > SSL certificate verification > OFF
1. Login
POST https://localhost:3000/auth/login

Body:

{
  "email": "admin@example.com",
  "password": "admin123"
}

Response includes:

accessToken
csrfToken
2. Get All Users
GET https://localhost:3000/users

Headers:

Authorization: Bearer <accessToken>
3. Create User
POST https://localhost:3000/users

Headers:

Authorization: Bearer <accessToken>
x-csrf-token: <csrfToken>
Content-Type: application/json

Body:

{
  "name": "New User",
  "email": "newuser@example.com",
  "password": "123456",
  "role": "user"
}
4. Get User by ID
GET https://localhost:3000/users/1

Headers:

Authorization: Bearer <accessToken>
5. Update User
PUT https://localhost:3000/users/1

Headers:

Authorization: Bearer <accessToken>
x-csrf-token: <csrfToken>
Content-Type: application/json

Body:

{
  "name": "Updated User",
  "email": "updated@example.com"
}
6. Delete User
DELETE https://localhost:3000/users/1

Headers:

Authorization: Bearer <accessToken>
x-csrf-token: <csrfToken>
Security Implementation
JWT Authentication

JWT is used to verify that a user has logged in.

The token must be sent in the Authorization header:

Authorization: Bearer <accessToken>
Role-Based Authorization

Some endpoints are restricted to admin users only.

Examples:

GET /users requires admin role.
POST /users requires admin role.
DELETE /users/:id requires admin role.
HTTPS

The API runs using HTTPS with a self-signed certificate.

CSRF Protection

POST, PUT, and DELETE requests require a CSRF token.

The token must be sent in the request header:

x-csrf-token: <csrfToken>
SQL Injection Protection

SQL injection is prevented by using parameterized queries.

Example:

pool.query("SELECT * FROM users WHERE email = $1", [email]);

This is safer than directly inserting user input into SQL strings.

Notes
Do not upload .env to GitHub.
Do not upload certs/key.pem to GitHub.
Use .env.example to show required environment variables.

## Run with Docker Compose

```bash
docker compose up -d --build

Check running containers:

docker compose ps

Stop containers:

docker compose down

Reset database:

docker compose down -v
docker compose up -d --build

ถ้าเพิ่ม README แล้ว อย่าลืม:

```bash
git add README.md
git commit -m "Update README with Docker instructions"
git push


