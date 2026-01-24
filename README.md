# Spring Security-JWT-Audit Application

This project demonstrates a secure REST API built with Spring Boot, featuring JWT-based authentication with access tokens and secure refresh tokens stored in HTTP-only cookies, role-based authorization, rate limiting, centralized exception handling, and auditing/logging mechanisms using Aspect-Oriented Programming (AOP), designed as a production-ready backend foundation.

## **Technologies**

- **Java 21**
- **Spring Boot 4.x**: Foundation framework for application development.
- **Spring Security**: Manages user authentication and access control.
- **Spring Data JPA**: Streamlines data persistence and database operations.
- **JWT (JSON Web Tokens)**: Provides stateless authentication mechanism.
- **io.jsonwebtoken (JJWT)**: Library for generating and validating JWT tokens.
- **Lombok**: Minimizes repetitive Java code through annotations.
- **PostgreSQL 17**: Primary database for data storage and management.
- **Bucket4j**: Controls API request frequency through rate limiting.
- **Caffeine**: Delivers fast in-memory data caching capabilities.
- **Docker + Docker Compose**: Ensures consistent application packaging and orchestration.

## **Core Features**

### **Authentication & Authorization**
- JWT-based stateless authentication (access + refresh tokens)
- User registration, login, logout with token management
- Role-based authorization: SYSTEM → ADMIN → MANAGER → USER
- Automatic token rotation and device tracking
- Secure HTTP-only cookies (SameSite=Strict)

### **Security & Rate Limiting**
- Endpoint-specific rate limiting with Bucket4j
- IP-based throttling with configurable buckets
- BCrypt password encoding
- Token revocation and session management
- One active session per device

### **Audit & Logging**
- Multi-logger architecture (AUDIT, SECURITY, ERROR, APP)
- AOP-based auditing with MDC context enrichment
- Automatic entity auditing (CreatedAt, UpdatedAt, CreatedBy, UpdatedBy)
- Structured logging with rotation and retention policies

### **User Management**
- Role-based CRUD operations
- Username uniqueness validation
- Automatic password hashing
- Cascade token cleanup on user deletion

### **Infrastructure**
- PostgreSQL database with JPA
- Docker multi-stage builds with health checks
- Docker Compose orchestration
- API versioning (/api/{version}/...)

## **Setup and Installation**

### **Prerequisites**
- Docker
- Docker Compose

### **Getting Started**

#### **1. Clone the Repository**

```bash
git clone https://github.com/PaulStna/Spring-Security-JWT-Audit.git
cd Spring-Security-JWT-Audit
```

#### **2. Run with Docker Compose**

```bash
docker compose up -d
```

The application will start on `http://localhost:8080`

## **API Documentation**

### **Authentication Endpoints**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/register` | Register a new user account |
| `POST` | `/api/v1/auth/login` | Authenticate user and receive tokens |
| `POST` | `/api/v1/auth/refresh` | Refresh access token using refresh token cookie |
| `POST` | `/api/v1/auth/logout` | Invalidate session and clear tokens |

**Request Body (register/login):**
```json
{
  "username": "<username>",
  "password": "<plain_password>"
}
```

**Response (register/login/refresh):**
```json
{
  "authToken": "<jwt_auth_token>"
}
```
**+ Cookie:** `refreshToken` (HTTP-only, Secure, SameSite=Strict, 15 days)

**Notes:**
- **register/login**: Creates new session, sets `refreshToken` cookie, tracks device and IP
- **refresh**: Requires `refreshToken` cookie, returns new access token and rotates refresh token
- **logout**: Requires `refreshToken` cookie, invalidates session and deletes cookie

---

### **User Management Endpoints**

| Method | Endpoint | Description | Required Role |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/users` | Get all users | `MANAGER` |
| `GET` | `/api/v1/users/{id}` | Get user by ID | `MANAGER` |
| `POST` | `/api/v1/users` | Create new user | `ADMIN` |
| `PUT` | `/api/v1/users/{id}` | Update user | `MANAGER` |
| `DELETE` | `/api/v1/users/{id}` | Delete user | `ADMIN` |

**Authentication:** All endpoints require `Authorization: Bearer <access_token>` header

**Request Body (POST/PUT):**
```json
{
  "username": "<username>",
  "password": "<plain_password>",
  "roles": ["USER", "MANAGER"]
}
```

**Notes:**
- `{id}` is a UUID path parameter
- DELETE automatically revokes all user tokens and sessions

---

## **Security Notes**

- All authentication endpoints track User-Agent and IP address for security auditing
- Refresh tokens are bound to specific devices (one active session per device)
- Rate limiting applies to all authentication endpoints based on endpoint + IP address
- Passwords are automatically hashed using BCrypt

## Demo / Development Considerations
The following configurations are **intentionally insecure** and exist **only for local testing and demonstration purposes**:

- The `.env` file is committed and exposed to simplify application setup
- Default system/admin/manager users use `{noop}` password encoding
- User-related endpoint responses may expose sensitive fields (e.g. password, audit metadata) **solely to demonstrate auditing and security mechanisms**
- Secrets and credentials **must be externalized** and properly secured in real environments

## **Further Development**
- Input validation & sanitization
- Testing suite
- Monitoring & observability
- Enhanced error handling