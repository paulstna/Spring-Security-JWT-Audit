# Spring Security-JWT-Audit Application

This project demonstrates a secure REST API built with Spring Boot, featuring JWT-based authentication with access tokens and secure refresh tokens stored in HTTP-only cookies, role-based authorization, rate limiting, centralized exception handling, and auditing/logging mechanisms using Aspect-Oriented Programming (AOP), designed as a production-ready backend foundation.

---

## **Technologies**

### **Core Framework**
- **Java 21:** LTS version with modern language features
- **Spring Boot 4.x:** Application framework
- **Spring Security:** Authentication and authorization
- **Spring Data JPA:** Data persistence layer

### **Security**
- **JSON Web Tokens (JWT):** Stateless authentication
- **io.jsonwebtoken (JJWT):** JWT creation and parsing library
- **BCrypt:** Password hashing algorithm

### **Database**
- **PostgreSQL 17:** Production relational database

### **Rate Limiting & Caching**
- **Bucket4j:** Token bucket rate limiting
- **Caffeine:** High-performance in-memory cache

### **Logging**
- **SLF4J:** Logging facade
- **Logback:** Logging implementation
- **AspectJ:** AOP runtime for logging aspects

### **Build & Deployment**
- **Maven:** Dependency management and build tool
- **Docker:** Containerization
- **Docker Compose:** Multi-container orchestration

---

## **Features**

### **Authentication & Authorization**

#### **Authentication Flow**
- **User Registration:** Secure user registration with username, password validation, and role assignment
- **User Login:** Username/password authentication with JWT token generation
- **Token Refresh:** Automatic access token renewal using refresh tokens
- **User Logout:** Complete token revocation and session termination with cookie cleanup

#### **Token Management**
- **JWT-Based Authentication:** Stateless authentication using JSON Web Tokens
- **Dual Token System:**
  - **Access Token:** Short-lived (15 minutes) for API authentication
  - **Refresh Token:** Long-lived (15 days) stored in HTTP-only cookies
- **Token Features:**
  - Database persistence with metadata (User-Agent, IP address)
  - Automatic rotation on each refresh request
  - Device association and tracking
  - Signature verification and expiration validation
  - Immediate revocation capability

#### **Authorization**
- **Role-Based Access Control:** Hierarchical role system
  - SYSTEM → ADMIN → MANAGER → USER
- **Endpoint-Level Authorization:** Method-level security annotations
- **Role Management:** Flexible role assignment with validation

---

### **Security & Protection**

#### **Rate Limiting**
- **Endpoint-Specific Limits:** Configurable rate limits per endpoint using Bucket4j
- **IP-Based Throttling:** Rate limiting based on client IP address
- **Token Bucket Configuration:**
  - **Login:** 5 requests, refills 2 tokens every 60 seconds
  - **Register:** 3 requests, refills 3 tokens every 600 seconds
  - **Refresh:** 3 requests, refills 3 tokens every 300 seconds
- **Caffeine Cache Integration:** In-memory caching for performance
- **Graceful Error Handling:** HTTP 429 responses with Retry-After headers

#### **Authentication Security**
- **Password Security:**
  - BCrypt hashing with DelegatingPasswordEncoder
  - Automatic encoding on user creation and updates
- **Cookie Security:**
  - HttpOnly flag (prevents XSS access)
  - Secure flag (HTTPS only)
  - SameSite=Strict (CSRF protection)
- **Token Validation:**
  - Comprehensive JWT signature verification
  - Expiration checks
  - Revocation status validation

#### **Session Management**
- **Device Tracking:** User-Agent and IP address tracking per token
- **Single Session Per Device:** One active session per User-Agent
- **Automatic Cleanup:** Cascade deletion of tokens on user removal

---

### **Logging & Auditing**

#### **Multi-Logger Architecture**
Four specialized loggers with dedicated appenders:
- **AUDIT:** Authentication events (login, register, refresh, logout)
- **SECURITY:** Security failures and suspicious activities
- **ERROR:** System errors and exceptions
- **APP:** General application logging

#### **Audit Trail Features**
- **AOP-Based Auditing:** Non-invasive cross-cutting concern implementation
- **MDC Context Enrichment:** Structured logging with contextual data:
  - User ID and username
  - Client IP address
  - Trace ID (UUID)
  - Event type and action
  - Timestamp (ISO 8601)
- **Event Classification:**
  - Success/failure tracking
  - Failure reason categorization (invalid credentials, expired tokens, etc.)
  - User-Agent logging

#### **Log Management**
- **Async Appenders:** Non-blocking I/O for performance
- **Log Rotation:** Time-based rotation with gzip compression
- **Retention Policies:**
  - Audit logs: 365 days
  - Security logs: 180 days
  - Error logs: 90 days
  - Application logs: 30 days
- **Structured Output:** Consistent JSON-like patterns with hierarchical context

---

### **Database & Persistence**

#### **JPA Entity Auditing**
- **Automatic Timestamps:**
  - `createdAt`: Entity creation timestamp
  - `updatedAt`: Last modification timestamp
- **User Tracking:**
  - `createdBy`: User ID who created the entity
  - `updatedBy`: User ID who last modified the entity
- **System User Fallback:** Configurable system user ID for non-authenticated operations
- **Entity Listeners:** Transparent auditing via `@EntityListeners(AuditingEntityListener.class)`

#### **Database Schema**
- **PostgreSQL 17:** Production-grade relational database
- **Entity Relationships:**
  - User ↔ Roles: Many-to-Many
  - User ↔ RefreshTokens: One-to-Many with cascade delete
- **Data Integrity:**
  - Username uniqueness constraints
  - Foreign key relationships
  - Automatic orphan removal

---

### **User Management**

#### **CRUD Operations**
- **Create Users:** Admin-level user creation with role assignment
- **Read Users:**
  - List all users (MANAGER+ access)
  - Get specific user by ID
- **Update Users:** Modify username, password, and roles (MANAGER+ access)
- **Delete Users:** Remove users with automatic token cleanup (ADMIN only)

#### **User Features**
- **Username Uniqueness:** Validation to prevent duplicates
- **Password Management:**
  - Automatic BCrypt encoding
  - Secure password updates
- **Default Role Assignment:** New users automatically receive USER role
- **Role Validation:** Ensures valid roles are assigned

---

### **Architecture & Design**

#### **Design Patterns**
- **Aspect-Oriented Programming (AOP):**
  - Audit logging aspect
  - Security logging aspect
  - Error logging aspect
- **Repository Pattern:** Data access abstraction layer
- **Service Layer Pattern:** Business logic separation
- **DTO Pattern:** Request/response data transfer objects
- **Builder Pattern:** Token and entity construction
- **Delegation Pattern:** Password encoding, JWT operations

#### **Error Handling**
- **Global Exception Handler:** Centralized `@ControllerAdvice` for error management
- **Custom Exceptions:** Domain-specific exceptions with meaningful messages
- **Business Exception Filtering:** Separation of expected vs. system errors in logs
- **Structured Error Responses:** Consistent JSON format with:
  - Timestamp
  - Status code
  - Error message
  - Request path
  - Trace ID

#### **Configuration Management**
- **Externalized Configuration:** Environment variables for sensitive data
- **YAML Configuration:** Hierarchical application.yml structure
- **Custom Properties:**
  - JWT secret and expiration times
  - Rate limit bucket configurations
  - Database connection settings
  - Logging levels and patterns

---

### **Deployment & Infrastructure**

#### **Docker Support**
- **Multi-Stage Builds:** Optimized Docker image creation
  - Dependency layer (cached)
  - Build layer (Maven compilation)
  - Runtime layer (Alpine JRE)
- **Security Features:**
  - Non-root user execution
  - Minimal base image (Alpine)
  - No unnecessary packages
- **Health Checks:** Container health monitoring
- **Volume Mapping:**
  - Persistent log storage
  - Database data persistence
- **Network Isolation:** Dedicated Docker network for service communication

#### **Docker Compose Orchestration**
- **Service Dependencies:** Automatic startup ordering with health checks
- **Environment Variables:** Centralized configuration via `.env` file
- **Init Scripts:** Automatic database initialization on first run
- **Service Definitions:**
  - Application container
  - PostgreSQL container
  - Shared network and volumes

---

### **Additional Features**
- **API Versioning:** Path-based versioning pattern `/api/{version}/...`
- **Request Tracing:** UUID-based trace ID via MDC for request tracking
- **Health Endpoints:** Spring Boot Actuator integration (if enabled)


## **Development Roadmap**

### **Short-term Improvements**
- [ ] Input validation with Jakarta Bean Validation
- [ ] Request/response sanitization
- [ ] Comprehensive unit and integration testing suite

### **Medium-term Goals**
- [ ] OpenAPI/Swagger documentation
- [ ] Configurable IP change detection for token validation
- [ ] Enhanced exception handling in AOP aspects

### **Long-term Enhancements**
- [ ] Monitoring and metrics
- [ ] API rate limiting per user/role
- [ ] Multi-factor authentication (MFA)
- [ ] OAuth2/OIDC integration