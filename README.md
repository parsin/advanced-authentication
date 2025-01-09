# Secure Authentication Service with OTP and Password-Based Login, JWT Tokens, and Refresh Token Management

### Overview

This project is a secure authentication service implemented in Java using Spring Boot. It provides two authentication methods:

1. **Password-based Authentication:** Users log in using their username and password.
2. **OTP-based Authentication:** Users authenticate using a One-Time Password (OTP) sent to them.
   
The service also employs JWT tokens for session management, ensuring scalability and secure stateless communication. It includes mechanisms to prevent common security vulnerabilities and supports token-based session handling with refresh tokens.

### Features

The following guides illustrate how to use some features concretely:

* **Password Authentication:** Users provide their credentials (username and password) to authenticate.
* **OTP Authentication:** Users request an OTP sent to their device, which they use to authenticate without needing a password.
* **Token Management:** The service generates and validates JWT tokens (Access Token and Refresh Token).
* **Rate Limiting:** Prevents abuse of OTP requests with rate-limiting and penalty mechanisms.
* **Refresh Token Rotation:** Ensures the integrity of user sessions and invalidates old tokens when new ones are issued.
* **Role-based Authorization:** Grants access to resources based on user roles.
* **Secure Token Storage:** Stores tokens in Redis to manage active sessions.
* **Attack Prevention:** Implements measures against replay attacks, token reuse, and brute force attacks.

### Authentication Methods

1. Password-based Authentication

   The user logs in with their username and password. The system:
* Authenticates the user credentials using the AuthenticationManager. 
* Generates a new pair of Access and Refresh tokens upon successful login. 
* Invalidates old tokens to enhance security.

2. OTP-based Authentication

    The user can authenticate using a One-Time Password (OTP):
* The system verifies the OTP against the user’s session stored in Redis. 
* If valid, the user is authenticated and issued a new set of tokens. 
* The OTP session is invalidated after use to prevent reuse.

### JWT Token Management

#### Why Use Refresh Tokens for Session Management?
JWTs are stateless, which makes them highly scalable, but managing long-lived sessions requires Refresh Tokens:
1.	**Short-lived Access Tokens:** Access tokens are valid for a short time, reducing the risk of unauthorized access if stolen.
2.	**Long-lived Refresh Tokens:** Refresh tokens allow users to obtain a new access token without reauthentication, ensuring a seamless user experience.
3.	**Secure Session Management:** Refresh tokens are stored in Redis and invalidated after use (refresh token rotation), mitigating token reuse attacks.

### Security Measures
#### Attack Prevention
1.	**Replay Attacks:**
* Tokens are invalidated after use.
* OTP sessions are invalidated upon authentication.
2.	**Token Reuse:**
* Refresh tokens are rotated, ensuring a new refresh token is issued for every access token refresh.
* Old tokens are stored in Redis and marked invalid after rotation.
3.	**Brute Force Attacks:**
* Rate-limiting OTP requests using Redis.
* Penalty sessions prevent repeated OTP requests from malicious actors.
4.	**Token Expiration:**
* Short-lived access tokens minimize the impact of leaked tokens.
* Expired tokens are automatically rejected.
5.	**Data Encryption:**
* JWT tokens are signed with a secure HMAC-SHA256 algorithm using a Base64-encoded secret.
6.	**Role-based Security:**
* Role-based authorization restricts access to resources based on user roles.

### API Response Standardization
Using a standardized response DTO improves consistency and readability for API consumers. Each response contains:
* Status Code: Indicates success or failure.
* Message: Describes the result of the operation.
* Data: Encapsulates the response payload, if any.

### How to Run the Service
1.	**Pre-requisites:**
* Java 21
* Redis
* PostgreSQL or MySQL

### Additional Notes
#### OTP Code Generation

The OTP code is a 4-digit random number, ensuring simplicity while maintaining security for short-lived sessions.

#### Redis Usage

Redis is used for:
* Storing active token sessions.
* Managing OTP sessions and penalty sessions.
* Token invalidation for refresh token rotation.

### Conclusion
This authentication service ensures a secure, scalable, and user-friendly authentication system with modern best practices. By combining password and OTP-based authentication, along with robust token management and security measures, the system is well-suited for real-world applications where security and performance are paramount.