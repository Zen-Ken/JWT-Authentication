# JSON Web Token (JWT) Anatomy

A JWT is composed of three parts separated by dots (`.`):

```
xxxxx.yyyyy.zzzzz
```

## Structure

### 1. Header

**Purpose**: Describes the token type and signing algorithm

**Example**:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- `alg`: Algorithm used for signing (e.g., HS256, RS256)
- `typ`: Token type (always "JWT")

**Encoded**: Base64Url encoded

---

### 2. Payload

**Purpose**: Contains the claims (user data and metadata)

**Example**:

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622
}
```

**Types of Claims (RFC 7519)**:

1. **Standard Claims** (RFC 7519 Section 4.1):

   - Optional but recommended standardized claims
   - `iss`: Issuer - who created and signed the token
   - `sub`: Subject - user identifier (typically user ID)
   - `aud`: Audience - intended recipient of the token
   - `exp`: Expiration Time - when the token expires (Unix timestamp)
   - `nbf`: Not Before - token not valid before this time (Unix timestamp)
   - `iat`: Issued At - when the token was created (Unix timestamp)
   - `jti`: JWT ID - unique identifier for the token

2. **Public Claims** (RFC 7519 Section 4.2):

   - Claims defined in the IANA JSON Web Token Registry
   - Or collision-resistant names (e.g., using namespaces)
   - Examples: `name`, `email`, `email_verified`, `preferred_username`
   - Should be registered to avoid conflicts

3. **Private Claims** (RFC 7519 Section 4.3):
   - Custom claims agreed upon between parties
   - Application-specific data
   - Examples: `role`, `permissions`, `userId`, `organizationId`
   - Not registered, use with caution to avoid collisions

**Encoded**: Base64Url encoded

**⚠️ Warning**: Payload is NOT encrypted, only encoded. Anyone can decode and read it. Never store sensitive data like passwords.

---

### 3. Signature

**Purpose**: Verifies the token hasn't been tampered with

**How it's created**:

```javascript
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret);
```

**Process**:

1. Take the encoded header and payload
2. Combine them with a dot
3. Hash using the algorithm specified in header
4. Sign with the secret key

**Verification**: Server re-creates the signature and compares it to the received signature

---

## Complete JWT Example

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiamRvZSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQyNjIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

**Breaking it down**:

1. **Header**: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

   - Decodes to: `{"alg":"HS256","typ":"JWT"}`

2. **Payload**: `eyJuYW1lIjoiamRvZSIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjQyNjIyfQ`

   - Decodes to: `{"name":"jdoe","iat":1516239022,"exp":1516242622}`

3. **Signature**: `SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
   - Cannot be decoded (it's a hash)
   - Can only be verified using the secret

---

## Key Takeaways

- **3 Parts**: Header, Payload, Signature (separated by `.`)
- **Encoded, Not Encrypted**: Anyone can decode and read the payload
- **Stateless**: Server doesn't need to store session data
- **Signature Validates Integrity**: Prevents tampering
- **Secret Key is Critical**: Never expose your signing secret

---

## Decoding JWTs

Try decoding JWTs at: [jwt.io](https://jwt.io)

**Remember**: Decoding ≠ Verifying. Always verify the signature server-side.
