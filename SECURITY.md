# Tang Server - Security Features

This document describes the security features implemented in the Rust Tang server to ensure maximum protection against various attack vectors.

## Security Enhancements

### 1. Cryptographic Security

#### Constant-Time Operations
- **Key ID comparison**: Uses constant-time comparison (`subtle::ConstantTimeEq`) to prevent timing attacks when looking up keys
- **Secure random generation**: Uses OS-level random number generation (`OsRng`) for all cryptographic key generation

#### Cryptographic Algorithms
- **NIST P-256**: All elliptic curve operations use the FIPS-approved P-256 curve
- **SHA-256**: Key thumbprints use SHA-256 for consistent, secure hashing
- **ECDH**: Key exchange uses Elliptic Curve Diffie-Hellman

### 2. Input Validation

#### Key ID Validation
All key IDs are validated to prevent path traversal and injection attacks:
- Length limits (1-256 characters)
- No path traversal characters (`..`, `/`, `\\`)
- No control characters
- Only base64url-safe characters allowed

#### JWK Validation
All incoming JWKs are validated for:
- Correct key type (EC only)
- Supported curve (P-256 only)
- Valid coordinate encoding
- Proper structure

### 3. File System Security

#### Key Storage
- **Restrictive permissions**: Key directory set to `0700` (owner-only access)
- **File permissions**: Individual key files set to `0600` (owner read/write only)
- **Permission verification**: Existing directories checked for secure permissions on startup
- **Atomic writes**: Keys written to temp files first, then renamed atomically

#### Path Traversal Prevention
- All file paths validated before access
- Paths must be within the key database directory
- Filename sanitization prevents directory traversal

### 4. Network Security

#### Rate Limiting
- **Per-IP rate limiting**: Prevents DoS attacks from single sources
- **Configurable limits**: Default 100 req/sec, burst of 200
- **Secure mode**: Stricter limits (50 req/sec, burst 100)

#### Request Limits
- **Body size limits**: Default 16KB, secure mode 8KB
- **Request timeouts**: Default 10s, secure mode 5s
- **Connection handling**: Proper timeout and cleanup

### 5. Security Headers

All responses include comprehensive security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
```

### 6. TLS/HTTPS Support

- **TLS 1.2/1.3**: Uses `rustls` for modern TLS support
- **Certificate validation**: Certificates must be in PEM format
- **Secure ciphers**: Only secure cipher suites enabled
- **HSTS**: Strict Transport Security enforced when TLS is enabled

### 7. Error Handling

#### Information Disclosure Prevention
- **Generic errors**: Production mode returns generic error messages
- **No stack traces**: Internal errors logged but not exposed
- **Sanitized messages**: Error details removed from responses

#### Audit Logging
- All key operations logged with timestamps
- Security events logged at appropriate levels
- Request failures logged for monitoring

### 8. DoS Protection

- **Rate limiting**: Per-IP request limits
- **Timeout enforcement**: All requests have hard timeouts
- **Resource limits**: Body size limits prevent memory exhaustion
- **Connection limits**: Handled at the HTTP server level

## Configuration

### Default Mode
Balanced security for development/testing:
```bash
tang serve -d ./keys
```

### Secure Mode
Production-ready security hardening:
```bash
tang serve -d ./keys --secure --tls --tls-cert cert.pem --tls-key key.pem
```

### Custom Configuration
```bash
tang serve \
  --secure \
  --tls \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem \
  --rate-limit 50 \
  --max-body-size 8192 \
  -p 9090
```

## Security Best Practices

### 1. Production Deployment

**ALWAYS use HTTPS in production:**
```bash
tang serve --secure --tls --tls-cert cert.pem --tls-key key.pem
```

**Set proper file permissions:**
```bash
chmod 700 /var/db/tang
chmod 600 /var/db/tang/*.jwk
```

**Run as non-root user:**
```bash
useradd -r -s /bin/false tang
chown -R tang:tang /var/db/tang
sudo -u tang tang serve --secure --tls ...
```

### 2. Key Management

**Generate keys securely:**
```bash
tang keygen -d /var/db/tang
tang keygen -d /var/db/tang --signing
```

**Rotate keys regularly:**
```bash
# Generate new keys
tang keygen -d /var/db/tang
tang keygen -d /var/db/tang --signing

# Hide old keys (they still work for recovery)
tang hide -d /var/db/tang <OLD_KEY_ID>
```

**Backup keys securely:**
```bash
tar czf tang-keys-backup.tar.gz /var/db/tang
chmod 600 tang-keys-backup.tar.gz
# Store in secure, encrypted backup
```

### 3. Network Security

**Use a reverse proxy:**
- nginx or Apache in front of Tang
- Additional layer of security headers
- Load balancing and caching
- Connection pooling

**Firewall rules:**
```bash
# Allow only necessary traffic
ufw allow 9090/tcp
ufw enable
```

**Network isolation:**
- Run Tang in isolated network segment
- Use VPN for remote access
- Limit access to trusted networks

### 4. Monitoring

**Enable structured logging:**
```bash
RUST_LOG=tang=info,tower_http=debug tang serve --secure ...
```

**Monitor for:**
- Rate limit violations
- Authentication failures (if added)
- Unusual access patterns
- File system permission changes

**Set up alerts for:**
- High error rates
- Rate limit threshold violations
- Failed key loads
- Permission changes

### 5. Regular Updates

- Keep Rust toolchain updated
- Update dependencies regularly
- Monitor security advisories
- Test updates in staging first

## Security Limitations

### Current Limitations

1. **No client authentication**: Tang protocol is intentionally anonymous
2. **No request signing**: Clients don't authenticate requests
3. **Network-based security**: Security relies on network topology
4. **Limited JWE support**: Only basic ECDH key recovery implemented

### Mitigations

- **Network isolation**: Tang should be on trusted networks only
- **VPN access**: Use VPN for remote client access
- **Firewall rules**: Strict firewall configuration
- **Rate limiting**: Prevents some abuse scenarios

## Threat Model

### Protected Against

✅ **Path traversal attacks**: Strict input validation
✅ **Timing attacks**: Constant-time key lookups
✅ **DoS attacks**: Rate limiting and timeouts
✅ **Information disclosure**: Sanitized error messages
✅ **File permission issues**: Automatic permission enforcement
✅ **MITM attacks**: TLS/HTTPS support
✅ **XSS/Clickjacking**: Comprehensive security headers

### Not Protected Against

❌ **Physical access**: If attacker has root access, keys can be read
❌ **Network eavesdropping** (without TLS): Use TLS in production
❌ **Compromised client**: Client security is client responsibility
❌ **Social engineering**: User education required

## Security Reporting

If you discover a security vulnerability:

1. **Do not** open a public GitHub issue
2. Email security concerns privately
3. Include details for reproduction
4. Allow reasonable time for fix
5. Coordinate disclosure timing

## Compliance

This implementation follows:

- **NIST recommendations** for elliptic curve cryptography
- **OWASP guidelines** for secure web applications
- **RFC 7638** for JWK thumbprints
- **RFC 7517** for JSON Web Keys
- **CIS benchmarks** for file permissions

## Auditing

For security audits, focus on:

1. **Cryptographic operations** ([src/crypto.rs](src/crypto.rs), [src/jwk.rs](src/jwk.rs))
2. **Input validation** ([src/security.rs](src/security.rs))
3. **File operations** ([src/keys.rs](src/keys.rs))
4. **Network handling** ([src/server_secure.rs](src/server_secure.rs))
5. **Error handling** (all modules)

## References

- [Tang Project](https://github.com/latchset/tang)
- [RFC 7638 - JWK Thumbprint](https://tools.ietf.org/html/rfc7638)
- [RFC 7517 - JSON Web Key](https://tools.ietf.org/html/rfc7517)
- [NIST SP 800-56A - ECC](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
