# Tang (Rust Implementation)
Note: this is not ready for production
A Rust implementation of [Tang](https://github.com/latchset/tang) - a Network-Based Cryptographic Binding Server.

## Overview

Tang is a server for binding data to network presence. It provides a secure, stateless, anonymous alternative to key escrow services. Tang allows data to be encrypted and decrypted only when a system is on a specific network, using the McCallum-Relyea cryptographic exchange protocol.

## Features

### Core Features
- **Stateless Design**: No server-side state management required
- **Anonymous**: No authentication or client tracking
- **JOSE Standards**: Uses JSON Object Signing and Encryption (JOSE) for key management
- **Key Rotation**: Support for rotating keys without service interruption
- **RESTful API**: Simple HTTP endpoints for key advertisement and recovery

### Security Features ✨
- **TLS/HTTPS Support**: Built-in TLS with rustls for secure communications
- **Rate Limiting**: Per-IP rate limiting to prevent DoS attacks
- **Security Headers**: Comprehensive HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- **Input Validation**: Strict validation to prevent path traversal and injection attacks
- **Constant-Time Operations**: Timing attack mitigation for sensitive operations
- **Secure File Permissions**: Automatic enforcement of restrictive file permissions (0700/0600)
- **Audit Logging**: Structured logging for security events
- **Timeout Protection**: Request timeouts to prevent resource exhaustion

See [SECURITY.md](SECURITY.md) for detailed security documentation.

## Installation

```bash
cargo build --release
```

## Usage

### Starting the Server

```bash
# Development mode (default settings)
cargo run -- serve -d ./keys

# Production mode with TLS and secure defaults
cargo run -- serve --secure --tls --tls-cert cert.pem --tls-key key.pem -d ./keys

# Custom configuration
cargo run -- serve \
  --secure \
  --rate-limit 50 \
  --max-body-size 8192 \
  -p 9090 \
  -d ./keys
```

**Production Deployment**: Always use `--secure` and `--tls` flags in production! See [SECURITY.md](SECURITY.md) for best practices.

### Key Management

```bash
# Generate a new exchange key
cargo run -- keygen -d ./keys

# Generate a new signing key
cargo run -- keygen -d ./keys --signing

# List active keys
cargo run -- list -d ./keys

# Hide a key (for key rotation)
cargo run -- hide -d ./keys <KEY_ID>
```

## API Endpoints

### GET /adv
Advertise all active public keys (both signing and exchange keys).

**Response**: JSON Web Key Set (JWKS)

```bash
curl http://localhost:9090/adv
```

### GET /adv/{kid}
Advertise keys using a specific signing key.

**Parameters**:
- `kid`: Key ID of the signing key

### POST /rec/{kid}
Perform key recovery using the specified exchange key.

**Parameters**:
- `kid`: Key ID of the exchange key

**Request Body**: JWK containing the client's public key

**Response**: JWK containing the recovery result

## Key Rotation

Tang supports seamless key rotation:

1. Generate new signing and exchange keys:
   ```bash
   cargo run -- keygen -d ./keys --signing
   cargo run -- keygen -d ./keys
   ```

2. Hide old keys (they'll still work for recovery but won't be advertised):
   ```bash
   cargo run -- hide -d ./keys <OLD_KEY_ID>
   ```

3. The server automatically picks up key changes without restart

## Architecture

- **src/main.rs**: CLI and server initialization
- **src/server.rs**: HTTP server and endpoint handlers
- **src/keys.rs**: Key management and storage
- **src/jwk.rs**: JSON Web Key (JWK) implementation
- **src/crypto.rs**: Cryptographic operations (ECDH, key recovery)
- **src/error.rs**: Error types

## Security

- Uses NIST P-256 elliptic curve cryptography
- Implements blinded key exchanges to prevent client identification
- Stateless design prevents timing attacks
- No authentication required (security through network topology)

## Testing

```bash
# Run all tests
cargo test

# Run with logging
RUST_LOG=debug cargo test -- --nocapture
```

## Differences from Original Tang

This Rust implementation aims to be compatible with the original C implementation but may have some differences:

- Uses pure Rust cryptographic libraries (p256, elliptic-curve)
- May not implement all JWE/JWS variations initially
- Focuses on P-256 curve (original supports multiple curves)

## License

MIT

## Contributing

Contributions welcome! This is a defensive security tool designed to help protect data through network binding.

## See Also

- [Original Tang (C implementation)](https://github.com/latchset/tang)
- [Clevis](https://github.com/latchset/clevis) - Automated decryption framework (client for Tang)
- [RFC 7516 (JWE)](https://tools.ietf.org/html/rfc7516)
- [RFC 7517 (JWK)](https://tools.ietf.org/html/rfc7517)
>>>>>>> d0049a5 (Tang in rust init)
