# Tang Server - Quick Start Guide

## Build

```bash
cargo build --release
```

The binary will be at `./target/release/tang`

## Quick Start

### 1. Generate Keys

```bash
# Generate an exchange key
cargo run --release -- keygen -d ./keys

# Generate a signing key
cargo run --release -- keygen -d ./keys --signing
```

### 2. Start the Server

```bash
# Start on default port 9090
cargo run --release -- serve -d ./keys

# Or specify a custom port
cargo run --release -- serve -d ./keys -p 8080
```

### 3. Test the Server

```bash
# Health check
curl http://localhost:9090/health

# Get advertised keys
curl http://localhost:9090/adv | jq '.'
```

## Example Output

### Listing Keys
```bash
$ cargo run -- list -d ./keys
Listing active keys in: ./keys
  -X9sy34-LdW3qfTRUvBsNUCR_pR-o-PX48UBncIgDp0 - sig (EC)
  5vxI4stGNSe4fzQOny2x9Ac_1Ny-psdXBLWsasSNw2U - enc (EC)
```

### Advertisement Response
```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "sig",
      "alg": "ES256",
      "kid": "-X9sy34-LdW3qfTRUvBsNUCR_pR-o-PX48UBncIgDp0"
    },
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "enc",
      "key_ops": ["deriveKey"],
      "kid": "5vxI4stGNSe4fzQOny2x9Ac_1Ny-psdXBLWsasSNw2U"
    }
  ]
}
```

## Key Rotation

To rotate keys without downtime:

```bash
# 1. Generate new keys
cargo run -- keygen -d ./keys --signing
cargo run -- keygen -d ./keys

# 2. Hide old keys (they still work for recovery but aren't advertised)
cargo run -- hide -d ./keys <OLD_KEY_ID>

# 3. Server automatically picks up changes (no restart needed)
```

## API Endpoints

### GET /health
Health check endpoint

**Response**: `OK`

### GET /adv
Advertise all active public keys

**Response**: JSON Web Key Set (JWKS)

### GET /adv/:kid
Advertise keys signed with a specific signing key

**Response**: JSON Web Key Set (JWKS)

### POST /rec/:kid
Perform key recovery operation

**Request Body**: JWK with client's public key
**Response**: JWK with recovery result

## Running Tests

```bash
cargo test
```

## Production Deployment

For production, consider:

1. Running behind a reverse proxy (nginx, Apache)
2. Using systemd for service management
3. Setting appropriate file permissions on the key directory
4. Regular key rotation schedule
5. Monitoring and logging

Example systemd unit file location: `/etc/systemd/system/tang.service`

## Compatibility

This Rust implementation aims to be compatible with the original C implementation of Tang and should work with Clevis clients.

## Need Help?

- Check the full [README.md](README.md) for detailed documentation
- See [examples/basic_usage.sh](examples/basic_usage.sh) for automated examples
- Report issues at the project repository
