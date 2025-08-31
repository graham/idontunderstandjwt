# 🎓 JWT Learning Tool

**Learn JSON Web Tokens (JWTs) hands-on with an interactive, educational CLI tool!**

This project helps developers understand JWT concepts through practical experience. Generate keys, create tokens, verify signatures, and manage authentication sessions—all while learning the underlying concepts with detailed explanations.

![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=flat&logo=typescript&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-43853D?style=flat&logo=node.js&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=flat&logo=JSON%20web%20tokens&logoColor=white)

## 🌟 Why This Tool?

JWTs are everywhere in modern web development, but they can be confusing. This tool bridges the gap between theory and practice by:

- 📚 **Teaching while doing** - Every operation includes educational explanations
- 🔍 **Showing the details** - See exactly what happens during token creation and verification
- 🛡️ **Promoting security** - Learn best practices and common pitfalls
- 🎯 **Hands-on learning** - No more abstract tutorials—create real tokens!

## ✨ Features

### 🔑 **Key Management**
- Generate RSA, ECDSA, and EdDSA key pairs
- Store multiple keys with unique identifiers
- Export public JWKS for sharing
- Learn about public/private key cryptography

### 🎫 **Token Operations**
- Create JWT tokens with custom claims
- Verify tokens against multiple keys
- Parse token structure without verification
- Understand the signing and verification process

### 📁 **Session Management**
- Create authentication sessions with access/refresh tokens
- Practice real-world token refresh patterns
- Manage multiple user sessions
- Learn modern authentication flows

### 🎓 **Educational Features**
- Step-by-step explanations for every operation
- JWT concept explanations with examples
- Algorithm comparisons and recommendations
- Security best practices and warnings

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation

1. **Clone and install**
   ```bash
   git clone <repository-url>
   cd idontunderstandjwt
   npm install
   ```

2. **Build the project**
   ```bash
   npm run build
   ```

3. **Start learning!**
   ```bash
   npm run cli -- learn-basics
   ```

## 📚 Learning Journey

### Step 1: Understand the Basics
```bash
# Learn JWT fundamentals
npm run cli -- learn-basics

# Compare different algorithms
npm run cli -- compare-algorithms
```

### Step 2: Create Your First Key
```bash
# Generate an RSA key pair
npm run cli -- generate-key

# See what keys you have
npm run cli -- list-keys
```

### Step 3: Create and Verify Tokens
```bash
# Create a token (use the key ID from step 2)
npm run cli -- create-token -k <your-key-id> -s alice -i "myapp"

# Verify the token you just created
npm run cli -- verify-token -t "<your-token>"
```

### Step 4: Explore Sessions
```bash
# Create an authentication session
npm run cli -- create-session -n alice-session -s alice -k <your-key-id>

# Check session status
npm run cli -- session-status -n alice-session

# Get the access token
npm run cli -- get-session-token -n alice-session
```

## 📖 Command Reference

### Key Management
```bash
# Generate different types of keys
npm run cli -- generate-key                           # RS256 (default) with creative name
npm run cli -- generate-key -a ES256                  # ECDSA with creative name
npm run cli -- generate-key -a Ed25519                # EdDSA with creative name
npm run cli -- generate-key -d "My signing key"       # With description (gets creative name)

# Generate with custom names
npm run cli -- generate-key -n my-api-key             # Custom name
npm run cli -- generate-key -n prod-key -d "Production key"  # Custom name + description

# List all keys (shows creative names like "fluffy-cat", "strong-seahorse")
npm run cli -- list-keys

# Export public keys (safe to share)
npm run cli -- export-jwks -o public-keys.json

# Remove a key (use the creative name as key-id)
npm run cli -- remove-key -k fluffy-cat
```

### Token Operations
```bash
# Create tokens with various claims
npm run cli -- create-token -k <key-id> -s user123
npm run cli -- create-token -k <key-id> -s alice -i "myapp" -a "api.myapp.com"
npm run cli -- create-token -k <key-id> --payload '{"role":"admin","team":"eng"}'

# Verify tokens (tests against all available keys)
npm run cli -- verify-token -t "<token>"
npm run cli -- verify-token -t "<token>" -i "expected-issuer"

# Parse token structure
npm run cli -- parse-token -t "<token>"
```

### Session Management
```bash
# Create session with access/refresh tokens
npm run cli -- create-session -n my-session -s user123 -k <key-id>

# Session operations
npm run cli -- list-sessions
npm run cli -- session-status -n my-session
npm run cli -- refresh-session -n my-session
npm run cli -- get-session-token -n my-session -t access
npm run cli -- get-session-token -n my-session -t refresh

# Clean up
npm run cli -- remove-session -n my-session
```

### Educational Commands
```bash
# Learn JWT concepts
npm run cli -- learn-basics

# Compare signing algorithms
npm run cli -- compare-algorithms

# Skip explanations for faster operation
npm run cli -- <any-command> --no-explain
```

### Cleanup Commands
```bash
# Clear everything (with confirmation)
npm run cli -- clear

# Clear everything without confirmation
npm run cli -- clear --force

# Clear only keys, keep sessions
npm run cli -- clear --keys-only

# Clear only sessions, keep keys
npm run cli -- clear --sessions-only

# Also remove backup files
npm run cli -- clear --include-backups

# Silent cleanup (no explanations)
npm run cli -- clear --no-explain --force
```

## 💡 Real-World Examples

### API Authentication Setup
```bash
# 1. Generate a key for your API
npm run cli -- generate-key -d "Production API signing key"

# 2. Create a user session
npm run cli -- create-session -n user-john -s john123 -k <key-id> \
  --payload '{"role":"user","permissions":["read","write"]}'

# 3. Get the access token for API requests
npm run cli -- get-session-token -n user-john -t access

# 4. Export public keys for your API to verify tokens
npm run cli -- export-jwks -o ./public/jwks.json
```

### Testing Token Verification
```bash
# Generate multiple keys to simulate key rotation
npm run cli -- generate-key -a RS256 -d "Primary key"
npm run cli -- generate-key -a ES256 -d "Backup key"

# Create token with one key
npm run cli -- create-token -k <key1-id> -s testuser

# Verify shows which keys work and which don't
npm run cli -- verify-token -t "<token>"
```

### Learning Different Algorithms
```bash
# Try different signing algorithms
npm run cli -- generate-key -a RS256    # RSA
npm run cli -- generate-key -a ES256    # ECDSA  
npm run cli -- generate-key -a Ed25519  # EdDSA

# Create tokens with each and compare
npm run cli -- create-token -k <rsa-key> -s alice
npm run cli -- create-token -k <ec-key> -s alice
npm run cli -- create-token -k <ed25519-key> -s alice
```

## 📁 What Gets Created

```
your-project/
├── jwt-keys/              # JWT key storage directory
│   ├── fluffy-cat.json           # Public key for "fluffy-cat"
│   ├── fluffy-cat-private.json   # Private key for "fluffy-cat" (keep secret!)
│   ├── strong-seahorse.json      # Public key for "strong-seahorse"  
│   ├── strong-seahorse-private.json  # Private key for "strong-seahorse" (keep secret!)
│   └── jwks.json                 # Combined public JWKS (for compatibility)
└── sessions/              # Authentication sessions
    ├── alice-session.json
    └── bob-session.json
```

### File Purposes

- **`jwt-keys/`** - Directory containing all JWT key files, organized by key name
- **`{key-name}.json`** (e.g., `fluffy-cat.json`) - Individual public key files. Safe to share with other services.
- **`{key-name}-private.json`** (e.g., `fluffy-cat-private.json`) - Individual private key files for signing. **Keep these secret!**
- **`jwt-keys/jwks.json`** - Combined public JWKS containing all public keys. Used for compatibility and exports.
- **`sessions/`** - Directory storing authentication sessions with access/refresh token pairs.
- **`{session-name}.json`** (e.g., `alice-session.json`) - Individual session files with token data.

## 🔒 Security Notes

### ⚠️ **Important Security Considerations**

1. **Private Keys** - Never share `*-private.json` files or commit them to version control
2. **Token Expiration** - Use short-lived access tokens (15 minutes) with longer refresh tokens
3. **Key Rotation** - Regularly generate new keys and phase out old ones
4. **Issuer/Audience** - Always validate these claims in production
5. **HTTPS Only** - Never send JWTs over unencrypted connections

### 🛡️ **Production Checklist**

- [ ] Private keys stored securely (not in code)
- [ ] Public JWKS served over HTTPS
- [ ] Token expiration times appropriate for your use case
- [ ] Issuer and audience claims validated
- [ ] Key rotation strategy in place
- [ ] Monitoring for token abuse

## 🎯 Educational Value

This tool teaches you:

- **JWT Structure** - Header, payload, and signature components
- **Cryptographic Concepts** - Public/private keys, digital signatures
- **Token Lifecycle** - Creation, verification, expiration, refresh
- **Security Best Practices** - Key management, claim validation
- **Real-world Patterns** - Session management, key rotation

Every command includes detailed explanations, so you're not just running commands—you're learning the underlying concepts.

## 🐛 Troubleshooting

### Common Issues

**"Key not found" error**
```bash
# List available keys to see valid key IDs
npm run cli -- list-keys
```

**"Failed to verify token"**
```bash
# Parse the token to see its structure
npm run cli -- parse-token -t "<token>"

# Check if the key ID in the token matches your available keys
npm run cli -- list-keys
```

**Build errors**
```bash
# Clean build
rm -rf dist/
npm run build
```

**Session errors**
```bash
# List available sessions
npm run cli -- list-sessions

# Check specific session status
npm run cli -- session-status -n <session-name>
```

## 🤝 Contributing

Contributions welcome! This tool is designed to be educational, so:

- **Documentation** - Help improve explanations and examples
- **Features** - Add new educational features or JWT capabilities  
- **Examples** - Share real-world use cases and scenarios
- **Bug fixes** - Help make the tool more robust

### Development Setup
```bash
git clone <repository-url>
cd idontunderstandjwt
npm install
npm run dev    # Watch mode for development
npm run lint   # Check code quality
```

## 📄 License

MIT License - feel free to use this for learning and teaching!

## 🙏 Acknowledgments

Built with:
- [jose](https://github.com/panva/jose) - Comprehensive JWT library
- [Commander.js](https://github.com/tj/commander.js) - CLI framework
- [Chalk](https://github.com/chalk/chalk) - Terminal colors
- TypeScript for type safety and great developer experience

---

**Happy learning! 🎓** If you find this tool helpful, consider starring the repository and sharing it with others who are learning about JWTs.