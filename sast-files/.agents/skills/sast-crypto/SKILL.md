---
name: sast-crypto
description: >-
  Detect insecure cryptography in a codebase — weak hashes (MD5/SHA-1 for
  security), weak ciphers (DES/3DES/RC4), bad modes (ECB), IV reuse, short
  keys, and weak PRNGs (Math.random, rand()) used for security-sensitive
  values. Uses a three-phase approach: recon (find crypto primitive calls),
  batched verify (analyze purpose and usage in parallel subagents, 3 sites
  each), and merge (consolidate batch results). Requires sast/architecture.md
  (run sast-analysis first). Outputs findings to sast/crypto-results.md and
  sast/crypto-results.json. Use when asked to find weak crypto, broken hashes,
  insecure ciphers, or weak random number generation.
version: 0.1.0
---

# Insecure Cryptography Detection

You are performing a focused security assessment to find insecure cryptography — broken or misused primitives that undermine confidentiality, integrity, or authenticity. This skill uses a three-phase approach with subagents: **recon** (find every crypto primitive call site), **batched verify** (analyze each site's purpose and parameters for exploitable weakness, in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Insecure Cryptography

Insecure cryptography means using broken or misused primitives: MD5/SHA-1 for authentication, DES/3DES/RC4 ciphers, ECB mode, IV reuse, short keys, or `Math.random` for security-sensitive values. The underlying math may be fine in isolation, but the primitive is either known-broken, unsuitable for the purpose, or used in a way that collapses its security guarantees.

The core pattern: *the code selects or configures a cryptographic primitive in a way that a well-understood attack can defeat — collision, plaintext recovery, IV reuse distinguishing, prediction of random output, or offline brute force.*

Cryptography is rarely broken at the algorithm level by the application — it is almost always broken at the *integration* level: wrong algorithm for the job, wrong mode, wrong parameters, wrong source of randomness. This skill targets those integration failures.

### What Insecure Crypto IS

**1. Weak hashes used for security (authentication, integrity, password storage)**
- `MD5` for anything security-sensitive — collisions are practical (`md5`, `createHash('md5')`, `MessageDigest.getInstance("MD5")`, `hashlib.md5`, `md5.Sum`).
- `SHA-1` for signatures, HMAC, certificate fingerprints, or password hashing — collisions were demonstrated in 2017 (SHAttered) and are only cheaper now.
- Unsalted, single-round hashes (even SHA-256) for password storage — vulnerable to rainbow tables and GPU-accelerated brute force.

**2. Weak symmetric ciphers**
- `DES` — 56-bit key, broken by brute force in hours on modern hardware.
- `3DES` / `TripleDES` / `DESede` — effective 112-bit security, SWEET32 birthday attack on 64-bit block size, deprecated by NIST.
- `RC4` — biased keystream, practical plaintext recovery (RFC 7465 prohibits it in TLS).
- `Blowfish` in new code (64-bit block size → SWEET32).

**3. Insecure cipher modes**
- `ECB` (Electronic Codebook) — identical plaintext blocks produce identical ciphertext blocks, leaking structure (the ECB penguin). Never use ECB for anything larger than one block.
- `CBC` without authentication — vulnerable to padding oracle attacks when decryption errors are observable.
- `CTR` with predictable or reused nonce — stream cipher keystream reuse, XOR recovery.
- `GCM` with reused `(key, IV)` pair — catastrophic: reveals authentication key, forgery of arbitrary messages.

**4. IV / nonce misuse**
- Zero IV (`new byte[16]`, `\x00 * 16`, hardcoded constant).
- Static/hardcoded IV reused for multiple messages.
- Deriving IV from a counter that resets, the message content, or another deterministic source with the same key.
- For AES-GCM specifically: any IV reuse under the same key breaks confidentiality AND authenticity.

**5. Short / weak keys**
- RSA keys < 2048 bits (512, 1024 bits).
- AES keys derived from short passwords without a proper KDF (PBKDF2/Argon2/scrypt with sufficient iterations and salt).
- Elliptic curves below 224 bits, or named curves known to be weak.
- DH/DSA parameters < 2048 bits.

**6. Weak PRNG for security-sensitive values**
- JavaScript `Math.random()` used for session IDs, password reset tokens, CSRF tokens, API keys, invitation codes, OTP codes, nonces.
- Java `java.util.Random` (not `SecureRandom`) for tokens.
- Python `random` module (not `secrets` or `os.urandom`) for tokens.
- C/C++ `rand()` / `srand(time(NULL))` for keys, IVs, session IDs.
- PHP `mt_rand()` / `rand()` (use `random_bytes` / `random_int`).
- Ruby `rand` / `Random.rand` (use `SecureRandom`).

**7. Password hashing with fast, unsalted hashes**
- `sha1(password)`, `md5(password)`, `sha256(password)` with no salt.
- Even `sha256(password + salt)` is insufficient — password hashing needs a KDF that is deliberately slow and memory-hard.

### What Insecure Crypto is NOT

Do not flag these as crypto findings:

- **JWT `alg: none` or algorithm confusion** — route these to `sast-jwt`.
- **Hardcoded API keys, secrets, or private keys in public code** — route these to `sast-hardcodedsecrets`. This skill analyzes how crypto is *used*, not where its inputs are stored.
- **Certificate validation bypass** (`rejectUnauthorized: false`, `verify=False` on requests) — usually a TLS / configuration issue, covered elsewhere.
- **Weak TLS cipher suites at the server config level** — an infrastructure/IaC concern (see `sast-iac`).
- **Predictable integer IDs exposed as references** — that's IDOR, not a PRNG finding.
- **Correct use of a secure primitive** — `AES-256-GCM` with `crypto.randomBytes(12)` per message is fine.
- **Non-security hashes**: MD5/SHA-1 used for file dedupe, ETags, content fingerprinting, or cache keys where collisions are not a threat — note and downgrade to informational (see false-positive handling below).

### Patterns That Prevent Insecure Crypto

**1. Strong integrity hashes**
```python
# Integrity / digests: SHA-256, SHA-3, BLAKE2, BLAKE3
import hashlib
digest = hashlib.sha256(data).hexdigest()
# BLAKE2 is also fine:
digest = hashlib.blake2b(data).hexdigest()
```

**2. Password hashing with a real KDF**
```python
# Python — Argon2id is the modern default
from argon2 import PasswordHasher
ph = PasswordHasher()
stored = ph.hash(password)

# bcrypt is acceptable (cost >= 12)
import bcrypt
stored = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# scrypt is acceptable with appropriate N, r, p
```

**3. AEAD ciphers with a fresh IV per message**
```javascript
// Node.js — AES-256-GCM with a random 12-byte IV, per message
const iv = crypto.randomBytes(12);                 // fresh every time
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
const tag = cipher.getAuthTag();
// Transmit (iv, ct, tag). Never reuse iv with the same key.
```

```python
# Python — ChaCha20-Poly1305 (also AEAD)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
nonce = os.urandom(12)                             # fresh every time
aead = ChaCha20Poly1305(key)
ct = aead.encrypt(nonce, plaintext, associated_data)
```

**4. Cryptographically secure random for tokens**
```javascript
// Node.js
const token = crypto.randomBytes(32).toString('hex');

// Browsers (Web Crypto)
const buf = new Uint8Array(32);
crypto.getRandomValues(buf);
```

```python
# Python
import secrets
token = secrets.token_urlsafe(32)
# or:
token = os.urandom(32)
```

```java
// Java
import java.security.SecureRandom;
SecureRandom sr = new SecureRandom();
byte[] token = new byte[32];
sr.nextBytes(token);
```

**5. Modern signature schemes**
```python
# Ed25519 signatures — fast, small, no parameter choices to get wrong
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sk = Ed25519PrivateKey.generate()
sig = sk.sign(message)
```

**6. Always prefer AEAD (authenticated encryption)**
- AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, AES-CCM.
- Never use a raw cipher (CBC, CTR) without a MAC — you will get padding oracle or malleability bugs.

---

## Vulnerable vs. Secure Examples

### Node.js — `crypto` module

```javascript
// VULNERABLE: MD5 used to hash passwords or auth tokens
const crypto = require('crypto');
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');   // broken
}

// VULNERABLE: SHA-1 used for token fingerprint / integrity
const fingerprint = crypto.createHash('sha1').update(token).digest('hex');

// VULNERABLE: DES / 3DES cipher
const cipher = crypto.createCipheriv('des-ede3-cbc', key, iv);    // 64-bit block
const cipher2 = crypto.createCipheriv('des-cbc', key, iv);        // 56-bit key

// VULNERABLE: ECB mode leaks plaintext structure
const cipher = crypto.createCipheriv('aes-256-ecb', key, null);

// VULNERABLE: hardcoded / zero IV with CBC
const iv = Buffer.alloc(16, 0);                                   // all zeros
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);     // IV reused every call

// VULNERABLE: Math.random for session IDs, reset tokens, CSRF, API keys
function generateResetToken() {
  return Math.random().toString(36).slice(2);                     // predictable
}
function makeApiKey() {
  let s = '';
  for (let i = 0; i < 32; i++) s += Math.floor(Math.random() * 16).toString(16);
  return s;
}

// SECURE: SHA-256 for integrity, Argon2id for passwords
const digest = crypto.createHash('sha256').update(data).digest('hex');

const argon2 = require('argon2');
const hash = await argon2.hash(pw, { type: argon2.argon2id });

// SECURE: AES-256-GCM with a fresh random IV per message
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
const tag = cipher.getAuthTag();

// SECURE: crypto.randomBytes for tokens
const resetToken = crypto.randomBytes(32).toString('hex');
```

### Python — `hashlib` / `cryptography` / `Crypto`

```python
# VULNERABLE: MD5 / SHA-1 for password storage or auth
import hashlib
def hash_password(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()           # broken
def token_digest(t: str) -> str:
    return hashlib.sha1(t.encode()).hexdigest()           # broken for auth

# VULNERABLE: unsalted SHA-256 for password storage (too fast, rainbow tables)
def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

# VULNERABLE: DES / 3DES / RC4
from Crypto.Cipher import DES, DES3, ARC4
cipher = DES.new(key, DES.MODE_CBC, iv)
cipher = DES3.new(key, DES3.MODE_CBC, iv)
cipher = ARC4.new(key)

# VULNERABLE: ECB mode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.AES(key), modes.ECB())

# VULNERABLE: static / zero IV
iv = b'\x00' * 16
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

# VULNERABLE: random module for security tokens
import random
def reset_token():
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))

# SECURE: Argon2id (preferred) or bcrypt for passwords
from argon2 import PasswordHasher
ph = PasswordHasher()
stored = ph.hash(pw)

# SECURE: SHA-256 for integrity
digest = hashlib.sha256(data).hexdigest()

# SECURE: AES-GCM with fresh nonce
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = os.urandom(12)
aead = AESGCM(key)
ct = aead.encrypt(nonce, plaintext, aad)

# SECURE: secrets for tokens
import secrets
reset_token = secrets.token_urlsafe(32)
```

### Java — `javax.crypto` / `java.security`

```java
// VULNERABLE: MD5 / SHA-1 for auth
MessageDigest md = MessageDigest.getInstance("MD5");
MessageDigest md = MessageDigest.getInstance("SHA-1");

// VULNERABLE: DES / 3DES / RC4
Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");
Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
Cipher c = Cipher.getInstance("RC4");

// VULNERABLE: ECB mode (this is the JVM default when no mode is specified!)
Cipher c = Cipher.getInstance("AES");                       // defaults to AES/ECB/PKCS5Padding
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");

// VULNERABLE: static / zero IV
byte[] iv = new byte[16];                                   // all zeros
IvParameterSpec ivSpec = new IvParameterSpec(iv);
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, key, ivSpec);

// VULNERABLE: java.util.Random for tokens
Random r = new Random();
long token = r.nextLong();

// SECURE: SHA-256 for integrity, Argon2/BCrypt for passwords
MessageDigest md = MessageDigest.getInstance("SHA-256");

// SECURE: AES-GCM with a fresh IV
SecureRandom sr = new SecureRandom();
byte[] iv = new byte[12];
sr.nextBytes(iv);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
c.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

// SECURE: SecureRandom for tokens
byte[] token = new byte[32];
new SecureRandom().nextBytes(token);
```

### Go — `crypto/*`

```go
// VULNERABLE: MD5 / SHA-1 for auth
import "crypto/md5"
import "crypto/sha1"
sum := md5.Sum(password)            // broken
sum := sha1.Sum(token)              // broken for auth

// VULNERABLE: DES / 3DES / RC4
import "crypto/des"
import "golang.org/x/crypto/rc4"
block, _ := des.NewCipher(key)
block, _ := des.NewTripleDESCipher(key)
c, _ := rc4.NewCipher(key)

// VULNERABLE: ECB mode (implemented manually since Go stdlib does not expose it — that's a signal)
// Any handwritten per-block loop using block.Encrypt directly without chaining is ECB.

// VULNERABLE: zero / static IV
iv := make([]byte, aes.BlockSize)   // all zeros
stream := cipher.NewCBCEncrypter(block, iv)

// VULNERABLE: math/rand for tokens
import "math/rand"
token := strconv.FormatInt(rand.Int63(), 16)

// SECURE: SHA-256, AES-GCM with fresh nonce, crypto/rand for tokens
import "crypto/sha256"
import "crypto/rand"
import "crypto/cipher"

sum := sha256.Sum256(data)

aesgcm, _ := cipher.NewGCM(block)
nonce := make([]byte, aesgcm.NonceSize())
if _, err := rand.Read(nonce); err != nil { panic(err) }
ct := aesgcm.Seal(nil, nonce, plaintext, aad)

tok := make([]byte, 32)
rand.Read(tok)
```

### PHP — `openssl_*` / `hash`

```php
// VULNERABLE: MD5 / SHA-1 for passwords or auth
$hash = md5($password);
$hash = sha1($password);
$hash = hash('md5', $token);
$hash = hash('sha1', $token);

// VULNERABLE: DES / 3DES / RC4 / ECB
$ct = openssl_encrypt($pt, 'des-cbc', $key, 0, $iv);
$ct = openssl_encrypt($pt, 'des-ede3-cbc', $key, 0, $iv);
$ct = openssl_encrypt($pt, 'rc4', $key);
$ct = openssl_encrypt($pt, 'aes-256-ecb', $key);

// VULNERABLE: static / zero IV
$iv = str_repeat("\0", 16);
$ct = openssl_encrypt($pt, 'aes-256-cbc', $key, 0, $iv);

// VULNERABLE: rand / mt_rand for tokens
$token = '';
for ($i = 0; $i < 32; $i++) $token .= dechex(mt_rand(0, 15));

// SECURE: password_hash (bcrypt/argon2), AES-256-GCM, random_bytes
$hash = password_hash($password, PASSWORD_ARGON2ID);

$iv = random_bytes(12);
$ct = openssl_encrypt($pt, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

$token = bin2hex(random_bytes(32));
```

### Ruby — `OpenSSL` / `Digest`

```ruby
# VULNERABLE: MD5 / SHA-1 for auth
require 'digest'
h = Digest::MD5.hexdigest(password)
h = Digest::SHA1.hexdigest(token)

# VULNERABLE: DES / 3DES / RC4 / ECB
cipher = OpenSSL::Cipher.new('des-cbc')
cipher = OpenSSL::Cipher.new('des-ede3-cbc')
cipher = OpenSSL::Cipher.new('rc4')
cipher = OpenSSL::Cipher.new('aes-256-ecb')

# VULNERABLE: zero IV
cipher.iv = "\x00" * 16

# VULNERABLE: rand for tokens
token = (0...32).map { rand(16).to_s(16) }.join

# SECURE: SHA-256, AES-GCM, SecureRandom
h = Digest::SHA256.hexdigest(data)

require 'securerandom'
cipher = OpenSSL::Cipher.new('aes-256-gcm').encrypt
cipher.key = key
cipher.iv  = SecureRandom.random_bytes(12)
ct = cipher.update(pt) + cipher.final
tag = cipher.auth_tag

token = SecureRandom.hex(32)
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

### Phase 1: Recon — Find Crypto Primitive Calls

Launch a subagent with the following instructions:

> **Goal**: Find every call site in the codebase that invokes a cryptographic primitive — hashing, symmetric encryption, asymmetric sign/verify, key derivation, or random number generation. Write results to `sast/crypto-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the tech stack, languages in use, and security-sensitive domains (auth, sessions, tokens, data at rest).
>
> **What to search for**:
>
> **1. Hash construction / digest calls**
> - Node.js: `crypto.createHash(...)`, `crypto.createHmac(...)`
> - Python: `hashlib.md5(`, `hashlib.sha1(`, `hashlib.new("md5"`, `hashlib.new("sha1"`, `hashlib.sha256(` (flag for review if used on passwords), `hmac.new(`
> - Java: `MessageDigest.getInstance(...)`, `Mac.getInstance(...)`
> - Go: `crypto/md5`, `crypto/sha1`, `crypto/sha256`, `hmac.New(`
> - PHP: `md5(`, `sha1(`, `hash(`, `hash_hmac(`
> - Ruby: `Digest::MD5`, `Digest::SHA1`, `Digest::SHA256`, `OpenSSL::HMAC`
>
> **2. Symmetric cipher construction**
> - Node.js: `crypto.createCipher(` (deprecated), `crypto.createCipheriv(`, `crypto.createDecipheriv(`
> - Python: `Cipher(algorithms.AES(`, `DES.new(`, `DES3.new(`, `ARC4.new(`, `AES.new(`, `Fernet(`
> - Java: `Cipher.getInstance(` — capture the transformation string
> - Go: `des.NewCipher`, `des.NewTripleDESCipher`, `aes.NewCipher`, `rc4.NewCipher`, `cipher.NewCBCEncrypter`, `cipher.NewGCM`
> - PHP: `openssl_encrypt(`, `openssl_decrypt(`, `mcrypt_*` (legacy)
> - Ruby: `OpenSSL::Cipher.new(`, `.encrypt`, `.decrypt`
>
> **3. Asymmetric sign / verify / keypair generation**
> - `RSA.generate(`, `generateKeyPair(`, `KeyPairGenerator.getInstance(`
> - `Signature.getInstance(`, `sign(`, `verify(`
> - Note key sizes and curve names where visible
>
> **4. Algorithm strings to flag during recon** — wherever they appear as literals:
> - `md5`, `MD5`, `"MD5"`
> - `sha1`, `SHA-1`, `SHA1`, `"SHA-1"`
> - `des`, `DES`, `3des`, `DES3`, `DESede`, `TripleDES`
> - `rc4`, `RC4`, `ARC4`, `ARCFOUR`
> - `ecb`, `ECB` — any transformation string containing `ECB`
> - `blowfish` (for new code)
> - Plain `"AES"` as a Java `Cipher.getInstance` argument (defaults to ECB)
>
> **5. PRNG / random calls**
> - JavaScript: `Math.random(`, `Math.floor(Math.random()`
> - Node.js: `crypto.randomBytes(` (secure, note), `crypto.pseudoRandomBytes(` (insecure)
> - Python: `random.random(`, `random.randint(`, `random.choice(`, `random.getrandbits(`, `random.SystemRandom(` (secure), `secrets.` (secure), `os.urandom(` (secure)
> - Java: `new Random(`, `Math.random(`, `ThreadLocalRandom`, `SecureRandom` (secure)
> - Go: `math/rand` (insecure), `crypto/rand` (secure)
> - PHP: `rand(`, `mt_rand(`, `random_bytes(` (secure), `random_int(` (secure)
> - Ruby: `rand(`, `Random.rand(`, `SecureRandom.` (secure)
> - C/C++: `rand(`, `srand(`, `RAND_bytes(` (secure)
>
> **6. IV / nonce construction near cipher calls**
> - Hardcoded byte arrays passed as IV: `Buffer.alloc(16, 0)`, `new byte[16]`, `b'\x00' * 16`, `str_repeat("\0", 16)`
> - IVs derived from constants, counters, timestamps, or the plaintext itself
> - IVs generated once at module load and reused
>
> **7. Password-hashing context clues**
> - Variables / column names: `password`, `pwd`, `passwd`, `pw_hash`, `password_hash`
> - Functions: `hashPassword`, `check_password`, `verify_password`, `login`, `register`, `signup`
> - If you see a hash call near these, note the context — Phase 2 will determine whether the hash is fit for purpose.
>
> **What to skip during recon**:
> - Tests and fixtures unless they document real production usage
> - Vendored / third-party code (`node_modules/`, `vendor/`, `venv/`, `site-packages/`)
> - Compiled output (`dist/`, `build/`, `.next/`, `out/`)
> - Documentation and example snippets clearly marked as examples
>
> **Output format** — write to `sast/crypto-recon.md`:
>
> ```markdown
> # Crypto Recon: [Project Name]
>
> ## Summary
> Found [N] crypto primitive call sites.
>
> ## Call Sites
>
> ### 1. [Descriptive name — e.g., "MD5 hashing in password reset flow"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Primitive category**: [hash / symmetric cipher / asymmetric / PRNG / KDF / HMAC / IV construction]
> - **Algorithm / function**: [e.g., MD5, AES-256-CBC, DES, Math.random, SHA-1, 3DES, AES-ECB]
> - **Apparent purpose**: [best-guess from surrounding context — e.g., "password storage", "session ID generation", "file dedupe", "API request signing", "CSRF token"]
> - **Nearby context**: [function name, endpoint, or class]
> - **Code snippet**:
>   ```
>   [the call site with ~3 lines of context]
>   ```
>
> [Repeat for each call site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/crypto-recon.md`. If the recon found **zero crypto primitive call sites** (the summary reports "Found 0" or the "Call Sites" section is empty), **skip Phase 2 and Phase 3 entirely**. Instead, write the following to `sast/crypto-results.md` and a matching `sast/crypto-results.json` with `"findings": []`, then stop:

```markdown
# Crypto Analysis Results

No crypto primitive usage detected in this codebase.
```

Only proceed to Phase 2 if Phase 1 found at least one call site worth analyzing.

### Phase 2: Verify — Usage Analysis (Batched)

After Phase 1 completes, read `sast/crypto-recon.md` and split the call sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/crypto-recon.md` and count the numbered call-site sections (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/crypto-batch-N.md` where N is the 1-based batch number.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned crypto call site, determine whether the primitive and its parameters are safe for the purpose the code uses it for. Write results to `sast/crypto-batch-[N].md`.
>
> **Your assigned call sites** (from the recon phase):
>
> [Paste the full text of the assigned sections here, preserving the original numbering.]
>
> **Context**: You will be given the project's architecture summary. Use it to understand which parts of the system handle authentication, sessions, tokens, and data at rest.
>
> **For each call site, answer two questions:**
>
> **Question 1: What is this primitive actually used for?**
>
> Read the surrounding code — caller, callee, variable names, endpoint, database column, response body — to classify the purpose:
> - **Security-sensitive**: password hashing, session / reset / CSRF / API tokens, message authentication, signing, data-at-rest encryption, key derivation, IV/nonce for AEAD, certificate fingerprints used in auth decisions.
> - **Non-security**: file dedupe, ETag / cache key, content fingerprinting for idempotency, checksum of non-sensitive data, test seeds, deterministic sharding.
>
> A weak primitive (MD5, SHA-1) in a non-security context is **not a vulnerability** — it is a false-positive candidate. Downgrade it: classify **Not Vulnerable** and note the purpose. Call this out explicitly so a reviewer can confirm the downgrade.
>
> If the purpose is ambiguous (e.g., a hash used as "a unique ID" that is later used as an authentication token), treat it as security-sensitive unless you can clearly rule that out.
>
> **Question 2: Is the primitive / usage actually weak?**
>
> Check specifically:
>
> - **Hash**: Is it MD5 or SHA-1 used for any security purpose? For passwords specifically, is a proper KDF (Argon2id / bcrypt / scrypt / PBKDF2 with ≥ 100k iterations) used, or is it a raw/unsalted fast hash?
> - **Symmetric cipher**: Is the algorithm DES / 3DES / RC4 / Blowfish? Is the mode ECB? Is it CBC/CTR without any authentication (MAC) afterwards? Is it a Java `Cipher.getInstance("AES")` call that silently defaults to ECB?
> - **IV / nonce**: Trace where the IV comes from. Is it hardcoded? Zero bytes? A module-level constant reused across calls? Derived from the plaintext or a counter that resets? For GCM specifically, any IV reuse with the same key is catastrophic — flag hard.
> - **Key material**: Is the key size adequate (RSA ≥ 2048, AES-128+, ECC ≥ 224)? Is the key derived from a weak source (short password, no KDF)?
> - **PRNG**: Is a non-cryptographic RNG (`Math.random`, `java.util.Random`, Python `random`, Go `math/rand`, PHP `rand`/`mt_rand`, Ruby `rand`, C `rand`) used to generate a session ID, password reset token, CSRF token, OTP, API key, invitation code, or cryptographic IV/key? Those are all attacker-predictable.
> - **Password hashing**: Is `sha1(password)`, `md5(password)`, or bare `sha256(password)` — with or without a static salt — used to store or compare credentials?
>
> **Classification**:
> - **Vulnerable**: Weak primitive used in a confirmed security-sensitive context with no effective mitigation — attack is directly practical (e.g., MD5 password hash, `Math.random` reset token, AES-ECB of user data, zero IV in AES-CBC of session cookie).
> - **Likely Vulnerable**: Weak primitive in a context that appears security-sensitive but requires confirming a secondary condition (e.g., the token is generated from `Math.random` but may or may not be used for authentication — trace is partial).
> - **Not Vulnerable**: Either the primitive is modern and correctly used, or it is a weak primitive used in a clearly non-security context (file dedupe, ETag). For the second case, note `Weak primitive used in non-security context — downgraded.`
> - **Needs Manual Review**: Cannot determine purpose or parameter safety from static analysis alone.
>
> **Output format** — write to `sast/crypto-batch-[N].md`:
>
> ```markdown
> # Crypto Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Vulnerability class**: [Weak hash (MD5 for passwords) / Weak cipher (3DES) / ECB mode / IV reuse / Weak PRNG (Math.random for reset token) / Unsalted password hash / Short key / etc.]
> - **Purpose**: [what the code uses this primitive for — confirmed security-sensitive]
> - **Issue**: [exactly what is wrong — algorithm, mode, IV, RNG]
> - **Attack scenario**: [step-by-step: what an attacker does, what they recover / predict / forge]
> - **Impact**: [credential theft, session hijack, token prediction, ciphertext forgery, plaintext recovery, etc.]
> - **Evidence**:
>   ```
>   [code snippet]
>   ```
> - **Remediation**: [concrete fix — e.g., "Replace MD5 with Argon2id via the argon2 library", "Switch to AES-256-GCM with crypto.randomBytes(12) per message", "Generate reset tokens with crypto.randomBytes(32).toString('hex')"]
> - **Dynamic Test**:
>   ```
>   [how to reproduce — e.g., "Capture 10 consecutive reset tokens, feed to a Math.random predictor (v8-randomness-predictor) to recover future tokens", "Run hashcat -m 0 against the leaked MD5 column", "Encrypt two known plaintexts and observe identical ECB blocks"]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Vulnerability class**: [class]
> - **Purpose**: [suspected use]
> - **Issue**: [what appears wrong]
> - **Uncertainty**: [what needs confirming — e.g., "Cannot fully confirm the token is used for authentication without reading all consumers"]
> - **Remediation**: [fix]
> - **Dynamic Test**:
>   ```
>   [attempt to exploit]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Reason**: [e.g., "AES-256-GCM with crypto.randomBytes(12) per message", "SHA-256 used purely for file dedupe — no auth decision depends on it", "MD5 used as ETag cache key — non-security; downgraded"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Uncertainty**: [why automated analysis cannot classify]
> - **Suggestion**: [what to check manually — "Confirm whether `userToken` in this module is shown to users or used as an authentication credential"]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/crypto-batch-*.md` file and merge them into a single `sast/crypto-results.md` and canonical `sast/crypto-results.json`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/crypto-batch-1.md`, `sast/crypto-batch-2.md`, ... files.
2. Collect every finding across the batches, preserving classification and all detail fields.
3. Count totals for the executive summary.
4. Write the merged markdown report to `sast/crypto-results.md` using the `## Findings` template below.
5. Write the canonical JSON to `sast/crypto-results.json` — one object per finding with the required fields (`id`, `skill`, `severity`, `title`, `description`, `location`, `remediation`). If there are no findings, still emit `{"findings": []}`.
6. After writing both result files, **delete all intermediate files**: `sast/crypto-recon.md` and every `sast/crypto-batch-*.md`.

---

## Findings

Use this template for `sast/crypto-results.md`:

```markdown
# Crypto Analysis Results: [Project Name]

## Executive Summary
- Call sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

### [VULNERABLE] Descriptive name
- **File**: `path/to/file.ext` (lines X-Y)
- **Vulnerability class**: [Weak hash / Weak cipher / ECB mode / IV reuse / Weak PRNG / Unsalted password hash / Short key]
- **Purpose**: [confirmed use]
- **Issue**: [what is wrong]
- **Attack scenario**: [step-by-step attacker flow]
- **Impact**: [what the attacker gains]
- **Evidence**:
  ```
  [code snippet]
  ```
- **Remediation**: [concrete replacement]
- **Dynamic Test**:
  ```
  [reproduction command or steps]
  ```

### [LIKELY VULNERABLE] Descriptive name
- **File**: `path/to/file.ext` (lines X-Y)
- **Vulnerability class**: [class]
- **Issue**: [what appears wrong]
- **Uncertainty**: [what needs to be confirmed]
- **Remediation**: [fix]
- **Dynamic Test**:
  ```
  [attempt to exploit]
  ```

### [NOT VULNERABLE] Descriptive name
- **File**: `path/to/file.ext` (lines X-Y)
- **Reason**: [why it is safe — or "weak primitive in non-security context, downgraded"]

### [NEEDS MANUAL REVIEW] Descriptive name
- **File**: `path/to/file.ext` (lines X-Y)
- **Uncertainty**: [why]
- **Suggestion**: [what to check manually]
```

Use this schema for `sast/crypto-results.json`:

```json
{
  "findings": [
    {
      "id": "crypto-1",
      "skill": "sast-crypto",
      "severity": "high",
      "title": "MD5 used for password hashing in user registration",
      "description": "hashPassword() in src/auth/register.js uses crypto.createHash('md5'). MD5 is broken and fast hashes are unsuitable for password storage; offline GPU brute force recovers plaintexts in seconds per hash.",
      "location": { "file": "src/auth/register.js", "line": 42, "column": 10 },
      "remediation": "Replace with Argon2id (argon2 library) or bcrypt with cost >= 12. Re-hash on next login."
    }
  ]
}
```

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to every subagent as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 call sites per subagent**. 1-3 sites → one subagent; 10 sites → four subagents (3+3+3+1). Always launch batch subagents **in parallel**, never sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file — keeps each context small.
- **Purpose drives classification**: MD5/SHA-1 is fine for file dedupe, content ETags, or cache keys where collisions do not cross a trust boundary. The same MD5 on a password column is critical. Phase 2 must decide which it is — if ambiguous, escalate to security-sensitive.
- **Always check for non-security FP**: If a hash is used purely to compute a content fingerprint for deduplication, caching, or idempotency, note it explicitly and classify as Not Vulnerable with the reason `Weak primitive used in non-security context — downgraded.` This protects the report from noise while leaving an audit trail.
- **IV reuse under AES-GCM is catastrophic**: it is not a "probably bad" finding, it is immediate plaintext recovery + forgery. Always flag hard.
- **Java's `Cipher.getInstance("AES")` defaults to ECB** — if the transformation string has no mode, treat as ECB.
- **Node's `crypto.createCipher(...)`** (no `iv` in the name) is deprecated and derives key/IV from a password via MD5 — any use is a finding.
- **PRNG context matters**: `Math.random()` for animation timing is fine; `Math.random()` for a password reset token is critical. Trace every suspect PRNG call to its consumer.
- Do not flag JWT issues here — route them to `sast-jwt`. Do not flag hardcoded secrets here — route them to `sast-hardcodedsecrets`. This skill is about *how* crypto primitives are chosen and invoked, not *where* their inputs live.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives in crypto are often silently catastrophic.
- Clean up intermediate files: delete `sast/crypto-recon.md` and all `sast/crypto-batch-*.md` files after the final `sast/crypto-results.md` and `sast/crypto-results.json` are written.
