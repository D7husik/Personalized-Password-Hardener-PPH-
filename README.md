
# Personalized Password Hardener (PPH)

## 🎯 Project Overview

The Personalized Password Hardener is a cryptographic tool that strengthens user passwords by combining them with personal metadata using modern cryptographic techniques. This creates strong, yet memorable passwords based on information unique to the user.

## 🔬 Theoretical Foundation

### Cryptographic Concepts

1. **PBKDF2 (Password-Based Key Derivation Function 2)**
   - Industry-standard key derivation function
   - Uses HMAC-SHA256 as the pseudorandom function
   - Applies 100,000 iterations to resist brute-force attacks
   - Each iteration makes dictionary attacks exponentially more expensive

2. **Entropy Calculation**
   - Measures password randomness in bits
   - Formula: `Entropy = L × log₂(N)` where:
     - L = password length
     - N = character set size
   - Higher entropy = stronger password

3. **Salt Generation**
   - Cryptographically secure random 32-byte salt
   - Prevents rainbow table attacks
   - Unique per password hardening operation

### Mathematical Foundations

- **Hash Functions**: One-way functions from discrete mathematics
- **Computational Complexity**: Time complexity of O(n × iterations)
- **Brute Force Resistance**: 2^entropy possible combinations

## 🚀 Features

- ✅ Password hardening using PBKDF2-HMAC-SHA256
- ✅ Personal metadata integration
- ✅ Real-time entropy calculation
- ✅ Multiple password strength variants (short, medium, long)
- ✅ Brute force attack simulation
- ✅ Crack time estimation
- ✅ Interactive web interface
- ✅ Password strength visualization
- ✅ Secure cryptographic salt generation

## 📋 Requirements

```
Python 3.8+
Flask==2.3.0
```

## 🛠️ Installation

1. **Clone or create the project directory:**

```bash
mkdir password-hardener
cd password-hardener
```

2. **Create project structure:**

```
password-hardener/
│
├── pph_core.py          # Core cryptographic engine
├── app.py               # Flask web server
├── templates/
│   └── index.html       # Web interface
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

3. **Install dependencies:**

```bash
pip install flask
```

4. **Run the application:**

```bash
python app.py
```

5. **Access the web interface:**

Open your browser and navigate to `http://localhost:5000`

## 💻 Usage

### Web Interface

1. Enter your base password
2. (Optional) Add personal metadata:
   - House name/number
   - Phone last 4 digits
   - Core memory/phrase
   - Username/handle
   - Birthday token
   - Custom field
3. Click "Harden Password"
4. View results with three strength variants
5. Copy your preferred hardened password

### Python API

```python
from pph_core import PasswordHardener

# Initialize
pph = PasswordHardener()

# Define metadata
metadata = {
    'house_name': 'Sunset Villa',
    'phone_suffix': '5847',
    'core_memory': 'first_dog_max',
    'handle_name': 'cooluser123',
    'birthday_token': '0315'
}

# Harden password
result = pph.harden_password("MyPassword123", metadata)

# Access hardened passwords
print(result['hardened_short'])   # 16 characters
print(result['hardened_medium'])  # 24 characters
print(result['hardened_long'])    # 32 characters

# Analyze strength
analysis = pph.analyze_password_strength(result['hardened_medium'])
print(f"Entropy: {analysis['entropy']} bits")
print(f"Strength: {analysis['strength']}")
print(f"Crack time: {analysis['crack_time']['display']}")
```

## 🔐 Security Features

### 1. **PBKDF2-HMAC-SHA256**
- 100,000 iterations (OWASP recommended minimum)
- SHA-256 hash function (256-bit output)
- Resistance against GPU-accelerated attacks

### 2. **Cryptographic Salt**
- 32-byte (256-bit) random salt
- Generated using `secrets` module
- Unique per hardening operation

### 3. **Entropy Enhancement**
- Original password entropy preserved
- Additional entropy from metadata
- Cryptographic mixing of inputs

### 4. **Constant-Time Comparison**
- Uses `hmac.compare_digest()` for password verification
- Prevents timing attacks

## 📊 Password Strength Analysis

The tool provides comprehensive strength analysis:

| Entropy (bits) | Strength | Crack Time (1B attempts/sec) |
|----------------|----------|------------------------------|
| < 28           | Very Weak | Seconds to Minutes          |
| 28-36          | Weak      | Hours to Days               |
| 36-60          | Moderate  | Years                       |
| 60-80          | Strong    | Centuries                   |
| > 80           | Very Strong | Beyond astronomical time   |

## 🧪 Testing & Simulation

### Brute Force Simulation

```python
# Simulate brute force attack
result = pph.simulate_brute_force("password123", max_attempts=1000000)
print(result)
```

### Entropy Calculation

```python
# Calculate password entropy
entropy = pph.compute_entropy("MyPassword123!")
print(f"Entropy: {entropy} bits")
```

## 📐 Discrete Mathematics Concepts

### 1. **Combinatorics**
- Total password combinations = N^L
- N = character set size
- L = password length

### 2. **Logarithmic Complexity**
- Entropy = log₂(combinations)
- Information-theoretic security measure

### 3. **Hash Function Properties**
- Deterministic
- Pre-image resistance
- Collision resistance
- Avalanche effect

## 🎓 Educational Value

This project demonstrates:

1. **Practical Cryptography**
   - Industry-standard algorithms
   - Secure implementation practices

2. **Discrete Mathematics Application**
   - Entropy calculations
   - Combinatorial analysis
   - Hash function theory

3. **Software Engineering**
   - Clean code architecture
   - API design
   - Web application development

## ⚠️ Important Notes

- **Never** store your base password or metadata in plain text
- Use unique metadata combinations for different services
- Store only the salt and hardened hash (not the base password)
- This is for educational purposes; for production, use established password managers

## 🔮 Future Enhancements

- [ ] Database integration for secure storage
- [ ] Password history tracking
- [ ] Multi-factor authentication support
- [ ] Advanced brute-force visualization
- [ ] Password policy enforcement
- [ ] Export/Import functionality
- [ ] Mobile application

## 📚 References

- PBKDF2: RFC 2898
- OWASP Password Storage Cheat Sheet
- NIST Digital Identity Guidelines (SP 800-63B)
- Applied Cryptography by Bruce Schneier

## 👨‍💻 Technical Stack

- **Backend**: Python 3.8+
- **Cryptography**: hashlib, hmac, secrets
- **Web Framework**: Flask
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Mathematics**: Entropy calculations, combinatorics

## 📄 License

This project is for educational purposes. Feel free to use and modify.

## 🤝 Contributing

Contributions welcome! Please focus on:
- Security improvements
- Performance optimization
- Educational documentation
- Additional cryptographic features

---

**Created for educational purposes to demonstrate practical cryptography and discrete mathematics applications.**
