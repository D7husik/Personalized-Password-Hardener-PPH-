import hashlib
import hmac
import secrets
import string
import math
from typing import Dict, List, Tuple
import json

class PasswordHardener:
    """
    Personalized Password Hardener using cryptographic techniques
    and personal metadata to create strong, memorable passwords.
    """
    
    def __init__(self):
        self.metadata_weights = {
            'house_name': 0.2,
            'phone_suffix': 0.15,
            'core_memory': 0.25,
            'handle_name': 0.15,
            'birthday_token': 0.15,
            'custom': 0.1
        }
        self.iterations = 100000
    
    def collect_metadata(self, metadata: Dict[str, str]) -> str:
        """Combine and normalize metadata fields"""
        combined = ""
        for key, value in metadata.items():
            if value:
                combined += value.strip().lower()
        return combined
    
    def generate_salt(self) -> str:
        """Generate a cryptographically secure salt"""
        return secrets.token_hex(16)
    
    def compute_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        
        if charset_size == 0:
            return 0.0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def harden_password(self, base_password: str, metadata: Dict[str, str], 
                       salt: str = None, iterations: int = None) -> Dict:
        """
        Main function to harden password using PBKDF2-HMAC-SHA256
        
        Args:
            base_password: Original password
            metadata: Dictionary of personal metadata
            salt: Optional salt (if regenerating password)
            iterations: Number of iterations (default 100000)
        """
        if iterations is None:
            iterations = self.iterations
            
        # Collect and process metadata
        metadata_string = self.collect_metadata(metadata)
        
        # Generate or use provided salt
        if salt is None:
            salt = self.generate_salt()
        
        # Combine base password with metadata
        combined_input = f"{base_password}:{metadata_string}"
        
        # Apply PBKDF2
        hardened = hashlib.pbkdf2_hmac(
            'sha256',
            combined_input.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )
        
        # Convert to base64-like string
        hardened_hex = hardened.hex()
        
        # Create various strength outputs
        result = {
            'original_entropy': self.compute_entropy(base_password),
            'salt': salt,
            'iterations': iterations,
            'hardened_full': hardened_hex,
            'hardened_short': self._create_memorable_password(hardened_hex[:32]),
            'hardened_medium': self._create_memorable_password(hardened_hex[:48]),
            'hardened_long': self._create_memorable_password(hardened_hex[:64]),
        }
        
        # Calculate entropies
        result['short_entropy'] = self.compute_entropy(result['hardened_short'])
        result['medium_entropy'] = self.compute_entropy(result['hardened_medium'])
        result['long_entropy'] = self.compute_entropy(result['hardened_long'])
        
        return result
    
    def regenerate_password(self, base_password: str, metadata: Dict[str, str],
                           salt: str, variant: str = 'medium') -> str:
        """
        Regenerate a previously created password using the same salt
        
        Args:
            base_password: Original password
            metadata: Same metadata used originally
            salt: The salt from original generation
            variant: 'short', 'medium', or 'long'
        
        Returns:
            Regenerated password
        """
        result = self.harden_password(base_password, metadata, salt=salt)
        
        variant_map = {
            'short': 'hardened_short',
            'medium': 'hardened_medium',
            'long': 'hardened_long'
        }
        
        return result.get(variant_map.get(variant, 'hardened_medium'))
    
    def _create_memorable_password(self, hex_string: str) -> str:
        """Convert hex to more memorable password format"""
        # Mix of uppercase, lowercase, digits, and symbols
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ""
        
        for i in range(0, len(hex_string), 2):
            if i + 1 < len(hex_string):
                byte_val = int(hex_string[i:i+2], 16)
                password += chars[byte_val % len(chars)]
        
        return password
    
    def verify_password(self, base_password: str, metadata: Dict[str, str],
                       salt: str, stored_hash: str, iterations: int = None) -> bool:
        """Verify a password against stored hash"""
        if iterations is None:
            iterations = self.iterations
            
        metadata_string = self.collect_metadata(metadata)
        combined_input = f"{base_password}:{metadata_string}"
        
        computed = hashlib.pbkdf2_hmac(
            'sha256',
            combined_input.encode('utf-8'),
            salt.encode('utf-8'),
            iterations
        )
        
        return hmac.compare_digest(computed.hex(), stored_hash)
    
    def estimate_crack_time(self, entropy: float) -> Dict[str, str]:
        """Estimate time to crack password based on entropy"""
        # Assume 1 billion attempts per second
        attempts_per_second = 1e9
        total_combinations = 2 ** entropy
        seconds = total_combinations / attempts_per_second
        
        time_units = [
            ('centuries', 3153600000),
            ('years', 31536000),
            ('months', 2592000),
            ('days', 86400),
            ('hours', 3600),
            ('minutes', 60),
            ('seconds', 1)
        ]
        
        for unit, divisor in time_units:
            if seconds >= divisor:
                value = seconds / divisor
                return {
                    'numeric': round(value, 2),
                    'unit': unit,
                    'display': f"{round(value, 2)} {unit}"
                }
        
        return {'numeric': seconds, 'unit': 'seconds', 'display': f"{seconds} seconds"}
    
    def analyze_password_strength(self, password: str) -> Dict:
        """Comprehensive password strength analysis"""
        analysis = {
            'length': len(password),
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_symbols': any(c in string.punctuation for c in password),
            'entropy': self.compute_entropy(password)
        }
        
        analysis['crack_time'] = self.estimate_crack_time(analysis['entropy'])
        
        # Strength rating
        entropy = analysis['entropy']
        if entropy < 28:
            analysis['strength'] = 'Very Weak'
            analysis['color'] = 'red'
        elif entropy < 36:
            analysis['strength'] = 'Weak'
            analysis['color'] = 'orange'
        elif entropy < 60:
            analysis['strength'] = 'Moderate'
            analysis['color'] = 'yellow'
        elif entropy < 80:
            analysis['strength'] = 'Strong'
            analysis['color'] = 'lightgreen'
        else:
            analysis['strength'] = 'Very Strong'
            analysis['color'] = 'green'
        
        return analysis
    
    def simulate_brute_force(self, password: str, max_attempts: int = 1000000) -> Dict:
        """Simulate brute force attack (simplified)"""
        charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
        attempts = 0
        
        # This is a simplified simulation for demonstration
        for _ in range(min(max_attempts, 10000)):
            attempts += 1
            guess = ''.join(secrets.choice(charset) for _ in range(len(password)))
            if guess == password:
                return {
                    'cracked': True,
                    'attempts': attempts,
                    'password': password
                }
        
        return {
            'cracked': False,
            'attempts': attempts,
            'message': f'Not cracked after {attempts} attempts'
        }


# Example usage
if __name__ == "__main__":
    pph = PasswordHardener()
    
    metadata = {
        'house_name': 'Sunset Villa',
        'phone_suffix': '5847',
        'core_memory': 'first_dog_max',
        'handle_name': 'cooluser123',
        'birthday_token': '0315'
    }
    
    base_password = "MySimplePass123"
    
    print("=" * 60)
    print("PERSONALIZED PASSWORD HARDENER")
    print("=" * 60)
    
    # Generate password
    result = pph.harden_password(base_password, metadata)
    
    print(f"\nOriginal Password: {base_password}")
    print(f"Hardened Medium: {result['hardened_medium']}")
    print(f"Salt (Recovery Key): {result['salt']}")
    print(f"Entropy: {result['original_entropy']} → {result['medium_entropy']} bits")
    
    # Demonstrate regeneration
    print("\n--- PASSWORD REGENERATION ---")
    regenerated = pph.regenerate_password(base_password, metadata, result['salt'], 'medium')
    print(f"Regenerated: {regenerated}")
    print(f"Match: {regenerated == result['hardened_medium']}")
    
    print("\n" + "=" * 60)