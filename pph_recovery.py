"""
Password Recovery Module for PPH System
Allows users to regenerate their hardened passwords using:
- Base password
- Personal metadata
- Secret recovery key (salt)
"""

import hashlib
import hmac
import json
from typing import Dict, Optional
import string


class PasswordRecovery:
    """
    Handles password recovery and regeneration using stored secret keys
    """
    
    def __init__(self):
        self.iterations = 100000
        
    def generate_hardened_password(self, base_password: str, 
                                   metadata: Dict[str, str], 
                                   secret_key: str,
                                   length: int = 24) -> str:
        """
        Regenerate hardened password using base password, metadata, and secret key
        
        Args:
            base_password: Original user password
            metadata: Dictionary of personal metadata
            secret_key: The salt/secret key from original generation
            length: Desired password length (16, 24, or 32)
            
        Returns:
            Regenerated hardened password
        """
        # Collect and normalize metadata
        metadata_string = self._collect_metadata(metadata)
        
        # Combine password with metadata
        combined_input = f"{base_password}:{metadata_string}"
        
        # Apply PBKDF2 with the stored secret key
        hardened = hashlib.pbkdf2_hmac(
            'sha256',
            combined_input.encode('utf-8'),
            secret_key.encode('utf-8'),
            self.iterations
        )
        
        # Convert to readable password
        hardened_hex = hardened.hex()
        password = self._hex_to_password(hardened_hex, length)
        
        return password
    
    def _collect_metadata(self, metadata: Dict[str, str]) -> str:
        """Combine and normalize metadata fields"""
        combined = ""
        for key, value in metadata.items():
            if value:
                combined += value.strip().lower()
        return combined
    
    def _hex_to_password(self, hex_string: str, length: int) -> str:
        """Convert hex to readable password format"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ""
        
        for i in range(0, min(length * 2, len(hex_string)), 2):
            byte_val = int(hex_string[i:i+2], 16)
            password += chars[byte_val % len(chars)]
        
        return password[:length]
    
    def verify_recovery_credentials(self, base_password: str,
                                    metadata: Dict[str, str],
                                    secret_key: str,
                                    expected_password: str) -> bool:
        """
        Verify that the provided credentials can regenerate the expected password
        
        Args:
            base_password: User's base password
            metadata: Personal metadata
            secret_key: Secret recovery key
            expected_password: The password that should be regenerated
            
        Returns:
            True if credentials match, False otherwise
        """
        regenerated = self.generate_hardened_password(
            base_password, 
            metadata, 
            secret_key,
            len(expected_password)
        )
        
        return hmac.compare_digest(regenerated, expected_password)
    
    def save_recovery_info(self, secret_key: str, 
                          metadata_hints: Dict[str, str],
                          filename: str = "recovery_info.json") -> None:
        """
        Save recovery information to file (WITHOUT base password)
        
        Args:
            secret_key: The secret key to store
            metadata_hints: Optional hints for metadata (not full values)
            filename: Output file name
        """
        recovery_data = {
            'secret_key': secret_key,
            'metadata_hints': metadata_hints,
            'iterations': self.iterations,
            'algorithm': 'PBKDF2-HMAC-SHA256',
            'warning': 'Keep this file secure! Store base password separately.'
        }
        
        with open(filename, 'w') as f:
            json.dump(recovery_data, f, indent=2)
        
        print(f"Recovery info saved to {filename}")
        print("⚠️  IMPORTANT: Store your base password separately!")
    
    def load_recovery_info(self, filename: str = "recovery_info.json") -> Dict:
        """
        Load recovery information from file
        
        Args:
            filename: Input file name
            
        Returns:
            Dictionary with recovery information
        """
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise Exception(f"Recovery file '{filename}' not found!")
        except json.JSONDecodeError:
            raise Exception(f"Invalid recovery file format!")


class RecoveryManager:
    """
    High-level interface for managing password recovery
    """
    
    def __init__(self):
        self.recovery = PasswordRecovery()
    
    def create_recovery_package(self, base_password: str,
                               metadata: Dict[str, str],
                               secret_key: str,
                               output_file: str = "recovery_info.json") -> Dict:
        """
        Create a complete recovery package
        
        Returns:
            Dictionary with all recovery information
        """
        # Generate hardened passwords
        short_pass = self.recovery.generate_hardened_password(
            base_password, metadata, secret_key, 16
        )
        medium_pass = self.recovery.generate_hardened_password(
            base_password, metadata, secret_key, 24
        )
        long_pass = self.recovery.generate_hardened_password(
            base_password, metadata, secret_key, 32
        )
        
        # Create metadata hints (first 2 chars only)
        hints = {}
        for key, value in metadata.items():
            if value and len(value) >= 2:
                hints[key] = value[:2] + "..."
            elif value:
                hints[key] = value[0] + "..."
            else:
                hints[key] = "Not provided"
        
        # Save recovery info
        self.recovery.save_recovery_info(secret_key, hints, output_file)
        
        return {
            'secret_key': secret_key,
            'passwords': {
                'short': short_pass,
                'medium': medium_pass,
                'long': long_pass
            },
            'metadata_hints': hints,
            'recovery_file': output_file
        }
    
    def recover_password(self, base_password: str,
                        metadata: Dict[str, str],
                        recovery_file: str = "recovery_info.json",
                        variant: str = "medium") -> str:
        """
        Recover password using stored recovery information
        
        Args:
            base_password: User's base password
            metadata: Personal metadata
            recovery_file: Path to recovery info file
            variant: Password variant (short/medium/long)
            
        Returns:
            Recovered password
        """
        # Load recovery info
        recovery_info = self.recovery.load_recovery_info(recovery_file)
        secret_key = recovery_info['secret_key']
        
        # Determine length
        length_map = {'short': 16, 'medium': 24, 'long': 32}
        length = length_map.get(variant, 24)
        
        # Regenerate password
        recovered = self.recovery.generate_hardened_password(
            base_password,
            metadata,
            secret_key,
            length
        )
        
        return recovered


# Example usage and testing
if __name__ == "__main__":
    print("=" * 70)
    print("PASSWORD RECOVERY MODULE - DEMONSTRATION")
    print("=" * 70)
    
    # Initialize
    manager = RecoveryManager()
    
    # Original password creation scenario
    print("\n1. ORIGINAL PASSWORD CREATION")
    print("-" * 70)
    
    base_password = "MySecurePass123"
    metadata = {
        'house_name': 'Sunset Villa',
        'phone_suffix': '5847',
        'core_memory': 'first_dog_max',
        'handle_name': 'cooluser123',
        'birthday_token': '0315'
    }
    
    # In real usage, this would come from the original PPH generation
    secret_key = "a1b2c3d4e5f67890abcdef1234567890"  # 32-char hex string
    
    print(f"Base Password: {base_password}")
    print(f"Metadata: {list(metadata.values())}")
    print(f"Secret Key: {secret_key}")
    
    # Create recovery package
    print("\n2. CREATING RECOVERY PACKAGE")
    print("-" * 70)
    
    package = manager.create_recovery_package(
        base_password,
        metadata,
        secret_key,
        "my_recovery.json"
    )
    
    print(f"✓ Recovery file created: {package['recovery_file']}")
    print(f"✓ Generated passwords:")
    print(f"  - Short:  {package['passwords']['short']}")
    print(f"  - Medium: {package['passwords']['medium']}")
    print(f"  - Long:   {package['passwords']['long']}")
    print(f"\n✓ Metadata hints saved:")
    for key, hint in package['metadata_hints'].items():
        print(f"  - {key}: {hint}")
    
    # Simulate password recovery
    print("\n3. PASSWORD RECOVERY SIMULATION")
    print("-" * 70)
    print("User provides: Base password + Metadata + Recovery file")
    
    # Recover medium variant
    recovered_medium = manager.recover_password(
        base_password,
        metadata,
        "my_recovery.json",
        "medium"
    )
    
    print(f"\n✓ Recovered Medium Password: {recovered_medium}")
    print(f"✓ Original Medium Password:  {package['passwords']['medium']}")
    print(f"✓ Match: {recovered_medium == package['passwords']['medium']}")
    
    # Recover all variants
    print("\n4. RECOVERING ALL VARIANTS")
    print("-" * 70)
    
    variants = ['short', 'medium', 'long']
    for variant in variants:
        recovered = manager.recover_password(
            base_password,
            metadata,
            "my_recovery.json",
            variant
        )
        original = package['passwords'][variant]
        match = "✓ MATCH" if recovered == original else "✗ MISMATCH"
        print(f"{variant.capitalize():8} - {match}")
    
    # Test verification
    print("\n5. CREDENTIAL VERIFICATION")
    print("-" * 70)
    
    recovery_obj = PasswordRecovery()
    is_valid = recovery_obj.verify_recovery_credentials(
        base_password,
        metadata,
        secret_key,
        package['passwords']['medium']
    )
    
    print(f"Credentials valid: {is_valid}")
    
    # Test with wrong password
    print("\n6. TESTING WITH INCORRECT PASSWORD")
    print("-" * 70)
    
    wrong_password = "WrongPassword123"
    try:
        recovered_wrong = manager.recover_password(
            wrong_password,
            metadata,
            "my_recovery.json",
            "medium"
        )
        print(f"Generated with wrong password: {recovered_wrong}")
        print(f"Original password:             {package['passwords']['medium']}")
        print(f"Match: {recovered_wrong == package['passwords']['medium']}")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n" + "=" * 70)
    print("IMPORTANT SECURITY NOTES:")
    print("=" * 70)
    print("1. Store base password separately (NOT in recovery file)")
    print("2. Keep recovery file secure")
    print("3. Remember your metadata exactly as entered")
    print("4. Secret key is required for regeneration")
    print("5. All three components needed: password + metadata + secret key")
    print("=" * 70)