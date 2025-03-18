import random
import string
import bcrypt
import re
import requests
import hashlib
from colorama import Fore, Style, init

# Initialize Colorama for colored console output
init(autoreset=True)

class PasswordGenerator:
    def __init__(self, length=12, use_uppercase=True, use_lowercase=True, use_numbers=True, use_special=True):
        self.length = length
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_numbers = use_numbers
        self.use_special = use_special

    def generate_password(self):
        character_pool = ""
        if self.use_uppercase:
            character_pool += string.ascii_uppercase
        if self.use_lowercase:
            character_pool += string.ascii_lowercase
        if self.use_numbers:
            character_pool += string.digits
        if self.use_special:
            character_pool += string.punctuation

        if not character_pool:
            raise ValueError("At least one character type must be selected.")

        return ''.join(random.choice(character_pool) for _ in range(self.length))

class PasswordStrengthChecker:
    def check_strength(self, password):
        length_score = len(password) >= 12
        upper_score = bool(re.search(r'[A-Z]', password))
        lower_score = bool(re.search(r'[a-z]', password))
        number_score = bool(re.search(r'[0-9]', password))
        special_score = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        score = sum([length_score, upper_score, lower_score, number_score, special_score])

        strength = Fore.RED + "Weak"
        if score >= 4:
            strength = Fore.GREEN + "Strong"
        elif score == 3:
            strength = Fore.YELLOW + "Moderate"

        return strength + Style.RESET_ALL, self.get_security_insights(password)

    def get_security_insights(self, password):
        insights = []
        if len(password) < 12:
            insights.append("🔹 Consider using at least 12 characters.")
        if not re.search(r'[A-Z]', password):
            insights.append("🔹 Include at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            insights.append("🔹 Include at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            insights.append("🔹 Include at least one number.")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
            insights.append("🔹 Include at least one special character.")
        if re.search(r'(.)\1{2,}', password):
            insights.append("🔹 Avoid repeating characters.")
        if len(set(password)) < len(password) / 2:
            insights.append("🔹 Avoid using too many similar characters.")

        return insights

class PasswordStorage:
    @staticmethod
    def hash_password(password):
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt)

def check_pwned(password):
    try:
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5_char, tail = sha1_password[:5], sha1_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{first5_char}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        hashes = (line.split(':') for line in response.text.splitlines())
        return any(tail == h for h, _ in hashes)
    except requests.RequestException as e:
        print(Fore.RED + f"⚠️ Network error: {e}" + Style.RESET_ALL)
        return False  # Assume safe if we cannot check

if __name__ == "__main__":
    try:
        print(Fore.CYAN + "=" * 40)
        print("🔐 Password Generator & Strength Checker 🔐")
        print("=" * 40 + Style.RESET_ALL)

        length = int(input(Fore.YELLOW + "👉 Password length (8-64): " + Style.RESET_ALL) or 12)
        length = max(8, min(length, 64))

        use_lowercase = input("✅ Include lowercase letters? (Y/n): ").strip().lower() != 'n'
        use_uppercase = input("✅ Include uppercase letters? (Y/n): ").strip().lower() != 'n'
        use_numbers = input("✅ Include numbers? (Y/n): ").strip().lower() != 'n'
        use_special = input("✅ Include special characters? (Y/n): ").strip().lower() != 'n'

        generator = PasswordGenerator(length, use_uppercase, use_lowercase, use_numbers, use_special)
        new_password = generator.generate_password()

        if check_pwned(new_password):
            print(Fore.RED + "\n🚨 Warning: This password has been compromised in data breaches! 🚨")
            print("❌ Do NOT use this password." + Style.RESET_ALL)
            regenerate = input("🔄 Generate a new one? (Y/n): ").strip().lower()
            if regenerate != 'n':
                new_password = generator.generate_password()
        else:
            print(Fore.GREEN + "\n✅ Good News: This password has NOT been found in any known data breaches!" + Style.RESET_ALL)

        print(Fore.CYAN + "\n" + "=" * 40)
        print("🎉 Generated Password 🎉")
        print("=" * 40)
        print(Fore.GREEN + f"🔑 {new_password}" + Style.RESET_ALL)
        print("=" * 40)

        checker = PasswordStrengthChecker()
        strength, insights = checker.check_strength(new_password)

        print(Fore.BLUE + "\n📊 Password Strength: " + strength)
        print("=" * 40)
        print("💡 Security Insights:")
        for insight in insights:
            print(insight)

        hashed_password = PasswordStorage.hash_password(new_password)

        print(Fore.MAGENTA + "\n🔒 Hashed Password (Store this securely!)")
        print("=" * 40)
        print(Fore.WHITE + hashed_password.decode('utf-8'))
        print("=" * 40 + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"❌ Error: {e}" + Style.RESET_ALL)
