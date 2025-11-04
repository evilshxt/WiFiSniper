"""
Password Generator Module
Advanced password generation with patterns and rules
"""

import string
import random
import itertools
from core.logger import Logger

logger = Logger()

class AdvancedPasswordGenerator:
    def __init__(self):
        self.logger = logger

    def generate_from_template(self, template, count=100):
        """
        Generate passwords from a template with placeholders
        Template examples:
        - "Pass??" -> Pass followed by 2 random chars
        - "User@###" -> User@ followed by 3 digits
        - "Test!@@@" -> Test! followed by 3 symbols
        """
        self.logger.info(f"Generating passwords from template: {template}")

        passwords = set()

        # Define character sets
        char_sets = {
            '?': string.ascii_letters,  # Letters
            '#': string.digits,         # Numbers
            '@': '!@#$%^&*()_+-=[]{}|;:,.<>?',  # Symbols
            '*': string.ascii_letters + string.digits,  # Alphanumeric
            '^': string.ascii_uppercase,  # Uppercase
            'v': string.ascii_lowercase,  # Lowercase
        }

        for _ in range(count * 2):  # Generate more to account for duplicates
            password = ""
            i = 0
            while i < len(template):
                char = template[i]
                if char in char_sets:
                    password += random.choice(char_sets[char])
                else:
                    password += char
                i += 1

            passwords.add(password)

            if len(passwords) >= count:
                break

        result = list(passwords)[:count]
        self.logger.success(f"Generated {len(result)} unique passwords")
        return result

    def generate_leet_speak(self, base_words, intensity=1, count=100):
        """
        Generate leet speak variations of words
        intensity: 1-3 (light to heavy leet speak)
        """
        self.logger.info(f"Generating leet speak passwords (intensity: {intensity})")

        leet_maps = {
            1: {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'},
            2: {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7',
                'g': '9', 'l': '1', 'z': '2', 'b': '8'},
            3: {'a': ['@', '4'], 'e': ['3', '€'], 'i': ['1', '!'], 'o': ['0', '()'],
                's': ['$', '5'], 't': ['7', '+'], 'g': ['9', '6'], 'l': ['1', '|'],
                'z': ['2', '7'], 'b': ['8', '6'], 'h': ['#', '|-|'], 'x': ['%', '><']}
        }

        leet_map = leet_maps.get(intensity, leet_maps[1])

        passwords = set()

        for word in base_words:
            # Generate variations
            variations = [word.lower(), word.upper(), word.capitalize()]

            # Apply leet speak
            for variation in variations:
                leet_word = variation
                for char, replacement in leet_map.items():
                    if isinstance(replacement, list):
                        for rep in replacement:
                            leet_word = leet_word.replace(char, rep)
                            leet_word = leet_word.replace(char.upper(), rep.upper())
                    else:
                        leet_word = leet_word.replace(char, replacement)
                        leet_word = leet_word.replace(char.upper(), replacement)

                passwords.add(leet_word)

                # Add with numbers/symbols
                for suffix in ['', '123', '!', '69', '007']:
                    passwords.add(leet_word + suffix)

        result = list(passwords)[:count]
        self.logger.success(f"Generated {len(result)} leet speak passwords")
        return result

    def generate_common_patterns(self, personal_info=None, count=1000):
        """
        Generate passwords based on common patterns and personal info
        """
        self.logger.info("Generating passwords from common patterns")

        if not personal_info:
            personal_info = {
                'name': 'john',
                'birth_year': '1990',
                'pet': 'fluffy',
                'city': 'paris'
            }

        base_words = []
        for key, value in personal_info.items():
            if value:
                base_words.extend([value, value.upper(), value.capitalize()])

        # Common patterns
        patterns = [
            "{word}{number}",
            "{word}{number}{symbol}",
            "{word}{symbol}{number}",
            "{number}{word}",
            "{number}{word}{symbol}",
            "{word1}{word2}",
            "{word1}{word2}{number}",
            "{word}{year}",
            "{word}{year}{symbol}"
        ]

        symbols = "!@#$%^&*"
        numbers = ["123", "456", "789", "000", "111", "999"]

        passwords = set()

        for word in base_words:
            for pattern in patterns:
                for number in numbers:
                    for symbol in symbols:
                        try:
                            pwd = pattern.format(
                                word=word,
                                number=number,
                                symbol=symbol,
                                year=personal_info.get('birth_year', '2024'),
                                word1=word,
                                word2=random.choice(base_words) if base_words else word
                            )
                            passwords.add(pwd)
                        except KeyError:
                            continue

        result = list(passwords)[:count]
        self.logger.success(f"Generated {len(result)} pattern-based passwords")
        return result

    def generate_brute_force(self, charset=string.ascii_lowercase, min_length=4, max_length=8, count=1000):
        """
        Generate brute force style passwords
        """
        self.logger.info(f"Generating brute force passwords (length {min_length}-{max_length})")

        passwords = set()

        # Generate all possible combinations
        for length in range(min_length, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                password = ''.join(combo)
                passwords.add(password)
                if len(passwords) >= count:
                    break
            if len(passwords) >= count:
                break

        result = list(passwords)[:count]
        self.logger.success(f"Generated {len(result)} brute force passwords")
        return result

    def generate_mixed_dictionary(self, dictionaries=None, rules=None, count=10000):
        """
        Generate passwords by mixing dictionary words with rules
        """
        if not dictionaries:
            dictionaries = [
                ['password', 'admin', 'user', 'login', 'welcome', 'system'],
                ['red', 'blue', 'green', 'black', 'white', 'yellow'],
                ['dog', 'cat', 'bird', 'fish', 'horse', 'rabbit']
            ]

        if not rules:
            rules = [
                lambda words: ''.join(words),  # Concatenate
                lambda words: ''.join(word.capitalize() for word in words),  # CamelCase
                lambda words: '_'.join(words),  # Underscore
                lambda words: '-'.join(words),  # Hyphen
                lambda words: ''.join(words) + '123',  # Add numbers
                lambda words: ''.join(words) + '!',  # Add symbol
            ]

        self.logger.info("Generating mixed dictionary passwords")

        passwords = set()

        # Generate combinations from dictionaries
        for combo in itertools.product(*dictionaries):
            for rule in rules:
                try:
                    password = rule(list(combo))
                    passwords.add(password)
                    if len(passwords) >= count:
                        break
                except Exception:
                    continue
            if len(passwords) >= count:
                break

        result = list(passwords)[:count]
        self.logger.success(f"Generated {len(result)} dictionary-based passwords")
        return result

    def save_to_file(self, passwords, filename, format_type='text'):
        """
        Save generated passwords to file
        """
        try:
            with open(filename, 'w') as f:
                if format_type == 'text':
                    for pwd in passwords:
                        f.write(pwd + '\n')
                elif format_type == 'csv':
                    f.write('password\n')
                    for pwd in passwords:
                        f.write(f'"{pwd}"\n')
                elif format_type == 'json':
                    import json
                    json.dump(passwords, f, indent=2)

            self.logger.success(f"Saved {len(passwords)} passwords to {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save passwords: {e}")
            return False

    def analyze_password_strength(self, passwords):
        """
        Analyze the strength of generated passwords
        """
        if not passwords:
            return None

        analysis = {
            'total': len(passwords),
            'avg_length': sum(len(p) for p in passwords) / len(passwords),
            'has_upper': sum(1 for p in passwords if any(c.isupper() for c in p)) / len(passwords) * 100,
            'has_lower': sum(1 for p in passwords if any(c.islower() for c in p)) / len(passwords) * 100,
            'has_digit': sum(1 for p in passwords if any(c.isdigit() for c in p)) / len(passwords) * 100,
            'has_symbol': sum(1 for p in passwords if any(not c.isalnum() for c in p)) / len(passwords) * 100,
        }

        print("\nPassword Analysis:")
        print(f"Total passwords: {analysis['total']}")
        print(f"Average length: {analysis['avg_length']:.1f}")
        print(f"With uppercase: {analysis['has_upper']:.1f}%")
        print(f"With lowercase: {analysis['has_lower']:.1f}%")
        print(f"With digits: {analysis['has_digit']:.1f}%")
        print(f"With symbols: {analysis['has_symbol']:.1f}%")

        return analysis

# Convenience functions
def generate_from_template(template, count=100):
    """Generate passwords from template"""
    generator = AdvancedPasswordGenerator()
    return generator.generate_from_template(template, count)

def generate_leet_speak(base_words, intensity=1, count=100):
    """Generate leet speak passwords"""
    generator = AdvancedPasswordGenerator()
    return generator.generate_leet_speak(base_words, intensity, count)

def generate_common_patterns(personal_info=None, count=1000):
    """Generate pattern-based passwords"""
    generator = AdvancedPasswordGenerator()
    return generator.generate_common_patterns(personal_info, count)