import secrets
import string
import argparse
import sys

# Owner: Nitin Patel

def generate_password(length, use_letters=True, use_numbers=True, use_symbols=True):
    """
    Generate a strong random password of specified length.
    
    Args:
        length (int): Desired password length
        use_letters (bool): Include letters in password
        use_numbers (bool): Include numbers in password
        use_symbols (bool): Include symbols in password
    
    Returns:
        str: Generated password
    
    Raises:
        ValueError: If length is too short or no character types selected
    """
    # Validate inputs
    if length < 4:
        raise ValueError("Password length must be at least 4 characters for security")
    
    # Define character pools
    char_pools = []
    
    if use_letters:
        char_pools.append(string.ascii_letters)  # Both uppercase and lowercase
    if use_numbers:
        char_pools.append(string.digits)
    if use_symbols:
        char_pools.append(string.punctuation)
    
    if not char_pools:
        raise ValueError("At least one character type (letters, numbers, or symbols) must be selected")
    
    # Ensure password contains at least one character from each selected pool
    password_chars = []
    
    # Pick one character from each pool
    for pool in char_pools:
        password_chars.append(secrets.choice(pool))
    
    # Fill the rest with random characters from all pools combined
    all_chars = ''.join(char_pools)
    remaining_length = length - len(password_chars)
    
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(all_chars))
    
    # Shuffle the characters to avoid predictable patterns
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)

def get_password_strength(password):
    """
    Evaluate password strength based on length and character diversity.
    
    Returns a string rating: 'Weak', 'Medium', 'Strong', or 'Very Strong'
    """
    score = 0
    
    # Check length
    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    
    # Check character variety
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    
    # Determine strength
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    elif score <= 6:
        return "Strong"
    else:
        return "Very Strong"

def main():
    """Main function to handle user interaction."""
    # Command line argument support
    parser = argparse.ArgumentParser(description='Generate a strong random password')
    parser.add_argument('-l', '--length', type=int, help='Password length')
    parser.add_argument('--no-letters', action='store_true', help='Exclude letters')
    parser.add_argument('--no-numbers', action='store_true', help='Exclude numbers')
    parser.add_argument('--no-symbols', action='store_true', help='Exclude symbols')
    parser.add_argument('-n', '--number', type=int, default=1, help='Number of passwords to generate')
    
    args = parser.parse_args()
    
    try:
        # Get password length from user or command line
        if args.length:
            length = args.length
        else:
            while True:
                try:
                    length = int(input("Enter desired password length (minimum 8 recommended): "))
                    if length < 4:
                        print("Password length must be at least 4 characters. Please try again.")
                        continue
                    break
                except ValueError:
                    print("Please enter a valid number.")
        
        # Get character preferences from user (if not using command line args)
        use_letters = not args.no_letters
        use_numbers = not args.no_numbers
        use_symbols = not args.no_symbols
        
        if not any([use_letters, use_numbers, use_symbols]):
            print("Error: At least one character type must be enabled.")
            sys.exit(1)
        
        # Generate passwords
        print(f"\n{'='*50}")
        print(f"Generating {args.number} password(s) of length {length}...")
        print(f"Characters: {'Letters' if use_letters else ''} "
              f"{'Numbers' if use_numbers else ''} "
              f"{'Symbols' if use_symbols else ''}")
        print(f"{'='*50}\n")
        
        for i in range(args.number):
            password = generate_password(length, use_letters, use_numbers, use_symbols)
            strength = get_password_strength(password)
            print(f"Password {i+1}: {password}")
            print(f"Strength: {strength}")
            
            # Show character composition
            char_count = {
                'Letters': sum(1 for c in password if c.isalpha()),
                'Numbers': sum(1 for c in password if c.isdigit()),
                'Symbols': sum(1 for c in password if c in string.punctuation)
            }
            print(f"Composition: {char_count}")
            print("-" * 40)
        
        print("\nTip: Never share your passwords with anyone!")
        
    except KeyboardInterrupt:
        print("\n\nPassword generation cancelled.")
        sys.exit(0)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

# Demonstration function
def demonstration():
    """Demonstrate various password generation scenarios."""
    print("=" * 60)
    print("PASSWORD GENERATOR DEMONSTRATION")
    print("=" * 60)
    
    test_cases = [
        {"length": 8, "use_letters": True, "use_numbers": True, "use_symbols": True},
        {"length": 12, "use_letters": True, "use_numbers": True, "use_symbols": False},
        {"length": 16, "use_letters": True, "use_numbers": False, "use_symbols": True},
        {"length": 20, "use_letters": True, "use_numbers": True, "use_symbols": True},
    ]
    
    for i, case in enumerate(test_cases, 1):
        try:
            password = generate_password(**case)
            strength = get_password_strength(password)
            print(f"\nTest Case {i}:")
            print(f"  Length: {case['length']}")
            print(f"  Options: Letters={case['use_letters']}, Numbers={case['use_numbers']}, Symbols={case['use_symbols']}")
            print(f"  Password: {password}")
            print(f"  Strength: {strength}")
        except ValueError as e:
            print(f"  Error: {e}")

if __name__ == "__main__":
    # Uncomment the following line to see a demonstration
    # demonstration()
    
    main()