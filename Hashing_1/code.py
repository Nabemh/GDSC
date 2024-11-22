#Change the calculate_hash function to hash user passwords using SHA256 hashing algorithm

def calculate_hash(password):
    """Create your hash function here

    This function should store the password hash securely, never storing the plain text password.
    """
    
    return password  # Returns password as plain text

def subscribe(user_name, password):
    """Registers a new user account."""
    account = user_name + ': ' + calculate_hash(password) + '\n'
    try:
        with open('accounts.txt', 'w') as f:
            f.write(account)
        print('[+] You are now registered!')
    except IOError as e:
        print(f'Error creating account: {e}')

def login(user_name, password):
    """Authenticates a user."""
    try:
        with open('accounts.txt', 'r') as f:
            account_file = f.read().strip()
    except FileNotFoundError:
        print('No accounts file found. Please register first.')
        return

    if not account_file:
        print('No accounts found.')
        return

    user_name_file, password_file = account_file.split(':')
    hashed_password = calculate_hash(password)

    if user_name == user_name_file and hashed_password == password_file:
        print('You are authenticated :)')
    else:
        print('[!] Invalid username or password')

def main():
    """Handles user interaction."""
    while True:
        choice = input("Enter:\n 1] to subscribe\n 2] to login\n 3] to exit\nChoice: ")

        if choice == '1':
            user_name = input("Enter a username: ")
            password = input("Enter a password: ")
            subscribe(user_name, password)
        elif choice == '2':
            user_name = input("Enter a username: ")
            password = input("Enter a password: ")
            login(user_name, password)
        elif choice == '3':
            print('Exiting...')
            break
        else:
            print('[!] Invalid choice')

if __name__ == '__main__':
    main()
