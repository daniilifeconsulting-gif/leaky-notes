from werkzeug.security import generate_password_hash, check_password_hash

password = "SuperSecret123"

# Force a method that works on older Python/hashlib versions
password_hash = generate_password_hash(password, method="pbkdf2:sha256")
print("Stored hash:")
print(password_hash)
print()

print("Check correct password:", check_password_hash(password_hash, "SuperSecret123"))
print("Check WRONG password:", check_password_hash(password_hash, "WrongPassword"))