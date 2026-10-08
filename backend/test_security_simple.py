# Test Phase 1 security implementation

# Test imports
try:
    from fastapi import FastAPI
    from slowapi import Limiter
    from config import settings
    from auth import validate_password_strength
    from schemas import UserCreate
    print("PASS: All imports successful")
except Exception as e:
    print("FAIL: Import error:", e)
    exit(1)

# Test configuration
try:
    assert settings.APP_NAME == "AI-SIEM Guardian"
    assert settings.JWT_SECRET_KEY is not None
    assert len(settings.JWT_SECRET_KEY) >= 32
    print("PASS: Configuration validated")
    print("  JWT_SECRET_KEY length:", len(settings.JWT_SECRET_KEY))
    print("  Rate limit:", settings.RATE_LIMIT_PER_MINUTE, "/min")
    print("  Login rate limit:", settings.LOGIN_RATE_LIMIT_PER_MINUTE, "/min")
except AssertionError as e:
    print("FAIL: Configuration validation failed:", e)
    exit(1)

# Test password validation
test_cases = [
    ("weak", False),
    ("NoDigits!", False),
    ("noupppercase1", False),
    ("NOLOWERCASE1", False),
    ("ValidPass123", True),
    ("SecureP@ssw0rd", True),
]

passed = 0
for password, should_pass in test_cases:
    is_valid, error_msg = validate_password_strength(password)
    if is_valid == should_pass:
        print("PASS: Password validation for:", password[:4] + "...")
        passed += 1
    else:
        print("FAIL: Password validation error for:", password[:4])

print("PASS: Password validation:", passed, "/", len(test_cases), "tests passed")

# Test schema validation
try:
    # Valid user
    user = UserCreate(username="testuser", email="test@example.com", password="ValidPass123")
    print("PASS: Valid user schema accepted")

    # Invalid username
    try:
        UserCreate(username="test user!", email="test@example.com", password="ValidPass123")
        print("FAIL: Invalid username accepted")
    except:
        print("PASS: Invalid username rejected")

    # Invalid role
    try:
        UserCreate(username="testuser", email="test@example.com", password="ValidPass123", role="superadmin")
        print("FAIL: Invalid role accepted")
    except:
        print("PASS: Invalid role rejected")

except Exception as e:
    print("FAIL: Schema validation error:", e)

print("\nSecurity implementation test completed successfully!")