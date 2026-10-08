import sys
from unittest.mock import MagicMock

# Mock the problematic modules before importing anything
class MockHTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)

class MockDepends:
    def __init__(self, dependency):
        self.dependency = dependency

class MockStatus:
    HTTP_400_BAD_REQUEST = 400
    HTTP_401_UNAUTHORIZED = 401
    HTTP_403_FORBIDDEN = 403
    HTTP_404_NOT_FOUND = 404
    HTTP_500_INTERNAL_SERVER_ERROR = 500

class MockWebSocket:
    pass

class MockSecurity:
    class OAuth2PasswordBearer:
        def __init__(self, *args, **kwargs):
            pass

# Create and install the mock fastapi module
mock_fastapi = MagicMock()
mock_fastapi.Depends = MockDepends
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.status = MockStatus()
mock_fastapi.WebSocket = MockWebSocket

mock_security = MagicMock()
mock_security.OAuth2PasswordBearer = MockSecurity.OAuth2PasswordBearer

sys.modules['fastapi'] = mock_fastapi
sys.modules['fastapi.security'] = mock_security

print("Mocks installed")
print("fastapi in sys.modules:", 'fastapi' in sys.modules)
print("fastapi.security in sys.modules:", 'fastapi.security' in sys.modules)

# Now try to import
try:
    sys.path.append('D:/std/ai-siem-guardian/backend')
    print("About to import auth...")
    import auth
    print("Auth imported successfully!")
    print("hash_password function:", auth.hash_password)
except Exception as e:
    print(f"Error importing auth: {e}")
    import traceback
    traceback.print_exc()