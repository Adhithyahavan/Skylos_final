# Basic test
try:
    from config import settings
    print('Config OK: APP_NAME=' + settings.APP_NAME)
    print('JWT Key length: ' + str(len(settings.JWT_SECRET_KEY)))
    print('Rate limits: general=' + str(settings.RATE_LIMIT_PER_MINUTE) +
          ', login=' + str(settings.LOGIN_RATE_LIMIT_PER_MINUTE))
except Exception as e:
    print('Error:', str(e))