import jwt


def authenticate(request):
    token = request.headers["Authorization"]
    return jwt.decode(token, options={"verify_signature": False})
