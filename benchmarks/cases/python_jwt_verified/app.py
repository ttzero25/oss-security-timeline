import jwt


def authenticate(request):
    token = request.headers["Authorization"]
    return jwt.decode(token, "trusted-key", algorithms=["HS256"])
