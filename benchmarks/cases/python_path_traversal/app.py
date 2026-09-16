def download(request):
    filename = request.args["filename"]
    with open(filename, "rb") as source:
        return source.read()
