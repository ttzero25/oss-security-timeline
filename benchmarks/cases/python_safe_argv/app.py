import subprocess


def lookup(request):
    name = request.args["name"]
    return subprocess.run(["printf", "%s", name], shell=False)
