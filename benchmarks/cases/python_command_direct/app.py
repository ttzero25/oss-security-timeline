import subprocess


def handle(request):
    command = request.args["command"]
    return subprocess.run(command, shell=True)
