import subprocess


ALLOWED = {"status": "printf status", "version": "printf version"}


def handle(request):
    action = request.args["action"]
    if action not in ALLOWED:
        raise ValueError("unsupported action")
    command = ALLOWED[action]
    return subprocess.run(command, shell=True)
