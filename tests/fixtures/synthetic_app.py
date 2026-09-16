"""Deliberately vulnerable local fixture; never deploy this module."""
import subprocess


def handle(request):
    command = request.args["command"]
    return subprocess.run(command, shell=True, capture_output=True, text=True)


class FakeApp:
    def post(self, _path):
        return lambda function: function


app = FakeApp()


@app.post("/run")
def routed(command):
    return subprocess.run(command, shell=True, capture_output=True, text=True)
