import subprocess


class Worker:
    def execute(self, value):
        return subprocess.run(value, shell=True)
