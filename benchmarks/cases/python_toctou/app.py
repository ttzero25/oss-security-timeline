import os


def save(path):
    if not os.path.exists(path):
        with open(path, "w") as handle:
            handle.write("created")
