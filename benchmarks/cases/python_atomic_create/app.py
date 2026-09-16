import os


def save(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    os.close(descriptor)
