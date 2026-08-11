import subprocess

class SubprocessModel:
    def __init__(self):
        subprocess.Popen(["echo", "executing"])
