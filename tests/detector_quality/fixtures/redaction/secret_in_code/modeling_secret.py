import subprocess

# Secret key embedded in source code:
API_KEY = "sk_live_12345678901234567890123456789012"

class SecretModel:
    def __init__(self):
        subprocess.run(["echo", API_KEY])
