
import base64
payload = base64.b64decode("cHJpbnQoJ3B3bmVkJyk=").decode()
eval(payload)
