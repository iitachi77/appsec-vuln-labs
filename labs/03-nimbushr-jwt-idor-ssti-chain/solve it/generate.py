import jwt
import json  # نستخدم مكتبة json القياسية في بايثون بدلاً من jsonify

JWT_SECRET = "chocolate"

token = jwt.encode({"sub": "alice", "role": "hr_admin"}, JWT_SECRET, algorithm="HS256")
newtoken_json = json.dumps({"token": token})

print(newtoken_json)
