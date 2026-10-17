"""Mock AWS Instance Metadata Service (IMDSv1-style). Internal only."""
import os
from flask import Flask, Response

app = Flask(__name__)
ROLE = "reportforge-role"
SECRET = os.environ.get("ROLE_SECRET", "changeme")

CREDS = """{
  "Code" : "Success",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAREPORTFORGEEXAMPLE",
  "SecretAccessKey" : "%s",
  "Token" : "FwoGZXIvYXdzEExampleSessionToken==",
  "Expiration" : "2026-12-31T23:59:59Z"
}""" % SECRET


@app.route("/latest/meta-data/")
def md():
    return "iam/\ninstance-id\nlocal-ipv4\n"


@app.route("/latest/meta-data/iam/security-credentials/")
def role_list():
    return ROLE + "\n"


@app.route("/latest/meta-data/iam/security-credentials/<role>")
def creds(role):
    if role == ROLE:
        return Response(CREDS, mimetype="text/plain")
    return Response("Not found", status=404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
