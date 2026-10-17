"""
Minimal S3-compatible config store (stand-in for a private S3 bucket).
Reads are open (the bucket content isn't the secret); WRITES require the
instance role's secret in X-Amz-Secret (simplified SigV4). Internet-reachable
API, just like the real S3 API.
"""
import os
from flask import Flask, request, Response, jsonify

app = Flask(__name__)
SECRET = os.environ.get("STORE_SECRET", "changeme")

# Seed with one benign template so /reload works out of the box.
STORE = {
    "monthly-report.yaml": b"title: Monthly Summary\nsections:\n  - revenue\n  - signups\n",
}


@app.after_request
def cors(resp):
    # Lab convenience so the ReportForge browser dashboard can PUT here.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, PUT, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "X-Amz-Secret, Content-Type"
    return resp


@app.route("/<bucket>/<path:key>", methods=["OPTIONS"])
@app.route("/<bucket>", methods=["OPTIONS"])
def preflight(bucket, key=None):
    return Response("", status=204)


def authed(req):
    return req.headers.get("X-Amz-Secret", "") == SECRET


@app.route("/<bucket>", methods=["GET"])
def list_bucket(bucket):
    return jsonify({"keys": list(STORE.keys())})


@app.route("/<bucket>/<path:key>", methods=["GET"])
def get_obj(bucket, key):
    if key not in STORE:
        return Response("NoSuchKey", status=404)
    return Response(STORE[key], mimetype="application/octet-stream")


@app.route("/<bucket>/<path:key>", methods=["PUT"])
def put_obj(bucket, key):
    if not authed(request):
        return Response("AccessDenied: valid credentials required", status=403)
    STORE[key] = request.get_data()
    return Response("OK", status=200)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
