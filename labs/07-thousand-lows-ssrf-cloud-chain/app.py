"""
ReportForge — internal report-generation microservice (Flask).
Runs on an AWS EC2 instance. Loads YAML report templates from an S3 config
bucket, lets staff import new templates from a URL, and renders reports.

------------------------------------------------------------------------------
SECURITY REVIEW (previous AppSec engineer):
  Reviewed 2026-09. Several findings, ALL rated LOW / informational — nothing
  that warranted blocking the release. Inline notes marked [AppSec: ...].
  Verdict: "No High/Critical issues. Ship it."
------------------------------------------------------------------------------
Your job: decide whether that verdict was correct.
"""
import os
import traceback

import yaml
import requests
import boto3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Templates and config live in S3; the app reads them using the EC2 instance role.
CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "reportforge-config-prod")
s3 = boto3.client("s3")

TEMPLATES = {}


def load_template_bytes(data: bytes):
    # [AppSec: yaml.load() without SafeLoader was flagged. But we only ever load
    #  OUR OWN templates from OUR OWN private config bucket, which only this app
    #  can write to. Attacker can't control these bytes. Rated LOW.]
    return yaml.load(data)


@app.route("/")
def home():
    return (
        "<h2>ReportForge</h2>"
        "<p>Endpoints: /reload, /import?url=, /render (POST), /templates</p>"
    )


@app.route("/templates")
def list_templates():
    return jsonify({"loaded": list(TEMPLATES.keys())})


@app.route("/reload")
def reload_templates():
    # [AppSec: no authentication on this endpoint. But it only reloads templates
    #  from our trusted bucket — worst case someone forces a refresh. Rated LOW.]
    objs = s3.list_objects_v2(Bucket=CONFIG_BUCKET).get("Contents", [])
    for o in objs:
        key = o["Key"]
        body = s3.get_object(Bucket=CONFIG_BUCKET, Key=key)["Body"].read()
        TEMPLATES[key] = load_template_bytes(body)
    return jsonify({"reloaded": list(TEMPLATES.keys())})


@app.route("/import")
def import_template():
    # Fetch a template from a URL so staff can preview it before saving to S3.
    # [AppSec: this is a Server-Side Request Forgery sink. But it only performs
    #  a GET and returns the response body as a text preview — there are no
    #  sensitive internal HTTP services on this network worth reaching, and it
    #  can't reach the database. Rated LOW.]
    url = request.args.get("url", "")
    if not url:
        return "provide ?url=", 400
    r = requests.get(url, timeout=5)
    return r.text[:5000]


@app.route("/render", methods=["POST"])
def render_report():
    # Renders a loaded template with user-supplied values.
    body = request.get_json(force=True, silent=True) or {}
    key = body.get("template", "")
    values = body.get("values", {})
    tpl = TEMPLATES.get(key)
    if tpl is None:
        return jsonify({"error": "unknown template; call /reload first"}), 404
    title = tpl.get("title", "Report")
    # [AppSec: title comes from the trusted template, values from the user.
    #  Looks fine. Rated informational.]
    html = render_template_string(
        "<h1>" + title + "</h1><ul>{% for k,v in values.items() %}"
        "<li>{{k}}: {{v}}</li>{% endfor %}</ul>",
        values=values,
    )
    return html


@app.errorhandler(Exception)
def handle_error(e):
    # [AppSec: verbose errors are on in production, but this is an INTERNAL
    #  service behind the load balancer, so leakage risk is minimal. Rated LOW.]
    return (
        jsonify(
            {
                "error": str(e),
                "trace": traceback.format_exc(),
                "config_bucket": CONFIG_BUCKET,
                "region": os.environ.get("AWS_REGION", "eu-central-1"),
            }
        ),
        500,
    )

"""
if __name__ == "__main__":
    # [AppSec: debug=True in prod was noted. Low — convenient for the team.]
    app.run(host="0.0.0.0", port=8080, debug=True)
"""
# Changing Debug mode to False for production deployment   
if __name__ == "__main__":
    # [AppSec: debug=True in prod was noted. Low — convenient for the team.]
    app.run(host="0.0.0.0", port=8080, debug=False)