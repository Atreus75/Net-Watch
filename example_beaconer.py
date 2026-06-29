# This is an example beaconer program. Netwatch can detect the type of behavior emulated by this script.
from time import sleep
from requests import Session 
from random import randint

c = 0
session = Session()
while True:
    base = 3
    interval = randint(int(base/2), int(base+base/2))
    sleep(interval)
    c += 1
    status = session.get("http://[C2 IP HERE]:[PORT]/").status_code
    print(f"{c}° request: {status}")
