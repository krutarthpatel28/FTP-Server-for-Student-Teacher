# upload_assignment.py
from ftplib import FTP
import os

HOST = "127.0.0.1"   # or server IP if remote
PORT = 2121
USER = "teacher1"
PASS = "teachpass"

local_file = "assignment1.txt"   # make sure this file exists locally
remote_dir = "/assignments"

# create a local example assignment if missing
if not os.path.exists(local_file):
    with open(local_file, "w") as f:
        f.write("Assignment 1: Solve problems A, B, C\n")

ftp = FTP()
ftp.connect(HOST, PORT, timeout=10)
ftp.login(USER, PASS)
ftp.cwd(remote_dir)              # change to assignments dir on server
with open(local_file, "rb") as f:
    ftp.storbinary(f"STOR {local_file}", f)
print("Uploaded", local_file, "to", remote_dir)
ftp.quit()
