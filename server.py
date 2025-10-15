#!/usr/bin/env python3
"""
Simple role-aware FTP server for teacher/student assignment workflow.

- Teachers can upload to /assignments and download any files under / (full access).
- Students can:
    * list and download files from /assignments/
    * upload files only into /submissions/<their-username>/
    * not overwrite other students' submissions.
"""

import os
import json
import logging
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.filesystems import AbstractedFS

# ---- CONFIG ----
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
HOST = "0.0.0.0"
PORT = 2121
ENABLE_TLS = False  # Set True if you configure certfile/keyfile below
CERTFILE = "cert.pem"
KEYFILE = "key.pem"
LOG_FILE = "ftp_server.log"
# ----------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# Utility: ensure base dirs exist
def ensure_directories(user_list):
    assignments = os.path.join(BASE_DIR, "assignments")
    submissions = os.path.join(BASE_DIR, "submissions")
    os.makedirs(assignments, exist_ok=True)
    os.makedirs(submissions, exist_ok=True)
    # create per-student submissions directory
    for u in user_list:
        if u.get("role") == "student":
            p = os.path.join(submissions, u["username"])
            os.makedirs(p, exist_ok=True)


# Custom FTP handler that enforces path-based rules
class RoleAwareFTPHandler(FTPHandler):
    def on_connect(self):
        logging.info(f"Connection from {self.remote_ip}:{self.remote_port}")

    def on_disconnect(self):
        logging.info(f"Disconnect from {self.remote_ip}:{self.remote_port}")

    def on_login(self, username):
        logging.info(f"Login: {username} from {self.remote_ip}:{self.remote_port}")

    def on_login_failed(self, username, password):
        logging.warning(f"Failed login: {username} from {self.remote_ip}:{self.remote_port}")

    # helper to map ftp path (as client sends) to real fs path
    def _realpath_for_ftp(self, ftp_path):
        """
        Convert an FTP path (as seen by client) into server filesystem path,
        using the handler's fs (AbstractedFS).
        """
        try:
            # ftp2fs maps ftp path to real filesystem path under the user's home
            return self.fs.ftp2fs(ftp_path)
        except Exception:
            # fallback: try to join with home
            return os.path.abspath(os.path.join(self.fs.home, ftp_path.lstrip("/")))

    def ftp_STOR(self, line):
        """
        Called when client does STOR <filename> (upload).
        We check whether the uploader is allowed to write to the target location.
        If yes, call the base implementation; otherwise return 550.
        """
        # 'line' usually contains filename (and optional mode)
        # We'll re-use parent logic after checks
        parts = line.split()
        if not parts:
            self.respond("501 Syntax error in parameters or arguments.")
            return

        filename = parts[0]
        username = getattr(self, "username", None)
        role = self.authorizer.get_user_role(username) if hasattr(self.authorizer, "get_user_role") else None

        # map to server filesystem absolute path
        target_real = self._realpath_for_ftp(filename)
        # make relative path inside BASE_DIR for checks
        try:
            rel = os.path.relpath(target_real, BASE_DIR)
        except Exception:
            rel = target_real

        # Prevent escaping base dir
        if rel.startswith(".."):
            self.respond("550 Permission denied.")
            return

        # Student rules:
        # - Allowed to upload only into submissions/<username>/
        if role == "student":
            expected_prefix = os.path.join("submissions", username)
            if not rel.replace("\\", "/").startswith(expected_prefix.replace("\\", "/")):
                self.respond("550 Students may only upload to their own submissions folder.")
                return

        # Teacher rules: teacher may upload anywhere under BASE_DIR (teacher role)
        # For other roles or missing role: deny
        if role not in ("teacher", "student"):
            self.respond("550 Permission denied (unknown role).")
            return

        # Delegate to base implementation (which will actually open stream and receive file)
        logging.info(f"STOR attempt by {username}: FTP path={filename} -> real={target_real}")
        return super().ftp_STOR(line)

    def ftp_RETR(self, line):
        """
        Called when client does RETR <filename> (download).
        Students may download only from /assignments/ (and their own submissions if you want).
        Teachers may download anywhere.
        """
        parts = line.split()
        if not parts:
            self.respond("501 Syntax error in parameters or arguments.")
            return

        filename = parts[0]
        username = getattr(self, "username", None)
        role = self.authorizer.get_user_role(username) if hasattr(self.authorizer, "get_user_role") else None

        target_real = self._realpath_for_ftp(filename)
        try:
            rel = os.path.relpath(target_real, BASE_DIR)
        except Exception:
            rel = target_real

        if rel.startswith(".."):
            self.respond("550 Permission denied.")
            return

        if role == "student":
            # Allow retrieval from assignments/ and their own submissions (optional)
            allowed1 = os.path.join("assignments")
            allowed2 = os.path.join("submissions", username)
            rel_norm = rel.replace("\\", "/")
            if not (rel_norm.startswith(allowed1.replace("\\", "/")) or rel_norm.startswith(allowed2.replace("\\", "/"))):
                self.respond("550 Students can only download assignments and their own submissions.")
                return

        if role not in ("teacher", "student"):
            self.respond("550 Permission denied (unknown role).")
            return

        logging.info(f"RETR by {username}: FTP path={filename} -> real={target_real}")
        return super().ftp_RETR(line)


# Extend DummyAuthorizer to store roles
class RoleAuthorizer(DummyAuthorizer):
    def __init__(self):
        super().__init__()
        # map username -> role
        self._roles = {}

    def add_user_with_role(self, username, password, homedir, role, perm="elr"):
        """
        role: 'teacher' or 'student'
        perm: basic permission string; we keep restricted perms for students here and enforce further in handler
        """
        # ensure home exists
        os.makedirs(homedir, exist_ok=True)
        super().add_user(username, password, homedir, perm=perm)
        self._roles[username] = role

    def get_user_role(self, username):
        return self._roles.get(username)


def load_users(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    return data


def main():
    # load users
    if not os.path.exists(USERS_FILE):
        raise SystemExit(f"Please create a users.json at {USERS_FILE}")

    users = load_users(USERS_FILE)
    ensure_directories(users)

    # Build authorizer
    auth = RoleAuthorizer()

    # Common home: we set everyone to BASE_DIR as home to make path checks simpler.
    # Alternatively, could set per-user homes; our handler enforces fine-grained rules.
    for u in users:
        username = u["username"]
        password = u["password"]
        role = u.get("role", "student")
        # For safety, give students only read/list rights by default, uploads are checked by handler.
        if role == "teacher":
            perm = "elradfmwMT"  # full perms for teacher
        else:
            perm = "elr"  # list & retrieve allowed; store handled by handler checks
        auth.add_user_with_role(username, password, BASE_DIR, role=role, perm=perm)

    # choose handler class (TLS or plain)
    handler_class = TLS_FTPHandler if ENABLE_TLS else RoleAwareFTPHandler
    handler = handler_class
    handler.authorizer = auth
    # Root dir for handler's fs mapping
    handler.abstracted_fs = AbstractedFS

    # Attach base dir to server for our handlers to reference
    address = (HOST, PORT)
    server = FTPServer(address, handler)
    server.base_dir = BASE_DIR  # convenience attribute for handlers

    # TLS configuration if enabled
    if ENABLE_TLS:
        if not (os.path.exists(CERTFILE) and os.path.exists(KEYFILE)):
            logging.error("TLS enabled but cert/key files not found.")
            raise SystemExit("TLS enabled but cert/key file(s) not found.")
        handler.tls_control_required = True
        handler.certfile = CERTFILE
        handler.keyfile = KEYFILE
        logging.info("TLS enabled for FTP server (FTPS).")

    print(f"Starting FTP server on {HOST}:{PORT}")
    print(f"Base dir: {BASE_DIR}")
    logging.info(f"Starting server on {HOST}:{PORT} with base_dir={BASE_DIR}")
    server.serve_forever()


if __name__ == "__main__":
    main()
