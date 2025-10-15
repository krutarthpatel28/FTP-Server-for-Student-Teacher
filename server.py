#!/usr/bin/env python3
"""
Fixed server.py — robust handling when clients send local absolute paths
(e.g. FileZilla sending "/Users/krutarthpatel/Downloads/file.docx" as STOR).
"""

import os
import json
import logging
from datetime import datetime
from pathlib import Path

# Robust import for optional TLS handler
try:
    from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler  # type: ignore
except Exception:
    from pyftpdlib.handlers import FTPHandler  # type: ignore
    try:
        from pyftpdlib.contrib.handlers import TLS_FTPHandler  # type: ignore
    except Exception:
        TLS_FTPHandler = None  # type: ignore

from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.filesystems import AbstractedFS

# CONFIG
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
HOST = "0.0.0.0"
PORT = 2121
ENABLE_TLS = False
CERTFILE = "cert.pem"
KEYFILE = "key.pem"
LOG_FILE = "ftp_server.log"

# Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logging.getLogger().addHandler(console)


def ensure_directories(users):
    os.makedirs(os.path.join(BASE_DIR, "assignments"), exist_ok=True)
    subs = os.path.join(BASE_DIR, "submissions")
    os.makedirs(subs, exist_ok=True)
    for u in users:
        if u.get("role") == "student":
            os.makedirs(os.path.join(subs, u["username"]), exist_ok=True)


class RoleAuthorizer(DummyAuthorizer):
    def __init__(self):
        super().__init__()
        self._roles = {}

    def add_user_with_role(self, username, password, homedir, role, perm="elr"):
        os.makedirs(homedir, exist_ok=True)
        super().add_user(username, password, homedir, perm=perm)
        self._roles[username] = role

    def get_user_role(self, username):
        return self._roles.get(username)


class RoleAwareFTPHandler(FTPHandler):
    """
    Handler with robust ftp->real path mapping and role checks.
    Fix: treat client-sent local absolute paths as local filenames (use basename).
    """

    def on_connect(self):
        logging.info(f"Connect from {self.remote_ip}:{self.remote_port}")

    def on_disconnect(self):
        logging.info(f"Disconnect from {self.remote_ip}:{self.remote_port}")

    def on_login(self, username):
        logging.info(f"Login: {username} from {self.remote_ip}:{self.remote_port}")

    def _is_local_path_sent_by_client(self, ftp_path: str) -> bool:
        """
        Try to detect if the client accidentally sent a *local* absolute path.
        Heuristics:
         - ftp_path is absolute (os.path.isabs) AND
           (it contains BASE_DIR as substring OR it starts with the local user home dir)
        If true, we should treat it as a client-local path and use basename().
        """
        if not ftp_path:
            return False
        if not os.path.isabs(ftp_path):
            return False
        try:
            # example: "/Users/krutarthpatel/Downloads/..."
            home = str(Path.home())
            if ftp_path.startswith(home):
                return True
        except Exception:
            pass
        # also, if ftp_path contains the server BASE_DIR segments (client gave a path copied from server),
        # treat as local-style and use basename to avoid double-joining.
        if os.path.abspath(BASE_DIR).replace("\\", "/") in ftp_path.replace("\\", "/"):
            return True
        # last-resort: if it contains more than two path components and includes '/Users/' (macos), assume local
        if "/Users/" in ftp_path.replace("\\", "/"):
            return True
        return False

    def _resolve_ftp_to_real(self, ftp_path: str) -> str:
        """
        Resolve ftp_path (absolute or relative) to an absolute filesystem path.
        - If the client looks like it sent a local absolute path, use basename(ftp_path)
          and resolve relative to current ftp cwd.
        - Prefer self.fs.ftp2fs when available (respects cwd/home).
        - Fallback: join fs.home + fs.cwd + ftp_path.
        Returns normalized absolute path.
        """
        if self._is_local_path_sent_by_client(ftp_path):
            # treat as client-local path: use only basename (client intends to store the file in cwd)
            ftp_path = os.path.basename(ftp_path)
            logging.debug("Detected local client path; using basename => %s", ftp_path)

        # Try the standard mapping first
        real = None
        try:
            real = self.fs.ftp2fs(ftp_path)
            real = os.path.abspath(real)
        except Exception:
            real = None

        if not real or not os.path.isabs(real):
            # fallback resolution relative to ftp home + cwd
            ftp_cwd = getattr(self.fs, "cwd", "/")
            ftp_home = getattr(self.fs, "home", BASE_DIR)
            candidate = os.path.join(ftp_home, ftp_cwd.lstrip("/"), ftp_path.lstrip("/"))
            real = os.path.abspath(candidate)

        real = os.path.normpath(real)
        logging.debug("Resolved FTP path '%s' -> real '%s' (home=%s cwd=%s)", ftp_path, real, getattr(self.fs, "home", None), getattr(self.fs, "cwd", None))
        return real

    def _is_within(self, child_abs: str, parent_abs: str) -> bool:
        child = os.path.normpath(os.path.abspath(child_abs))
        parent = os.path.normpath(os.path.abspath(parent_abs))
        try:
            common = os.path.commonpath([child, parent])
            return common == parent
        except Exception:
            return False

    def ftp_STOR(self, line: str):
        parts = line.split()
        if not parts:
            self.respond("501 Syntax error in parameters or arguments.")
            return

        ftp_target_raw = parts[0]
        username = getattr(self, "username", None)
        role = getattr(self.authorizer, "get_user_role", lambda u: None)(username)

        # Resolve to server filesystem path (with local-path sanitization)
        target_real = self._resolve_ftp_to_real(ftp_target_raw)
        logging.debug("ftp_STOR: raw=%r resolved=%r", ftp_target_raw, target_real)

        # Must be inside BASE_DIR
        if not self._is_within(target_real, BASE_DIR):
            logging.warning("Denied STOR: target outside BASE_DIR: %s (user=%s)", target_real, username)
            self.respond("550 Permission denied.")
            return

        # Student: must be within BASE_DIR/submissions/<username>
        if role == "student":
            expected_dir = os.path.join(BASE_DIR, "submissions", username)
            if not self._is_within(target_real, expected_dir):
                logging.info("Denied STOR for student %s -> attempted target=%s not under %s", username, target_real, expected_dir)
                self.respond("550 Students may only upload to their own submissions folder.")
                return

        if role not in ("teacher", "student"):
            self.respond("550 Permission denied (unknown role).")
            return

        # Ensure parent directory exists
        parent = os.path.dirname(target_real)
        try:
            os.makedirs(parent, exist_ok=True)
        except Exception:
            logging.exception("Unable to create upload directory: %s", parent)
            self.respond("550 Server error preparing upload directory.")
            return

        # If student would overwrite an existing file, append timestamp
        if role == "student" and os.path.exists(target_real):
            base, ext = os.path.splitext(os.path.basename(ftp_target_raw))
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            new_basename = f"{base}_{ts}{ext}"
            ftp_cwd = getattr(self.fs, "cwd", "/").rstrip("/")
            if ftp_cwd in ("", "/"):
                new_ftp_target = f"/{new_basename}"
            else:
                new_ftp_target = f"{ftp_cwd}/{new_basename}"
            logging.info("Student upload would overwrite; renaming upload to %s", new_ftp_target)
            return super().ftp_STOR(new_ftp_target)

        logging.info("Allowing STOR: user=%s role=%s ftp_raw=%s real=%s", username, role, ftp_target_raw, target_real)
        return super().ftp_STOR(line)

    def ftp_RETR(self, line: str):
        parts = line.split()
        if not parts:
            self.respond("501 Syntax error in parameters or arguments.")
            return
        ftp_target = parts[0]
        username = getattr(self, "username", None)
        role = getattr(self.authorizer, "get_user_role", lambda u: None)(username)

        target_real = self._resolve_ftp_to_real(ftp_target)
        if not self._is_within(target_real, BASE_DIR):
            self.respond("550 Permission denied.")
            return

        if role == "student":
            allowed1 = os.path.join(BASE_DIR, "assignments")
            allowed2 = os.path.join(BASE_DIR, "submissions", username)
            if not (self._is_within(target_real, allowed1) or self._is_within(target_real, allowed2)):
                self.respond("550 Students can only download assignments and their own submissions.")
                return

        if role not in ("teacher", "student"):
            self.respond("550 Permission denied (unknown role).")
            return

        logging.info("Allowing RETR: user=%s ftp=%s real=%s", username, ftp_target, target_real)
        return super().ftp_RETR(line)


def load_users(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    if not os.path.exists(USERS_FILE):
        raise SystemExit("Please create users.json next to server.py")

    users = load_users(USERS_FILE)
    ensure_directories(users)

    auth = RoleAuthorizer()
    for u in users:
        username = u["username"]
        password = u["password"]
        role = u.get("role", "student")
        perm = "elradfmwMT" if role == "teacher" else "elrw"
        auth.add_user_with_role(username, password, BASE_DIR, role, perm=perm)
        logging.info("Added user %s role=%s perm=%s", username, role, perm)

    handler_class = TLS_FTPHandler if (ENABLE_TLS and TLS_FTPHandler is not None) else RoleAwareFTPHandler
    if ENABLE_TLS and TLS_FTPHandler is None:
        raise SystemExit("FTPS requested but TLS handler not available; install pyOpenSSL")

    handler = handler_class
    handler.authorizer = auth
    handler.abstracted_fs = AbstractedFS

    server = FTPServer((HOST, PORT), handler)
    server.base_dir = BASE_DIR

    logging.info("Starting FTP server on %s:%s with BASE_DIR=%s", HOST, PORT, BASE_DIR)
    print(f"Starting FTP server on {HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
        print("Server stopped.")


if __name__ == "__main__":
    main()
