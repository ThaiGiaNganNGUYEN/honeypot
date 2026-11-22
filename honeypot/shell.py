"""In-memory shell for the SSH decoy.

Commands are answered from a fake filesystem that lives in this file.
Nothing here reads the host disk, starts a process, or opens a network connection.
"""

from __future__ import annotations

METACHARS = set(";|&`$()<>")
MAX_COMMAND = 400

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "admin:x:1000:1000:Gateway Admin:/home/admin:/bin/bash\n"
    "backup:x:1001:1001:Backup:/home/backup:/usr/sbin/nologin\n"
)
_NOTES = (
    "Lab worksheet item 4: the guest network passphrase is printed on the worksheet.\n"
    "It is intentionally not stored on this host.\n"
)
_HISTORY = "uptime\ndf -h\nls /var/log\n"
_SYSLOG = "Nov 22 08:01:02 prod-gateway sshd[412]: Server listening on 0.0.0.0 port 22.\n"
_ISSUE = "Ubuntu 22.04.5 LTS \\n \\l\n"
_OS_RELEASE = 'NAME="Ubuntu"\nVERSION="22.04.5 LTS"\nID=ubuntu\n'

FILES = {
    "/etc/passwd": _PASSWD,
    "/etc/os-release": _OS_RELEASE,
    "/etc/issue": _ISSUE,
    "/home/admin/notes.txt": _NOTES,
    "/home/admin/.bash_history": _HISTORY,
    "/var/log/syslog": _SYSLOG,
    "/root/README": "Training decoy. Commands typed here are logged and are not executed.\n",
    "/tmp/README.txt": "This directory is a training decoy.\n",
}
DIRS = {
    "/",
    "/etc",
    "/home",
    "/home/admin",
    "/home/backup",
    "/tmp",
    "/var",
    "/var/log",
    "/root",
}


class FakeShell:
    def __init__(self, username: str, hostname: str) -> None:
        self.username = username or "admin"
        self.hostname = hostname
        self.cwd = self.home
        self.closed = False
        self.history: list[str] = []

    @property
    def home(self) -> str:
        if self.username == "root":
            return "/root"
        candidate = f"/home/{self.username}"
        if candidate in DIRS:
            return candidate
        return "/"

    def prompt(self) -> str:
        sigil = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{self.cwd}{sigil} "

    def handle(self, raw: str) -> str:
        line = raw.strip()
        if not line:
            return ""
        self.history.append(line)
        if len(self.history) > 100:
            self.history = self.history[-100:]
        if len(line) > MAX_COMMAND:
            return "bash: command too long"
        if any(ch in line for ch in METACHARS):
            return "bash: unsupported operator"
        parts = line.split()
        cmd, args = parts[0], parts[1:]
        key = cmd.lower()
        if key in {"wget", "curl"}:
            return f"{key}: unable to resolve host address"
        if key in {"exit", "logout", "quit"}:
            self.closed = True
            return ""
        handler = _DISPATCH.get(key)
        if handler is None:
            return f"bash: {cmd}: command not found"
        return handler(self, args)

    def resolve(self, raw: str) -> str:
        text = raw.strip()
        if not text.startswith("/"):
            base = "" if self.cwd == "/" else self.cwd
            text = f"{base}/{text}"
        parts: list[str] = []
        for part in text.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return "/" + "/".join(parts) if parts else "/"

    def denied(self, path: str) -> bool:
        if self.username == "root":
            return False
        return path == "/root" or path.startswith("/root/")

    def is_dir(self, path: str) -> bool:
        if path in DIRS:
            return True
        prefix = path.rstrip("/") + "/"
        return any(name.startswith(prefix) for name in FILES)


def _pwd(shell: FakeShell, _args: list[str]) -> str:
    return shell.cwd


def _cd(shell: FakeShell, args: list[str]) -> str:
    target = shell.home if not args else shell.resolve(args[0])
    if shell.denied(target):
        return f"bash: cd: {target}: Permission denied"
    if not shell.is_dir(target):
        return f"bash: cd: {target}: No such file or directory"
    shell.cwd = target
    return ""


def _ls(shell: FakeShell, args: list[str]) -> str:
    show_all = any(arg.startswith("-") and "a" in arg for arg in args)
    long_form = any(arg.startswith("-") and "l" in arg for arg in args)
    targets = [arg for arg in args if not arg.startswith("-")] or ["."]
    blocks: list[str] = []
    for target in targets:
        path = shell.resolve(target)
        if shell.denied(path):
            blocks.append(f"ls: cannot open directory '{target}': Permission denied")
            continue
        if path in FILES and not shell.is_dir(path):
            blocks.append(_entry(shell, path, path.rsplit("/", 1)[-1], long_form))
            continue
        if not shell.is_dir(path):
            blocks.append(f"ls: cannot access '{target}': No such file or directory")
            continue
        names = _children(path)
        if not show_all:
            names = [name for name in names if not name.startswith(".")]
        if not names:
            blocks.append("")
            continue
        lines = [_entry(shell, _join(path, name), name, long_form) for name in names]
        blocks.append("\n".join(lines))
    return "\n".join(blocks).rstrip("\n")


def _children(path: str) -> list[str]:
    prefix = "/" if path == "/" else path.rstrip("/") + "/"
    names: set[str] = set()
    for directory in DIRS:
        if directory.startswith(prefix):
            rest = directory[len(prefix) :]
            if rest and "/" not in rest:
                names.add(rest)
    for filename in FILES:
        if filename.startswith(prefix):
            rest = filename[len(prefix) :]
            if rest and "/" not in rest:
                names.add(rest)
    return sorted(names)


def _join(directory: str, name: str) -> str:
    if directory == "/":
        return "/" + name
    return directory.rstrip("/") + "/" + name


def _entry(shell: FakeShell, path: str, name: str, long_form: bool) -> str:
    if not long_form:
        return name
    mode = "drwxr-xr-x" if shell.is_dir(path) and path not in FILES else "-rw-r--r--"
    if path in DIRS and path not in FILES:
        mode = "drwxr-xr-x"
    return f"{mode} 1 {shell.username} {shell.username} 128 Nov 22 09:00 {name}"


def _cat(shell: FakeShell, args: list[str]) -> str:
    if not args:
        return "cat: missing operand"
    chunks: list[str] = []
    for arg in args:
        path = shell.resolve(arg)
        if path in {"/etc/shadow", "/etc/gshadow"} or shell.denied(path):
            chunks.append(f"cat: {path}: Permission denied")
            continue
        if path == "/etc/hostname":
            chunks.append(shell.hostname)
            continue
        if path in FILES:
            chunks.append(FILES[path].rstrip("\n"))
            continue
        if shell.is_dir(path):
            chunks.append(f"cat: {path}: Is a directory")
            continue
        chunks.append(f"cat: {path}: No such file or directory")
    return "\n".join(chunks)


def _echo(_shell: FakeShell, args: list[str]) -> str:
    return " ".join(args)


def _whoami(shell: FakeShell, _args: list[str]) -> str:
    return shell.username


def _id(shell: FakeShell, _args: list[str]) -> str:
    if shell.username == "root":
        return "uid=0(root) gid=0(root) groups=0(root)"
    return f"uid=1000({shell.username}) gid=1000({shell.username}) groups=1000({shell.username})"


def _uname(shell: FakeShell, _args: list[str]) -> str:
    return f"Linux {shell.hostname} 5.15.0-122-generic #132-Ubuntu SMP x86_64 GNU/Linux"


def _hostname(shell: FakeShell, _args: list[str]) -> str:
    return shell.hostname


def _ps(_shell: FakeShell, _args: list[str]) -> str:
    return "\n".join(
        [
            "PID TTY      TIME CMD",
            "  1 ?        00:00:01 init",
            "412 ?        00:00:00 sshd",
            "880 pts/0    00:00:00 bash",
        ]
    )


def _ip(_shell: FakeShell, _args: list[str]) -> str:
    return "\n".join(
        [
            "2: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500",
            "    inet 10.8.0.15/24 brd 10.8.0.255 scope global eth0",
        ]
    )


def _df(_shell: FakeShell, _args: list[str]) -> str:
    return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        20G  4.1G   15G  22% /"


def _uptime(_shell: FakeShell, _args: list[str]) -> str:
    return " 09:00:00 up 14 days,  3:11,  1 user,  load average: 0.00, 0.01, 0.00"


def _date(_shell: FakeShell, _args: list[str]) -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")


def _who(shell: FakeShell, _args: list[str]) -> str:
    return f"{shell.username} pts/0 Nov 22 09:00 (10.8.0.8)"


def _history(shell: FakeShell, _args: list[str]) -> str:
    return "\n".join(f"{index:>4}  {item}" for index, item in enumerate(shell.history, start=1))


def _help(_shell: FakeShell, _args: list[str]) -> str:
    names = ", ".join(sorted((*_DISPATCH, "wget", "curl", "exit")))
    return "Training shell commands: " + names


_DISPATCH = {
    "pwd": _pwd,
    "cd": _cd,
    "ls": _ls,
    "cat": _cat,
    "echo": _echo,
    "whoami": _whoami,
    "id": _id,
    "uname": _uname,
    "hostname": _hostname,
    "ps": _ps,
    "ip": _ip,
    "ifconfig": _ip,
    "df": _df,
    "uptime": _uptime,
    "date": _date,
    "who": _who,
    "w": _who,
    "history": _history,
    "help": _help,
}
