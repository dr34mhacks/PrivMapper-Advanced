"""Terminal colours and logging helpers."""


class Colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    NC = "\033[0m"


def log(msg): print(f"\n{Colors.BLUE}[*]{Colors.NC} {msg}")


def ok(msg):  print(f"{Colors.GREEN}[+]{Colors.NC} {msg}")


def warn(msg): print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")


def err(msg): print(f"{Colors.RED}[-]{Colors.NC} {msg}")
