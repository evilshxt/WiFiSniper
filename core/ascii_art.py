from pyfiglet import Figlet
from rich.console import Console

def print_banner(color: str = "cyan"):
    f = Figlet(font="alligator2")
    banner = f.renderText("WiFiSniper")
    console = Console()
    console.print(banner, style=color)
