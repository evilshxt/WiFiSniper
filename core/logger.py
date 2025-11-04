from rich.console import Console
from rich.markup import escape

class Logger:
    def __init__(self):
        self.console = Console()

    def info(self, message):
        self.console.print(f":information: [bold cyan]INFO[/]: {escape(str(message))}")

    def success(self, message):
        self.console.print(f":white_check_mark: [bold green]SUCCESS[/]: {escape(str(message))}")

    def warning(self, message):
        self.console.print(f":warning: [bold yellow]WARNING[/]: {escape(str(message))}")

    def error(self, message):
        self.console.print(f":x: [bold red]ERROR[/]: {escape(str(message))}")
