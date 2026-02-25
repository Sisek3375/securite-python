import logging
from dotenv import load_dotenv

load_dotenv()

COLORS = {
    logging.INFO: "\033[32m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
}
RESET = "\033[0m"
FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = COLORS.get(record.levelno, RESET)
        return f"{color}{super().format(record)}{RESET}"


file_handler = logging.FileHandler("app.log", mode="a")
file_handler.setFormatter(logging.Formatter(FORMAT))

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(ColorFormatter(FORMAT))

logging.basicConfig(level=logging.INFO, handlers=[file_handler, stream_handler])
