import logging

from termcolor import colored

logging.basicConfig(format="%(process)d - %(levelname)s - %(message)s", level=logging.INFO)


def info(message: str) -> None:
    """
    Log information
    :param message: The message
    """
    logging.info(colored(message, "green"))


def warn(message: str) -> None:
    """
    Log a warning
    :param message: The message
    """
    logging.warning(colored(message, "yellow", attrs=["bold"]))


def detect(message: str) -> None:
    """
    Log a detection
    :param message: The message
    """
    logging.info(colored(message, "red", attrs=["bold"]))
