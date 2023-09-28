import logging

from termcolor import colored

logging.basicConfig(format="%(process)d - %(levelname)s - %(message)s", level=logging.INFO)


def info(message: str):
    logging.info(colored(message, "green"))


def warn(message: str):
    logging.warning(colored(message, "yellow", attrs=["bold"]))


def detect(message: str):
    logging.info(colored(message, "red", attrs=["bold"]))
