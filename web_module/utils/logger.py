
import logging
import sys

def get_logger(name="web_module"):

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)

    log_format = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(log_format)

    logger.addHandler(handler)
    return logger

def set_level(logger, level):

    levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    if level in levels:
        logger.setLevel(levels[level])
        for h in logger.handlers:
            h.setLevel(levels[level])
