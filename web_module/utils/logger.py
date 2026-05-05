"""
Capa de logging descrita en la documentacion de la actividad 1.4.
Registra acciones realizadas durante la ejecucion sin almacenar
contenido sensible del sitio analizado.
"""

import logging
import sys


def get_logger(name="web_module"):

    # Retorna un logger configurado con formato estandar
    logger = logging.getLogger(name)

    # Evita duplicar handlers si el logger ya fue configurado
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

    # Cambia el nivel de logging para activar modo verbose desde la cli
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
