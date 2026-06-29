import logging
import os
import traceback
from toolkitTCU.integrity_module.utils.LoadConfig import ConfigLoader, MODULE_DIR

class Logger:

    def __init__(self, load_config: ConfigLoader):
        self.loggers = {
            "GENERAL": "system.log",
            "SYSTEM" : "system.log",
            "DATABASE": "system.log",
            "BACKUP" : "system.log",
            "INTEGRITY": "events.log",
            "EXCEPTION" : "errors.log",
            "EVENT" : "events.log",
            "BACKUP_DEBUG" : "debug.log",
            "DEBUG":"debug.log"
        }
        self.log_directory = load_config.load_config().get("logging", {}).get(
            "directory", os.path.join(MODULE_DIR, "utils", "logs")
        )

    def set_logger(self, name, level):
        levels = {
            "DEBUG" : logging.DEBUG,
            "INFO"  : logging.INFO,
            "WARNING" : logging.WARNING,
            "ERROR" : logging.ERROR,
            "CRITICAL" : logging.CRITICAL
        }

        log_path = os.path.join(self.log_directory, self.loggers[name])
        if not os.path.exists(self.log_directory):
            os.makedirs(self.log_directory)
            open(log_path, "w").close()

        logger = logging.getLogger(name)
        logger.setLevel(levels[level])
        if logger.handlers:
            return logger

        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(name)s] [%(message)s]')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    def add_to_log(self, name, level, message):
        try:
            logger = self.set_logger(name, level)
            if (level == "DEBUG"):
                logger.debug(message)
            elif (level == "INFO"):
                logger.info(message)
            elif(level == "WARNING"):
                logger.warning(message)
            elif(level == "ERROR"):
                logger.error(message)
            elif(level == "CRITICAL"):
                logger.critical(message)
        except Exception as e:
            print(traceback.format_exc())
            print(e)

