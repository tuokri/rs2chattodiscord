import logging
import multiprocessing as mp
import sys
from logging import NOTSET
from logging.handlers import RotatingFileHandler

LOGGER_LOCK = mp.Lock()


class LockingLogger(logging.Logger):
    def __init__(self, name, level=NOTSET):
        logging.Logger.__init__(self, name, level=level)
        self.__mp_custom_lock = LOGGER_LOCK

    def debug_with_lock(self, msg, *args, **kwargs):
        with self.__mp_custom_lock:
            self.debug(msg, *args, **kwargs)

    def info_with_lock(self, msg, *args, **kwargs):
        with self.__mp_custom_lock:
            self.info(msg, *args, **kwargs)

    def error_with_lock(self, msg, *args, **kwargs):
        with self.__mp_custom_lock:
            self.error(msg, *args, **kwargs)


def get_logger(name: str, lock=LOGGER_LOCK) -> logging.Logger:
    print("get_logger(): LOGGER_LOCK id: ", id(LOGGER_LOCK))

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s:%(name)s:%(levelname)s:%(message)s")

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = RotatingFileHandler(
        "rs2chattodiscord" + ".log", maxBytes=1024 * 1024 * 10, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    ll = LockingLogger(name, logging.DEBUG)
    ll.addHandler(console_handler)
    ll.addHandler(file_handler)

    logger.__mp_custom_lock = lock
    logger.debug = LockingLogger.debug_with_lock.__get__(ll, LockingLogger)
    logger.info = LockingLogger.info_with_lock.__get__(ll, LockingLogger)
    logger.error = LockingLogger.error_with_lock.__get__(ll, LockingLogger)

    return logger
