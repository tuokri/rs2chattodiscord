import logging
import sys
from logging.handlers import RotatingFileHandler


def listener_configurer():
    root = logging.getLogger()
    h = RotatingFileHandler(
        "rs2chattodiscord" + ".log", maxBytes=1024 * 1024 * 10, encoding="utf-8")
    f = logging.Formatter("%(asctime)s:%(processName)s:%(name)s:%(levelname)s:%(message)s")
    h.setFormatter(f)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(f)

    root.addHandler(console_handler)
    root.addHandler(h)


def worker_configurer(queue):
    h = logging.handlers.QueueHandler(queue)  # Just the one handler needed
    root = logging.getLogger()
    root.addHandler(h)
    # send all messages, for demo; no other level or filter logic applied.
    root.setLevel(logging.DEBUG)


def listener_process(queue, configurer):
    configurer()
    while True:
        # noinspection PyBroadException
        try:
            record = queue.get()
            if record is None:  # We send this as a sentinel to tell the listener to quit.
                break
            logger = logging.getLogger(record.name)
            logger.handle(record)  # No level or filter logic applied - just do it!
        except Exception:
            import sys
            import traceback
            print("Whoops! Problem:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
