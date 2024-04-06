import logging


def get_logger(level: str | None) -> logging.Logger:
  """
  Get a configured logger instance.
  """
  logger = logging.getLogger(__name__)
  logger.propagate = False  # we need this so the root logger doesn't start logging messages

  if not level:
    logger.disabled = True
    return logger

  log_level_obj = getattr(logging, level.upper(), logging.INFO)
  logger.setLevel(log_level_obj)

  formatter = logging.Formatter("[%(levelname)8s] ---- %(message)s")

  stream_handler = logging.StreamHandler()
  stream_handler.setFormatter(formatter)

  logger.addHandler(stream_handler)

  return logger
