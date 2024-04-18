import json
import logging
import os


class StravaOAuthCacheError(Exception):
  pass


class StravaOAuthCache:
  def __init__(self, source: str, logger: logging.Logger | None):
    self.source = source
    self.logger = logger if logger else logging.getLogger(__name__)

  def write_to_cache(self, **data: dict) -> dict:
    """
    Save the access and refresh tokens to the cache.
    """
    self.logger.info("Saving tokens to cache")

    # write to cache
    try:
      with open(self.source, "w") as f:
        json.dump(data, f, indent=2)
    except (OSError, ValueError) as e:
      raise StravaOAuthCacheError(f"Failed to write to cache: {e}")

    self.logger.debug(f"{data=}")
    return data

  def update_cache(self, **data: dict) -> dict:
    """
    Update the values in the cache.
    """
    self.logger.info("Updating values in cache")

    if not os.path.exists(self.source):
      raise StravaOAuthCacheError(f"Cache file: {self.source} does not exist")

    # read current cache values
    try:
      with open(self.source, "r") as f:
        cache_data = json.load(f)
    except (OSError, ValueError) as e:
      raise StravaOAuthCacheError(f"Failed to update cache: {e}")

    # update cache values
    for key, val in data.items():
      try:
        cache_data[key] = val
      except KeyError as e:
        raise StravaOAuthCacheError(f"Failed to update {key} in cache: {e}")

    # write updated value back to cache
    self.write_to_cache(**cache_data)

    self.logger.debug(f"{cache_data=}")
    return cache_data

  def read_from_cache(self, *keys: str) -> dict:
    """
    Read the access and refresh tokens from the cache.
    """
    self.logger.info("Retrieving access token from cache")

    if not os.path.exists(self.source):
      raise StravaOAuthCacheError(f"Cache file: {self.source} does not exist")

    data = {}

    # read from cache
    try:
      with open(self.source, "r") as f:
        cache_data = json.load(f)
    except (OSError, ValueError, KeyError) as e:
      raise StravaOAuthCacheError(f"Failed to read from cache: {e}")

    for key in keys:
      try:
        data[key] = cache_data[key]
      except KeyError as e:
        raise StravaOAuthCacheError(f"Failed to read {key} from cache: {e}")

    self.logger.debug(f"{data=}")
    return data
