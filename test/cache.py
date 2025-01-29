
import json
import os
import tempfile
import unittest

from strava_auth.cache import StravaOAuthCache, StravaOAuthCacheError

class TestStravaOAuthCache(unittest.TestCase):
  def test_write_to_cache(self):
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      cache = StravaOAuthCache(f.name, None)
      test_data = {"token": "test_token", "athlete": "test_athlete"}
      
      # Write to cache
      result = cache.write_to_cache(**test_data)
      
      # Verify file exists and contains data
      self.assertEqual(result, test_data)
      with open(f.name, 'r') as fp:
        data = json.load(fp)
        self.assertEqual(data, test_data)

    # Clean up file
    os.remove(f.name)

  def test_read_from_cache(self):
    # Create test file with data
    test_data = {"token": "test_token", "athlete": "test_athlete"}
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      json.dump(test_data, f)
      f.flush()
      
      cache = StravaOAuthCache(f.name, None)
      result = cache.read_from_cache("token", "athlete")
      
      self.assertEqual(result, test_data)

    # Clean up file
    os.remove(f.name)

  def test_update_cache(self):
    # Create test file with initial data
    initial_data = {"token": "initial_token"}
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      json.dump(initial_data, f)
      f.flush()
      
      cache = StravaOAuthCache(f.name, None)
      updated_data = {"token": "updated_token"}
      result = cache.update_cache(**updated_data)
      
      self.assertEqual(result["token"], updated_data["token"])

    # Clean up file
    os.remove(f.name)

  def test_read_non_existent_key(self):
    # Create test file with data
    test_data = {"token": "test_token"}
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
      json.dump(test_data, f)
      f.flush()
      
      cache = StravaOAuthCache(f.name, None)
      
      with self.assertRaises(StravaOAuthCacheError):
        cache.read_from_cache("non_existent_key")

    # Clean up file
    os.remove(f.name)

  def test_update_non_existent_cache(self):
    # Try to update cache that doesn't exist
    cache = StravaOAuthCache("non_existent_file.json", None)
    
    with self.assertRaises(StravaOAuthCacheError):
      cache.update_cache(test_key="test_value")

if __name__ == "__main__":
  unittest.main()
