
import os
import json
from strava_auth.cache import StravaOAuthCache, StravaOAuthCacheError

def create_test_cache_file():
    """Create a test cache file with unique name"""
    return f"test_cache_{os.getpid()}.json"

def cleanup_test_cache_file(filename):
    """Remove the test cache file"""
    if os.path.exists(filename):
        os.remove(filename)

def test_write_to_cache():
    """Test writing data to cache"""
    cache_file = create_test_cache_file()
    
    try:
        cache = StravaOAuthCache(cache_file, logger=None)
        data = {"token": "test_token", "athlete": "test_athlete"}
        result = cache.write_to_cache(**data)
        
        # Verify file exists and contains data
        assert os.path.exists(cache_file)
        with open(cache_file, 'r') as f:
            cached_data = json.load(f)
            assert cached_data == data
            assert result == data
            
    finally:
        cleanup_test_cache_file(cache_file)

def test_read_from_cache():
    """Test reading data from cache"""
    cache_file = create_test_cache_file()
    
    # Create test data first
    data = {"token": "test_token", "athlete": "test_athlete"}
    with open(cache_file, 'w') as f:
        json.dump(data, f)
    
    try:
        cache = StravaOAuthCache(cache_file, logger=None)
        result = cache.read_from_cache("token", "athlete")
        
        assert result["token"] == data["token"]
        assert result["athlete"] == data["athlete"]
        
    finally:
        cleanup_test_cache_file(cache_file)

def test_update_cache():
    """Test updating existing cache data"""
    cache_file = create_test_cache_file()
    
    # Create initial data
    initial_data = {"token": "initial_token", "athlete": "initial_athlete"}
    with open(cache_file, 'w') as f:
        json.dump(initial_data, f)
    
    try:
        cache = StravaOAuthCache(cache_file, logger=None)
        new_data = {"token": "updated_token"}
        result = cache.update_cache(**new_data)
        
        # Verify the update
        with open(cache_file, 'r') as f:
            updated_data = json.load(f)
            assert updated_data["token"] == new_data["token"]
            assert updated_data["athlete"] == initial_data["athlete"]
            
    finally:
        cleanup_test_cache_file(cache_file)

def test_cache_file_not_found():
    """Test error handling when cache file doesn't exist"""
    cache_file = create_test_cache_file()
    
    cache = StravaOAuthCache(cache_file, logger=None)
    
    try:
        cache.read_from_cache("token")
        assert False, "Expected StravaOAuthCacheError"
    except StravaOAuthCacheError:
        pass

if __name__ == "__main__":
    print("Running cache tests...")
    test_write_to_cache()
    print("Write test passed")
    
    test_read_from_cache()
    print("Read test passed")
    
    test_update_cache()
    print("Update test passed")
    
    test_cache_file_not_found()
    print("Error handling test passed")
    
    print("All cache tests passed successfully!")
