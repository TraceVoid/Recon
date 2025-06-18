import pytest
from spider.utils import network_utils

def test_is_valid_url():
    assert network_utils.is_valid_url("http://example.com", "http://example.com") is True
    assert network_utils.is_valid_url("https://example.com/path", "http://example.com") is True
    assert network_utils.is_valid_url("http://evil.com", "http://example.com") is False
    assert network_utils.is_valid_url("javascript:alert(1)", "http://example.com") is False

def test_join_urls():
    assert network_utils.join_urls("http://example.com", "test") == "http://example.com/test"
    assert network_utils.join_urls("http://example.com/", "/test") == "http://example.com/test"
    assert network_utils.join_urls("http://example.com/path", "../test") == "http://example.com/test"