import pytest
from scanner import Scanner


def test_scan_method():
    scanner = Scanner()
    result = scanner.scan('192.168.1.1')
    assert isinstance(result, dict)


def test_scan_invalid_ip():
    scanner = Scanner()
    with pytest.raises(ValueError):
        scanner.scan('invalid_ip')


def test_scan_range():
    scanner = Scanner()
    results = scanner.scan_range('192.168.1.1', '192.168.1.10')
    assert len(results) == 10  # Assuming it scans the range correctly
    assert all(isinstance(result, dict) for result in results)  # Assuming results are dicts
