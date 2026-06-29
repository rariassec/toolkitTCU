
from toolkitTCU.network_module.utils import utils as U

def test_validate_target_ip_y_cidr():
    assert U.validate_target("192.168.1.1") is True
    assert U.validate_target("192.168.1.0/24") is True

def test_validate_target_rango():
    assert U.validate_target("192.168.1.1-192.168.1.5") is True

def test_validate_target_invalido():
    assert U.validate_target("no-es-ip") is False
    assert U.validate_target("999.999.999.999") is False

def test_expand_ip_range():
    res = U.expand_ip_range("192.168.1.1-192.168.1.3")
    assert res == "192.168.1.1 192.168.1.2 192.168.1.3"

def test_expand_ip_range_ip_unica():
    assert U.expand_ip_range("192.168.1.1") == "192.168.1.1"

def test_is_private_ip():
    assert U.is_private_ip("10.0.0.1") is True
    assert U.is_private_ip("192.168.0.5") is True
    assert U.is_private_ip("8.8.8.8") is False
    assert U.is_private_ip("no-es-ip") is False

def test_is_valid_ip():
    assert U.is_valid_ip("1.2.3.4") is True
    assert U.is_valid_ip("texto") is False

def test_is_valid_domain():
    assert U.is_valid_domain("ejemplo.org") is True
    assert U.is_valid_domain("sub.dominio.com") is True
    assert U.is_valid_domain("sindominio") is False
