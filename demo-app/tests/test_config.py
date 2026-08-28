from app import config


def test_defaults_safe():
    d = config.load_defaults()
    assert d["app"]["name"] == "DocuFlow"


def test_strict_yaml():
    assert config.load_strict_yaml("a: 1")["a"] == 1
