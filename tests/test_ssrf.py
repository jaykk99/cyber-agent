import socket

import pytest

from app.ssrf import SSRFBlocked, check_host, check_url


def fake_resolver(public_ip):
    def resolve(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (public_ip, 0))]
    return resolve


def test_public_host_passes():
    assert check_host("example.com", resolve=fake_resolver("93.184.216.34")) == "example.com"


def test_private_ip_blocked():
    with pytest.raises(SSRFBlocked):
        check_host("internal.example", resolve=fake_resolver("10.0.0.5"))


def test_loopback_blocked():
    with pytest.raises(SSRFBlocked):
        check_host("x.example", resolve=fake_resolver("127.0.0.1"))


def test_metadata_blocked():
    with pytest.raises(SSRFBlocked):
        check_host("x.example", resolve=fake_resolver("169.254.169.254"))


def test_benchmarking_range_allowed_for_proxied_public_hosts():
    # 198.18/15 is benchmarking space, but CDNs/proxies resolve real public
    # hosts into it; the metadata endpoint stays blocked above.
    assert check_host("x.example", resolve=fake_resolver("198.18.189.239")) == "x.example"


def test_localhost_blocked():
    with pytest.raises(SSRFBlocked):
        check_host("localhost")


def test_non_http_scheme_blocked():
    with pytest.raises(SSRFBlocked):
        check_url("ftp://example.com/file")


def test_unresolvable_blocked():
    def boom(host, port):
        raise socket.gaierror("nope")
    with pytest.raises(SSRFBlocked):
        check_host("does-not-exist.invalid", resolve=boom)
