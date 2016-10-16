# vim: ft=python fileencoding=utf-8 sts=4 sw=4 et:

# Copyright 2016 Florian Bruhin (The Compiler) <mail@qutebrowser.org>
#
# This file is part of qutebrowser.
#
# qutebrowser is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# qutebrowser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with qutebrowser.  If not, see <http://www.gnu.org/licenses/>.

import http.server
import threading
import logging

from PyQt5.QtCore import QUrl, QDateTime, QDate, QTime, Qt
from PyQt5.QtNetwork import QNetworkProxy, QNetworkProxyQuery

from qutebrowser.browser.webkit.network import pac


def _pac_common_test(test_str, use_fixed_dt=True):
    date = QDate(2016, 8, 26)
    time = QTime(10, 30, 0)
    tz = 7200

    fun_str_f = """
        function FindProxyForURL(domain, host) {{
            {}
            return "DIRECT; PROXY 127.0.0.1:8080; SOCKS 192.168.1.1:4444";
        }}
    """

    fun_str = fun_str_f.format(test_str)

    if use_fixed_dt:
        dt = QDateTime(date, time, Qt.OffsetFromUTC, tz)
        res = pac.PACResolver(fun_str, fixed_dt=dt)
    else:
        res = pac.PACResolver(fun_str)

    proxies = res.resolve(QNetworkProxyQuery(QUrl("https://example.com/test")))
    assert len(proxies) == 3
    assert proxies[0].type() == QNetworkProxy.NoProxy
    assert proxies[1].type() == QNetworkProxy.HttpProxy
    assert proxies[1].hostName() == "127.0.0.1"
    assert proxies[1].port() == 8080
    assert proxies[2].type() == QNetworkProxy.Socks5Proxy
    assert proxies[2].hostName() == "192.168.1.1"
    assert proxies[2].port() == 4444


def _pac_equality_test(call, expected):
    test_str_f = """
        var res = ({0});
        var expected = ({1});
        if(res !== expected) {{
            throw new Error("failed test {0}: got '" + res + "', expected '" + expected + "'");
        }}
    """
    _pac_common_test(test_str_f.format(call, expected))


def _pac_except_test(caplog, call):
    test_str_f = """
        var thrown = false;
        try {{
            var res = ({0});
        }} catch(e) {{
            thrown = true;
        }}
        if(!thrown) {{
            throw new Error("failed test {0}: got '" + res + "', expected exception");
        }}
    """
    with caplog.at_level(logging.ERROR):
        _pac_common_test(test_str_f.format(call))


def _pac_noexcept_test(call):
    test_str_f = """
        var res = ({0});
    """
    _pac_common_test(test_str_f.format(call), use_fixed_dt=False)


# pylint: disable=line-too-long, invalid-name


def test_isPlainHostName():
    _pac_equality_test("isPlainHostName('www')", "true")
    _pac_equality_test("isPlainHostName('www.netscape.com')", "false")


def test_dnsDomainIs():
    _pac_equality_test("dnsDomainIs('www.netscape.com', '.netscape.com')", "true")
    _pac_equality_test("dnsDomainIs('www', '.netscape.com')", "false")
    _pac_equality_test("dnsDomainIs('www.mcom.com', '.netscape.com')", "false")


def test_localHostOrDomainIs():
    _pac_equality_test("localHostOrDomainIs('www.netscape.com', 'www.netscape.com')", "true")
    _pac_equality_test("localHostOrDomainIs('www', 'www.netscape.com')", "true")
    _pac_equality_test("localHostOrDomainIs('www.mcom.com', 'www.netscape.com')", "false")
    _pac_equality_test("localHostOrDomainIs('home.netscape.com', 'www.netscape.com')", "false")


def test_isResolvable():
    _pac_equality_test("isResolvable('www.netscape.com')", "true")
    _pac_equality_test("isResolvable('bogus.domain.foobar')", "false")


def test_isInNet():
    _pac_equality_test("isInNet('198.95.249.79', '198.95.249.79', '255.255.255.255')", "true")
    _pac_equality_test("isInNet('198.95.249.78', '198.95.249.79', '255.255.255.255')", "false")
    _pac_equality_test("isInNet('198.95.249.78', '198.95.0.0', '255.255.0.0')", "true")
    _pac_equality_test("isInNet('198.96.249.78', '198.95.0.0', '255.255.0.0')", "false")


def test_myIpAddress():
    _pac_equality_test("isResolvable(myIpAddress())", "true")


def test_dnsDomainLevels():
    _pac_equality_test("dnsDomainLevels('www')", "0")
    _pac_equality_test("dnsDomainLevels('www.netscape.com')", "2")


def test_shExpMatch():
    _pac_equality_test("shExpMatch('http://home.netscape.com/people/ari/index.html', '*/ari/*')", "true")
    _pac_equality_test("shExpMatch('http://home.netscape.com/people/montulli/index.html', '*/ari/*')", "false")


def test_weekdayRange(caplog):
    _pac_equality_test("weekdayRange('MON', 'FRI')", "true")
    _pac_equality_test("weekdayRange('MON', 'FRI', 'GMT')", "true")
    _pac_equality_test("weekdayRange('SAT')", "false")
    _pac_equality_test("weekdayRange('SAT', 'GMT')", "false")
    _pac_equality_test("weekdayRange('FRI', 'MON')", "false")

    _pac_noexcept_test("weekdayRange('SAT')")
    _pac_except_test(caplog, "weekdayRange('SAT', 'SAT', 'SAT')")


def test_dateRange(caplog):
    _pac_equality_test("dateRange(26)", "true")
    _pac_equality_test("dateRange(26, 'GMT')", "true")
    _pac_equality_test("dateRange(1, 15)", "false")
    _pac_equality_test("dateRange(24, 'DEC')", "false")
    _pac_equality_test("dateRange('APR', 'SEP')", "true")
    _pac_equality_test("dateRange(1, 'JUN', 30, 'AUG')", "true")
    _pac_equality_test("dateRange(1, 'JUN', 1995, 30, 'AUG', 2016)", "true")
    _pac_equality_test("dateRange('OCT', 2016, 'MAR', 2017)", "false")
    _pac_equality_test("dateRange(2016)", "true")
    _pac_equality_test("dateRange(2016, 2014)", "false")

    _pac_except_test(caplog, "dateRange()")
    _pac_except_test(caplog, "dateRange('GMT')")
    _pac_except_test(caplog, "dateRange(2016, 'JUN')")
    _pac_except_test(caplog, "dateRange(2016, 2016, 2016)")


def test_timeRange(caplog):
    _pac_equality_test("timeRange(10)", "true")
    _pac_equality_test("timeRange(12, 13)", "false")
    _pac_equality_test("timeRange(8, 'GMT')", "true")
    _pac_equality_test("timeRange(9, 17)", "true")
    _pac_equality_test("timeRange(8, 30, 17, 0, 'GMT')", "true")
    _pac_equality_test("timeRange(0, 0, 0, 8, 30, 0, 'GMT')", "true")

    _pac_except_test(caplog, "timeRange()")
    _pac_except_test(caplog, "timeRange(0, 0, 0, 0, 0, 0, 0)")


def test_proxyBindings():
    _pac_equality_test("JSON.stringify(ProxyConfig.bindings)", "'{}'")


def test_invalid_port():
    test_str = """
        function FindProxyForURL(domain, host) {
            return "PROXY 127.0.0.1:FOO";
        }
    """

    res = pac.PACResolver(test_str)
    try:
        res.resolve(QNetworkProxyQuery(QUrl("https://example.com/test")))
        assert False
    except pac.ParseProxyError:
        pass


def test_fetch():
    test_str = """
        function FindProxyForURL(domain, host) {
            return "DIRECT; PROXY 127.0.0.1:8080; SOCKS 192.168.1.1:4444";
        }
    """

    class PACHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)

            self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
            self.end_headers()

            self.wfile.write(bytes(test_str, "ascii"))

    def serve():
        httpd = http.server.HTTPServer(("127.0.0.1", 8081), PACHandler)
        httpd.handle_request()
        print("Closing thread")

    serve_thread = threading.Thread(target=serve, daemon=True)
    serve_thread.start()
    try:
        res = pac.PACFetcher(QUrl("pac+http://127.0.0.1:8081"))
        assert res.is_fetched()
        serve_thread.join()
        proxies = res.resolve(QNetworkProxyQuery(QUrl("https://example.com/test")))
        assert len(proxies) == 3
    finally:
        serve_thread.join()
