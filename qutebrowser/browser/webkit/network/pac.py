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

"""Evaluation of PAC scripts."""

import sys
import ipaddress
import fnmatch
import itertools
import functools

from PyQt5.QtCore import (QObject, QVariant, QMetaType, QDateTime,
                          QEventLoop, pyqtSlot)
from PyQt5.QtNetwork import (QNetworkProxy, QNetworkRequest, QHostInfo,
                             QNetworkReply, QNetworkAccessManager,
                             QHostAddress)
from PyQt5.QtQml import QJSEngine, QJSValue

from qutebrowser.utils import log


class ParseProxyError(Exception):

    """Error in parsing PAC result string."""

    pass


class EvalProxyError(Exception):

    """Error in evaluating PAC script."""

    pass


def _js_slot(*args):
    """Wrap a methods as a JavaScript function.

    Register a PACContext method as a JavaScript function, and catch
    exceptions returning them as JavaScript Error objects.

    Args:
        args: Types of method arguments.

    Return: Wrapped method.
    """
    def _decorator(method):
        @functools.wraps(method)
        def new_method(self, *args, **kwargs):
            try:
                return method(self, *args, **kwargs)
            except:
                e = str(sys.exc_info()[0])
                # pylint: disable=protected-access
                log.network.exception("PAC evaluation error")
                return self._error_con.callAsConstructor([e])
                # pylint: enable=protected-access
        return pyqtSlot(*args, result=QJSValue)(new_method)
    return _decorator


class _PACContext(QObject):

    """Implementation of PAC API.

    See http://web.archive.org/web/20060424005037/wp.netscape.com/eng/mozilla/2.0/relnotes/demo/proxy-live.html
    """

    def __init__(self, engine, *, fixed_dt=None):
        """Create a new PAC API implementation instance.

        Args:
            engine: QJSEngine which is used for running PAC.
            fixed_dt: QDateTime to use instead of system time.
        """
        super().__init__(parent=engine)
        self._engine = engine
        self._error_con = engine.globalObject().property("Error")
        self._fixed_dt = fixed_dt

    @_js_slot(str)
    def isPlainHostName(self, host):
        """Test if host is a plain hostname.

        Return True if and only if there is no domain name in the hostname (no
        dots).

        Args:
            host: The hostname from the URL (excluding port number).
        """
        return '.' not in host

    @_js_slot(str, str)
    def dnsDomainIs(self, host, domain):
        """Test if host belongs to domain.

        Return true if and only if the domain of hostname matches.

        Args:
            host: The hostname from the URL.
            domain: The domain name to test the hostname against.
        """
        return host.endswith(domain)

    @_js_slot(str, str)
    def localHostOrDomainIs(self, host, hostdom):
        """Test if host is local or belongs to domain.

        Return true if the hostname matches exactly the specified hostname, or
        if there is no domain name part in the hostname, but the unqualified
        hostname matches.

        Args:
            host: The hostname from the URL.
            hostdom: Fully qualified hostname to match against.
        """
        if "." not in host:
            hostdom_name, _dot, _domain = hostdom.partition('.')
            return host == hostdom_name
        else:
            return host == hostdom

    @_js_slot(str)
    def isResolvable(self, host):
        """Test if hostname is resolvable.

        Tries to resolve the hostname. Return true if succeeds.

        Args:
            host: The hostname from the URL.
        """
        ips = QHostInfo.fromName(host)
        return bool(ips.error() == QHostInfo.NoError and ips.addresses())

    @_js_slot(str, str, str)
    def isInNet(self, host, pattern, mask):
        """Test if host IP is in network.

        Return True if and only if the IP address of the host matches the
        specified IP address pattern. Pattern and mask specification is done
        the same way as for SOCKS configuration.

        Args:
            host: A DNS hostname, or IP address. If a hostname is passed, it
                  will be resolved into an IP address by this function.
            pattern: an IP address pattern in the dot-separated format.
            mask: mask for the IP address pattern informing which parts of
                  the IP address should be matched against. 0 means ignore,
                  255 means match.
        """
        host_ip = ipaddress.ip_address(host)
        network = ipaddress.ip_network("{}/{}".format(pattern, mask))
        return host_ip in network

    @_js_slot(str)
    def dnsResolve(self, host):
        """Resolve a DNS hostname.

        Resolves the given DNS hostname into an IP address, and returns it
        in the dot-separated format as a string.

        Args:
            host: hostname to resolve.
        """
        ips = QHostInfo.fromName(host)
        if ips.error() != QHostInfo.NoError or not ips.addresses():
            err_f = "Failed to resolve host during PAC evaluation: {}"
            log.network.error(err_f.format(host))
            return ""
        else:
            return ips.addresses()[0].toString()

    @_js_slot()
    def myIpAddress(self):
        """Get host IP address.

        Return the server IP address of the current machine, as a string in
        the dot-separated integer format.
        """
        return QHostAddress(QHostAddress.LocalHost).toString()

    @_js_slot(str)
    def dnsDomainLevels(self, host):
        """Count number of DNS domain levels.

        Return the number (integer) of DNS domain levels (number of dots)
        in the hostname.

        Args:
            host: the hostname from the URL.
        """
        return host.count('.')

    @_js_slot(str, str)
    def shExpMatch(self, mstr, shexp):
        """Test is string matches shell expression.

        Return true if the string matches the specified shell expression.
        Currently, the patterns are shell expressions, not regular
        expressions.

        Args:
            mstr: Any string to compare (e.g. the URL, or the hostname).
            shexp: a shell expression to compare against.
        """
        return fnmatch.fnmatchcase(mstr, shexp)

    def _get_dt(self, gmt):
        if self._fixed_dt is not None:
            if gmt:
                return self._fixed_dt.toUTC()
            else:
                return self._fixed_dt
        else:
            if gmt:
                return QDateTime.currentDateTimeUtc()
            else:
                return QDateTime.currentDateTime()

    @staticmethod
    def _in_range(avals, vals, bvals, ranges):
        """Test if a tuple is between two tuples in numerical order."""
        carry_a = 0
        carry_val = 0
        carry_b = 0
        for a, val, b, r in zip(avals, vals, bvals, ranges):
            if a is not None:
                a_c = a + carry_a
                val_c = val + carry_val
                b_c = b + carry_b
                if a_c < val_c < b_c:
                    return True
                elif not a_c <= val_c <= b_c:
                    return False
                carry_a += a * r
                carry_val += val * r
                carry_b += b * r
        return True

    @_js_slot(QVariant)
    def weekdayRange(self, args):
        """Test is current date is between two week days.

        Only the first parameter is mandatory. Either the second, the third,
        or both may be left out.

        If only one parameter is present, the function returns a value of
        true on the weekday that the parameter represents. If the string
        "GMT" is specified as a second parameter, times are taken to be in
        GMT. Otherwise, they are assumed to be in the local timezone.

        If both wd1 and wd1 are defined, the condition is true if the
        current weekday is in between those two ordered weekdays. Bounds are
        inclusive, but the bounds are ordered. If the "GMT" parameter is
        specified, times are taken to be in GMT. Otherwise, the local
        timezone is used.
        """
        weekdays = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")

        # Expects list of all arguments because the function has different
        # modes expecting different number of them.
        if isinstance(args, QJSValue):
            args = args.toVariant()
        wd1 = args[0]
        wd2 = wd1
        gmt = args[-1] == "GMT"
        if gmt:
            args = args[:-1]

        if len(args) == 2:
            wd2 = args[1]
        elif len(args) != 1:
            raise EvalProxyError("Invalid number of arguments")

        avals = (weekdays.index(wd1),)
        bvals = (weekdays.index(wd2),)
        d = self._get_dt(gmt).date()
        val = (d.dayOfWeek() - 1,)

        return self._in_range(avals, val, bvals, (1,))

    def _date_range(self, args1, args2, gmt):
        """Test if current date is between two date points.

        Args:
            args1, args2: two dictionaries with optional "year", "month" and
            "day".
            gmt: Should the UTC time be used.
        """
        def _to_tuple(args):
            months = ("JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG",
                      "SEP", "OCT", "NOV", "DEC")

            if "month" in args:
                m = months.index(args["month"])
            else:
                m = None

            return (args.get("year"), m, args.get("day"))

        ranges = (31 * 12, 31, 1)

        d = self._get_dt(gmt).date()
        val = (d.year(), d.month() - 1, d.day())

        return self._in_range(_to_tuple(args1), val, _to_tuple(args2), ranges)

    @_js_slot(QVariant)
    def dateRange(self, args):
        """Test if current date is between two date points.

        If only a single value is specified (from each category: day, month,
        year), the function returns a true value only on days that match
        that specification. If both values are specified, the result is true
        between those times, including bounds, but the bounds are ordered.

        Order of arguments: day, month, year.
        """
        order = ("day", "month", "year")

        # Complex logic because of all the modes the function can run in.
        # We first try to normalize arguments to pairs of day, month and year
        # (which can be None to indicate that this pair doesn't need to be
        # checked).
        if isinstance(args, QJSValue):
            args = args.toVariant()
        args1 = {}
        args2 = {}
        gmt = args[-1] == "GMT"
        if gmt:
            args = args[:-1]

        my_order = []
        count = 0
        for arg in args:
            # Flaky detection of argument type based on its domain. Sigh --
            # JavaScript...
            argtype = "year"
            if isinstance(arg, str):
                argtype = "month"
            elif arg >= 1 and arg <= 31:
                argtype = "day"

            if argtype in args1:
                break
            # If e.g. days are specified after a year.
            ord_pos = order.index(argtype)
            if any([x in args1 for x in order[ord_pos + 1:]]):
                raise EvalProxyError("Invalid arguments order")

            args1[argtype] = arg
            my_order.append(argtype)
            count += 1

        if len(args) == 2 * count:
            for e, i in zip(my_order, itertools.count(0)):
                args2[e] = args[count + i]
        elif len(args) == count:
            args2 = args1
        else:
            raise EvalProxyError("Invalid number of arguments")

        if not args1:
            raise EvalProxyError("Nothing is passed to check the range")

        return self._date_range(args1, args2, gmt)

    def _time_range(self, args1, args2, gmt):
        """Test if current time is between two time points.

        Args:
            args1, args2: Two dictionaries with optional "hour", "min" and
            "sec".
            gmt: Should the UTC time be used.
        """
        def _to_tuple(args):
            return (args.get("hour"), args.get("min"), args.get("sec"))

        ranges = (3600, 60, 1)

        t = self._get_dt(gmt).time()
        val = (t.hour(), t.minute(), t.second())

        return self._in_range(_to_tuple(args1), val, _to_tuple(args2), ranges)

    @_js_slot(QVariant)
    def timeRange(self, args):
        """Test if current time is between two time points.

        If only a single value is specified (from each category: hour,
        minute, second), the function returns a true value only at times
        that match that specification. If both values are specified, the
        result is true between those times, including bounds, but the bounds
        are ordered.

        Order: hour, min, sec. Next argument can't be specified without
        previous.
        """
        order = ("hour", "min", "sec")

        # Same as dateRange but simpler because need to autodetect less (at
        # least seconds always follow minutes always follow hours...).
        if isinstance(args, QJSValue):
            args = args.toVariant()
        args1 = {}
        args2 = {}
        gmt = args[-1] == "GMT"
        if gmt:
            args = args[:-1]

        if len(args) == 1:
            args1["hour"] = args[0]
            args2["hour"] = args[0] + 1
        else:
            if len(args) % 2 != 0 or len(args) > len(order) * 2:
                raise EvalProxyError("Invalid number of args")
            nargs = int(len(args) / 2)

            for e, i in zip(order[:nargs], itertools.count(0)):
                args1[e] = args[i]
                args2[e] = args[nargs + i]

        if not args1:
            raise EvalProxyError("Nothing is passed to check the range")

        return self._time_range(args1, args2, gmt)


class PACResolver(object):
    """Evaluate PAC script files and resolve proxies."""

    @staticmethod
    def _parse_proxy_host(host_str):
        host, _colon, port_str = host_str.partition(':')
        try:
            port = int(port_str)
        except ValueError:
            raise ParseProxyError("Invalid port number")
        return (host, port)

    @staticmethod
    def _parse_proxy_entry(proxy_str):
        """Parse one proxy string entry, as described in PAC specification."""
        config = [c for c in proxy_str.split(' ') if c]
        if not config:
            raise ParseProxyError("Empty proxy entry")
        elif config[0] == "DIRECT":
            if len(config) != 1:
                raise ParseProxyError("Invalid number of parameters")
            return QNetworkProxy(QNetworkProxy.NoProxy)
        elif config[0] == "PROXY":
            if len(config) != 2:
                raise ParseProxyError("Invalid number of parameters")
            host, port = PACResolver._parse_proxy_host(config[1])
            return QNetworkProxy(QNetworkProxy.HttpProxy, host, port)
        elif config[0] == "SOCKS":
            if len(config) != 2:
                raise ParseProxyError("Invalid number of parameters")
            host, port = PACResolver._parse_proxy_host(config[1])
            return QNetworkProxy(QNetworkProxy.Socks5Proxy, host, port)
        else:
            err = "Unknown proxy type: {}"
            raise ParseProxyError(err.format(config[0]))

    @staticmethod
    def _parse_proxy_string(proxy_str):
        proxies = proxy_str.split(';')
        return [PACResolver._parse_proxy_entry(x) for x in proxies]

    def __init__(self, pac_str, fixed_dt=None):
        """Create a PAC resolver.

        Args:
            pac_str: JavaScript code containing PAC resolver.
            fixed_dt: Assume fixed date and time instead of system time.
        """
        self._engine = QJSEngine()

        self._ctx = _PACContext(self._engine, fixed_dt=fixed_dt)
        self._engine.globalObject().setProperty("PAC",
            self._engine.newQObject(self._ctx))
        proxy_config = self._engine.newObject()
        proxy_config.setProperty("bindings", self._engine.newObject())
        self._engine.globalObject().setProperty("ProxyConfig", proxy_config)
        ctx_meta = self._ctx.metaObject()
        for i in range(ctx_meta.methodCount()):
            m = ctx_meta.method(i)
            if m.typeName() == "QJSValue":
                name = bytes(m.name()).decode()
                if (m.parameterCount() == 1 and
                        m.parameterType(0) == QMetaType.QVariant):
                    call_str_f = "PAC.{}([].slice.call(arguments))"
                else:
                    call_str_f = "PAC.{}.apply(PAC, arguments)"
                decl_str_f = """
                    function {}() {{
                        var res = {};
                        if (res instanceof Error) {{
                            throw res;
                        }} else {{
                            return res;
                        }}
                    }}
                """
                call_str = call_str_f.format(name)
                eval_str = decl_str_f.format(name, call_str)
                self._engine.evaluate(eval_str)

        self._engine.evaluate(pac_str, "pac")
        global_js_object = self._engine.globalObject()
        self._resolver = global_js_object.property("FindProxyForURL")
        if not self._resolver.isCallable():
            err = "Cannot resolve FindProxyForURL function, got '{}' instead"
            raise EvalProxyError(err.format(self._resolver.toString()))

    def resolve(self, query):
        """Resolve a proxy via PAC.

        Args:
            query: QNetworkProxyQuery.

        Return:
            A list of QNetworkProxy objects in order of preference.
        """
        result = self._resolver.call([query.url().toString(),
                                      query.peerHostName()])
        result_str = result.toString()
        if not result.isString():
            err = "Got strange value from FindProxyForURL: '{}'"
            raise EvalProxyError(err.format(result_str))
        return self._parse_proxy_string(result_str)


class PACFetcher(QObject):

    """Asynchronous fetcher of PAC files."""

    def __init__(self, url, parent=None):
        """Resolve a PAC proxy from URL.

        Args:
            url: QUrl of a PAC proxy.
        """
        pac_prefix = "pac+"

        super().__init__(parent)

        assert url.scheme().startswith(pac_prefix)
        url.setScheme(url.scheme()[len(pac_prefix):])

        self._manager = QNetworkAccessManager()
        self._manager.setProxy(QNetworkProxy(QNetworkProxy.NoProxy))
        self._reply = self._manager.get(QNetworkRequest(url))
        self._reply.finished.connect(self._finish)
        self._pac = None
        self._loop = None

    @pyqtSlot()
    def _finish(self):
        if self._reply.error() != QNetworkReply.NoError:
            log.network.error("Can't fetch PAC file from URL")
        else:
            try:
                pacscript = bytes(self._reply.readAll()).decode()
            except UnicodeError:
                log.network.exception("Invalid encoding of a PAC file")
            try:
                self._pac = PACResolver(pacscript)
                log.network.debug("Successfully evaluated PAC file.")
            except EvalProxyError as e:
                error = "Error in PAC evaluation: {!s}.".format(e)
                log.network.exception(error)
        if self._loop is not None:
            self._reply.deleteLater()
        else:
            self._manager = None
            del self._reply

    def _wait(self):
        if self._manager is not None:
            self._loop = QEventLoop()
            self._reply.destroyed.connect(self._loop.quit)
            self._loop.exec()
            self._loop = None
            self._manager = None
            del self._reply

    def is_fetched(self):
        """Check if PAC script is successfully fetched.

        Return: True iff PAC script is downloaded and evaluated successfully.
        """
        self._wait()
        return self._pac is not None

    def resolve(self, query):
        """Resolve a query via PAC.

        Args: QNetworkProxyQuery.

        Return: A list of QNetworkProxy objects in order of preference.
        """
        self._wait()
        try:
            return self._pac.resolve(query)
        except (EvalProxyError, ParseProxyError) as e:
            log.network.exception("Error in PAC resolution: {!s}.".format(e))
            error_host = "pac-resolve-error.qutebrowser.invalid"
            return QNetworkProxy(QNetworkProxy.HttpProxy, error_host, 9)
