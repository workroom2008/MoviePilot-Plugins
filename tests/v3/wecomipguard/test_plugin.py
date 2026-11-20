"""WeComIPGuard 关键纯函数测试。

这些用例只覆盖不依赖宿主运行时的逻辑（IP 解析、Cookie 解析、配置读取），
可以在没有 MoviePilot 运行环境的机器上直接跑。
"""

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module():
    """按文件路径加载插件模块，避免依赖宿主 app 包。"""
    plugin_file = Path(__file__).resolve().parents[3] / "plugins.v3" / "wecomipguard" / "__init__.py"
    # 宿主依赖在无 MoviePilot 环境下不可用，这里注入最小桩模块
    for name in [
        "app",
        "app.sdk",
        "app.sdk.events",
        "app.sdk.logging",
        "app.sdk.config",
        "app.schemas",
        "app.schemas.types",
        "app.plugins",
        "app.adapters",
        "app.adapters.external",
        "app.adapters.external.cookiecloud",
        "cloakbrowser",
        "apscheduler",
        "apscheduler.schedulers",
        "apscheduler.schedulers.background",
        "apscheduler.triggers",
        "apscheduler.triggers.cron",
    ]:
        sys.modules.setdefault(name, _Stub(name))

    sys.modules["app.sdk.events"].eventmanager = _Stub("eventmanager")
    sys.modules["app.sdk.events"].Event = object
    sys.modules["app.sdk.logging"].logger = _Stub("logger")
    sys.modules["app.sdk.config"].settings = _Stub("settings")
    sys.modules["app.schemas.types"].EventType = _Stub("EventType")
    sys.modules["app.schemas.types"].MessageChannel = _Stub("MessageChannel")
    sys.modules["app.schemas.types"].NotificationType = _Stub("NotificationType")
    sys.modules["app.plugins"]._PluginBase = _Stub("_PluginBase")
    sys.modules["app.adapters.external.cookiecloud"].CookieCloudHelper = _Stub("CookieCloudHelper")

    spec = importlib.util.spec_from_file_location("wecomipguard_under_test", plugin_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Stub:
    """通用桩对象，任何属性访问都返回自身，可被调用。"""

    def __init__(self, name: str = "stub"):
        self._name = name

    def __getattr__(self, item):
        return _Stub(item)

    def __call__(self, *args, **kwargs):
        return _Stub("call")

    def __getitem__(self, item):
        return _Stub("item")


class TestParseIpv4:
    """公网 IPv4 解析与校验。"""

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("Current IP Address: 106.112.158.166", "106.112.158.166"),
            ("106.112.158.166\n", "106.112.158.166"),
            ('{"ip":"8.8.8.8"}', "8.8.8.8"),
            ("https://ddns.oray.com/checkip: 1.2.3.4", "1.2.3.4"),
        ],
    )
    def test_extracts_valid_ipv4(self, text, expected):
        module = _load_module()
        assert module.WeComIPGuard._parse_ipv4(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            # IPv6 文本不能当成 IPv4
            "当前 IP：240e:341:7146:4a00:c42c:9d6c:c666:11e1 来自于：中国 河北",
            # 私网 / 回环地址要过滤
            "192.168.1.5",
            "127.0.0.1",
            "10.0.0.1",
            # 非法数值
            "999.1.1.1",
            # 版本号不能被误判
            "v1.2.3.4.5.6",
            "",
            None,
        ],
    )
    def test_rejects_invalid_or_non_public(self, text):
        module = _load_module()
        assert module.WeComIPGuard._parse_ipv4(text) is None


class TestParseCookieHeader:
    """Cookie HeaderString 解析。"""

    def test_parses_pairs_and_skips_malformed(self):
        module = _load_module()
        result = module.WeComIPGuard._parse_cookie_header("a=1; b=2;c=3; bad; =x; d=")
        assert result == {"a": "1", "b": "2", "c": "3", "d": ""}

    def test_value_can_contain_equals(self):
        module = _load_module()
        assert module.WeComIPGuard._parse_cookie_header("k=a=b==c") == {"k": "a=b==c"}

    def test_empty_input(self):
        module = _load_module()
        assert module.WeComIPGuard._parse_cookie_header("") == {}


class TestConfigDefaults:
    """配置读取的边界行为。"""

    def test_as_int_falls_back_on_bad_value(self):
        module = _load_module()
        assert module.WeComIPGuard._as_int("abc", 15) == 15
        assert module.WeComIPGuard._as_int(None, 180) == 180
        assert module.WeComIPGuard._as_int(0, 15) == 15
        assert module.WeComIPGuard._as_int("30", 15) == 30

    def test_default_ip_sources_are_https(self):
        module = _load_module()
        sources = module.WeComIPGuard._default_ip_urls
        assert sources, "必须至少有一个内置 IP 源"
        assert all(url.startswith("https://") for url in sources)
