import configparser
import os
import stat
import sys
from dataclasses import dataclass
from typing import Optional, Union

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.forcepoint/forcepoint.conf")


class ConfigError(Exception):
    pass


@dataclass
class SMCConfig:
    url: str
    api_key: str
    domain: str
    verify: Union[bool, str] = True
    api_version: Optional[str] = None
    timeout: int = 10


def _warn_permissions(path):
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(
            "fptail: warning: %s is readable by group/other and contains an "
            "API key - run `chmod 600 %s`" % (path, path),
            file=sys.stderr,
        )


def _str_to_verify(value: str) -> Union[bool, str]:
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    return value  # path to a CA bundle/cert


def load_config(profile: str = "default", config_path: str = DEFAULT_CONFIG_PATH,
                 cli_overrides: Optional[dict] = None) -> SMCConfig:
    cli_overrides = {k: v for k, v in (cli_overrides or {}).items() if v is not None}

    values = {
        "url": os.environ.get("FPTAIL_URL"),
        "api_key": os.environ.get("FPTAIL_API_KEY"),
        "verify": os.environ.get("FPTAIL_VERIFY"),
        "domain": os.environ.get("FPTAIL_DOMAIN"),
        "api_version": os.environ.get("FPTAIL_API_VERSION"),
        "timeout": os.environ.get("FPTAIL_TIMEOUT"),
    }
    values = {k: v for k, v in values.items() if v is not None}

    if os.path.isfile(config_path):
        _warn_permissions(config_path)
        parser = configparser.ConfigParser()
        parser.read(config_path)
        section = "smc" if profile in ("default", None) else "smc:%s" % profile
        if profile not in ("default", None) and section not in parser:
            raise ConfigError("no [%s] section in %s" % (section, config_path))
        if section in parser:
            for key in ("url", "api_key", "verify", "domain", "api_version", "timeout"):
                if key in parser[section] and key not in values:
                    values[key] = parser[section][key]

    values.update(cli_overrides)

    if "url" not in values or "api_key" not in values:
        raise ConfigError(
            "missing SMC url/api_key - set --url/--api-key, FPTAIL_URL/FPTAIL_API_KEY, "
            "or create %s (see --help)" % config_path
        )

    if not values.get("domain"):
        raise ConfigError(
            "no SMC domain set - pass --domain, set FPTAIL_DOMAIN, or add 'domain =' to the "
            "%s section in %s. This is required to stop logs from different customers/domains "
            "getting mixed up. Pass --domain 'Shared Domain' if that is genuinely what you want."
            % ("[smc]" if profile in ("default", None) else "[smc:%s]" % profile, config_path)
        )

    verify = values.get("verify", True)
    if isinstance(verify, str):
        verify = _str_to_verify(verify)

    return SMCConfig(
        url=values["url"],
        api_key=values["api_key"],
        domain=values["domain"],
        verify=verify,
        api_version=values.get("api_version"),
        timeout=int(values.get("timeout", 10)),
    )
