import asyncio
import typing
import logging

from . import strings, models
logger = logging.getLogger(__name__)

class CheckFailed(Exception):
    def __init__(self, virus_type: str, virus_consequences: str, additional_info: str = ""):
        self.model = models.ScanResponse(result=False, virus_type=virus_type,
                            virus_consequences=virus_consequences, additional_info=additional_info)

class CheckProto(typing.Protocol):
    @staticmethod
    async def check(req: models.ScanRequest) -> str|None:
        ...

class _CheckHelper:
    @staticmethod
    def scheme(url: str) -> str:
        _split = url.find("://")
        return url[:(_split if _split != -1 else None)]
    @staticmethod
    def uri(url: str) -> str:
        _split = url.find("://")
        return url[(_split+3 if _split != -1 else None):]
    @staticmethod
    def domain(uri: str) -> str:
        _split = uri.find("/")
        return uri[:(_split if _split != -1 else None)]
helper = _CheckHelper()

class HTTPCheck(CheckProto):
    @staticmethod
    async def check(req):
        if helper.scheme(req.url) != "https":
            raise CheckFailed(virus_type=strings.UNSAFE_HTTP, virus_consequences=strings.UNSAFE_HTTP_DESC)

class DomainZoneInfo(CheckProto):
    @staticmethod
    async def check(req):
        domain = helper.domain(helper.uri(req.url))
        if domain.endswith('.ru'):
            return strings.RU_DOMAIN_ZONE
        elif domain.endswith(".com"):
            return strings.COM_DOMAIN_ZONE
        else:
            return strings.FN_DOMAIN_ZONE

_trusted_domains = frozenset({
    "yandex.ru", "ozon.ru", "mail.ru", "rutube.ru", "gov.ru"
})
class KnownTrusted(CheckProto):
    @staticmethod
    async def check(req):
        domain = helper.domain(helper.uri(req.url))
        if domain in _trusted_domains:
            return strings.TRUSTED_DOMAIN

enabled_checks: tuple[CheckProto, ...] = (HTTPCheck(), DomainZoneInfo(), KnownTrusted())

async def check(req: models.ScanRequest) -> models.ScanResponse:
    try:
        comments = await asyncio.gather(
            *(_chk.check(req) for _chk in enabled_checks),
            return_exceptions=True # set to False to handle first exception (faster, but less additional info)
        )
        _add = ""
        result = True
        virus_type = None
        virus_consequences = None
        for comment in comments:
            if isinstance(comment, Exception):
                if isinstance(comment, CheckFailed):
                    result = False
                    virus_type = comment.model.virus_type
                    virus_consequences = comment.model.virus_consequences
                else:
                    raise comment
            elif comment:
                _add += comment + "\n"
        return models.ScanResponse(result=result, additional_info=(strings.SAFE + _add if result else _add),
                                   virus_type=virus_type, virus_consequences=virus_consequences)
    except CheckFailed as e:
        return e.model
    except Exception as e:
        logger.warning("Error: %e", e, exc_info=True)
        return models.ScanResponse(result=False, additional_info=strings.CHECK_FAILED, virus_type=strings.ERROR, virus_consequences=strings.ERROR)

