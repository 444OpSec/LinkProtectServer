import asyncio
import typing
import logging
import aiohttp
import ipaddress
from urllib.parse import urlparse

_session: typing.Optional[aiohttp.ClientSession] = None

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

class HTTPCheck(CheckProto):
    @staticmethod
    async def check(req):
        if urlparse(req.url).scheme != "https":
            raise CheckFailed(virus_type=strings.UNSAFE_HTTP, virus_consequences=strings.UNSAFE_HTTP_DESC)

class DomainZoneInfo(CheckProto):
    @staticmethod
    async def check(req):
        domain = urlparse(req.url).hostname
        if not domain: return
        if domain.endswith('.ru'):
            return strings.RU_DOMAIN_ZONE
        elif domain.endswith(".com"):
            return strings.COM_DOMAIN_ZONE
        else:
            return strings.FN_DOMAIN_ZONE

class KnownTrusted(CheckProto):
    _trusted_domains = frozenset({"yandex.ru", "ozon.ru", "mail.ru", "rutube.ru", "gov.ru", "google.com"})
    
    @staticmethod
    async def check(req):
        domain = urlparse(req.url).hostname
        if domain in KnownTrusted._trusted_domains:
            return strings.TRUSTED_DOMAIN

class IPDomainCheck(CheckProto):
    """Проверка, является ли домен IP-адресом (часто используют фишеры)"""
    @staticmethod
    async def check(req: models.ScanRequest) -> str | None:
        parsed_url = urlparse(req.url)
        hostname = parsed_url.hostname
        if not hostname: return
        try:
            ipaddress.ip_address(hostname)
            raise CheckFailed(virus_type=strings.IP_DOMAIN, virus_consequences=strings.IP_DOMAIN_DESC)
        except ValueError:
            pass

class SuspiciousTLDCheck(CheckProto):
    """Проверка на использование дешевых/бесплатных доменных зон, используемых мошениками"""
    _bad_tlds = frozenset({".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".xyz", ".top", ".club"})
    
    @staticmethod
    async def check(req: models.ScanRequest) -> str | None:
        parsed_url = urlparse(req.url)
        hostname = parsed_url.hostname
        if hostname and any(hostname.endswith(tld) for tld in SuspiciousTLDCheck._bad_tlds):
            raise CheckFailed(virus_type=strings.SUSPICIOUS_TLD, virus_consequences=strings.SUSPICIOUS_TLD_DESC)

class URLShortenerCheck(CheckProto):
    """Предупреждение, если ссылка пропущена через сокращатель"""
    _shorteners = frozenset({
        "bit.ly", "tinyurl.com", "goo.gl", "clck.ru", "t.co", "is.gd", "vk.cc", "t.me"
    })
    
    @staticmethod
    async def check(req: models.ScanRequest) -> str | None:
        parsed_url = urlparse(req.url)
        hostname = parsed_url.hostname
        if hostname and hostname in URLShortenerCheck._shorteners:
            return strings.URL_SHORTENER_WARNING

class TyposquattingCheck(CheckProto):
    """Проверка на подделку известных брендов (например: yandex-login.ru, mial.ru)"""
    _target_brands = {"yandex", "ozon", "mail", "rutube", "sber", "vk", "tinkoff", "gosuslugi"}
    
    @staticmethod
    async def check(req: models.ScanRequest) -> str | None:
        parsed_url = urlparse(req.url)
        hostname = parsed_url.hostname
        if not hostname: return
        if hostname in KnownTrusted._trusted_domains or any(hostname.endswith("." + td) for td in KnownTrusted._trusted_domains):
            return
        # Поиск вхождения названий брендов в чужой домен
        hostname_lower = hostname.lower()
        for brand in TyposquattingCheck._target_brands:
            if brand in hostname_lower:
                raise CheckFailed(virus_type=strings.TYPOSQUATTING, virus_consequences=strings.TYPOSQUATTING_DESC)

class DeepContentCheck(CheckProto):
    """Активная проверка: скачивание страницы и анализ"""
    
    @staticmethod
    async def check(req: models.ScanRequest) -> str | None:
        if not req.settings.allow_get_links_contents or not req.settings.link_deep_check:
            return None
        if _session is None:
            logger.error("Not found session object")
            return
        try:
            # GET запрос с таймаутом, чтобы не сервер не завис
            async with _session.get(req.url, timeout=4) as response:
                content = await response.text(errors='ignore')
                
                # Простые эвристики поиска вредоносного JS или редиректов
                content_lower = content.lower()
                if "<script>eval(" in content_lower or "unescape(" in content_lower:
                    raise CheckFailed(virus_type=strings.MALICIOUS_CODE, virus_consequences=strings.MALICIOUS_CODE_DESC)
        except CheckFailed:
            raise
        except Exception as e:
            logger.debug(f"Deep check failed for {req.url}: {e}")
            return strings.DEEP_CHECK_FAILED_WARNING

enabled_checks: tuple[CheckProto, ...] = (
    HTTPCheck(),
    DomainZoneInfo(),
    KnownTrusted(),
    IPDomainCheck(),
    SuspiciousTLDCheck(),
    URLShortenerCheck(),
    TyposquattingCheck(),
    DeepContentCheck()
)

async def check(req: models.ScanRequest) -> models.ScanResponse:
    global _session
    if _session is None:
        _session = aiohttp.ClientSession()
    try:
        comments = await asyncio.gather(
            *(_chk.check(req) for _chk in enabled_checks),
            return_exceptions=req.settings.link_deep_check # set to False to handle first exception (faster, but less additional info)
        )
        _add = ""
        result = True
        virus_type = None
        virus_consequences = None
        for comment in comments:
            if isinstance(comment, BaseException):
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
