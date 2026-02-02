from pydantic import BaseModel, Field
from typing import Optional

class HealthCheck(BaseModel):
    status: str = "OK"

class UserSettings(BaseModel):
    allow_get_links_contents: bool = Field(..., description="Разрешил ли пользователь получать содержимое ссылки для проверок")
    link_deep_check: bool = Field(..., description="Проводить ли более длительные, но точные проверки")

class ScanRequest(BaseModel):
    url: str = Field(..., examples=["https://yandex.ru", "http://test.com"], description="Ссылка для проверки")
    settings: UserSettings

class ScanResponse(BaseModel):
    result: bool = Field(..., description="Безопасна ли ссылка")
    additional_info: str = Field(..., description="Дополнительная информация о ссылке")
    virus_type: Optional[str] = Field(None, description="Вид опасности, если обнаружена")
    virus_consequences: Optional[str] = Field(None, description="Опасные последствия перехода по вредоносной ссылке (если таковая)")
