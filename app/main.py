from fastapi import FastAPI
from fastapi.responses import ORJSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from .models import HealthCheck, ScanRequest, ScanResponse

from . import strings

app = FastAPI(
    title="LinkProtect Server",
    version="0.1",
    description="Сервер программного комплекса LinkProtect (Zащитник Ссылок), который обеспечивает проверку безопасности ссылок для клиента при помощи API",
    default_response_class=ORJSONResponse,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def read_root():
    """Welcome message"""
    return HTMLResponse('Это API сервер LinkProtect. Вы можете просмотреть документацию Swagger <a href="docs">здесь</a>')

@app.get("/health")
async def health() -> HealthCheck:
    """Perform a health check"""
    return HealthCheck(status="OK")

@app.post("/scan")
async def scan(req: ScanRequest) -> ScanResponse:
    if req.url.startswith("http://"):
        return ScanResponse(
            result=False,
            additional_info="",
            virus_type=strings.UNSAFE_HTTP,
            virus_consequences=strings.UNSAFE_HTTP_DESC)
    return ScanResponse(result=True, additional_info=strings.SAFE)
