# build
FROM python:3.12-slim AS builder

RUN pip install --upgrade pip
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix="/install" -r requirements.txt

# final
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local

COPY ./app ./app
COPY ./hypercorn_release.py .

CMD ["hypercorn", "-c", "file:hypercorn_release.py", "app.main:app"]
