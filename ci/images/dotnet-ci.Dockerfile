# Образ для стадии test: .NET 8 SDK + python3 (нужен tests/db_check.py и make_evil_zips.py).
FROM mcr.microsoft.com/dotnet/sdk:8.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
# Раннер всё равно запускает контейнер с UID текущего пользователя,
# но и сам образ не должен работать от root.
USER 1000:1000
