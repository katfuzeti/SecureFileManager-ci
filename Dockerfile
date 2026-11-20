# syntax=docker/dockerfile:1
# Многоступенчатая сборка: SDK (~800 МБ) остаётся в стадии build,
# в итоговый образ попадает только среда выполнения и опубликованная программа.

# ---------- стадия 1: сборка ----------
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
# Сначала только .csproj: слой с restore кэшируется, пока не изменились зависимости.
COPY SecureFileManager.csproj ./
RUN dotnet restore
COPY src/ ./src/
RUN dotnet publish -c Release --no-restore -o /app

# ---------- стадия 2: запуск ----------
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS final
ENV SECUREFM_HOME=/data \
    DOTNET_CLI_TELEMETRY_OPTOUT=1
# В образах .NET 8 есть непривилегированный пользователь app, его UID в $APP_UID.
RUN mkdir /data && chown "$APP_UID:$APP_UID" /data && chmod 700 /data
WORKDIR /app
COPY --from=build /app ./
USER $APP_UID
VOLUME ["/data"]
ENTRYPOINT ["dotnet", "securefm.dll"]
