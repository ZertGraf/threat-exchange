# Threat Exchange Service

REST-сервис для обмена информацией об угрозах по MD5-хешу. Реализует спецификацию
из `technical_specification.md`: Go, PostgreSQL, код сгенерирован из OpenAPI.

## Запуск

Нужен Docker с Docker Compose.

```bash
docker compose up --build -d
curl http://localhost:8080/readyz
```

API слушает `127.0.0.1:8080`, порт PostgreSQL наружу не публикуется. Данные хранятся
в именованном томе и переживают `docker compose down`. Настройки Compose можно положить
в `.env` (шаблон — `.env.example`).

```bash
curl -i -H "Content-Type: application/json" --data-binary @examples/create-threat.json http://localhost:8080/info
curl -i http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
curl -i -X PUT -H "Content-Type: application/json" --data-binary @examples/update-threat.json http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e
```

На Windows в PowerShell вместо `curl` нужен `curl.exe`.

Без Docker: Go 1.26+, переменная `DATABASE_URL` с адресом PostgreSQL, затем
`go run ./cmd/server`. Таблица создаётся при старте.

## API

Контракт — `api/openapi.yaml`, сервис отдаёт его по `GET /openapi.json`.

| Метод | Путь | Успех | Ошибки |
| --- | --- | --- | --- |
| POST | `/info` | `201` + запись + `Location` | `400`, `409` |
| GET | `/info/{md5}` | `200` + запись | `400`, `404` |
| PUT | `/info/{md5}` | `200` + обновлённая запись | `400`, `404` |

Ошибки возвращаются как `{"message": "...", "details": "..."}`. В `details` указано
поле и нарушенное правило, например
`body field severity: value is not one of the allowed values [...]`. Присланные значения,
тексты ошибок БД и секреты в ответы и логи не попадают.

Кроме этого, сервис может ответить `401` (нет ключа), `405` (метод не поддерживается,
есть заголовок `Allow`), `408`, `413` (тело больше 64 КБ), `415` (не `application/json`),
`429` (rate limit, есть `Retry-After`) и `503` (БД не уложилась в таймаут).

Служебные эндпоинты: `/healthz` (процесс жив), `/readyz` (доступна БД).

## Модель угрозы

| Поле | Правила | По умолчанию |
| --- | --- | --- |
| `md5` | 32 hex-символа, регистр не важен, в ответе — нижний; в PUT берётся только из пути | обязательно |
| `name` | 1–255 символов, не пустое после обрезки пробелов | обязательно |
| `description` | до 4096 символов | `""` |
| `severity` | `unknown`, `low`, `medium`, `high`, `critical` | `unknown` |
| `type` | `unknown`, `virus`, `worm`, `trojan`, `ransomware`, `spyware`, `adware`, `rootkit`, `other` | `unknown` |
| `tags` | до 20 уникальных меток `[a-z0-9][a-z0-9._-]{0,31}` | `[]` |
| `created_at`, `updated_at` | ставит сервер, UTC RFC 3339 | — |

Для создания достаточно `md5` и `name`, так что исходный минимальный запрос из
задания по-прежнему работает. Неизвестные поля, `null` и лишние JSON-значения после
объекта отклоняются. PUT заменяет запись целиком: если поле не передано, оно
сбрасывается в значение по умолчанию. Несуществующую запись PUT не создаёт.

## Конфигурация и защита

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `DATABASE_URL` / `DATABASE_URL_FILE` | — | строка подключения к PostgreSQL |
| `HTTP_ADDR` | `127.0.0.1:8080` | адрес прослушивания |
| `API_KEY` / `API_KEY_FILE` | выключено | ключ для заголовка `X-API-Key`, минимум 32 печатных ASCII-символа |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | выключено | PEM-сертификат и ключ, включают HTTPS (TLS 1.2+, HSTS) |
| `RATE_LIMIT_RPS`, `RATE_LIMIT_BURST` | `100`, `200` | token bucket на весь процесс |

- Ключ сравнивается за постоянное время. Запросы с неверным ключом расходуют отдельный
  bucket и не могут исчерпать квоту авторизованных клиентов.
- Rate limit общий на процесс, а не на IP: заголовкам вроде `X-Forwarded-For` сервис
  не доверяет. Лимиты по клиентам нужно настраивать на reverse proxy.
- Каждый запрос пишется в JSON-лог: метод, путь, статус, длительность. Заголовки и тела
  не логируются.
- Ограничены размер заголовков и тела, таймауты чтения, записи и обработки (5 секунд
  на запрос к БД). Паники перехватываются. Остановка graceful: активные запросы
  дорабатывают до 20 секунд.
- Образ: статический бинарник на distroless, UID 65532, read-only FS, без capabilities.

HTTPS: положить `certs/server.crt` и `certs/server.key`, затем
`docker compose -f compose.yaml -f compose.tls.yaml up --build -d`.
Ключ из файла как Docker secret: `secrets/api-key`, в `.env` указать
`API_KEY_FILE=./secrets/api-key`, затем запустить с `-f compose.secrets.yaml`.

## Тесты

Полный прогон в контейнерах на временной PostgreSQL (основную БД не трогает):

```bash
docker compose -f compose.test.yaml up --build --abort-on-container-exit --exit-code-from tests
docker compose -f compose.test.yaml down
```

Тесты запускаются с `-race`. Покрытие внутренних пакетов — около 93%.
Каждый интеграционный тест работает в своей случайной схеме.

Что проверяется:
- валидация и соответствие ответов OpenAPI-контракту;
- маппинг ошибок;
- аутентификация и rate limit;
- семантика PUT;
- сохранность данных после перезапуска;
- 24 одновременных создания одного MD5 через два инстанса: ровно один `201`, остальные `409`.

Без `TEST_DATABASE_URL` команда `go test ./...` запускает только unit-тесты.

Линтер и генерация:

```bash
docker run --rm -v "$PWD:/app:ro" -w /app golangci/golangci-lint:v2.15.0 golangci-lint run
go generate ./api
```

Модели и роутер генерирует [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen),
запросы валидирует kin-openapi через
[nethttp-middleware](https://github.com/oapi-codegen/nethttp-middleware).
Сгенерированный `api/api.gen.go` лежит в репозитории.

## Структура

```text
api/               OpenAPI-контракт, конфиг генератора, сгенерированный код
cmd/server/        запуск, HTTP/TLS, graceful shutdown
internal/config/   чтение и проверка переменных окружения
internal/httpapi/  обработчики, валидация, защита, тесты
internal/store/    репозиторий PostgreSQL и схема
compose*.yaml      деплой, тесты, оверрайды TLS и секретов
```

Уникальность MD5 обеспечивает первичный ключ, поэтому гонок нет и между инстансами.
CHECK-ограничения в БД дублируют проверки хеша, enum-полей и длин. Схема
применяется при старте под advisory lock. Это начальный bootstrap, а не система
миграций: несовместимые изменения схемы потребуют миграций.
