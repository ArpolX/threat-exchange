# Информационный сервис об угрозах
## Запуск

```sh
git clone https://github.com/ArpolX/threat-exchange
cd threat-exchange
cp .env.example .env
```


Затем запустите сервис:

```sh
docker compose up --build
```

## API
API доступен на `localhost:8080`, PostgreSQL - на `localhost:5432`. Порты задаются через `PORT_API` и `PORT_DB`, ключи - через `API_KEYS` в `.env`. Миграции применяются автоматически, данные сохраняются между запусками.

## Как проверить API через Postman

Во всех запросах добавьте в **Headers** заголовок `X-API-Key`: укажите один ключ
из `API_KEYS` в `.env` и `Content-Type`. 

1. **Создать запись:** `POST http://localhost:8080/info`.

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "name": "Test",
  "description": "Тестовая, куда без неё",
  "severity": "high",
  "category": "trojan",
  "source": "Postman",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

Ожидается `201 Created`: сохранённая запись с датами `created_at` и `updated_at`.
Повторная отправка того же запроса вернёт `409 Conflict`.

2. **Прочитать запись:** `GET http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e`.

Тело запроса не нужно. Ожидается `200 OK` и созданная запись.

3. **Обновить запись:** `PUT http://localhost:8080/info/d41d8cd98f00b204e9800998ecf8427e`.

```json
{
  "name": "Updated"
}
```

Ожидается `200 OK`. Повторите GET: имя должно измениться, описание и источник -
стать пустыми, опасность и категория - `unknown`, SHA-256 - `null`.

Для проверки ошибок уберите ключ (`401`), передайте пустое имя или некорректный
хеш (`400`), запросите отсутствующий корректный MD5 (`404`). По умолчанию лимит -
60 запросов за минутное окно на ключ. При превышении приходит `429`.

## Что внутри

```text
internal/controller/ - обработка ручек
internal/service/ - логика
internal/repository/ - бд
internal/http/handlers/ - маршруты
internal/http/middleware/ - API key, лимит запросов, валидация и логи
internal/infrastructure/ - подключение PostgreSQL, миграции, логгер
internal/domain/ - внутренние модели
test/ - тесты
```

MD5 уникален, хеши сохраняются в нижнем регистре. Валидация проверяет поля, длины и допустимые
значения; подробные правила описаны в [OpenAPI](api/openapi.yaml).

Папка `api` описывает HTTP-контракт:

- `openapi.yaml` - ручки, поля, ограничения и ответы;
- `dto_gen.go` - структуры запросов и ответов, сгенерированные из YAML;
- `spec.go` - встраивает спецификацию в бинарник, загружает её для валидации и содержит команду генерации;

Тест спецификации находится в `test/unit/api`. 
