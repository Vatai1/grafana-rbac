# grafana-rbac

Форк Grafana OSS v13.2.4 с настраиваемым RBAC, без рекламы Grafana Enterprise/Cloud, по умолчанию на русском.

## Что добавлено

| Возможность | Где |
|---|---|
| Права на каждый источник данных (Query / Edit / Admin) для пользователей, команд и ролей; UI: вкладка «Разрешения» у источника | `pkg/services/accesscontrol/ossaccesscontrol/datasource.go`, `pkg/services/datasources/guardian/` |
| Кастомные роли: CRUD и назначение пользователям/командам, защита от выдачи прав, которых нет у самого администратора | `pkg/services/accesscontrol/customroles/`, API `/api/access-control/roles`, `/users/:id/roles`, `/teams/:id/roles` |
| UI ролей: «Администрирование → Пользователи и доступ → Роли» (создание, разрешения, назначение); выбор ролей в списке пользователей, на странице команды и сервисного аккаунта | `public/app/features/custom-roles/`, `RolePicker` (включается фичей `accesscontrol` в `licensing/oss.go`) |
| Роли из YAML (формат Grafana Enterprise + `orgName`, `users`) | `deploy/provisioning/access-control/*.yaml`, `POST /api/admin/provisioning/access-control/reload` |
| Без плашек Enterprise/Cloud | `isOpenSourceBuildOrUnlicenced()`, футер, каталог плагинов, env в `docker-compose.yml` |

Все изменения относительно upstream — второй коммит репозитория (`git diff HEAD~1`).

## Запуск (dev)

```sh
cd deploy
export GF_ADMIN_PASSWORD=...        # пароль admin при первом старте
./build.sh dev                      # бэкенд + фронтенд + docker compose (Grafana :3001, PostgreSQL)
./setup.sh                          # воркспейсы, пользователи и права из access.json, перезагрузка YAML-ролей
```

## Сборка и публикация x86-образа

```sh
docker login
./deploy/build.sh push              # vatai12/grafana-rbac:<версия>-<коммит> и :latest
```

В prod-окружении задайте те же переменные, что в `docker-compose.yml`: `GF_DATABASE_*`, `GF_USERS_DEFAULT_LANGUAGE=ru-RU`,
`GF_CLOUD_MIGRATION_ENABLED=false`, `GF_NEWS_NEWS_FEED_ENABLED=false`.

## Проверки

```sh
cd deploy && ./setup.sh > e2e/pw.txt   # пароли тестовых пользователей (файл в .gitignore)
bash e2e/ds_e2e.sh && bash e2e/roles_e2e.sh
go test ./pkg/services/datasources/guardian/ ./pkg/services/accesscontrol/customroles/
```

Изменения прав применяются с задержкой до 30–60 с из-за штатных кэшей Grafana (`GF_AUTHORIZATION_CACHE_TTL`, кэш прав команд).
