# Форк Grafana v13.2.4: настраиваемые роли и права на источники данных

Цель: в OSS-сборке администратор организации может (а) ограничивать доступ к каждому источнику данных
по пользователям/командам, (б) создавать кастомные роли из произвольных permissions и назначать их
пользователям и командам, (в) описывать всё это файлами provisioning. Upstream: tag v13.2.4.

Опорные точки в коде:
- `pkg/services/accesscontrol/ossaccesscontrol/datasource.go` — заглушка: Get/Set*Permission возвращают nil.
- `pkg/services/accesscontrol/ossaccesscontrol/folder.go` — образец полноценного resourcepermissions.Service.
- `pkg/services/datasources/service/datasource.go:431` — при создании DS Viewer/Editor получают Query.
- `pkg/services/accesscontrol/acimpl/service.go` — движок уже читает права пользователей/команд из БД.
- `pkg/services/accesscontrol/database/` — таблицы role/permission/user_role/team_role.

## Step 1. Create fork build

Инициализировать git-репозиторий форка (ветка `cstm/main` от v13.2.4), добавить сборку Docker-образа
`grafana-cstm:13.2.4-rbac` из исходников и переключить `docker-compose.yml` на этот образ.
Критерии: `make build` проходит; образ стартует, `/api/health` отдаёт 13.2.4; `setup.sh` работает как раньше.

## Step 2. Implement datasource permissions

Заменить OSS-заглушку DatasourcePermissionsService на resourcepermissions.Service по образцу folder.go:
уровни Query/Edit/Admin, назначение пользователям, командам и базовым ролям, HTTP API
`/api/access-control/datasources/:uid` (GET/POST). Поведение по умолчанию сохраняется: новые DS дают Viewer/Editor Query.
Критерии: после снятия Query с Viewer и выдачи его пользователю X запрос `/api/ds/query` от Viewer Y → 403, от X → 200;
Go-тесты сервиса проходят. Out of scope: LBAC / фильтрация строк внутри источника.

## Step 3. Implement custom roles API

Добавить org-scoped CRUD кастомных ролей `/api/access-control/roles` (uid, name, permissions[action, scope])
поверх существующих таблиц role/permission и назначение ролей `/api/access-control/{users,teams}/:id/roles`
с инвалидацией кэша прав. Изменение ролей — только для org Admin / Grafana Admin (action `roles:write`).
Критерии: роль с `dashboards:read` на одну папку, выданная Viewer без прав на папку, открывает её; снятие роли закрывает;
Viewer не может создать роль (403). Out of scope: k8s IAM API (iam.grafana.app), Zanzana.

## Step 4. Add roles provisioning

Добавить загрузку `provisioning/access-control/*.yaml` в формате, совместимом с Grafana Enterprise
(roles + teams/users assignments), при старте сервера.
Критерии: роль из YAML появляется после рестарта; повторный старт идемпотентен; невалидный файл даёт понятную ошибку в логе.

## Step 5. Add RBAC admin UI

Включить во фронтенде вкладку Permissions у источника данных и страницу управления кастомными ролями
(список, создание, назначение пользователю/команде), снять license-гейты для этих экранов.
Критерии: админ без API выполняет сценарии шагов 2 и 3 через UI; Viewer не видит этих страниц.

## Step 6. Change setup.sh to manage datasources and roles

Расширить `access.json` и `setup.sh`: секции `datasources` (права по пользователям) и `roles`
(кастомные роли и их назначение) через новые API.
Критерии: повторный запуск идемпотентен; удаление записи из access.json отзывает доступ.

## Step 7. Security audit of new endpoints

Проверить новые эндпоинты шагов 2–4 на эскалацию привилегий (Editor выдаёт себе роль, межорг-доступ по uid).
