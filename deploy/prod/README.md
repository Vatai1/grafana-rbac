# Prod: один сервер + Docker Compose

Grafana (`vatai12/grafana-rbac`, linux/amd64) + PostgreSQL 16 + Caddy (HTTPS от Let's Encrypt) + ежедневный бэкап БД.
Наружу открыты только 80/443 (Caddy); Grafana и PostgreSQL доступны лишь внутри compose-сети.

## Установка

Нужно: Linux-сервер с Docker и Compose v2, DNS-запись `DOMAIN → IP сервера`, открытые порты 80 и 443.

```sh
git clone https://github.com/Vatai1/grafana-rbac.git && cd grafana-rbac/deploy/prod
cp .env.example .env && chmod 600 .env
# заполните DOMAIN, GRAFANA_TAG, и пароли:
sed -i "s|^GF_ADMIN_PASSWORD=.*|GF_ADMIN_PASSWORD=$(openssl rand -base64 24)|; s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -base64 24)|" .env
docker compose up -d
docker compose logs -f caddy grafana     # дождитесь выпуска сертификата и старта Grafana
```

Grafana: `https://<DOMAIN>`, вход `admin` / `GF_ADMIN_PASSWORD` из `.env` (используется только при первом старте;
дальше пароль меняется в профиле).

## Доступ: воркспейсы, пользователи, права

```sh
cd ..                                    # deploy/
vi access.json                           # воркспейсы, пользователи, папки, источники данных
vi provisioning/access-control/*.yaml    # кастомные роли и их назначение
set -a; . prod/.env; set +a
GRAFANA_URL=https://$DOMAIN ./setup.sh > users-passwords.txt   # пароли новых пользователей; сохраните и удалите файл
```

`setup.sh` идемпотентен — запускайте после каждой правки. Роли и права можно менять и в UI
(«Администрирование → Пользователи и доступ»).

## Обновление

```sh
sed -i 's|^GRAFANA_TAG=.*|GRAFANA_TAG=<новый тег>|' .env
docker compose pull grafana && docker compose up -d grafana
```

Перед обновлением сделайте ручной бэкап (ниже). Миграции БД Grafana выполняет сама при старте.

## Бэкапы

Контейнер `backup` раз в сутки пишет `backups/grafana-<дата>.sql.gz` (права 600) и удаляет файлы старше `BACKUP_KEEP_DAYS`.
Копируйте `backups/` за пределы сервера.

```sh
# ручной бэкап
docker compose exec -T backup sh -c 'umask 077; set -o pipefail; pg_dump -h postgres -U grafana grafana | gzip > /backups/manual-$(date +%Y%m%d-%H%M%S).sql.gz'

# восстановление (Grafana останавливается на время)
docker compose stop grafana
docker compose exec -T postgres sh -c 'dropdb -U grafana grafana && createdb -U grafana grafana'
gunzip -c backups/<файл>.sql.gz | docker compose exec -T postgres psql -q -U grafana -d grafana
docker compose start grafana
```

## Безопасность

- `.env` и `backups/` содержат секреты — права 600, в git не попадают.
- Остаточные риски и рекомендации — [../SECURITY.md](../SECURITY.md).
