# Управление альфа-версией

Подключение к серверу:

```bash
ssh zelyonka-fin
sudo smartdnsctl --version
sudo smartdnsctl status
```

## Добавить знакомого

```bash
sudo smartdnsctl create "Имя знакомого"
sudo smartdnsctl sync --cert
sudo smartdnsctl status
```

Первая команда выведет `id`, имя DoT, адрес DoH и личную ссылку активации. Сохрани ссылку у себя: сервер хранит только её хеш. Ссылка не восстанавливается из базы. При необходимости создать новую используй `reset-link`.

Перед выдачей адреса Android проверь `certificate_ready: true`. Выпуск сертификата обычно занимает некоторое время; при задержке DNS повторная попытка выполняется автоматически. При ограничении выпуска сертификатов новые имена DoT останутся неготовыми до устранения причины, уже выданные сертификаты продолжают работать. Новый пользователь может подключаться по DoH на основном имени после применения профиля.

Получателю нужно открыть свою ссылку из нужной сети, нажать активацию, затем настроить DNS. Не выдавай всем профиль владельца. Максимум — 30 активных профилей, включая владельца.

## Отключить пользователя или сменить ссылку

```bash
sudo smartdnsctl list
sudo smartdnsctl revoke uXXXXXXXXXXXX
sudo smartdnsctl reset-link uXXXXXXXXXXXX
```

Вместо `uXXXXXXXXXXXX` подставь ID пользователя. `revoke` отключает профиль и удаляет его сетевые допуски. `reset-link` действует для включённого пользователя, заменяет секрет и также очищает его сети. Пользователь должен снова активировать свою сеть.

## Исключения фильтрации

```bash
sudo smartdnsctl allow add example.com
sudo smartdnsctl allow remove example.com
sudo smartdnsctl allow list
sudo smartdnsctl allow add example.com --user uXXXXXXXXXXXX
```

Первые команды действуют глобально; `--user` задаёт исключение для идентифицированного профиля DoH/DoT. На обычном DNS роутера устройства определяются по общему внешнему IP, поэтому для него используй глобальные исключения. Исключения рекламы не отменяют правила направления сервисов через Финляндию.

## Сетевые допуски вручную

```bash
sudo smartdnsctl network list
sudo smartdnsctl network add --user uXXXXXXXXXXXX --ip ВНЕШНИЙ_IPV4
sudo smartdnsctl network remove --user uXXXXXXXXXXXX --ip ВНЕШНИЙ_IPV4
```

При добавлении четвёртой сети самая старая заменяется. Вручную разрешаются только публичные IPv4. В обычной работе пользователи активируют сети через личные ссылки.

## Состояние и диагностика

```bash
sudo systemctl status smartdns-portal.service smartdns-sync.timer smartdns-cert.timer
sudo journalctl -u smartdns-sync.service -n 30 --no-pager
sudo docker stats --no-stream zelyonka-smartdns
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo nginx -t
```

Если таймер синхронизации остановлен, новые активации не применяются и своевременный отзыв ACL прокси не выполняется. Восстановить:

```bash
sudo systemctl start smartdns-sync.timer
sudo smartdnsctl sync
```

Проверка продления сертификата:

```bash
sudo certbot renew --dry-run --no-random-sleep-on-renew   --config-dir /opt/zelyonka-smartdns/acme/config   --work-dir /opt/zelyonka-smartdns/acme/work   --logs-dir /opt/zelyonka-smartdns/acme/logs
```

Панель AdGuard Home доступна только через SSH-туннель:

```bash
ssh -F ~/.ssh/config -L 3005:127.0.0.1:3005 zelyonka-fin
```

Открыть `http://127.0.0.1:3005` на своём компьютере. Отдельной веб-аутентификации здесь нет: доступ ограничен loopback и SSH. Пользователей и правила веди через `smartdnsctl`, иначе синхронизация может перезаписать ручные изменения.

## Файлы на VPS

Основной каталог — `/opt/zelyonka-smartdns`. Исходники — `app/`, состояние — `state/users.sqlite3`, конфигурация нового AdGuard — `conf/`, сертификаты — `certs/`, ACME — `acme/`. Права ограничивают доступ к секретам и состоянию. Резервная копия исходной конфигурации находится по пути из файла `backup-location`.

Для резервного копирования данных останови портал и синхронизацию на время согласованной копии SQLite либо используй SQLite backup API. Секреты активации в базе отсутствуют; личные ссылки сохраняются получателями отдельно.

## Откат первого развёртывания

```bash
sudo /usr/local/sbin/smartdns-rollback
```

Команда останавливает новый сервис, закрывает добавленные порты и восстанавливает HAProxy из снимка первого развёртывания. Данные и резервная копия остаются на сервере. Если HAProxy менялся после этого снимка, предварительно сравни текущую конфигурацию с резервной: откат восстанавливает весь файл HAProxy.

## Границы альфы

VPS с 1 CPU / 2 ГБ разделяется с VPN. Проверка 30 профилей подтверждает короткую DNS-нагрузку и соединения через прокси, но не гарантирует пропускную способность 30 одновременных видеопотоков. Claude может запрашивать Cloudflare-проверку; доступ также зависит от аккаунта, репутации IP и сети клиента. Обновление списков доменов производится владельцем через `domains.txt` и `sudo smartdnsctl sync`.
