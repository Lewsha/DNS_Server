# DNS_Server
Кэширующий DNS-сервер.
Реализован парсинг пакетов DNS и ручная сборка ответного пакета.

Во время работы доступны следующие команды:
exit - завершить работу сервера
cache - вывести таблицу с информацией о кеше
forwarder_on - включить запросы к форвардеру
forwarder_off - выключить запросы к форвардеру

Запуск:
python DnsServer.py forwarder_address

ВНИМАНИЕ! Сервер сохраняет кэш только в случае завершения работы через команду exit.
