import socket
import random
import threading
import sys
import pickle  # Сериализация для файла кэша
import time
from DNSPacketParser import DNSPacket, DnsQuestion, parse_address


TIMEOUT = 2  # Устанавливаем постоянный таймаут в 2 секунды (просто потому что мы можем!)


class DnsCache:
    """Класс, в котором будет храниться кэш нашего сервака. Весь кэш, по сути, просто лист записей"""
    def __init__(self):
        self.cache = []

    def clear_cache(self):
        """Метод, очищающий кэш от устаревших записей"""
        to_remove = []
        """Проходим по кэшу, смотрим, если запись устарела, заносим ее в список на удаление"""
        for cache_item in self.cache:
            add_time, resource = cache_item
            if resource.r_ttl - (time.time() - add_time) < 0:
                to_remove.append(cache_item)
        """А потом удаляем нафиг"""
        for cache_item in to_remove:
            self.cache.remove(cache_item)

    def get_resources(self, question):
        """Метод, возвращающий данные из кэша
        (если они у нас, конечно, имеются)"""
        self.clear_cache()
        result = []
        for _, resource in self.cache:
            """question является объектом DnsQuestion"""
            if question.is_true_resource(resource):
                result.append(resource)
        return result

    def put_resource(self, resource):
        """Метод, добавляющий данные в кэш"""
        self.clear_cache()
        if resource not in map(lambda c: c[1], self.cache):
            self.cache.append((time.time(), resource))

    def get_status(self):
        """Метод, выводящий на экран данные обо всех имеющихся записях в кэше нашего сервака"""
        self.clear_cache()
        return '\n'.join(['Time: {:5d}s Resource: {:80}'.format(
            int(resource.r_ttl - (time.time() - add_time)),
            resource.to_string()
        ) for add_time, resource in self.cache])


class DnsServer(threading.Thread):
    """Собственно, наш сервак"""

    def __init__(self, forwarder):
        super().__init__(name='Server')  # Создаем поток нашего сервака
        self.forwarder = socket.gethostbyname(forwarder)  # Получаем адрес сервака по имени
        # (если дали на вход ip, то так и останется ip
        self.cache = DnsCache()  # Создаем серваку кэш
        self.server_runnable = False  # Флаг запуска
        self.serve_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Фигачим сокет по IPv4 и UDP
        self.serve_socket.settimeout(TIMEOUT)  # Задаем сокету наш таймаут
        self.serve_socket.bind(('', 53))  # Привязываем его к 53 порту
        self.forwarder_on = True  # По умолчанию включаем возможность получения инфы от сервака
        self.check_recursion()  # Проверяем хитрожопость/криворукость (нужное подчеркнуть) пользователя

    def check_recursion(self):
        """Проверка хитрожопости или криворукости пользователя.
        Видите ли, пользователь может указать в качестве сервера наш сервер.
        А как мы спросим у себя, если мы не знаем?"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Создаем udp сокет
        sock.settimeout(4)  # устанавливаем ему таймаут
        check_quest = DnsQuestion('recursion.check.packet.', 1, 1)  # создаем запрос dns
        check_pack = DNSPacket(
            0x6969, 0x0000, [check_quest],
            [], [], []).to_bytes()  # ну и создаем dns пакет, закладывая в него наш запрос
        sock.sendto(check_pack, (self.forwarder, 53))  # Отправляем наш пакет серверу, у которого спрашиваем инфу
        try:
            response = self.serve_socket.recv(1024)  # получаем какой-то ответ
            packet = DNSPacket.from_bytes(response)  # распаковываем его в читабельный вид
            """Если нам вернулся тот же самый QUESTION, что мы отправили, значит, 
            пользователь указал сам себя в качестве сервера для запросов
            Тогда мы выкидываем ошибку"""
            if packet.question == [check_quest]:
                raise Exception('В качестве форвардера указан сам сервер')
        except socket.error:
            pass
        finally:
            sock.close()

    def run(self):
        """run является методом класса threading.Trhread. Этот метод, по сути,
        вызывается после вызова метода start (как я понял,
        start производит грамотный запуск run в отдельном потоке)
        Работа метода составляет активность потока.
        И мы можем переопределять в своих классах (что здесь, собственно, и сделано)"""
        self.server_runnable = True  # Устанавливаем флаг, что мы таки работаем
        """А пока работаем, пробуем получать данные"""
        while self.server_runnable:
            try:
                data, addr = self.serve_socket.recvfrom(1024)
            except socket.error:
                continue
            print('Connection from {}'.format(addr))  # Если с кем-то законнектились, то пишем, с кем
            threading.Thread(
                target=self.serve_client, args=(addr, data)).start()  # После чего выделяем работу с ним
            # в отдельный поток и дальше клиент работает уже с serve_client

    def stop_server(self):
        """Ну, тут все просто, тормозим сервак"""
        self.serve_socket.close()

    def get_from_forwarder(self, question):
        """Метод получения данных от сервера"""
        """Если нам запрещено получать инфу от сервера, то возвращаем шиш"""
        if not self.forwarder_on:
            return []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # создаем udp сокет
        sock.settimeout(TIMEOUT)  # устанавливаем наш таймаут
        request = DNSPacket(
            random.randint(0, 0xffff), 0x0100, [question], [], [], []
        )  # создаем запрос, запихивая в него запрос пользователя
        sock.sendto(request.to_bytes(), (self.forwarder, 53))  # отправляем запрос на 53 порт сервака
        data = None
        try:
            data, _ = sock.recvfrom(1024)  # пробуем получить какую-нибудь инфу
        except socket.error:
            pass
        if not data:
            return []  # если ничего не получили, то возвращаем шиш
        response = DNSPacket.from_bytes(data)  # распаковываем полученные данные
        for answer in response.answer:
            self.cache.put_resource(answer)  # заносим новые данные в кэш
        for authority in response.authority:
            self.cache.put_resource(authority)  # заносим новые данные в кэш
        for additional in response.additional:
            self.cache.put_resource(additional)  # заносим новые данные в кэш
        return self.get_from_cache(question)  # А ПОТОМ ТАКИЕ БЕРЕМ И ИЗ КЭША ВОЗВРАЩАЕМ!

    def get_from_cache(self, question):
        """Метод получения данных из кэша.
        На заметочку: здесь метод всегда вроде как возвращает инфу,
        но на самом деле метод get_resources может вернуть нам пустой list.
        Тогда в методе serve_client if отработает верно и
        перескочит на получение данных от сервера."""
        """5 - type of CNAME (каноническое имя)
        Сначала мы пробуем достать из кэша какие-нибудь записи типа CNAME, 
        из них вычленить каноническое имя, а уже по нему получить интересующие нас данные"""
        c_name_question = DnsQuestion(
            question.q_name, 5, question.q_class)  # Создаем CNAME QUESTION
        c_name_resources = self.cache.get_resources(c_name_question)  # получаем данные из кэша по этому вопросу
        for c_name_resource in c_name_resources:
            canonical_name = \
                parse_address(c_name_resource.r_data).decode()  # Тут мы парсим каноническое имя из записи типа CNAME
            result = self.get_from_cache(DnsQuestion(
                canonical_name, question.q_type, question.q_class))  # По этому имени получаем нормальные данные
            if result:
                result.append(c_name_resource)
                return result  # Ну и возвращаем
        return self.cache.get_resources(question)  # обычно же мы просто возвращаем что-то из кэша

    def serve_client(self, addr, raw_packet):
        """Метод работы с клиентами. Каждого клиента метод run
        выделяет в отдельный поток и перенаправляет этому методу"""
        try:
            packet = DNSPacket.from_bytes(raw_packet)  # Распаковываем запрос
            response = DNSPacket(
                packet.packet_id, 0x8000,
                packet.question, [], [], []
            )  # Формируем ответ
            """Обрабатываем каждый запрос клиента"""
            for question in packet.question:
                resources = self.get_from_cache(question)  # Сначала пробуем получить ответ из кэша
                """Если получили ответ из кэша"""
                if resources:
                    print('In cahce: {}'.format(question.to_string()))  # Принтуем, что у нас есть инфа в кэше
                    response.answer.extend(resources)  # Пакуем в наш ответ информацию из кэша
                else:
                    """Если таки нет в кэше, придется спрашивать"""
                    print('Ask to forwarder: {}'
                          .format(question.to_string()))  # Принтуем, что отправляем запрос
                    resources = self.get_from_forwarder(question)  # Делаем запрос серваку, получаем данные
                    response.answer.extend(resources)  # Пакуем эти данные в ответ
            raw_response = response.to_bytes()  # Фигачим наш ответ в байты
            self.serve_socket.sendto(raw_response, addr)  # И отправляем обратно
        except Exception as ex:
            print(ex)


if __name__ == '__main__':
    forwarder_host = None  # Сервер, с которого будем брать инфу
    server = None  # наш сервер
    try:
        forwarder_host = sys.argv[1]  # получаем адрес сервака от пользователя
    except IndexError:
        print('Usage: python DnsServer.py <forwarder>')  # если не передали аргумент, то выход
        exit(-1)
    try:
        server = DnsServer(forwarder_host)  # создаем наш сервак
        try:
            with open('cache', 'rb') as file:  # открываем кэш на чтение байтов (файл сериализован)
                server.cache = pickle.load(file)  # грузим данные из кэша
        except Exception as ex:
            print('Can\'t load cache:')  # если словили ошибку на кэше, выведем, что к чему
            print(ex)
    except Exception as ex:
        # выводим ошибки создания сервака
        print('Не удалось запустить сервер.\n'
              'Проверте, что программа запускается от имени '
              'администратора и 53 порт свободен и форвардер'
              ' указан правильно.')
        print('Причина ошибки:', ex)
        exit(-1)
    server.start()  # запускаем сервак (метод threading.Thread)
    """Прога работает с консолью и имеет 4 команды:
    exit - завершить работу сервера
    cache - вывести таблицу с информацие о кэше
    forwarder_on - включить запросы к форвардеру
    forwarder_off - выключить запросы к форвардеру"""
    """Прога, по сути, смотрит, не появилась ли в консоли какая команда"""
    while True:
        cmd = input()
        if cmd == 'exit':
            """Сервак закрываем грамотно!"""
            server.server_runnable = False  # отрубаем сервак от работы с пользователем
            server.join()  # ждем завершения сервака (сервер наследуется от threading.Thread)
            """Затем ждем завершения всех второстепеннных потоков"""
            for thread in threading.enumerate():
                if thread == threading.main_thread():
                    continue
                thread.join()
            server.stop_server()  # теперь останавливаем сервак
            """Записываем инфу в кэш, чтобы не потерялась"""
            try:
                with open('cache', 'wb') as file:  # Открываем файл на запись байтов
                    pickle.dump(server.cache, file)  # Сериализуем кэш в файл
            except Exception as ex:
                # Ну и, как обычно если ловим ошибку, выводим инфу
                print('Can\'t save cache:')
                print(ex)
            print('Bye!')  # Прощаемся, выходим
            exit()
        elif cmd == 'cache':
            print('Cache status:')
            print(server.cache.get_status())  # кэш в проге является отдельной сущностью
        elif cmd == 'forwarder_on':
            print('Forwarder enabled')
            server.forwarder_on = True
        elif cmd == 'forwarder_off':
            print('Forwarder disabled')
            server.forwarder_on = False
