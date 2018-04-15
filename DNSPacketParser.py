import struct
import io

"""Заголовок сообщения dns - 12 байт.
Поля:
-Идентификция (2 байта) - значение в поле идентификации (identification) 
устанавливается клиентом и возвращается сервером. 
Это поле позволяет клиенту определить, на какой запрос пришел отклик.


-Флаги (flags) (2 байта):
    -QR (тип сообщения), 1-битовое поле: 0 обозначает - запрос, 1 обозначает - отклик.
    
    -opcode (код операции), 4-битовое поле. Обычное значение 0 (стандартный запрос). 
    Другие значения - это 1 (инверсный запрос) и 2 (запрос статуса сервера).
    
    -AA - 1-битовый флаг, который означает "авторитетный ответ" (authoritative answer). 
    Сервер DNS имеет полномочия для этого домена в разделе вопросов.
    
    -TC - 1-битовое поле, которое означает "обрезано" (truncated). 
    В случае UDP это означает, что полный размер отклика превысил 512 байт, 
    однако были возвращены только первые 512 байт отклика.
    
    -RD - 1-битовое поле, которое означает "требуется рекурсия" (recursion desired). 
    Бит может быть установлен в запросе и затем возвращен в отклике. 
    Этот флаг требует от DNS сервера обработать этот запрос самому 
    (т.е. сервер должен сам определить требуемый IP адрес, а не возвращать адрес другого DNS сервера), 
    что называется рекурсивным запросом (recursive query). 
    Если этот бит не установлен и запрашиваемый сервер DNS не имеет авторитетного ответа, 
    запрашиваемый сервер возвратит список других серверов DNS, к которым необходимо обратиться, 
    чтобы получить ответ. Это называется повторяющимся запросом (iterative query) . 
    Мы рассмотрим примеры обоих типов запросов в следующих примерах.
    
    -RA - 1-битовое поле, которое означает "рекурсия возможна" (recursion available). 
    Этот бит устанавливается в 1 в отклике, если сервер поддерживает рекурсию. 
    Мы увидим в наших примерах, что большинство серверов DNS поддерживают рекурсию, 
    за исключением нескольких корневых серверов (коневые сервера не в состоянии обрабатывать 
    рекурсивные запросы из-за своей загруженности).
    
    -Резерв - это 3-битовое поле должно быть равно 0 (не совсем).
    
    -rcode это 4-битовое поле кода возврата. Обычные значения: 0 (нет ошибок) и 3 (ошибка имени). 
    Ошибка имени возвращается только от полномочного сервера DNS и означает, что имя домена, 
    указанного в запросе, не существует.
    
-Количество запросов
-Количество записей ресурсов ответов
-Количество записей ресурсов прав доступа
-Количество дополнительных записей ресурсов
Эти последние четыре 16-битных поля заголовка указывают на количество пунктов в четырех полях переменной длины, 
которые завершают запись. В запросе количество вопросов (number of questions) обычно равно 1, 
а остальные три счетчика равны 0. В отклике количество ответов (number of answers) по меньшей мере равно 1, 
а оставшиеся два счетчика могут быть как нулевыми, так и ненулевыми.
"""
"""> - big-endian
H - безнаковое короткое (unsigned short), 2 байта
То есть тут мы как раз задаем формат упаковки заголовка - 6 полей по 2 байта"""
DNS_HEADER_FORMAT = '>HHHHHH'


# decompressors for RDATA
def decompress_r_data(r_type, r_len, stream):
    """Метод для распаковки данных ресурсных записей. Пришлось вывести из-за записей типа ns и cname"""
    """Пояснение, почему к ответам типа ns и cname такое особое отношение.
    У них в r_data зашиты доменные имена, а не ip, как, например, у записей типа A.
    Поэтому приходится их распаковывать особым образом"""
    if r_type in [2, 5]:
        return pack_address(parse_address(stream).decode())
    return stream.read(r_len)  # Если у нас просто ip, то тупо считываем нужное число байт


def parse_address(stream):
    """Метод для распаковки доменного имени из пришедшего пакета"""
    if type(stream) == bytearray:
        stream = io.BytesIO(stream)
    name = bytearray()  # создаем под результат bytearray
    while True:
        """ПОЯСНЕНИЕ! Внутри цикла есть break, который точно отработает 
        (если, конечно, мы ему сами нарочно не подсунет самолично сделанный фальшивый пакет)"""
        n = stream.read(1)[0]  # Считываем один байт (читаем именно так, чтобы байт перевелся сразу в число
        """ПОЯСНЕНИЕ! Имена доменов внутри пакета записываются так:
        имя разбито на домены (по точкам, в смысле).
        Каждый такой кусочек записывается следующим образом:
        байт на указание количества знаков в поддомене, а затем эти самые знаки
        (например, 2 e1 2 ru) Но есть нюанс, как всегда! В байте счетчика значения могут быть от 0 до 63,
        а если 2 первых байта выставлены в 1, то это признак использования сжатия. 
        Сжатие работает так. Первые 2 бита - единицы, а остальные 6 бит указывают смещение от начала пакета.
        И запись доменного имени заканчивается зануленным байтом"""
        if n & 0xC0:
            """Вот этот if сработает, если напоролись на сжатие"""
            m = stream.read(1)[0]  # Считываем следующий байт
            sub_name_offset = ((n & 0x3F) << 8) | m  # Вычисляем смещение относительно начала пакета
            current_offset = stream.tell()  # Спрашиваем текущее смещение
            stream.seek(sub_name_offset)  # Устанавливаем нужное нам
            sub_name = parse_address(stream)  # И уже оттуда забираем кусочек имени, нужный нам
            stream.seek(current_offset)  # Возвращаем указатель туда, где он был
            name.extend(sub_name)  # Добавляем к результату этот самый кусочек
            return name  # Возвращаем результат
        if not n:
            """Вот этот if отработает, когда напорется на байт нулей"""
            break
        name.extend(stream.read(n))  # Если у нас штатная ситуация (не сжатие),
        # то мы добавим к результату столько байт, сколько указано в байте-счетчике
        name.extend(b'.')  # Ну и после каждого кусочка добавляем точку
    return name  # возвращаем результат


def pack_address(name):
    """Метод для запаковки доменного имени"""
    result = bytearray()  # Создаем bytearray под результат
    sub_names = name.split('.')  # Разбиваем имя на домены
    for sub_name in sub_names:
        result.append(len(sub_name))  # Добавляем в результат длину домена
        result.extend(sub_name.encode())  # Ну и сам домен
    """ПОЯСНЕНИЕ! В пакете доменные имена хранятся в формате 
    "длина имени домена"-"домен с указанной длиной" """
    return result


class DnsResource:
    """Класс для создания, хранения, упаковки и распаковки ответов,
    additional и authority"""
    def __init__(self, r_name, r_type, r_class, r_ttl, r_data):
        self.r_name = r_name  # Доменное имя
        self.r_type = r_type  # Тип записи
        self.r_class = r_class  # Класс записи (он всегда 1, т.е. IN - интернет)
        self.r_ttl = r_ttl  # Время жизни
        self.r_len = len(r_data)  # Длинна данных в байтах
        self.r_data = r_data  # Сами данные ресурсной записи

    def to_string(self):
        """Метод для вывода на экран информации из ресурсной записи"""
        """Выводится в формате:
         {:20s} - 20 символов на строку (доменное имя)
         {:04X} - 4 символа на число в шестнадцатиричном представлении
         (2 таких на тип записи и класс записи)
         А время жизни и данные принтуем просто так
         """
        fmt = '{:20s} {:04X} {:04X} {} {}'
        return fmt.format(
            self.r_name, self.r_type, self.r_class, self.r_ttl,
            self.r_data)

    @staticmethod
    def parse_resource(stream):
        """Метод для распаковки инфы из полученного пакета"""
        r_name = parse_address(stream).decode()  # Вынимаем доменное имя
        r_type, r_class, r_ttl, r_len = \
            struct.unpack('>HHIH', stream.read(10))  # Вынимаем тип записи,
        # класс записи, время жизни, длину данных)
        r_data = decompress_r_data(r_type, r_len, stream)  # Распаковываем данные на основании полученной инфы
        return DnsResource(r_name, r_type, r_class, r_ttl, r_data)  # Возвращаем новый объект ресурсной записи,
        # созданный на основании полученных данных

    def to_bytes(self):
        """Метод для запаковки данных в ресурсную запись"""
        result = bytearray()
        result.extend(pack_address(self.r_name))  # Грамотно пакуем доменное имя
        result.extend(struct.pack('>HHIH', self.r_type, self.r_class,
                                  self.r_ttl, self.r_len))  # ну и все остальное
        result.extend(self.r_data)  # Данные просто добавляем (с ними и так все в порядке)
        return result  # возвращаем пользователю уже байты

    def __eq__(self, other):
        """Метод для проверки ресурсных записей на равенство"""
        if type(other) == DnsResource:
            return self.r_name == other.r_name and \
                self.r_type == other.r_type and \
                self.r_class == other.r_class and \
                self.r_data == other.r_data  # Просто сравниваем, без комментариев
        return False


class DnsQuestion:
    """Класс для работы с dns запросами"""
    def __init__(self, q_name, q_type, q_class):
        self.q_name = q_name  # Доменное имя
        self.q_type = q_type  # Тип запроса
        self.q_class = q_class  # Класс запроса (всегда 1, то есть IN - интернет)

    def is_true_resource(self, resource):
        """Метод, проверяющий, что запись в кэше нам действительно подходит
        (т.е. совпадают доменное имя, тип записи и класс записи)"""
        return self.q_name == resource.r_name and \
            self.q_type == resource.r_type and \
            self.q_class == resource.r_class  # Тупо сравниваем, без комментариев

    def to_string(self):
        """Метод для вывода данных из запроса на экран"""
        fmt = '{:20s} {:04X} {:04X}'  # строка из 20 символов и 2 шестнадцатеричных числа (буквы в верхнем регистре)
        return fmt.format(self.q_name, self.q_type, self.q_class)

    def __eq__(self, other):
        """Переопределенное сравнение для сравнения 2 запросов"""
        if type(other) == DnsQuestion:
            return self.q_name == other.q_name and \
                self.q_type == other.q_type and \
                self.q_class == other.q_class  # Тупо сравниваем, без комментариев
        return False

    @staticmethod
    def parse_question(stream):
        """Метод для распаковки запроса"""
        q_name = parse_address(stream).decode()  # Сначала вытаскиваем из запроса имя запрашиваемого домена
        q_type, q_class = struct.unpack('>HH', stream.read(4))  # Затем вынимаем информацию о типе
        # запроса и классе запроса (класс запроса обычно равен 1, с другим не сталкивался)
        return DnsQuestion(q_name, q_type, q_class)  # Возвращаем новый запрос, созданный по вытянутой инфе

    def to_bytes(self):
        result = bytearray()
        result.extend(pack_address(self.q_name))
        result.extend(struct.pack('>HH', self.q_type, self.q_class))
        return result


class DNSPacket:
    """Класс, позволяющий хранить пакет
    dns в юзабельном для нас формате"""
    def __init__(self, packet_id, flags, question, answer,
                 authority, additional):
        self.packet_id = packet_id  # идентификатор пакета
        # (число от 0 до 65535, позволяющее клиентам и сервакам понимать,
        # ответ на какой запрос они получили)
        self.flags = flags  # Флаги (первые 12 байт пакета)
        self.question = question  # запросы
        self.answer = answer  # ответы
        self.authority = authority  # Дополнительная инфа от авторитетных серваков
        self.additional = additional  # Еще дополнительная инфа от авторитетных серваков
        """НА ЗАМЕТОЧКУ! Разница между authority и additional.
        В первое авторитетные серваки помещают записи ns всех днс-серваков для конкретного домена, 
        а во второе авторитетные серваки помещают  ip для днс-серваков, 
        находящихся именно внутри конкретного домена (записи типа А). В чем профит, спросите меня вы? Да в том,
        что домены на всякий пожарный нередко заводят днс-серваки за пределами своего домена.
        Но администратор домена не может контролировать ip сервака в чужом домене, он может
        поменяться в любой момент. А сообщить ip своих серваков охота. А не сообщить хотя бы
        имена серваков в других доменах тоже нельзя, иначе нах их вообще заводить?
        Вот и приходится разводить эти два случая по разные углы."""

    def to_bytes(self):
        """Метод для перевода пакета в байты"""
        header = struct.pack(
            DNS_HEADER_FORMAT, self.packet_id, self.flags,
            len(self.question), len(self.answer),
            len(self.authority), len(self.additional)  # Запаковываем заголовок
        )
        result = bytearray()
        result.extend(header)
        """Присовокупляем к нему в правильном порядке остальные части пакета"""
        for question in self.question:
            result.extend(question.to_bytes())
        for answer in self.answer:
            result.extend(answer.to_bytes())
        for authority in self.authority:
            result.extend(authority.to_bytes())
        for additional in self.additional:
            result.extend(additional.to_bytes())
        return result  # Возвращаем переведенный в байты пакет

    @staticmethod
    def from_bytes(raw_packet):
        """Метод, позволяющий получить распарсенный dns пакет"""
        """
        Замечание!
        Модуль io используется для работы с различными объектами ввода-вывода.
        Мы конкретно используем т.н. Binary i/o.
        """
        stream = io.BytesIO(raw_packet)
        """Распаковываем первые 12 байт, чтобы получить заголовок пакета и, 
        соответственно, данные о нем"""
        packet_id, flags, q_count, an_count, ns_count, ar_count = \
            struct.unpack(DNS_HEADER_FORMAT, stream.read(12))

        """создаем массивы под запросы, ответы, authority и additional 
        (не знаю, как на русский грамотно перевести)"""
        questions = []
        answers = []
        authority = []
        additional = []

        """И теперь в зависимости от количества запросов, ответов и проч. забираем их из пакета"""
        for i in range(q_count):
            questions.append(DnsQuestion.parse_question(stream))
        for i in range(an_count):
            answers.append(DnsResource.parse_resource(stream))
        for i in range(ns_count):
            authority.append(DnsResource.parse_resource(stream))
        for i in range(ar_count):
            additional.append(DnsResource.parse_resource(stream))

        return DNSPacket(packet_id,
                         flags,
                         questions,
                         answers,
                         authority,
                         additional)
