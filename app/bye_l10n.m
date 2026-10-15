#import "bye_l10n.h"

NSString * const ByeLanguageDidChangeNotification = @"ByeLanguageDidChangeNotification";
static NSString * const ByeLanguageKey = @"ByeLanguage";

/* english, then russian, as pairs; a text that is not here shows as it is */
static NSString * const ByeRussian[] = {
    @" (in your list)", @" (в вашем списке)",
    @"A strategy has no \"|\" in it.", @"В стратегии не должно быть знака \"|\".",
    @"A strategy is empty.", @"Стратегия пуста.",
    @"About", @"О программе",
    @"Add a list", @"Добавить список",
    @"An IPv4 address, or \"system\"", @"Адрес IPv4 или \"system\"",
    @"App", @"Приложение",
    @"Apps that try QUIC fall back to tcp at once when it is refused.", @"Приложения, которые пробуют QUIC, сразу переходят на tcp, если его отклонить.",
    @"Architecture", @"Архитектура",
    @"Automatic", @"Автоматически",
    @"Automation", @"Автоматизация",
    @"Back", @"Назад",
    @"Built on", @"Основано на",
    @"Cancel", @"Отмена",
    @"Cannot write the list: %@", @"Не удалось записать список: %@",
    @"Checking: %@", @"Проверка: %@",
    @"Compatibility", @"Совместимость",
    @"Connect when the app opens", @"Подключаться при открытии приложения",
    @"Connect when the device starts", @"Подключаться при включении устройства",
    @"Connected", @"Подключено",
    @"Connecting...", @"Подключение...",
    @"Copied", @"Скопировано",
    @"Copy logs", @"Скопировать логи",
    @"Share as a .txt file", @"Поделиться файлом .txt",
    @"No app takes the file", @"Ни одно приложение не принимает файл",
    @"The report is on the pasteboard instead. Paste it into a message to send it.", @"Отчёт скопирован в буфер обмена. Вставьте его в сообщение, чтобы отправить.",
    @"The report was not saved", @"Отчёт не сохранён",
    @"Could not connect", @"Не удалось подключиться",
    @"Credits", @"Благодарности",
    @"Special thanks", @"Особая благодарность",
    @"Cut", @"Резать",
    @"DPI bypass and Telegram gateway", @"Обход DPI и шлюз для Telegram",
    @"Daemon unavailable", @"Даемон недоступен",
    @"Developer", @"Разработчик",
    @"Device", @"Устройство",
    @"Diagnostics", @"Диагностика",
    @"Disconnected", @"Отключено",
    @"Disconnecting...", @"Отключение...",
    @"Done", @"Готово",
    @"DNS failed: %@", @"DNS: не определяются %@",
    @"DNS lookup failed for %@. The results below cover only the resolved names.", @"Не удалось получить IPv4-адрес для %@. Результаты ниже относятся только к именам, для которых найден адрес.",
    @"Partial check", @"Неполная проверка",
    @"Edit", @"Правка",
    @"Error", @"Ошибка",
    @"Features", @"Возможности",
    @"Find strategies that work here", @"Найти рабочие стратегии",
    @"Flows", @"Потоки",
    @"General", @"Общие",
    @"Give the list a name.", @"Дайте списку название.",
    @"Glyphs", @"Значки",
    @"How it works", @"Как это работает",
    @"Language", @"Язык",
    @"Theme", @"Тема",
    @"Light", @"Светлое",
    @"Dark", @"Тёмное",
    @"Classic", @"Классическая",
    @"Modern", @"Современная",
    @"Appearance", @"Оформление",
    @"Libraries", @"Библиотеки",
    @"Line %@ is not a domain name.", @"Строка %@ не является доменным именем.",
    @"Links", @"Ссылки",
    @"Lists", @"Списки",
    @"Log", @"Журнал",
    @"Material Symbols (Apache 2.0) and drawings made for this app", @"Material Symbols (Apache 2.0) и рисунки, сделанные для этого приложения",
    @"Menu", @"Меню",
    @"Model", @"Модель",
    @"Name of the list", @"Название списка",
    @"Names", @"Имена",
    @"Names: %@", @"Имена: %@",
    @"Network", @"Сеть",
    @"New list", @"Новый список",
    @"None of the strategies got through. The names may be blocked by address, or the network is down.", @"Ни одна стратегия не прошла. Имена могут быть заблокированы по адресу, или сети нет.",
    @"OK", @"OK",
    @"Power", @"Питание",
    @"Probe", @"Подбор",
    @"Ready connections", @"Готовые соединения",
    @"Block QUIC (use TCP)", @"Блокировать QUIC (использовать TCP)",
    @"Telegram relay domains", @"Домены реле для Telegram",
    @"Restart the tunnel", @"Перезапустить туннель",
    @"Save", @"Сохранить",
    @"Security", @"Безопасность",
    @"Settings", @"Настройки",
    @"Start the check", @"Начать проверку",
    @"State", @"Состояние",
    @"Stop", @"Остановить",
    @"Stop the check", @"Остановить проверку",
    @"Stopped", @"Остановлено",
    @"Strategies", @"Стратегии",
    @"Strategy list with automatic retry\nName lists\nTelegram gateway with relays\nQUIC refusal\nStrategy probe", @"Список стратегий с автоповтором\nСписки имён\nШлюз Telegram с реле\nОтказ от QUIC\nПодбор стратегий",
    @"Suggestion", @"Рекомендация",
    @"System log", @"Системный журнал",
    @"Tap the button to start", @"Нажмите кнопку, чтобы начать",
    @"Telegram gateway", @"Шлюз Telegram",
    @"Test lists", @"Списки для проверки",
    @"The addresses are the ones this device resolves.", @"Адреса те, что определяет это устройство.",
    @"The check did not start", @"Проверка не началась",
    @"The check opens a real tls connection to each name once per strategy and waits for the server's answer. It takes a minute or more. The names come from the test lists, see the gear.", @"Проверка открывает настоящее tls-соединение к каждому имени по разу на стратегию и ждёт ответа сервера. Это занимает минуту или больше. Имена берутся из списков для проверки, см. шестерёнку.",
    @"The daemon opens a utun tunnel and takes the device's tcp and udp traffic. The first bytes of a tls hello are cut so a filter that matches the server name misses it. Telegram goes over websocket gateways. Routing needs root, and a jailbreak already provides it.", @"Даемон открывает туннель utun и забирает tcp и udp трафик устройства. Первые байты tls-приветствия режутся, и фильтр, который ищет имя сервера, его не находит. Telegram идёт через websocket-шлюзы. Маршруты требуют root, а джейлбрейк его даёт.",
    @"The list has no domain names.", @"В списке нет доменных имён.",
    @"The list was not saved", @"Список не сохранён",
    @"The lists decide which sites the bypass applies to: only the listed ones, or all the others.", @"Списки определяют, к каким сайтам применяется обход: только к перечисленным или ко всем остальным.",
    @"The lists were not saved", @"Списки не сохранены",
    @"The log is empty.", @"Журнал пуст.",
    @"The probe tries the first name of each chosen list.", @"Подбор пробует первое имя каждого выбранного списка.",
    @"The report is on the pasteboard. Paste it into a message to send it.", @"Отчёт в буфере обмена. Вставьте его в сообщение, чтобы отправить.",
    @"The setting was not saved", @"Настройка не сохранена",
    @"The tunnel restarts when you leave this screen.", @"Туннель перезапустится, когда вы покинете этот экран.",
    @"Token-authenticated control socket · certificate-checked gateway, no way around it · list files read as plain files only.", @"Сокет управления с токеном \u00b7 проверка сертификата шлюза без обхода \u00b7 файлы списков читаются только как обычные файлы.",
    @"Tunnel", @"Туннель",
    @"External interface", @"Внешний интерфейс",
    @"UDP", @"UDP",
    @"Up to four domains split by commas, or \"none\"", @"До четырёх доменов через запятую или \"none\"",
    @"Version", @"Версия",
    @"With no list chosen the bypass applies to every site.", @"Если список не выбран, обход применяется ко всем сайтам.",
    @"all sites except listed", @"всем сайтам, кроме списка",
    @"byedpid does not answer. Install the package again or load its launchd job.", @"byedpid не отвечает. Установите пакет заново или загрузите его задачу launchd.",
    @"does not resolve", @"не определяется",
    @"fails %u of %u", @"не проходит %u из %u",
    @"iOS version", @"Версия iOS",
    @"none", @"нет",
    @"only listed sites", @"только сайтам из списка",
    @"system", @"системный",
    @"The options of the original ByeDPI. Every -A starts a group that is tried after a failure it names. Groups: %lu.", @"Параметры оригинального ByeDPI. Каждый -A начинает группу, которую пробуют после названного в нём сбоя. Групп: %lu.",
    @"Left out on this device:", @"На этом устройстве не выполняется:",
    @"waiting", @"ожидание",
    @"works %u of %u, %u ms", @"проходит %u из %u, %u мс",
    @"Apply to", @"Применять к",
    @"Site lists", @"Списки сайтов",
    @"Find a working strategy", @"Подбор рабочей стратегии",
    @"Telegram: connections kept ready", @"Telegram: готовые соединения",
    @"Checks", @"Проверки",
    @"Daemon", @"Даемон",
    @"answers", @"отвечает",
    @"does not answer", @"не отвечает",
    @"What is wrong", @"Что не так",
    @"up on %@", @"поднят на %@",
    @"in order", @"в порядке",
    @"Warning", @"Предупреждение",
    @"down", @"выключен",
    @"off", @"выключен",
    @"Site list", @"Список сайтов",
    @"none, every site", @"нет, все сайты",
    @"%@ is missing", @"%@ не найден",
    @"on", @"включён",
    @"About this device", @"Об устройстве",
    @"Error as the daemon said it", @"Ошибка, как её назвал даемон",
    @"Daemon log", @"Журнал даемона",
    @"App log", @"Журнал приложения",
    @"TLS log", @"Журнал TLS",
    @"Tap here for diagnostics.", @"Нажмите здесь, чтобы открыть диагностику.",
    @"The daemon does not answer.", @"Даемон не отвечает.",
    @"The daemon is not running: its control socket is missing. Install the package again, or load the launchd job com.byebyedpi.byedpid.", @"Даемон не запущен: нет его сокета управления. Установите пакет заново или загрузите задачу launchd com.byebyedpi.byedpid.",
    @"The daemon has stopped: its control socket is there, but nothing answers on it. Look at /var/log/byebyedpi-system.log.", @"Даемон остановился: сокет управления есть, но на нём никто не отвечает. Посмотрите /var/log/byebyedpi-system.log.",
    @"The app is not allowed to use the daemon's control socket.", @"Приложению нельзя пользоваться сокетом управления даемона.",
    @"The daemon has not written its token yet. Wait a moment, or restart the daemon.", @"Даемон ещё не записал свой токен. Подождите немного или перезапустите даемон.",
    @"The app cannot read the daemon's token file.", @"Приложение не может прочитать файл токена даемона.",
    @"The daemon's token file is damaged. Restart the daemon.", @"Файл токена даемона повреждён. Перезапустите даемон.",
    @"The daemon does not accept the app's token. Restart the daemon.", @"Даемон не принимает токен приложения. Перезапустите даемон.",
    @"The daemon is busy and did not answer in time.", @"Даемон занят и не ответил вовремя.",
    @"The daemon ended the connection.", @"Даемон оборвал соединение.",
    @"Another VPN or tunnel is using the same addresses. Turn the other one off, then try again.", @"Другой VPN или туннель занял те же адреса. Выключите его и попробуйте снова.",
    @"Wi-Fi and mobile data are both in use. Turn one of them off, then try again.", @"Одновременно работают Wi-Fi и мобильные данные. Выключите одно из них и попробуйте снова.",
    @"Another VPN or tunnel carries the default route. Turn it off, then try again.", @"Другой VPN или туннель занял маршрут по умолчанию. Выключите его и попробуйте снова.",
    @"The system could not open a tunnel interface. See the system log for the cause.", @"Система не открыла интерфейс туннеля. Причина указана в системном журнале.",
    @"The network gives only an IPv6 DNS server. Enter an IPv4 DNS address in Settings.", @"Сеть выдала только IPv6 DNS-сервер. Укажите IPv4-адрес DNS в настройках.",
    @"The device has no DNS server yet. Connect to a network, or enter a DNS address in Settings.", @"У устройства пока нет DNS-сервера. Подключитесь к сети или укажите адрес DNS в настройках.",
    @"There is no network. Connect to Wi-Fi or mobile data, then try again.", @"Нет сети. Подключитесь к Wi-Fi или мобильным данным и попробуйте снова.",
    @"The routes could not be set. Another VPN may be running: turn it off, then try again.", @"Не удалось задать маршруты. Возможно, работает другой VPN: выключите его и попробуйте снова.",
    @"The site list cannot be used. Fix it in Lists, or choose no list.", @"Список сайтов нельзя использовать. Исправьте его в «Списках» или не выбирайте список.",
    @"The network changed and the tunnel could not follow. Start it again.", @"Сеть изменилась, и туннель не смог за ней последовать. Запустите его снова.",
    @"A local MTProto proxy. In Telegram it is a proxy of type MTProto on this device. It works with the tunnel on or off, and needs no strategy.", @"Локальный MTProto-прокси. В Telegram это прокси типа MTProto на этом устройстве. Работает при включённом и выключенном туннеле и не зависит от стратегии.",
    @"A native strategy like tlsrec=mid;split=1,mid, or ByeDPI options like -d1 -s5+s", @"Своя стратегия вроде tlsrec=mid;split=1,mid или параметры ByeDPI вроде -d1 -s5+s",
    @"A number from 1 to 65535. Telegram has to be given the same one.", @"Число от 1 до 65535. В Telegram нужно указать тот же.",
    @"Add the proxy to Telegram", @"Добавить прокси в Telegram",
    @"Carries Telegram of every app on the device while the tunnel is on, with no proxy setting. Ready connections wait for the next flow of each datacenter in use. A relay is a cloudflare domain that carries the gateway, for the proxy as well, when the network blocks telegram's addresses.", @"Проводит Telegram всех приложений на устройстве, пока туннель включён, без настройки прокси. Готовые соединения ждут следующий поток каждого используемого датацентра. Ретранслятор это домен cloudflare, который несёт шлюз, и для прокси тоже, когда сеть блокирует адреса telegram.",
    @"Change it", @"Изменить",
    @"Copy", @"Копировать",
    @"Copy the proxy link", @"Скопировать ссылку на прокси",
    @"Delete", @"Удалить",
    @"History", @"История",
    @"In use now", @"Сейчас используется",
    @"Keep in the history", @"Сохранить в историю",
    @"New secret", @"Новый секрет",
    @"No app takes tg:// links. Install Telegram, or copy the link and open it in the client you use.", @"Ни одно приложение не принимает ссылки tg://. Установите Telegram или скопируйте ссылку и откройте её в своём клиенте.",
    @"Nothing to paste", @"Нечего вставлять",
    @"Paste from the clipboard", @"Вставить из буфера обмена",
    @"Port", @"Порт",
    @"Proxy for Telegram", @"Прокси для Telegram",
    @"Use automatic mode", @"Включить автоматический режим",
    @"Running with", @"Работает с",
    @"Secret", @"Секрет",
    @"Server", @"Сервер",
    @"Starts with", @"Запустится с",
    @"Strategy", @"Стратегия",
    @"Strategy text", @"Текст стратегии",
    @"Telegram did not open", @"Telegram не открылся",
    @"Telegram proxy: 127.0.0.1:%@", @"Прокси для Telegram: 127.0.0.1:%@",
    @"Telegram through the tunnel", @"Telegram через туннель",
    @"The clipboard has no text. Copy a strategy first.", @"В буфере обмена нет текста. Сначала скопируйте стратегию.",
    @"Automatic mode cuts the first bytes of a connection and, when a site does not answer, tries the next cut by itself. It remembers what worked for each address. A text you write is used as it is.", @"Автоматический режим режет первые байты соединения и, если сайт не отвечает, сам пробует следующий вариант. Он запоминает, что сработало для каждого адреса. Текст, который вы написали, применяется как есть.",
    @"The ones that got through, best first. Tap one to use it, copy it or keep it in the history. The one you pick replaces automatic mode and is used as it is.", @"Те, что прошли, лучшие первыми. Нажмите на одну, чтобы использовать её, скопировать или сохранить в историю. Выбранная заменяет автоматический режим и применяется как есть.",
    @"The saved text below is not running yet. It applies after a restart of the tunnel.", @"Сохранённый ниже текст ещё не работает. Он применится после перезапуска туннеля.",
    @"The strategies you replaced. Tap one to put it back, copy it or delete it.", @"Стратегии, которые вы заменили. Нажмите на одну, чтобы вернуть её, скопировать или удалить.",
    @"The strategy was not saved", @"Стратегия не сохранена",
    @"Tries strategies on real sites over your network. Nothing is changed until you pick one.", @"Пробует стратегии на реальных сайтах в вашей сети. Пока вы не выберете одну, ничего не меняется.",
    @"Use", @"Использовать",
    @"tlsrec=P cuts the tls record, split=P,P cuts segments, oob=P sends one urgent byte, none sends the bytes as they are. Positions: N, name, name+N, mid, end. Clauses are joined with \";\". The options of the original ByeDPI work too, for example -d1 -s5+s -r1+s.", @"tlsrec=P режет tls-запись, split=P,P режет сегменты, oob=P отправляет один срочный байт, none отправляет байты как есть. Позиции: N, name, name+N, mid, end. Части соединяются через \";\". Параметры оригинального ByeDPI тоже работают, например -d1 -s5+s -r1+s.",
    @"Telegram proxy", @"Прокси для Telegram",
    nil
};

ByeLanguage ByeLanguageSetting(void) {
    NSInteger value = [[NSUserDefaults standardUserDefaults] integerForKey:ByeLanguageKey];
    return value == ByeLanguageEnglish || value == ByeLanguageRussian ? (ByeLanguage)value : ByeLanguageAuto;
}

void ByeSetLanguageSetting(ByeLanguage language) {
    if (language == ByeLanguageSetting()) return;
    [[NSUserDefaults standardUserDefaults] setInteger:language forKey:ByeLanguageKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:ByeLanguageDidChangeNotification object:nil];
}

BOOL ByeLanguageIsRussian(void) {
    switch (ByeLanguageSetting()) {
    case ByeLanguageEnglish: return NO;
    case ByeLanguageRussian: return YES;
    default: break;
    }
    NSArray *preferred = [NSLocale preferredLanguages];
    return preferred.count && [[preferred objectAtIndex:0] hasPrefix:@"ru"];
}

NSString *ByeL(NSString *english) {
    static NSDictionary *table;
    if (!ByeLanguageIsRussian()) return english;
    if (!table) {
        NSMutableDictionary *built = [NSMutableDictionary dictionary];
        for (size_t i = 0; ByeRussian[i]; i += 2) [built setObject:ByeRussian[i + 1] forKey:ByeRussian[i]];
        table = [built retain];
    }
    NSString *text = [table objectForKey:english];
    return text ? text : english;
}

NSString *ByeLF(NSString *english, ...) {
    va_list args;
    va_start(args, english);
    NSString *text = [[[NSString alloc] initWithFormat:ByeL(english) arguments:args] autorelease];
    va_end(args);
    return text;
}
