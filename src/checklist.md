Этапы выполнения (Твой план на неделю)
День 1-2: Парсинг PEB и Индирект Сисколлы (Фундамент)
PEB Parser:

Реализуй функцию get_ntdll_base() без использования GetModuleHandle.

Используй __readgsqword(0x60) для получения PEB, пройди по InMemoryOrderModuleList и найди ntdll.dll.
http://msk.nestor.minsk.by/kg/2004/39/kg43902.html
http://beta.delta-z.com/index.php/archives/222
http://algolist.ncstu.ru/ds/basic/simple_list.php

SSN Resolver:

Напиши функцию get_syscall_number(const char* function_name), которая парсит таблицу экспортов ntdll.dll и извлекает номер сискола (первые 4 байта функции).

Indirect Syscall:

Сделай обертку, которая принимает номер сискола и аргументы, находит адрес syscall; ret внутри ntdll и прыгает на него.

День 3: RAII + Интеграция сисколов
Перенеси свои RAII-обёртки (unique_virtual_buffer, unique_handle).

Перепиши функции выделения памяти и создания потоков, чтобы они использовали NtAllocateVirtualMemory и NtCreateThreadEx через твои индирект сисколлы.

Убедись, что VirtualProtect заменен на NtProtectVirtualMemory.

День 4: Обход AMSI и ETW
AMSI Bypass:

Напиши функцию, которая находит amsi.dll в памяти и патчит функцию AmsiScanBuffer (ставит ret в самом начале).

Используй VirtualProtect (или свой сисколл), чтобы сделать память доступной для записи.

ETW Bypass:

Найди в ntdll.dll функцию EtwEventWrite и запатчь её (первые байты заменяются на ret и nop).

День 5: Sleep Obfuscation
Напиши кастомную функцию SecureSleep(DWORD milliseconds).

Перед вызовом Sleep она должна зашифровать память с шеллкодом (XOR или AES).

После пробуждения — расшифровать.

Важно: шифровать/расшифровывать нужно через RAII-обёртку, чтобы при выходе из функции память всегда была валидной.

День 6: Early Bird APC Injection
Реализуй технику Early Bird:

Создай процесс в состоянии CREATE_SUSPENDED (например, calc.exe или notepad.exe).
Выдели память в этом процессе через NtAllocateVirtualMemory.
Запиши шеллкод.
Создай APC (Asynchronous Procedure Call) через NtQueueApcThread с точкой входа на твой шеллкод.
Запусти процесс через ResumeThread.
День 7: Сборка и Тестирование
Собери всё в единый проект. У тебя должна быть функция void execute() или int main(), которая:

Парсит PEB.
Готовит сисколлы.
Отключает AMSI/ETW.
Выполняет инжект через Early Bird.
Шифрует память перед сном (если есть ожидание).
Протестируй на Windows 10/11 с включенным Defender.

Напиши красивый README.md.

🧠 Где брать информацию (Без копирования, только понимание)
PEB/TEB: Ищи структуры PEB, PEB_LDR_DATA, LDR_DATA_TABLE_ENTRY на MSDN или в заголовочных файлах Windows.

Индирект Сисколлы: Посмотри, как работают проекты Hell's Gate и Halo's Gate.

AMSI/ETW: Читай статьи на тему AMSI Bypass via Memory Patching и ETW Patching.

Early Bird: Изучи механизм работы NtCreateProcess, NtQueueApcThread и ResumeThread.

Sleep Obfuscation: Посмотри, как работает VirtualProtect и шифрование памяти.

Важно: Не копируй готовый код. Читай концепции, смотри на псевдокод, пытайся понять логику. Если что-то не работает — лезь в документацию и думай, почему.

📝 Критерии успеха (Чек-лист)
□ PEB Parser находит ntdll.dll.
□ SSN Resolver возвращает номера для NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtQueueApcThread.
□ Индирект сисколлы вызываются через адрес внутри ntdll (не из твоего модуля).
□ AMSI отключается (можно проверить через GetProcAddress).
□ ETW отключается (можно проверить через логгер).
□ SecureSleep шифрует и расшифровывает память (можно поставить точки останова).
□ Early Bird успешно создаёт процесс и выполняет шеллкод.
