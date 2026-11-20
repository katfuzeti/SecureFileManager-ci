#!/usr/bin/env bash
# Сборка и проверка функций и защит. Запуск: ./tests/smoke_test.sh
set -u
cd "$(dirname "$0")/.."
TESTS="$PWD/tests"

dotnet build -c Release --nologo -v q || { echo "СБОРКА НЕ УДАЛАСЬ"; exit 2; }
BIN="$PWD/bin/Release/net8.0/securefm"

export SECUREFM_HOME="$(mktemp -d)"
trap 'rm -rf "$SECUREFM_HOME"' EXIT
DB="$SECUREFM_HOME/securefm.db"
A="$SECUREFM_HOME/storage/1/files"
# Пароль тестовых пользователей не хранится в коде: его выдаёт раннер CI
# (ci/secrets.env) или задаёт сам разработчик перед запуском.
PASS="${SECUREFM_TEST_PASSWORD:?Задайте переменную SECUREFM_TEST_PASSWORD (не короче 8 символов)}"
pass=0; fail=0

sfm() { printf '%s\n' "$@" | "$BIN" 2>&1; }
alice() { sfm login alice "$PASS" "$@"; }
bob() { sfm login bob "$PASS" "$@"; }
has() { case "$2" in *"$3"*) ok "$1";; *) ko "$1" "$2";; esac; }
hasnt() { case "$2" in *"$3"*) ko "$1" "$2";; *) ok "$1";; esac; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else ko "$1" "ожидалось [$3], получено [$2]"; fi; }
ok() { pass=$((pass + 1)); echo "  OK   $1"; }
ko() { fail=$((fail + 1)); echo "  FAIL $1"; printf '%s\n' "$2" | tail -n 8 | sed 's/^/       /'; }

echo "== Учётные записи =="
has "регистрация alice" "$(sfm register alice "$PASS" "$PASS")" "Пользователь создан"
has "регистрация bob" "$(sfm register bob "$PASS" "$PASS")" "Пользователь создан"
has "дубликат логина" "$(sfm register ALICE "$PASS" "$PASS")" "логин занят"
has "короткий пароль" "$(sfm register carol 123 123)" "Пароль: от 8"
HASH="$(python3 "$TESTS/db_check.py" "$DB" hash alice)"
has "пароль хеширован" "$HASH" 'pbkdf2-sha256$600000$'
hasnt "открытого пароля нет" "$HASH" "$PASS"
has "вход" "$(alice whoami)" "Вход выполнен"
has "без входа команды закрыты" "$(sfm 'read a.txt')" "Сначала выполните вход"
INJ="$(sfm login "' OR '1'='1' --" "' OR '1'='1")"
hasnt "SQL-инъекция при входе" "$INJ" "Вход выполнен"
has "SQL-инъекция: логин не принят при регистрации" "$(sfm register "x'; DROP TABLE Users;--" "$PASS" "$PASS")" "Логин: 3-50"
has "таблица Users цела" "$(alice whoami)" "Вход выполнен"

echo "== Диски и файлы =="
has "drives" "$(alice drives)" "всего:"
has "write" "$(alice 'write a.txt' 'привет' .)" "Готово (create)"
has "read" "$(alice 'read a.txt')" "привет"
has "повторный write запрещён" "$(alice 'write a.txt' 'x' .)" "уже существует"
has "append" "$(alice 'append a.txt' 'мир' .)" "Готово (modify)"
has "после append" "$(alice 'read a.txt')" "мир"
has "overwrite" "$(alice 'overwrite a.txt' 'новое' .)" "Готово (modify)"
has "mkdir" "$(alice 'mkdir d1')" "Готово"
has "ls" "$(alice ls)" "d1"
has "info" "$(alice 'info a.txt')" "SHA-256"
has "файл с пробелом" "$(alice 'write "c d.txt"' 'z' .)" "Готово"
has "rm" "$(alice 'rm a.txt')" "Готово"
eq "БД: файл помечен удалённым" "$(python3 "$TESTS/db_check.py" "$DB" active a.txt)" "0"
eq "БД: все типы операций" "$(python3 "$TESTS/db_check.py" "$DB" ops)" "create,delete,modify"
alice 'write d1/x.txt' 'x' . >/dev/null
has "rmdir непустого запрещён" "$(alice 'rmdir d1')" "не пуст"
has "rmdir -r" "$(alice 'rmdir -r d1')" "Готово"
eq "БД: rmdir -r отмечает файлы" "$(python3 "$TESTS/db_check.py" "$DB" active d1/x.txt)" "0"

echo "== Path traversal и ссылки =="
has "обход через .." "$(alice 'read ../../../securefm.db')" "[ОТКАЗ]"
has "абсолютный путь" "$(alice 'read /etc/passwd')" "[ОТКАЗ]"
has "запись через .." "$(alice 'write ../../evil.txt' x .)" "[ОТКАЗ]"
ln -s /etc/passwd "$A/lnk"; mkdir -p "$A/real"; ln -s /etc "$A/lnkdir"
OUT="$(alice 'read lnk')"; has "чтение ссылки" "$OUT" "[ОТКАЗ]"; hasnt "/etc/passwd не показан" "$OUT" "root:"
has "ссылка в середине пути" "$(alice 'read lnkdir/passwd')" "[ОТКАЗ]"
has "запись через ссылку" "$(alice 'overwrite lnk' x .)" "[ОТКАЗ]"
has "архивация ссылки" "$(alice 'zip . all.zip')" "[ОТКАЗ]"
rm -f "$A/lnk" "$A/lnkdir"; rmdir "$A/real"

echo "== Разделение пользователей =="
alice 'write secret.txt' 'alice-secret' . >/dev/null
OUT="$(bob 'read secret.txt')"; hasnt "bob не видит файл по имени" "$OUT" "alice-secret"
OUT="$(bob 'read ../../1/files/secret.txt')"; hasnt "bob не видит файл по пути" "$OUT" "alice-secret"
hasnt "журнал только свой" "$(bob 'log 100')" "c d.txt"

echo "== JSON и XML =="
has "json-write" "$(alice 'json-write a.json' '{"имя":"Иван","n":[1,2]}' .)" "Готово"
has "json-read" "$(alice 'json-read a.json')" "Иван"
has "плохой JSON" "$(alice 'json-write bad.json' '{bad' .)" "JSON некорректен"
DEEP="$(python3 -c "print('['*100+']'*100)")"
has "глубокий JSON" "$(alice 'json-write deep.json' "$DEEP" .)" "JSON некорректен"
has "xml-write" "$(alice 'xml-write a.xml' '<r><v>Текст</v></r>' .)" "Готово"
has "xml-read" "$(alice 'xml-read a.xml')" "Текст"
OUT="$(alice 'xml-write xxe.xml' '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>' '<r>&x;</r>' .)"
has "XXE" "$OUT" "[ОТКАЗ]"; hasnt "XXE не прочитал файл" "$OUT" "root:"
OUT="$(alice 'xml-write bl.xml' '<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>' '<l>&b;</l>' .)"
has "billion laughs" "$OUT" "[ОТКАЗ]"
has "отчёт JSON" "$(alice 'report-json r.json')" "Готово"
has "разбор отчёта JSON" "$(alice 'report-show r.json')" "Владелец: alice"
has "отчёт XML" "$(alice 'report-xml r.xml')" "Готово"
has "разбор отчёта XML" "$(alice 'report-show r.xml')" "Владелец: alice"
printf '{"Owner":"x","$type":"System.Diagnostics.Process"}' > "$A/evil.json"
has "лишнее поле при десериализации" "$(alice 'report-show evil.json')" "не соответствует схеме"

echo "== ZIP =="
mkdir -p "$A/pack/sub"; echo one > "$A/pack/1.txt"; echo two > "$A/pack/sub/2.txt"
has "zip" "$(alice 'zip pack p.zip')" "Файлов в архиве: 2"
has "unzip" "$(alice 'unzip p.zip out')" "Извлечено файлов: 2"
eq "содержимое совпало" "$(cat "$A/out/sub/2.txt")" "two"
eq "БД: извлечённый файл учтён" "$(python3 "$TESTS/db_check.py" "$DB" active out/sub/2.txt)" "1"
python3 "$TESTS/make_evil_zips.py" "$A"
has "zip slip" "$(alice 'unzip slip.zip s1')" "[ОТКАЗ]"
[ ! -e "$A/../../evil.txt" ] && [ ! -e "$A/s1" ] && ok "zip slip ничего не записал" || ko "zip slip ничего не записал" "файл создан"
has "абсолютное имя в архиве" "$(alice 'unzip abs.zip s2')" "[ОТКАЗ]"
[ ! -e /tmp/securefm_evil.txt ] && ok "абсолютное имя ничего не записало" || ko "абсолютное имя" "файл создан"
has "zip-бомба" "$(alice 'unzip bomb.zip s3')" "zip-бомба"
[ ! -e "$A/s3" ] && ok "бомба не распакована" || ko "бомба не распакована" "каталог создан"
has "ссылка в архиве" "$(alice 'unzip symlink.zip s4')" "[ОТКАЗ]"
has "слишком много файлов" "$(alice 'unzip many.zip s5')" "[ОТКАЗ]"
has "битый архив" "$(alice 'unzip broken.zip s6')" "повреждён"
hasnt "временные каталоги убраны" "$(ls "$SECUREFM_HOME/storage/1/tmp")" "unzip-"

echo "== Гонки =="
alice 'write race.txt' 'start' . >/dev/null
for i in 1 2 3 4 5 6 7 8; do alice 'append race.txt' "line$i" . >/dev/null & done; wait
eq "параллельный append не теряет данные" "$(wc -l < "$A/race.txt" | tr -d ' ')" "9"
TMPOUT="$(mktemp -d)"
for i in 1 2 3 4 5 6 7 8; do alice 'write once.txt' "w$i" . > "$TMPOUT/$i" & done; wait
eq "параллельный write создаёт файл один раз" "$(cat "$TMPOUT"/* | grep -c 'Готово (create)')" "1"
rm -rf "$TMPOUT"

echo "== Журнал и права =="
has "успех в журнале" "$(alice 'log 500')" "write"
has "отказ в журнале" "$(alice 'log 500')" "SecurityViolationException"
eq "журнал нельзя изменить" "$(python3 "$TESTS/db_check.py" "$DB" tamper | sort -u)" "blocked"
sfm login alice wrong >/dev/null
printf 'x\033[31mRED\033[0m\xe2\x80\xae\n' > "$A/esc.txt"
OUT="$(alice 'read esc.txt')"
hasnt "ESC вырезан" "$OUT" $'\033'; has "текст показан" "$OUT" "RED"
eq "права БД" "$(stat -c %a "$DB")" "600"
eq "права каталога данных" "$(stat -c %a "$SECUREFM_HOME")" "700"
alice 'write perm.txt' x . >/dev/null
eq "права файла" "$(stat -c %a "$A/perm.txt")" "600"

echo "== Блокировка входа =="
for i in 1 2 3 4 5; do sfm login bob wrong-password >/dev/null; done
hasnt "блокировка после 5 ошибок" "$(bob whoami)" "Вход выполнен"

echo
echo "Итог: пройдено $pass, не пройдено $fail"
[ "$fail" -eq 0 ]
