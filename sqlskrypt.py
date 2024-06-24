import requests
from bs4 import BeautifulSoup
import re
import logging
from payloads import payloads  # Импорт payloads из отдельного модуля
import concurrent.futures

# URL-адрес для проверки
url = "http://example.com/product.php"

# Настройка логирования
logging.basicConfig(
    filename='scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Функция для отправки GET-запросов с payloads
def send_get_request(url, payload):
    full_url = f"{url}?id={payload}"
    response = requests.get(full_url)
    return response


# Функция для отправки POST-запросов с payloads
def send_post_request(url, payload):
    data = {'id': payload}
    response = requests.post(url, data=data)
    return response


# Функция для отправки PUT-запросов с payloads
def send_put_request(url, payload):
    data = {'id': payload}
    response = requests.put(url, data=data)
    return response


# Функция для отправки DELETE-запросов с payloads
def send_delete_request(url, payload):
    full_url = f"{url}?id={payload}"
    response = requests.delete(full_url)
    return response


# Функция для проверки уязвимости на SQL-инъекцию
def check_sql_injection(url, payloads):
    log_file = 'sql_injection.log'
    logging.info("Начало проверки на SQL-инъекцию")

    # Список для хранения Future объектов
    futures = []
    with open(log_file, 'w') as log:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for payload in payloads:
                # Отправка GET-запроса
                future_get = executor.submit(send_get_request, url, payload)
                futures.append(future_get)

                # Отправка POST-запроса
                future_post = executor.submit(send_post_request, url, payload)
                futures.append(future_post)

                # Отправка PUT-запроса
                future_put = executor.submit(send_put_request, url, payload)
                futures.append(future_put)

                # Отправка DELETE-запроса
                future_delete = executor.submit(send_delete_request, url, payload)
                futures.append(future_delete)

            for future in concurrent.futures.as_completed(futures):
                response = future.result()
                check_response_for_sql_injection(response, payload, log)


def check_response_for_sql_injection(response, payload, log):
    soup = BeautifulSoup(response.text, 'html.parser')
    # Простейшая проверка наличия SQL-ошибок в ответе
    errors = ["You have an error in your SQL syntax", "Warning: mysql_fetch_array()",
              "Unclosed quotation mark after the character string"]
    for error in errors:
        if error in response.text:
            log.write(f"Возможная уязвимость найдена с payload: {payload} (HTTP {response.status_code})\n")
            logging.info(f"Возможная уязвимость найдена с payload: {payload} (HTTP {response.status_code})")
            break


# Справочная система для выбора модулей
def help_menu():
    print("Выберите модуль для работы:")
    print("1. Проверка на SQL-инъекции")
    print("2. Выход")
    choice = input("Введите номер модуля: ")

    if choice == '1':
        check_sql_injection(url, payloads)
    elif choice == '2':
        print("Выход.")
        logging.info("Выход из программы.")
    else:
        print("Неверный выбор, попробуйте снова.")
        help_menu()


# Запуск справочной системы
help_menu()
