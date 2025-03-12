import time
import json
from modules.virustotal import VirusTotal
from modules.vulners import Vulners


def main():
    vt = VirusTotal()

    file_path = "test/protected_archive.zip"
    password = "netology"
    # file_path = "test/EICAR"
    # password = ""

    try:
        # Отправляем файл на анализ
        file_id = vt.upload_file(file_path, password)
        print(f"Файл отправлен на анализ. ID файла: {file_id}")
        print("Ожидание завершения анализа...")
        time.sleep(600)
        # Получаем отчет по ID файла
        report = vt.get_report(file_id)
        results = report["data"]["attributes"]["results"]
        print("Антивирус и угроза:")
        for engine in results.values():
            if engine["result"] is not None:
                print(f"- {engine['engine_name']}: {engine['result']}")
        # Получаем данные о поведении по ID файла
        limit = 10
        behaviours = vt.get_behaviours(file_id, limit)
        if behaviours:
            print(f"Данные о поведении файла {file_id}:")
            print(behaviours)
        else:
            print(f"Данные о поведении для файла {file_id} отсутствуют.")

    except Exception as e:
        print(f"Ошибка: {e}")

    vulners = Vulners()
    # Список ПО для анализа
    software_list = [
        {"Program": "LibreOffice", "Version": "6.0.7"},
        {"Program": "7zip", "Version": "18.05"},
        {"Program": "Adobe Reader", "Version": "2018.011.20035"},
        {"Program": "nginx", "Version": "1.14.0"},
        {"Program": "Apache HTTP Server", "Version": "2.4.29"},
        {"Program": "DjVu Reader", "Version": "2.0.0.27"},
        {"Program": "Wireshark", "Version": "2.6.1"},
        {"Program": "Notepad++", "Version": "7.5.6"},
        {"Program": "Google Chrome", "Version": "68.0.3440.106"},
        {"Program": "Mozilla Firefox", "Version": "61.0.1"},
    ]

    try:
        # Анализируем ПО
        results = vulners.analyze_software(software_list)
        # Генерируем отчет
        report = vulners.generate_report(results)
        # Сохраняем отчет в файл
        vulners.save_report(report)
    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    main()
