import time
import json
from modules.vulners import Vulners
from modules.virustotal import VirusTotal


def main():
    vt = VirusTotal()

    file_path = "test/protected_archive.zip"
    password = "netology"
    # file_path = "test/EICAR"
    # password = ""

    try:
        # Отправляем файл на анализ
        analysis_id = vt.upload_file(file_path, password)
        print(f"Файл отправлен на анализ. ID анализа: {analysis_id}")
        print("Ожидание завершения анализа...")
        time.sleep(10)

        # Получаем отчет по ID анализа
        report = vt.get_report(analysis_id)
        results = report["data"]["attributes"]["results"]
        file_id = report["meta"]["file_info"]["sha256"]

        target_av = {
            "Fortinet",
            "McAfee Scanner",
            "Yandex",
            "Sophos",
        }  # Антивирусы для сравнения
        detected_av = set()  # Сработавшие антивирусы
        detected_target_av = set()  # Сработавшие антивирусы из списка

        print(f"ID файла: {file_id}\n")
        print("Антивирус и угроза:")
        for engine in results.values():
            if engine["result"] is not None:
                av_name = engine["engine_name"]
                detected_av.add(av_name)
                if av_name in target_av:
                    detected_target_av.add(av_name)
                print(f"- {av_name}: {engine['result']}")

        # Вывод списка сработавших антивирусов
        print("\nСписок антивирусов, которые обнаружили угрозу:")
        print(", ".join(sorted(detected_av)))

        # Проверка антивирусов из списка
        print("\nПроверка указанных антивирусов:")
        for av in target_av:
            status = (
                "✅ Обнаружил угрозу"
                if av in detected_target_av
                else "❌ Не обнаружил угрозу"
            )
            print(f"- {av}: {status}")

        # Получаем данные о поведении по ID файла
        behaviours = vt.get_behaviours(file_id)
        if behaviours:
            print(f"Данные о поведении файла {file_id}:")

            hostnames = set()
            resolved_ips = set()
            attack_techniques = []

            for entry in behaviours.get("data", []):
                attributes = entry.get("attributes", {})
            # Извлекаем hostname и resolved_ips
            dns_lookups = attributes.get("dns_lookups", [])
            for lookup in dns_lookups:
                if "hostname" in lookup:
                    hostnames.add(lookup["hostname"])
                if "resolved_ips" in lookup:
                    resolved_ips.update(lookup["resolved_ips"])

            # Извлекаем mitre_attack_techniques
            mitre_techniques = attributes.get("mitre_attack_techniques", [])
            for technique in mitre_techniques:
                attack_techniques.append(
                    {
                        "id": technique.get("id"),
                        "signature_description": technique.get("signature_description"),
                    }
                )

            print("Hostnames:")
            for hostname in hostnames:
                print(f"  - {hostname}")

            print("Resolved IPs:")
            for ip in resolved_ips:
                print(f"  - {ip}")

            print("MITRE Attack Techniques:")
            for technique in attack_techniques:
                print(f"   {technique['id']}: {technique['signature_description']}")
        else:
            print(f"Нет данных о поведении файла {file_id}")

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
        print("\nАнализа уязвимостей ПО с использованием базы данных Vulners")
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
