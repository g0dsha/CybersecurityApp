import requests
from config.settings import VULNERS_API_KEY


class Vulners:
    def __init__(self):
        self.api_key = VULNERS_API_KEY
        self.api_url = "https://vulners.com/api/v3/search/lucene/"

    def search_vulnerabilities(self, software_name, software_version):
        """
        Поиск уязвимостей для указанного программного обеспечения и версии.
        """
        query = f'"{software_name} {software_version}"'
        params = {"query": query, "apiKey": self.api_key, "size": 10}

        response = requests.get(self.api_url, params=params)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("data", {}).get("search", [])
            if vulnerabilities:
                results = []
                for vuln in vulnerabilities:
                    cve_list = vuln["_source"].get("cvelist", [])
                    exploit_available = vuln["_source"].get("exploit_available", False)
                    results.append(
                        {
                            "cve_list": cve_list,
                            "exploit_available": exploit_available,
                            "details": vuln["_source"],
                        }
                    )
                return results
            else:
                return None
        else:
            raise Exception(
                f"Vulners API error: {response.status_code}, {response.text}"
            )

    def analyze_software(self, software_list):
        """
        Поиск уязвимостей по списку ПО
        """
        results = {}

        for software in software_list:
            program = software["Program"]
            version = software["Version"]
            print(f"Анализ {program} {version}...")

            try:
                vulnerabilities = self.search_vulnerabilities(program, version)
                print(vulnerabilities)
                if vulnerabilities:
                    results[f"{program} {version}"] = vulnerabilities
                    print(f"Найдено уязвимостей: {len(vulnerabilities)}")
                else:
                    results[f"{program} {version}"] = "Уязвимости не найдены"
                    print("Уязвимости не найдены.")
            except Exception as e:
                results[f"{program} {version}"] = f"Ошибка: {e}"
                print(f"Ошибка при анализе: {e}")

            print("-" * 40)

        return results

    @staticmethod
    def generate_report(results):
        """
        Генерация отчета на основе результатов анализа.
        """
        report = []

        for software, data in results.items():
            report.append(f"Программное обеспечение: {software}")
            if isinstance(data, list):
                report.append("Статус: Найдены уязвимости")
                cve_list = []
                exploit_count = 0

                for vuln in data:
                    cve_list.extend(vuln["cve_list"])
                    if vuln["exploit_available"]:
                        exploit_count += 1

                report.append(
                    f"Список CVE: {', '.join(cve_list) if cve_list else 'Нет данных'}"
                )

                if exploit_count > 0:
                    report.append(f"Найдено эксплойтов: {exploit_count}")
                else:
                    report.append("Информация об эксплойтах: Нет данных")
            else:
                report.append("Статус: Уязвимости не найдены")
            report.append("-" * 40)

        return "\n".join(report)

    @staticmethod
    def save_report(report, filename="vulnerability_report.txt"):
        """
        Сохранить отчет в текстовый файл.
        """
        with open(filename, "w", encoding="utf-8") as file:
            file.write(report)
        print(f"Отчет сохранен в файл {filename}.")
