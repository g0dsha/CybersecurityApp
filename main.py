# main.py
import time
from modules.virustotal import VirusTotal

def main():
    vt = VirusTotal()

    file_path = "test/protected_archive.zip"
    password = "netology"

    try:
        #Отправляем файл на анализ
        analysis_id = vt.upload_file(file_path, password)
        print(f"Файл отправлен на анализ. ID анализа: {analysis_id}")

        print("Ожидание завершения анализа...")
        time.sleep(10)

        #Получаем отчет по ID анализа
        report = vt.get_analysis_report(analysis_id)
        results = report["data"]["attributes"]["results"]

        print("Антивирус и угроза:")
        for engine in results.values():
            if engine["result"] is not None:
                print(f"- {engine['engine_name']}: {engine['result']}")

    except Exception as e:
        print(f"Ошибка: {e}")

if __name__ == "__main__":
    main()
