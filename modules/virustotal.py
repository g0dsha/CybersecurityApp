import requests
from config.settings import VIRUSTOTAL_API_KEY


class VirusTotal:
    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.api_url = "https://www.virustotal.com/api/v3"

    def upload_file(self, file_path, password=None):
        """
        Отправляет файл на анализ в VirusTotal.
        """
        url = f"{self.api_url}/files"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }

        files = {"file": open(file_path, "rb")}

        # Если указан пароль, добавляем его в данные
        data = {}
        if password:
            data["password"] = password

        response = requests.post(url, headers=headers, files=files, data=data)

        files["file"].close()

        if response.status_code == 200:
            file_id = response.json()["data"]["id"]
            return file_id
        else:
            raise Exception(
                f"VirusTotal API error: {response.status_code}, {response.text}"
            )

    def get_report(self, file_id):
        """
        Получить отчет о сканировании файла по ID файла
        """
        url = f"{self.api_url}/analyses/{file_id}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(
                f"VirusTotal API error: {response.status_code}, {response.text}"
            )

    def get_behaviours(self, file_id, limit=10):
        """
        Получить данные о поведении файла
        """
        url = f"{self.api_url}/files/{file_id}/behaviours"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }
        params = {
            "limit": limit,
        }

        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()  # Возвращаем JSON-ответ
        elif response.status_code == 404:
            return None
        else:
            raise Exception(
                f"VirusTotal API error: {response.status_code}, {response.text}"
            )
