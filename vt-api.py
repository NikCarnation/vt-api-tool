import os
import json
from datetime import datetime
import requests
from ratelimit import limits, sleep_and_retry
from dotenv import load_dotenv

load_dotenv()
VT_API = os.getenv("VT_API_KEY")

BASE_FILE = "hashes.txt"
CALLS = 4
PERIOD = 60

@sleep_and_retry
@limits(calls=CALLS, period=PERIOD)
def vt_file_scan(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "accept": "application/json",
            "X-Apikey": VT_API
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        # threat_class = attributes.get("popular_threat_classification", {})
        # creation_ts = attributes.get("creation_date")
        # if creation_ts:
        #     creation_date = datetime.fromtimestamp(creation_ts).strftime('%Y-%m-%d %H:%M:%S')
        # else:
        #     creation_date = "Неизвестно"
        # threat_category = threat_class.get("popular_threat_category", "Не определена")

        resp_text = (
            f"SHA-1: {attributes.get('sha1', 'Нет данных')}\n"
            f"SHA-256: {attributes.get('sha256', 'Нет данных')}\n"
            f"MD5: {attributes.get('md5', 'Нет данных')}\n"
            f"{'_' * 70}\n\n"
        )
        return resp_text
    except requests.exceptions.RequestException as e:
        return f"Упс, ошибка: {e}"


def hash_scan(hash_list):
    scanned_list = []
    not_found_hashes = []
    
    for file_hash in hash_list:
        scanned_hash = vt_file_scan(str(file_hash))
        if scanned_hash.startswith("Упс, ошибка:"):
            not_found_hashes.append(file_hash)
        else:
            scanned_list.append(scanned_hash)
            
    return scanned_list, not_found_hashes


def main(base_file):
    if not VT_API:
        raise ValueError("API ключ не найден! Проверьте переменную VT_API_KEY в файле .env")

    hash_set = set()

    with open(base_file, "r", encoding="utf-8") as sha1_file:
        for line in sha1_file:
            for item in line.strip().split(","):
                if item.strip():
                    hash_set.add(item.strip().lower())

    with open("clear_hashes.txt", "rw", encoding="utf-8") as clear_file:
        for clear_hash in hash_set:
            clear_file.write(clear_hash)

    scanned_list, not_found_hashes = hash_scan(list(hash_set))

    with open("result.txt", "w", encoding="utf-8") as out_file:
        for hs in scanned_list:
            out_file.write(hs)
            
        if not_found_hashes:
            out_file.write("\n=== Не найденные хеши ===\n")
            for not_hash in not_found_hashes:
                out_file.write(f"{not_hash}\n")


if __name__ == "__main__":
    main(BASE_FILE)