import json
import os
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv

# ==========================================
# 載入 .env 環境變數檔案
# ==========================================
load_dotenv()

# 從環境變數讀取 Connection String
CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

# 檢查是否有成功讀到連線字串
if not CONNECTION_STRING:
    raise ValueError("❌ 錯誤：未在 .env 檔案中找到 'AZURE_STORAGE_CONNECTION_STRING'，請檢查設定！")

# 欲掃描的 Container 清單 (建議 Read/Write 都掃)
CONTAINERS_TO_SCAN = [
    "insights-logs-storageread",
    "insights-logs-storagewrite"
]

# 篩選日期範圍 (UTC 時間)
START_DATE = datetime(2026, 7, 1, tzinfo=timezone.utc)
END_DATE = datetime(2026, 7, 23, tzinfo=timezone.utc)

MAX_WORKERS = 10


def extract_storage_account_name(resource_id: str) -> str:
    """從 Azure resourceId 解析出原始 Storage Account 名稱"""
    if not resource_id:
        return "Unknown_Account"
    match = re.search(r"storageAccounts/([^/]+)", resource_id, re.IGNORECASE)
    if match:
        return match.group(1)
    return "Unknown_Account"


def parse_blob_records(blob_content: str):
    """解析 NDJSON 或 JSON Array"""
    records = []
    blob_content = blob_content.strip()
    if not blob_content:
        return records

    try:
        data = json.loads(blob_content)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "records" in data:
            return data["records"]
        elif isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        for line in blob_content.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def process_single_blob(container_client, blob_name):
    """處理單一 Blob 檔案，並按 Storage Account 區分統計資料"""
    account_tls_counts = defaultdict(Counter)
    account_low_tls_details = defaultdict(list)

    try:
        blob_client = container_client.get_blob_client(blob_name)
        download_stream = blob_client.download_blob()
        content = download_stream.readall().decode("utf-8")

        records = parse_blob_records(content)

        for record in records:
            props = record.get("properties", {})
            
            # 1. 取得 Resource ID 並解析出 Target Account
            resource_id = record.get("resourceId") or props.get("resourceId", "")
            target_account = extract_storage_account_name(resource_id)

            # 2. 取得 TLS 版本
            tls_version = (
                props.get("tlsVersion") 
                or record.get("tlsVersion") 
                or props.get("TLSVersion")
                or "Unknown/HTTP"
            )

            # 累積該 Account 的 TLS 版本次數
            account_tls_counts[target_account][tls_version] += 1

            # 3. 若非 TLS 1.2 以上，紀錄明細資訊
            if tls_version not in ["TLS 1.2", "TLS 1.3", "1.2", "1.3"]:
                account_low_tls_details[target_account].append({
                    "time": record.get("time"),
                    "tlsVersion": tls_version,
                    "callerIp": record.get("callerIpAddress") or props.get("callerIpAddress"),
                    "userAgent": record.get("userAgent") or props.get("userAgent"),
                    "operation": record.get("operationName") or props.get("operationName")
                })

    except Exception as e:
        print(f"⚠️ 處理 Blob 失敗 [{blob_name}]: {e}")

    return account_tls_counts, account_low_tls_details


def get_blobs_in_date_range(container_client, start_date, end_date):
    """依據 y=YYYY/m=MM/d=DD 過濾路徑"""
    matched_blobs = []
    for blob in container_client.list_blobs():
        match = re.search(r"y=(\d{4})/m=(\d{2})/d=(\d{2})", blob.name)
        if match:
            year, month, day = map(int, match.groups())
            blob_date = datetime(year, month, day, tzinfo=timezone.utc)
            if start_date <= blob_date <= end_date:
                matched_blobs.append(blob.name)
    return matched_blobs


def main():
    blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    
    # 總結各 Account 的統計
    global_tls_summary = defaultdict(Counter)
    global_low_tls_details = defaultdict(list)

    for container_name in CONTAINERS_TO_SCAN:
        print(f"\n📂 正在掃描 Container: [{container_name}]")
        try:
            container_client = blob_service_client.get_container_client(container_name)
            target_blobs = get_blobs_in_date_range(container_client, START_DATE, END_DATE)
            print(f"  └─ 找到 {len(target_blobs)} 個符合日期的 Log 檔案，開始處理...")

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [
                    executor.submit(process_single_blob, container_client, b_name)
                    for b_name in target_blobs
                ]

                for future in futures:
                    acc_counts, acc_details = future.result()
                    
                    # 合併統計數據
                    for acc, counts in acc_counts.items():
                        global_tls_summary[acc].update(counts)
                    for acc, details in acc_details.items():
                        global_low_tls_details[acc].extend(details)

        except Exception as e:
            print(f"❌ 讀取 Container [{container_name}] 時發生錯誤: {e}")

    # ==========================================
    # 報表輸出
    # ==========================================
    print("\n" + "=" * 60)
    print("📊 各 Storage Account 之 TLS 版本統計結果")
    print("=" * 60)

    if not global_tls_summary:
        print("未掃描到任何連線紀錄。")
        return

    for account, tls_counter in global_tls_summary.items():
        total_reqs = sum(tls_counter.values())
        print(f"\n🔹 Storage Account: [{account}] (總請求量: {total_reqs:,} 次)")
        print("-" * 55)
        
        for ver, count in tls_counter.most_common():
            pct = (count / total_reqs * 100) if total_reqs > 0 else 0
            print(f"  • {ver:<12}: {count:>10,} 次 ({pct:>6.2f}%)")

        # 列出該 Account 的低版 TLS 排行前 3 大來源
        low_tls_list = global_low_tls_details.get(account, [])
        if low_tls_list:
            print(f"\n  ⚠️ 發現 {len(low_tls_list):,} 筆低於 TLS 1.2 的連線，前三大來源分析：")
            ip_agent_rank = Counter()
            for item in low_tls_list:
                key = f"IP: {item['callerIp']} | Agent: {item['userAgent']} ({item['tlsVersion']})"
                ip_agent_rank[key] += 1
            
            for rank_key, rank_cnt in ip_agent_rank.most_common(3):
                print(f"     - [{rank_cnt:>4} 次] {rank_key}")
        else:
            print("  ✅ 該 Account 無任何低於 TLS 1.2 的連線。")


if __name__ == "__main__":
    main()