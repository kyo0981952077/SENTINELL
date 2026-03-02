import subprocess
import json
import os
from datetime import datetime

HISTORY_FILE = "update_history.json"

def run_git_update(status_callback=None):
    """Chạy lệnh git và gửi log về GUI qua callback"""
    command = ["git", "submodule", "update", "--remote", "--merge"]
    full_log = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        # Popen giúp đọc log của Git theo thời gian thực
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                clean_line = line.strip()
                full_log.append(clean_line)
                if status_callback:
                    status_callback(clean_line) # Gửi text về GUI

        return_code = process.poll()
        log_str = "\n".join(full_log).strip()
        
        # Đánh giá kết quả chi tiết hơn
        if return_code != 0:
            status = "Lỗi"
            final_log = log_str if log_str else "Lỗi kết nối hoặc Git chưa được cấu hình."
        elif "Updating" in log_str or "Fast-forward" in log_str:
            status = "Đã cập nhật"
            final_log = log_str
        else:
            status = "Không có bản mới"
            # Thay vì để trống, ta ghi chú rõ ràng
            final_log = "Mọi thứ đã được cập nhật. Không có thay đổi nào từ máy chủ GitHub."

        record = {
            "timestamp": timestamp,
            "status": status,
            "log": final_log # Sử dụng biến final_log đã xử lý
        }
        
        save_history(record)
        return record
    except Exception as e:
        return {"timestamp": timestamp, "status": "Lỗi", "log": str(e)}

def save_history(record):
    history = load_history()
    history.insert(0, record)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=4, ensure_ascii=False)

def clear_update_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
        return True
    return False

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except: return []
    return []