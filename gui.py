import json
import os
import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import updater 
import datetime
import scan # Import file scan.py đã sửa ở trên

ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("blue")

class MalwareScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PHẦN MỀM QUÉT MÃ ĐỘC - SENTINEL")
        self.geometry("1100x850")

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="SENTINEL", font=ctk.CTkFont(size=28, weight="bold"), text_color="#38bdf8")
        self.logo_label.pack(pady=40)

        self.btn_new_scan = ctk.CTkButton(self.sidebar_frame, text=" 🔄  New Scan", 
                                          fg_color="transparent", anchor="w", 
                                          command=self.reset_to_home) 
        self.btn_new_scan.pack(fill="x", padx=20, pady=10)

        self.btn_history_tab = ctk.CTkButton(self.sidebar_frame, text=" 📜  History", fg_color="transparent", anchor="w", command=self.show_history_window)
        self.btn_history_tab.pack(fill="x", padx=20, pady=10)

        # [NEW] Nút gạt chế độ Offline
        ctk.CTkLabel(self.sidebar_frame, text="Settings:", text_color="gray", anchor="w").pack(padx=20, pady=(30, 10), fill="x")
        self.offline_switch = ctk.CTkSwitch(self.sidebar_frame, text="Offline Mode", command=self.on_offline_toggle)
        self.offline_switch.pack(padx=20, pady=10, anchor="w")

        # --- MAIN CONTENT ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=40, pady=30, sticky="nsew")

        self.header = ctk.CTkLabel(self.main_frame, text="Security Dashboard", font=ctk.CTkFont(size=32, weight="bold"))
        self.header.pack(pady=(0, 20), anchor="w")

        # 1. KHUNG NHẬP URL
        self.input_frame = ctk.CTkFrame(self.main_frame, fg_color="#1e293b", corner_radius=15)
        self.input_frame.pack(fill="x", pady=10)
        
        self.url_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Nhập URL cần quét (hoặc nhấn Enter)...", width=500, height=45, border_width=0)
        self.url_entry.pack(side="left", padx=20, pady=20)
        self.url_entry.bind('<Return>', lambda event: self.scan_url()) 
        
        self.btn_scan_url = ctk.CTkButton(self.input_frame, text="QUÉT URL", width=140, height=45, 
                                          font=ctk.CTkFont(weight="bold"), command=self.scan_url)
        self.btn_scan_url.pack(side="left", padx=10)

        # 2. KHUNG CHỌN FILE
        self.file_container = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.file_container.pack(fill="x", pady=15)

        self.btn_pick_file = ctk.CTkButton(self.file_container, text="📥  CHỌN TẬP TIN ĐỂ PHÂN TÍCH", 
                                          fg_color="#38bdf8", hover_color="#0ea5e9", text_color="#0f172a",
                                          height=60, font=ctk.CTkFont(size=15, weight="bold"),
                                          command=self.choose_file)
        self.btn_pick_file.pack(fill="x")

        # Khung thông tin file
        self.file_info_display = ctk.CTkFrame(self.file_container, fg_color="#1e293b", height=60, corner_radius=10)
        
        self.file_name_label = ctk.CTkLabel(self.file_info_display, text="", font=ctk.CTkFont(weight="bold"), text_color="#38bdf8")
        self.file_name_label.pack(side="left", padx=20, pady=15)
        
        self.btn_remove_file = ctk.CTkButton(self.file_info_display, text="✖ Bỏ chọn", width=80, height=30, 
                                            fg_color="#f43f5e", hover_color="#e11d48", command=self.reset_file_ui)
        self.btn_remove_file.pack(side="right", padx=15)

        # 3. THANH LOADING
        self.loading_bar = ctk.CTkProgressBar(self.main_frame, orientation="horizontal", mode="indeterminate", height=4)
        self.loading_bar.set(0)

        # 4. KẾT QUẢ
        self.status_card = ctk.CTkFrame(self.main_frame, fg_color="#0f172a", border_width=2, border_color="#334155")
        self.status_card.pack(fill="both", expand=True, pady=10)

        self.status_text = ctk.CTkLabel(self.status_card, text="Sẵn sàng phân tích", font=ctk.CTkFont(size=18, weight="bold"))
        self.status_text.pack(pady=15)
        
        self.result_container = ctk.CTkFrame(self.status_card, fg_color="transparent")
        self.result_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.malicious_frame = ctk.CTkScrollableFrame(self.result_container, label_text="🚨 PHÁT HIỆN ĐỘC HẠI", label_text_color="#f43f5e")
        self.malicious_frame.grid(row=0, column=0, padx=5, sticky="nsew")

        self.clean_frame = ctk.CTkScrollableFrame(self.result_container, label_text="✅ THÔNG TIN AN TOÀN", label_text_color="#10b981")
        self.clean_frame.grid(row=0, column=1, padx=5, sticky="nsew")

        self.result_container.grid_columnconfigure(0, weight=1)
        self.result_container.grid_columnconfigure(1, weight=1)
        self.result_container.grid_rowconfigure(0, weight=1)



        # UPDATE GIT VERSION 
        self.update_container = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.update_container.pack(fill="x", pady=10)
        self.update_container.pack_propagate(False)
        self.btn_update = ctk.CTkButton(self.update_container, text="Cập nhật Rules", command=self.start_update_thread)
        self.btn_update.pack(pady=10, padx=20, fill="x")
        self.btn_up_history = ctk.CTkButton(self.update_container, text="Lịch sử Update", command=self.open_update_history_window, fg_color="#555555")
        self.btn_up_history.pack(pady=5, padx=20, fill="x")
        self.lbl_up_status = ctk.CTkLabel(self.update_container, text="", font=("Arial", 10), text_color="gray")
        self.lbl_up_status.pack(pady=(5,0))
        # Progress Bar
        self.prog_up = ctk.CTkProgressBar(self.update_container, mode="indeterminate")
        self.prog_up.pack(pady=5, padx=20, fill="x")
        self.prog_up.pack_forget()


    def start_update_thread(self):
        if messagebox.askyesno("Xác nhận", "Bắt đầu cập nhật bộ Rules từ GitHub?"):
            self.btn_update.configure(state="disabled")
            self.prog_up.pack(pady=5, padx=20, fill="x")
            self.prog_up.start()
            threading.Thread(target=self.run_update_process, daemon=True).start()

    def run_update_process(self):
        def cb(text):
            short_text = (text[:30] + '...') if len(text) > 30 else text
            self.after(0, lambda: self.lbl_up_status.configure(text=short_text))
        
        try:
            result = updater.run_git_update(status_callback=cb)
            self.after(0, lambda: self.finish_update(result))
        except Exception as e:
            self.after(0, lambda: self.finish_update({"status": "Lỗi", "log": str(e)}))

    def finish_update(self, result):
        self.prog_up.stop()
        self.prog_up.pack_forget()
        self.btn_update.configure(state="normal")
        self.lbl_up_status.configure(text="")
        messagebox.showinfo("Kết quả", f"Trạng thái: {result['status']}")
        scan.COMPILED_RULES = None

    def open_update_history_window(self):
        history = updater.load_history()
        win = ctk.CTkToplevel(self)
        win.title("Lịch sử Cập nhật")
        win.geometry("600x400")
        win.attributes('-topmost', True)

        # --- HEADER CỦA CỬA SỔ LỊCH SỬ ---
        header_frame = ctk.CTkFrame(win, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header_frame, text="LỊCH SỬ CẬP NHẬT RULES", 
                     font=ctk.CTkFont(size=16, weight="bold")).pack(side="left")

        self.btn_clear_up = ctk.CTkButton(header_frame, text="🗑️ Clean", 
                                     fg_color="#ef4444", hover_color="#dc2626",
                                     width=100, height=28,
                                     command=lambda: self.confirm_clear_update_history(win))
        self.btn_clear_up.pack(side="right")

        if not history:
            self.btn_clear_up.configure(state="disabled", fg_color="gray")
       
        # --- NỘI DUNG ---
        content_frame = ctk.CTkFrame(win, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        list_frame = ctk.CTkScrollableFrame(content_frame, width=220)
        list_frame.pack(side="left", fill="y", padx=5, pady=5)
        
        txt_log = ctk.CTkTextbox(content_frame)
        txt_log.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        def render_list():
            for widget in list_frame.winfo_children():
                widget.destroy()
            
            current_h = updater.load_history()
            if not current_h:
                ctk.CTkLabel(list_frame, text="Trống", text_color="gray").pack(pady=20)
                txt_log.delete("1.0", "end")
                return

            for item in current_h:
                btn = ctk.CTkButton(list_frame, text=f"{item['timestamp']}\n{item['status']}", 
                                    fg_color="transparent", border_width=1,
                                    command=lambda r=item: [txt_log.delete("1.0", "end"), txt_log.insert("1.0", r['log'])])
                btn.pack(fill="x", pady=2)

        render_list()


    def confirm_clear_update_history(self, window_to_refresh):
        """Xác nhận và xoá lịch sử"""
        if messagebox.askyesno("Xác nhận", "Bạn có chắc chắn muốn xoá toàn bộ nhật ký cập nhật không?"):
            updater.clear_update_history()
            messagebox.showinfo("Thông báo", "Đã xoá lịch sử cập nhật.")
            # Đóng và mở lại hoặc vẽ lại giao diện
            window_to_refresh.destroy()
            self.open_update_history_window()


    def on_offline_toggle(self):
        state = self.offline_switch.get()
        if state == 1:
            # CHẾ ĐỘ OFFLINE: Hiện tiêu đề và hiện cụm Update
            self.header.configure(text="Security Dashboard (OFFLINE MODE)")
            # Hiển thị container ở cuối Sidebar
        else:
            # CHẾ ĐỘ ONLINE: Trở về bình thường và ẩn cụm Update
            self.header.configure(text="Security Dashboard")
            # Ẩn hoàn toàn container

    def reset_to_home(self):
        self.url_entry.delete(0, 'end')
        self.reset_file_ui()
        self.status_text.configure(text="Sẵn sàng phân tích", text_color="white")
        self.status_card.configure(border_color="#334155")

    def reset_file_ui(self):
        self.file_info_display.pack_forget()
        self.btn_pick_file.pack(fill="x")
        self.file_name_label.configure(text="")
        for widget in self.malicious_frame.winfo_children(): widget.destroy()
        for widget in self.clean_frame.winfo_children(): widget.destroy()

    def toggle_loading(self, start=True):
        if start:
            self.loading_bar.pack(fill="x", pady=5, before=self.status_card)
            self.loading_bar.start()
            self.btn_scan_url.configure(state="disabled")
            self.btn_pick_file.configure(state="disabled")
            self.btn_remove_file.configure(state="disabled")
            self.offline_switch.configure(state="disabled") # Khóa nút toggle khi đang quét
        else:
            self.loading_bar.stop()
            self.loading_bar.pack_forget()
            self.btn_scan_url.configure(state="normal")
            self.btn_pick_file.configure(state="normal")
            self.btn_remove_file.configure(state="normal")
            self.offline_switch.configure(state="normal")

    def choose_file(self):
        path = filedialog.askopenfilename()
        if not path: return
        self.url_entry.delete(0, 'end')
        self.btn_pick_file.pack_forget()
        self.file_info_display.pack(fill="x")
        self.btn_remove_file.pack(side="right", padx=15)   
        self.file_name_label.configure(text=f"📄 {os.path.basename(path)}")
        
        # Kiểm tra chế độ Offline
        is_offline = (self.offline_switch.get() == 1)
        mode_text = "OFFLINE" if is_offline else "ONLINE"
        
        self.status_text.configure(text=f"⌛ Đang phân tích file ({mode_text})...", text_color="white")
        self.toggle_loading(True)
        
        def run():
            try:
                # [UPDATE] Truyền tham số offline_mode vào hàm scan
                result = scan.scan_file_main(path, offline_mode=is_offline)
                self.save_to_history(result)
                self.after(0, lambda: [self.update_ui_status(result["is_danger"], result), self.toggle_loading(False)])
            except Exception as e:
                error_msg = str(e) # Lưu thông báo lỗi vào một biến cụ thể
                self.after(0, lambda msg=error_msg: [messagebox.showerror("Lỗi", msg), self.toggle_loading(False)])
        threading.Thread(target=run, daemon=True).start()

    def scan_url(self):
        # [UPDATE] Chặn quét URL nếu đang ở chế độ Offline
        if self.offline_switch.get() == 1:
            messagebox.showwarning("Chế độ Offline", "Quét URL yêu cầu kết nối Internet.\nVui lòng tắt chế độ Offline để tiếp tục.")
            return

        url = self.url_entry.get().strip()
        if not url: return
        if self.file_info_display.winfo_ismapped():
            self.reset_file_ui()
        self.status_text.configure(text="⌛ Đang kiểm tra URL...", text_color="white")
        self.toggle_loading(True)
        
        def run():
            try:
                result = scan.scan_url_main(url)
                self.save_to_history(result)
                self.after(0, lambda: [self.update_ui_status(result["is_danger"], result), self.toggle_loading(False)])
            except Exception as e:
                 self.after(0, lambda: [messagebox.showerror("Lỗi", str(e)), self.toggle_loading(False)])
        threading.Thread(target=run, daemon=True).start()

    def view_history_item(self, data):
        self.reset_file_ui() 
        target = data.get("filename")
        if target:
            self.url_entry.delete(0, 'end') 
            self.btn_pick_file.pack_forget()
            self.file_info_display.pack(fill="x")
            self.file_name_label.configure(text=f"📄 [Lịch sử] {target}")
            self.btn_remove_file.pack_forget() 
            
        else:
            target = data.get("target", "")
            self.url_entry.delete(0, 'end')
            self.url_entry.insert(0, target)
            
        time_str = data.get("timestamp", "")
        is_danger = data.get("is_danger", False)
        
        # [UPDATE] Hiển thị chi tiết hơn trong lịch sử
        details = data.get("details", {})
        mode_scan = details.get("Mode", "UNKNOWN")
        
        if is_danger:
            result_text = "⚠️ KẾT QUẢ: PHÁT HIỆN MỐI ĐE DỌA"
            status_color = "#f43f5e" 
        else:
            result_text = "✅ KẾT QUẢ: HỆ THỐNG AN TOÀN"
            status_color = "#10b981" 

        final_text = f"🕒 Lịch sử ({mode_scan}): {time_str}\n{result_text}\n"
        
        self.status_text.configure(text=final_text, text_color=status_color)
        
        self.update_ui_status(data["is_danger"], data)

    def update_ui_status(self, is_danger, data):
        for widget in self.malicious_frame.winfo_children(): widget.destroy()
        for widget in self.clean_frame.winfo_children(): widget.destroy()

        if is_danger:
            self.status_card.configure(border_color="#f43f5e")
            if "Lịch sử" not in self.status_text.cget("text"):
                 self.status_text.configure(text="⚠️ PHÁT HIỆN NGUY HIỂM!", text_color="#f43f5e")
        else:
            self.status_card.configure(border_color="#10b981")
            if "Lịch sử" not in self.status_text.cget("text"):
                self.status_text.configure(text="✅ ĐỐI TƯỢNG AN TOÀN", text_color="#10b981")

        m_list = data.get("malicious_list", [])
        if not m_list: ctk.CTkLabel(self.malicious_frame, text="Sạch - Không có mã độc", text_color="gray").pack(pady=10)
        else:
            for item in m_list:
                ctk.CTkLabel(self.malicious_frame, text=f"✘ {item}", text_color="#f43f5e", font=("Consolas", 12, "bold"), anchor="w").pack(fill="x", padx=10, pady=2)

        c_list = data.get("clean_list", [])
        if not c_list: ctk.CTkLabel(self.clean_frame, text="Không có dữ liệu", text_color="gray").pack(pady=10)
        else:
            for item in c_list:
                ctk.CTkLabel(self.clean_frame, text=f"✔ {item}", text_color="#10b981", font=("Consolas", 12), anchor="w").pack(fill="x", padx=10, pady=1)

    def save_to_history(self, data):
        history_file = "history.json"
        current_history = []
        if os.path.exists(history_file):
            with open(history_file, "r", encoding="utf-8") as f:
                try: current_history = json.load(f)
                except: current_history = []
        data["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        current_history.insert(0, data)
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(current_history[:50], f, indent=4, ensure_ascii=False)

    def clear_history_action(self, scroll_frame, history_window): # Đã sửa thêm history_window
        if messagebox.askyesno("Xác nhận", "Xóa toàn bộ lịch sử?"):
            if os.path.exists("history.json"): os.remove("history.json")
            for widget in scroll_frame.winfo_children(): widget.destroy()
            ctk.CTkLabel(scroll_frame, text="Đã dọn dẹp.", text_color="gray").pack(pady=20)
            # history_window.destroy() # Nếu muốn đóng luôn

    def truncate_string(self, text, max_length=40):
        if len(text) <= max_length:
            return text
        return text[:20] + "..." + text[-15:]

    def show_history_window(self):
        history_window = ctk.CTkToplevel(self)
        history_window.title("Scan History")
        history_window.geometry("650x500")
        history_window.attributes('-topmost', True)
        header_frame = ctk.CTkFrame(history_window, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(header_frame, text="NHẬT KÝ HỆ THỐNG", 
                      font=ctk.CTkFont(size=20, weight="bold", family="Inter")).pack(side="left")

        scroll_frame = ctk.CTkScrollableFrame(history_window, fg_color="#0f172a")
        
        self.btn_clear = ctk.CTkButton(header_frame, text="🗑️ Xóa tất cả ", fg_color="#f43f5e", width=90,
                                  font=ctk.CTkFont(size=12, weight="bold"),
                                  command=lambda: self.clear_history_action(scroll_frame, history_window))
        self.btn_clear.pack(side="right")

        if not os.path.exists("history.json"):
            self.btn_clear.configure(state="disabled", fg_color="gray")

        scroll_frame.pack(padx=15, pady=(0, 15), fill="both", expand=True)

        if not os.path.exists("history.json"):
            ctk.CTkLabel(scroll_frame, text="Chưa có dữ liệu lịch sử quét.", text_color="gray").pack(pady=40)
            return

        try:
            with open("history.json", "r", encoding="utf-8") as f:
                history_data = json.load(f)
            
            if not history_data:
                ctk.CTkLabel(scroll_frame, text="Lịch sử trống.", text_color="gray").pack(pady=40)
                return

            for item in history_data:
                # Cách hiển thị mới cho Lịch sử
                row_item = ctk.CTkFrame(scroll_frame, fg_color="#1e293b", corner_radius=8)
                row_item.pack(fill="x", padx=5, pady=5)

                raw_target = item.get("filename") or item.get("target") or "Unknown"
                display_target = self.truncate_string(raw_target)
                time_str = item.get("timestamp", "")
                is_danger = item.get("is_danger", False)
                status_icon = "⚠️" if is_danger else "✅"
                status_color = "#f43f5e" if is_danger else "#10b981" 
                
                # Dòng trên: Kết quả
                btn_res = ctk.CTkButton(row_item, 
                                    text=f"{status_icon} {display_target}", 
                                    anchor="w", 
                                    fg_color="transparent", 
                                    text_color=status_color,
                                    hover_color="#334155",
                                    font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                                    command=lambda d=item: [self.view_history_item(d), history_window.destroy()])
                btn_res.pack(fill="x", padx=5, pady=(5,0))

                # Dòng dưới: Thời gian
                btn_time = ctk.CTkButton(row_item, 
                                    text=f"🕒 {time_str}", 
                                    anchor="w", 
                                    fg_color="transparent", 
                                    text_color="gray",
                                    hover_color="#334155",
                                    font=ctk.CTkFont(size=11),
                                    command=lambda d=item: [self.view_history_item(d), history_window.destroy()])
                btn_time.pack(fill="x", padx=5, pady=(0,5))

        except Exception as e:
            ctk.CTkLabel(scroll_frame, text=f"Lỗi: {e}").pack()

if __name__ == "__main__":
    app = MalwareScannerApp()
    app.mainloop()