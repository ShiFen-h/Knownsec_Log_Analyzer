import os
import sys
import gzip
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
import pandas as pd
import requests
from io import BytesIO
from tkinter.font import Font

# 攻击类型中英文映射
ATTACK_TYPE_MAPPING = {
    "SQLI": "SQL注入",
    "WEBSHELL": "webshell",
    "XSS": "XSS跨站",
    "FILEI": "敏感文件访问",
    "CODE": "代码执行",
    "SCANNER": "恶意扫描",
    "SPECIAL": "特殊攻击",
    "COLLECTOR": "恶意采集",
    "OS_COMMAND": "远程命令",
    "LRFI": "文件包含",
    "BASIC_CC": "基础CC攻击",
    "OTHER": "其它攻击",
    "GLOBAL_DEFENSE": "协同防御拦截",
    "LIMIT_RATE": "URL限速",
    "UA_BLACK": "UA黑名单",
    "DIR_LOCK": "后台锁",
    "URL_BLACK": "网址黑名单",
    "IP_BLACK": "IP黑名单",
    "AREA_LOCK": "区域访问控制",
    "APP_CC": "App防CC拦截",
    "PAC": "精准访问控制",
    "CC_IP_AREA": "IP访问区域限制",
    "ip_pv_ban": "IP访问行为限制",
    "STATUS_CODE": "高级扫描防护",
    "WAF_BLOCK": "动态阻断拦截",
    "GD_GOV_IP": "政府组织类",
    "GD_FINANCE_IP": "金融理财类",
    "GD_EDU_IP": "教育文化类",
    "GD_NEWS_IP": "新闻媒体类",
    "GD_MEDICAL_IP": "医疗健康类",
    "GD_OTHER_IP": "其它行业类",
    "PROXY_IP": "恶意代理屏蔽",
    "IDC_IP": "恶意IDC设备屏蔽",
    "BASESTATION_IP": "有攻击的基站屏蔽",
    "DIRECTSCAN_IP": "定向扫描器屏蔽",
    "AI_IP": "AI爬虫流量屏蔽",
    "ONION_IP": "洋葱路由屏蔽",
    "STARLINK_IP": "星联IP屏蔽",
    "SHODAN_IP": "撒旦IP屏蔽",
    "APT_IP": "APT攻击IP屏蔽",
    "GD_SCANER_IP": "漏洞扫描器攻击屏蔽",
    "GD_BRUTE_FORCE_IP": "网络爆破屏蔽",
    "GD_CYBER_PROTECTION_IP": "重保专项攻击屏蔽",
    "IDC_ACCESS_CONTROL_IP": "IDC访问控制"
}


class ModernButton(tk.Button):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            bg="#4a6fa5",
            fg="white",
            activebackground="#3a5a80",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            font=("Segoe UI", 10)
        )
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def on_enter(self, e):
        self.configure(bg="#3a5a80")

    def on_leave(self, e):
        self.configure(bg="#4a6fa5")


class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("日志分析工具")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f5f5f5")

        # 初始化日志数据
        self.log_data = None
        self.log_file_path = None

        # 创建主框架
        self.main_frame = tk.Frame(root, bg="#f5f5f5")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # 创建标签页
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # 下载日志标签页
        self.download_tab = tk.Frame(self.notebook, bg="#f5f5f5")
        self.notebook.add(self.download_tab, text="下载日志")
        self.setup_download_tab()

        # 上传日志标签页
        self.upload_tab = tk.Frame(self.notebook, bg="#f5f5f5")
        self.notebook.add(self.upload_tab, text="上传日志")
        self.setup_upload_tab()

        # 分析日志标签页
        self.analyze_tab = tk.Frame(self.notebook, bg="#f5f5f5")
        self.notebook.add(self.analyze_tab, text="分析日志")
        self.setup_analyze_tab()

        # 输出控制台
        self.console_frame = tk.LabelFrame(
            self.main_frame,
            text="控制台输出",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        self.console_frame.pack(fill=tk.BOTH, expand=False, pady=(10, 0))
        self.console = scrolledtext.ScrolledText(
            self.console_frame,
            height=10,
            wrap=tk.WORD,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333",
            selectbackground="#4a6fa5",
            selectforeground="white"
        )
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 重定向标准输出
        sys.stdout = TextRedirector(self.console, "stdout")
        sys.stderr = TextRedirector(self.console, "stderr")

    def setup_download_tab(self):
        """设置下载日志标签页"""
        # URL输入区
        url_frame = tk.LabelFrame(
            self.download_tab,
            text="日志URL列表",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        url_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        tk.Label(
            url_frame,
            text="请输入日志URL(每行一个):",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(anchor=tk.W, padx=5, pady=(0, 5))

        # 创建滚动文本框
        self.url_text = scrolledtext.ScrolledText(
            url_frame,
            height=8,
            wrap=tk.NONE,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333"
        )
        self.url_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 保存设置区
        save_frame = tk.LabelFrame(
            self.download_tab,
            text="保存设置",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        save_frame.pack(fill=tk.X, pady=(0, 10))

        # 保存路径
        path_row = tk.Frame(save_frame, bg="#f5f5f5")
        path_row.pack(fill=tk.X, pady=(0, 5))

        tk.Label(
            path_row,
            text="保存路径:",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.save_path_var = tk.StringVar()
        self.save_path_entry = tk.Entry(
            path_row,
            textvariable=self.save_path_var,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333",
            relief="solid",
            bd=1
        )
        self.save_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ModernButton(
            path_row,
            text="浏览...",
            command=self.select_save_path
        ).pack(side=tk.LEFT, padx=(5, 0))

        # 合并文件名
        merge_row = tk.Frame(save_frame, bg="#f5f5f5")
        merge_row.pack(fill=tk.X, pady=5)

        tk.Label(
            merge_row,
            text="合并文件名:",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.merge_filename_var = tk.StringVar(value="merged_logs.gz")
        self.merge_filename_entry = tk.Entry(
            merge_row,
            textvariable=self.merge_filename_var,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333",
            relief="solid",
            bd=1
        )
        self.merge_filename_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 下载按钮
        btn_frame = tk.Frame(self.download_tab, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        ModernButton(
            btn_frame,
            text="开始下载并合并",
            command=self.download_logs
        ).pack(pady=5)

        # 进度条
        progress_frame = tk.Frame(self.download_tab, bg="#f5f5f5")
        progress_frame.pack(fill=tk.X)

        tk.Label(
            progress_frame,
            text="进度:",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.download_progress = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            length=200,
            mode='determinate'
        )
        self.download_progress.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 状态标签
        self.download_status = tk.Label(
            progress_frame,
            text="等待开始...",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 9)
        )
        self.download_status.pack(side=tk.LEFT, padx=(10, 0))

    def setup_upload_tab(self):
        """设置上传日志标签页"""
        # 文件选择区
        upload_frame = tk.LabelFrame(
            self.upload_tab,
            text="上传日志文件",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        upload_frame.pack(fill=tk.BOTH, expand=False, pady=(0, 10))

        tk.Label(
            upload_frame,
            text="选择日志文件(支持多选):",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(anchor=tk.W, padx=5, pady=(0, 5))

        # 文件选择行
        file_row = tk.Frame(upload_frame, bg="#f5f5f5")
        file_row.pack(fill=tk.X, pady=5)

        self.upload_files_var = tk.StringVar()
        self.upload_files_entry = tk.Entry(
            file_row,
            textvariable=self.upload_files_var,
            state='readonly',
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333",
            relief="solid",
            bd=1
        )
        self.upload_files_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ModernButton(
            file_row,
            text="选择文件...",
            command=self.select_upload_files
        ).pack(side=tk.LEFT, padx=(5, 0))

        # 合并选项区
        options_frame = tk.LabelFrame(
            self.upload_tab,
            text="处理选项",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        options_frame.pack(fill=tk.X, pady=(0, 10))

        self.merge_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            options_frame,
            text="合并文件",
            variable=self.merge_var,
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9),
            activebackground="#f5f5f5",
            selectcolor="#f5f5f5"
        ).pack(anchor=tk.W, pady=5)

        merge_row = tk.Frame(options_frame, bg="#f5f5f5")
        merge_row.pack(fill=tk.X, pady=5)

        tk.Label(
            merge_row,
            text="合并文件名:",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.upload_merge_filename_var = tk.StringVar(value="merged_logs.gz")
        self.upload_merge_filename_entry = tk.Entry(
            merge_row,
            textvariable=self.upload_merge_filename_var,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333",
            relief="solid",
            bd=1
        )
        self.upload_merge_filename_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 上传按钮
        btn_frame = tk.Frame(self.upload_tab, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, pady=(0, 10))

        ModernButton(
            btn_frame,
            text="开始上传并分析",
            command=self.upload_logs
        ).pack(pady=5)

        # 进度条
        progress_frame = tk.Frame(self.upload_tab, bg="#f5f5f5")
        progress_frame.pack(fill=tk.X)

        tk.Label(
            progress_frame,
            text="进度:",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.upload_progress = ttk.Progressbar(
            progress_frame,
            orient=tk.HORIZONTAL,
            length=200,
            mode='determinate'
        )
        self.upload_progress.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # 状态标签
        self.upload_status = tk.Label(
            progress_frame,
            text="等待上传...",
            bg="#f5f5f5",
            fg="#666666",
            font=("Segoe UI", 9)
        )
        self.upload_status.pack(side=tk.LEFT, padx=(10, 0))

    def setup_analyze_tab(self):
        """设置分析日志标签页"""
        # 查询功能区
        query_frame = tk.LabelFrame(
            self.analyze_tab,
            text="日志查询",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        query_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            query_frame,
            text="查询IP(每行一个，支持模糊匹配):",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 9)
        ).pack(anchor=tk.W, padx=5, pady=(0, 5))

        # IP查询输入框
        self.ip_query_text = scrolledtext.ScrolledText(
            query_frame,
            height=5,
            wrap=tk.NONE,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333"
        )
        self.ip_query_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 按钮区
        btn_frame = tk.Frame(query_frame, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        ModernButton(
            btn_frame,
            text="查询IP攻击记录",
            command=self.query_ips
        ).pack(side=tk.LEFT, pady=5, padx=(0, 5))

        ModernButton(
            btn_frame,
            text="分析日志时间分布",
            command=self.analyze_time
        ).pack(side=tk.LEFT, pady=5)

        # 结果展示区
        result_frame = tk.LabelFrame(
            self.analyze_tab,
            text="分析结果",
            bg="#f5f5f5",
            fg="#333333",
            font=("Segoe UI", 10),
            relief="flat",
            bd=1
        )
        result_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # 结果文本框
        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            height=15,
            wrap=tk.WORD,
            font=('Segoe UI', 9),
            bg="white",
            fg="#333333",
            insertbackground="#333333"
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # 操作按钮区
        action_frame = tk.Frame(self.analyze_tab, bg="#f5f5f5")
        action_frame.pack(fill=tk.X)

        ModernButton(
            action_frame,
            text="复制结果",
            command=self.copy_results
        ).pack(side=tk.LEFT, pady=5, padx=(0, 5))

        ModernButton(
            action_frame,
            text="清空日志数据",
            command=self.clear_log_data
        ).pack(side=tk.LEFT, pady=5)

    def select_save_path(self):
        path = filedialog.askdirectory()
        if path:
            self.save_path_var.set(path)

    def select_upload_files(self):
        files = filedialog.askopenfilenames(
            title="选择日志文件",
            filetypes=[("日志文件", "*.gz *.log *.txt"), ("所有文件", "*.*")]
        )
        if files:
            self.upload_files_var.set("\n".join(files))

    def download_logs(self):
        urls = self.url_text.get("1.0", tk.END).strip().split("\n")
        save_path = self.save_path_var.get()
        merge_filename = self.merge_filename_var.get()

        if not urls or not urls[0]:
            messagebox.showerror("错误", "请输入至少一个URL")
            return

        if not save_path:
            messagebox.showerror("错误", "请选择保存路径")
            return

        if not merge_filename:
            merge_filename = "merged_logs.gz"

            # 创建保存目录
        os.makedirs(save_path, exist_ok=True)

        # 启动下载线程
        thread = threading.Thread(
            target=self._download_logs_thread,
            args=(urls, save_path, merge_filename),
            daemon=True
        )
        thread.start()

    def _download_logs_thread(self, urls, save_path, merge_filename):
        self.download_progress["value"] = 0
        self.download_progress["maximum"] = len(urls)
        self.download_status.config(text="开始下载...")

        downloaded_files = []
        failed_urls = []

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        for i, url in enumerate(urls):
            try:
                if not url.strip():
                    continue

                self.download_status.config(text=f"正在下载: {url}")
                print(f"正在下载: {url}")

                response = requests.get(url, headers=headers, stream=True, timeout=30)
                response.raise_for_status()

                # 生成临时文件名
                temp_filename = os.path.join(save_path, f"temp_{i}.gz")

                with open(temp_filename, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                downloaded_files.append(temp_filename)
                self.download_progress["value"] = i + 1
                print(f"成功下载: {url}")

            except Exception as e:
                failed_urls.append(url)
                print(f"下载失败: {url} - {str(e)}", file=sys.stderr)

                # 合并文件
        if downloaded_files:
            try:
                self.download_status.config(text="正在合并文件...")
                print("开始合并下载的日志文件...")

                merged_path = os.path.join(save_path, merge_filename)
                self._merge_gz_files(downloaded_files, merged_path)

                # 删除临时文件
                for f in downloaded_files:
                    try:
                        os.remove(f)
                    except:
                        pass

                        # 加载合并后的日志
                self._load_log_data(merged_path)

                self.download_status.config(text=f"成功下载 {len(downloaded_files)} 个文件，失败 {len(failed_urls)} 个")
                print(f"合并完成，保存到: {merged_path}")
                print(f"下载结果: 成功 {len(downloaded_files)} 个，失败 {len(failed_urls)} 个")
                if failed_urls:
                    print("失败的URL:")
                    for url in failed_urls:
                        print(f"- {url}")

            except Exception as e:
                self.download_status.config(text="合并文件失败")
                print(f"合并文件失败: {str(e)}", file=sys.stderr)
        else:
            self.download_status.config(text="没有文件下载成功")
            print("没有文件下载成功", file=sys.stderr)

    def _merge_gz_files(self, input_files, output_file):
        with gzip.open(output_file, 'wb') as f_out:
            for file in input_files:
                try:
                    with gzip.open(file, 'rb') as f_in:
                        f_out.write(f_in.read())
                except Exception as e:
                    print(f"合并文件 {file} 时出错: {str(e)}", file=sys.stderr)
                    continue

    def upload_logs(self):
        files = self.upload_files_var.get().split("\n")
        merge = self.merge_var.get()
        merge_filename = self.upload_merge_filename_var.get()

        if not files or not files[0]:
            messagebox.showerror("错误", "请选择至少一个文件")
            return

        if merge and not merge_filename:
            merge_filename = "merged_logs.gz"

            # 启动上传线程
        thread = threading.Thread(
            target=self._upload_logs_thread,
            args=(files, merge, merge_filename),
            daemon=True
        )
        thread.start()

    def _upload_logs_thread(self, files, merge, merge_filename):
        self.upload_progress["value"] = 0
        self.upload_progress["maximum"] = len(files)
        self.upload_status.config(text="开始处理文件...")

        valid_files = []

        for i, file in enumerate(files):
            if not file.strip():
                continue

            self.upload_status.config(text=f"正在处理: {os.path.basename(file)}")
            print(f"正在处理: {file}")

            try:
                # 检查文件是否存在
                if not os.path.exists(file):
                    print(f"文件不存在: {file}", file=sys.stderr)
                    continue

                    # 检查文件是否为空
                if os.path.getsize(file) == 0:
                    print(f"文件为空: {file}", file=sys.stderr)
                    continue

                valid_files.append(file)
                self.upload_progress["value"] = i + 1

            except Exception as e:
                print(f"处理文件 {file} 时出错: {str(e)}", file=sys.stderr)

        if valid_files:
            try:
                if merge:
                    self.upload_status.config(text="正在合并文件...")
                    print("开始合并上传的日志文件...")

                    # 如果只有一个文件且是.gz，直接使用
                    if len(valid_files) == 1 and valid_files[0].endswith('.gz'):
                        merged_path = valid_files[0]
                    else:
                        # 合并文件
                        merged_path = os.path.join(os.path.dirname(valid_files[0]), merge_filename)
                        self._merge_gz_files(valid_files, merged_path)

                        # 加载合并后的日志
                    self._load_log_data(merged_path)

                    self.upload_status.config(text="文件合并完成")
                    print(f"合并完成，保存到: {merged_path}")
                else:
                    # 只加载第一个文件
                    self._load_log_data(valid_files[0])
                    self.upload_status.config(text="文件加载完成")
                    print(f"加载文件: {valid_files[0]}")

            except Exception as e:
                self.upload_status.config(text="处理文件失败")
                print(f"处理文件失败: {str(e)}", file=sys.stderr)
        else:
            self.upload_status.config(text="没有有效文件")
            print("没有有效文件", file=sys.stderr)

    def _load_log_data(self, file_path):
        try:
            self.upload_status.config(text="正在解析日志...")
            print(f"开始解析日志文件: {file_path}")

            # 读取.gz文件
            with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                lines = f.readlines()

                # 解析日志
            data = []
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 26:  # 确保有足够字段
                    try:
                        # 根据字段定义解析
                        log_entry = {
                            'time': parts[1],
                            'duration': float(parts[2]),
                            'attack_type': parts[3],
                            'block_type': parts[4],
                            'client_ip': parts[5],
                            'proxy_ips': parts[6],
                            'domain': parts[8],
                            'url': parts[9],
                            'method': parts[10],
                            'referer': parts[11],
                            'cache_status': parts[12],
                            'status_code': int(parts[14]),
                            'size': int(parts[15]),
                            'user_agent': parts[17],
                            'port_protocol': parts[19],
                            'rule_id': parts[22],
                            'client_port': parts[23]
                        }
                        data.append(log_entry)
                    except (IndexError, ValueError) as e:
                        print(f"解析日志行出错: {line.strip()} - {str(e)}", file=sys.stderr)
                        continue

            self.log_data = pd.DataFrame(data)
            self.log_file_path = file_path
            self.upload_status.config(text="日志解析完成")
            print(f"日志解析完成，共 {len(self.log_data)} 条记录")

        except Exception as e:
            self.upload_status.config(text="解析日志失败")
            print(f"解析日志失败: {str(e)}", file=sys.stderr)
            self.log_data = None
            self.log_file_path = None

    def query_ips(self):
        if self.log_data is None:
            messagebox.showerror("错误", "请先下载或上传日志文件")
            return

        ip_text = self.ip_query_text.get("1.0", tk.END).strip()
        if not ip_text:
            messagebox.showerror("错误", "请输入至少一个IP")
            return

        ips = [ip.strip() for ip in ip_text.split("\n") if ip.strip()]

        try:
            # 查询IP
            results = []
            for ip in ips:
                # 模糊匹配
                matched = self.log_data[self.log_data['client_ip'].str.contains(ip, regex=False)]

                if not matched.empty:
                    # 按攻击类型和状态码分组
                    grouped = matched.groupby(['client_ip', 'attack_type',
                                               'status_code']).size().reset_index(name='count')

                    for _, row in grouped.iterrows():
                        attack_type = ATTACK_TYPE_MAPPING.get(row['attack_type'], row['attack_type'])
                        results.append({
                            'IP': row['client_ip'],
                            '攻击类型': attack_type,
                            '状态码': row['status_code'],
                            '次数': row['count']
                        })

            if results:
                # 转换为DataFrame
                result_df = pd.DataFrame(results)

                # 如果是单个IP，按次数排序
                if len(ips) == 1:
                    result_df = result_df.sort_values('次数', ascending=False)
                else:
                    # 多个IP按IP排序
                    result_df = result_df.sort_values('IP')

                    # 合并相同IP的不同攻击类型
                merged_results = []
                for ip, group in result_df.groupby('IP'):
                    attack_types = ", ".join(group['攻击类型'].unique())
                    status_codes = ", ".join(map(str, sorted(group['状态码'].unique())))
                    total_count = group['次数'].sum()

                    merged_results.append({
                        'IP': ip,
                        '攻击类型': attack_types,
                        '状态码': status_codes,
                        '总次数': total_count
                    })

                    # 显示结果
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, f"共分析 {len(self.log_data)} 条日志\n\n")

                if len(ips) == 1:
                    self.result_text.insert(tk.END, f"查询IP: {ips[0]} 的详细攻击记录:\n\n")
                else:
                    self.result_text.insert(tk.END, f"查询 {len(ips)} 个IP的攻击记录:\n\n")

                    # 显示合并后的结果
                for result in merged_results:
                    self.result_text.insert(tk.END,
                                            f"IP: {result['IP']}\n"
                                            f"攻击类型: {result['攻击类型']}\n"
                                            f"状态码: {result['状态码']}\n"
                                            f"总次数: {result['总次数']}\n"
                                            f"{'-' * 50}\n"
                                            )

                print(f"查询完成，找到 {len(merged_results)} 个IP的攻击记录")
            else:
                self.result_text.delete(1.0, tk.END)
                self.result_text.insert(tk.END, "没有找到匹配的IP攻击记录")
                print("没有找到匹配的IP攻击记录")

        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"查询出错: {str(e)}")
            print(f"查询出错: {str(e)}", file=sys.stderr)

    def analyze_time(self):
        if self.log_data is None:
            messagebox.showerror("错误", "请先下载或上传日志文件")
            return

        try:
            # 提取日期部分
            self.log_data['date'] = self.log_data['time'].str.split('<SP>').str[0]

            # 统计日期分布
            date_counts = self.log_data['date'].value_counts().sort_index()

            # 显示结果
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"共分析 {len(self.log_data)} 条日志\n\n")
            self.result_text.insert(tk.END, "日志时间分布:\n\n")

            for date, count in date_counts.items():
                self.result_text.insert(tk.END, f"{date}: {count} 条\n")

            print("时间分析完成")

        except Exception as e:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"时间分析出错: {str(e)}")
            print(f"时间分析出错: {str(e)}", file=sys.stderr)

    def clear_log_data(self):
        self.log_data = None
        self.log_file_path = None
        self.result_text.delete(1.0, tk.END)
        print("已清空日志数据")

    def copy_results(self):
        result = self.result_text.get("1.0", tk.END)
        if result.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            print("结果已复制到剪贴板")
        else:
            print("没有结果可复制", file=sys.stderr)


class TextRedirector:
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag

    def write(self, text):
        self.widget.configure(state="normal")
        if self.tag == "stderr":
            self.widget.insert("end", text, ("error",))
        else:
            self.widget.insert("end", text, (self.tag,))
        self.widget.configure(state="disabled")
        self.widget.see("end")

    def flush(self):
        pass


if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()