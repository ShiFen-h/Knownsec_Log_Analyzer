#增加了日志源管理，若之前有已加载的日志，则弹窗提示清理之前加载的日志。
#优化下载的合并进度条
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import gzip
import time
import threading
import requests
import os
import random
from collections import defaultdict, Counter
import datetime
import re
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
import matplotlib
matplotlib.use('Agg')  # 使用非交互式后端

class LogAnalyzerApp:
    def __init__(self, master):
        # 首先初始化所有属性
        self.uploaded_log_content = None
        self.latest_downloaded_log_path = None
        self._log_content_cache = None
        
        self.master = master
        self.master.title("日志分析工具")
        self.master.geometry("1800x1400") 
        
        # 初始化StringVar变量，确保在创建相关UI组件之前完成
        self.url_var = tk.StringVar()
        self.path_var = tk.StringVar()
        self.merge_name_var = tk.StringVar(value="merged_log.gz")
        
        # 添加缓存
        self._analysis_names = {
            'url_top': 'URL TOP',
            'ip_top': '访问IP TOP',
            'ua_top': '请求UA TOP',
            'status_top': '状态码 TOP',
            'url_ip_top': 'URL TOP IP统计',
            'domain_url_top': '域名及URL TOP',
            'domain_url_no_param_top': '域名及URL TOP(去参)',
            'error_status_top': '40X/50X异常状态码 TOP',
            'response_time_dist': '响应时间分布',
            'traffic_ip_top': '消耗流量TOP IP',
            'traffic_url_no_param_top': '流量TOP URL(去参)',
            'traffic_domain_top': '流量TOP域名',
            'concurrent_top': '并发TOP统计'
        }

        # 创建Notebook作为标签容器
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # 创建四个标签页
        self.create_download_tab()
        self.create_upload_tab()
        self.create_custom_analysis_tab()
        self.create_common_analysis_tab()

        # 设置中文字体
        self.font = FontProperties(fname=r"C:\Windows\Fonts\simhei.ttf")
        plt.rcParams['font.sans-serif'] = ['SimHei']
        plt.rcParams['axes.unicode_minus'] = False

    def _get_analysis_name(self, key):
        """获取分析选项的显示名称"""
        analysis_names = {
            'url_top': 'URL TOP',
            'url_top_no_param': 'URL TOP(去参)',  # 使用中文括号
            'ip_top': '访问IP TOP',
            'ua_top': '请求UA TOP',
            'status_top': '状态码 TOP',
            'url_ip_top': 'URL TOP IP统计',
            'domain_url_top': '域名及URL TOP',
            'domain_url_no_param_top': '域名及URL TOP(去参)',
            'error_status_top': '40X/50X异常状态码 TOP',
            'response_time_dist': '响应时间分布',
            'traffic_ip_top': '消耗流量TOP IP',
            'traffic_url_no_param_top': '流量TOP URL(去参)',
            'traffic_domain_top': '流量TOP域名',
            'concurrent_top': '并发TOP统计'
        }
        return analysis_names.get(key, key)

    def _update_status(self, message, widget_name="result_text", prefix=""):
        """统一的状态更新方法"""
        def update_text():
            widget = getattr(self, widget_name, self.result_text)
            widget.config(state=tk.NORMAL)
            if prefix:
                widget.insert(tk.END, f"[{prefix}] {message}\n")
            else:
                widget.insert(tk.END, f"{message}\n")
            widget.see(tk.END)
            widget.config(state=tk.DISABLED)
        self.master.after(0, update_text)

    def _get_log_content(self):
        """获取日志内容（带缓存）"""
        try:
            # 如果已经有缓存，直接返回
            if self._log_content_cache is not None:
                return self._log_content_cache

            # 尝试读取下载的日志文件（优先使用下载的日志）
            if hasattr(self, 'latest_downloaded_log_path') and self.latest_downloaded_log_path:
                if os.path.exists(self.latest_downloaded_log_path):
                    try:
                        # 根据文件扩展名决定打开方式
                        if self.latest_downloaded_log_path.endswith('.gz'):
                            with gzip.open(self.latest_downloaded_log_path, 'rt', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        else:
                            with open(self.latest_downloaded_log_path, 'rt', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        
                        if content:
                            self._log_content_cache = content
                            return content
                    except Exception as e:
                        messagebox.showerror("错误", f"读取日志文件失败: {str(e)}")
                        return None

            # 如果没有下载的日志，则使用上传的日志内容
            if hasattr(self, 'uploaded_log_content') and self.uploaded_log_content:
                self._log_content_cache = self.uploaded_log_content
                return self._log_content_cache
            
            # 如果既没有下载的日志也没有上传的日志，显示错误信息
            messagebox.showwarning("警告", "没有可用的日志内容。请先上传或下载日志文件。")
            return None
            
        except Exception as e:
            messagebox.showerror("错误", f"获取日志内容时发生错误: {str(e)}")
            return None

    def _clear_log_source(self):
        """清空日志源"""
        if hasattr(self, 'uploaded_log_content'):
            delattr(self, 'uploaded_log_content')
        if hasattr(self, 'latest_downloaded_log_path'):
            delattr(self, 'latest_downloaded_log_path')
        
        # 清空缓存
        self._log_content_cache = None
        
        # 清空显示
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.config(state=tk.DISABLED)
        
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        
        # 禁用校验按钮
        self.validate_upload_btn.config(state=tk.DISABLED)
        
        messagebox.showinfo("提示", "日志源已清空")

    def _merge_gz_files(self, input_files, output_file):
        """合并gz文件的方法"""
        try:
            self._update_status(f"开始合并 {len(input_files)} 个文件到: {os.path.basename(output_file)}")
            
            # 确保输出目录存在
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with gzip.open(output_file, 'wb') as f_out:
                for file_idx, file_path in enumerate(input_files):
                    if not os.path.exists(file_path):
                        self._update_status(f"警告: 文件不存在，跳过: {os.path.basename(file_path)}")
                        continue
                        
                    try:
                        self._update_status(f"正在合并: {os.path.basename(file_path)} ({file_idx + 1}/{len(input_files)})")
                        
                        # 尝试作为gz文件读取
                        try:
                            with gzip.open(file_path, 'rb') as f_in:
                                while True:
                                    chunk = f_in.read(8192)
                                    if not chunk:
                                        break
                                    f_out.write(chunk)
                        except Exception as gz_error:
                            # 如果不是gz格式，尝试作为普通文件读取
                            self._update_status(f"文件不是gz格式，尝试作为普通文件读取: {os.path.basename(file_path)}")
                            with open(file_path, 'rb') as f_in:
                                while True:
                                    chunk = f_in.read(8192)
                                    if not chunk:
                                        break
                                    f_out.write(chunk)
                        
                        # 每合并完一个文件，更新进度条
                        current_progress = self.progress_bar['value']
                        self.progress_bar['value'] = current_progress + (1.0 / len(input_files))
                        self.master.update_idletasks()
                            
                    except Exception as e_merge:
                        self._update_status(f"合并文件时出错: {os.path.basename(file_path)} - {str(e_merge)}")
                        continue
            
            # 获取合并后文件的大小
            merged_size = os.path.getsize(output_file)
            self._update_status(f"成功合并文件: {os.path.basename(output_file)} (大小: {self._format_size(merged_size)})")
            
            return True
            
        except Exception as e:
            self._update_status(f"合并文件失败: {str(e)}")
            return False

    def create_upload_tab(self):
        """创建日志上传标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="日志上传")
        
        # 文件类型过滤器
        self.filetypes = [
            ("Gzip压缩文件", "*.gz"),
            ("文本文件", "*.txt"),
            ("日志文件", "*.log"),
            ("所有文件", "*.*")
        ]
        
        # 上传区域
        upload_frame = ttk.LabelFrame(frame, text="上传日志文件", padding=10)
        upload_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
        
        # 文件选择按钮
        self.select_log_btn = ttk.Button(
            upload_frame, 
            text="选择日志文件",
            command=self._select_log_file,
            bootstyle=PRIMARY,
            takefocus=0  # 使用0而不是False
        )
        self.select_log_btn.bind('<FocusIn>', lambda e: self.master.focus_set())
        self.select_log_btn.configure(style='TButton')
        self.select_log_btn.pack(pady=10)
        
        # 文件路径显示
        self.file_path_var = tk.StringVar()
        file_path_label = ttk.Label(
            upload_frame, 
            textvariable=self.file_path_var,
            wraplength=400
        )
        file_path_label.pack()
        
        # 添加校验按钮
        self.validate_upload_btn = ttk.Button(
            upload_frame,
            text="校验上传日志",
            command=self._validate_uploaded_log,
            bootstyle=INFO,  # 保持原有的 bootstyle
            takefocus=0,  # 禁用焦点
            state=tk.DISABLED  # 初始状态为禁用
        )
        self.validate_upload_btn.pack(pady=5)
        # 确保按钮不会获得焦点
        self.validate_upload_btn.bind('<FocusIn>', lambda e: self.master.focus_set())
        
        self.progress = ttk.Progressbar(
            upload_frame, 
            orient=tk.HORIZONTAL, 
            length=400, 
            mode='determinate'
        )
        self.progress.pack(pady=10)
        
        # 日志预览区域
        preview_frame = ttk.LabelFrame(frame, text="日志预览", padding=10)
        preview_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
        
        self.preview_text = tk.Text(
            preview_frame, 
            height=10, 
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)
    
    def _select_log_file(self):
        """选择日志文件"""
        # 检查是否已有加载的日志
        has_uploaded_log = hasattr(self, 'uploaded_log_content') and self.uploaded_log_content is not None
        has_downloaded_log = hasattr(self, 'latest_downloaded_log_path') and self.latest_downloaded_log_path is not None
        
        if has_uploaded_log or has_downloaded_log:
            if messagebox.askyesno("提示", "当前已有加载的日志，是否先清空已加载的日志？"):
                self._clear_log_source()
            else:
                return

        file_paths = filedialog.askopenfilenames(
            title="选择日志文件",
            filetypes=self.filetypes
        )
        if file_paths:
            self.file_path_var.set(f"已选择 {len(file_paths)} 个文件")
            # 清空预览区域
            self.preview_text.config(state=tk.NORMAL)
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, f"已选择 {len(file_paths)} 个文件:\n")
            self.preview_text.config(state=tk.DISABLED)
            self._load_log_files(file_paths)
    
    def _load_log_files(self, file_paths):
        """加载并合并多个日志文件"""
        start_time = time.time()
        try:
            all_lines = []
            total_count = 0
            self.progress['value'] = 0
            self.progress['maximum'] = len(file_paths)

            # 显示每个文件的大小
            total_size = 0
            for file_path in file_paths:
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    total_size += file_size
                    if file_size < 1024:
                        size_str = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_str = f"{file_size/1024:.2f} KB"
                    elif file_size < 1024 * 1024 * 1024:
                        size_str = f"{file_size/(1024*1024):.2f} MB"
                    else:
                        size_str = f"{file_size/(1024*1024*1024):.2f} GB"
                    self.preview_text.config(state=tk.NORMAL)
                    self.preview_text.insert(tk.END, f"- {os.path.basename(file_path)} (大小: {size_str})\n")
                    self.preview_text.config(state=tk.DISABLED)

            for i, file_path in enumerate(file_paths):
                if not file_path: # 跳过无效路径
                    self.progress['value'] = i + 1
                    continue

                if file_path.endswith('.gz'):
                    with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                else:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                all_lines.extend(lines)
                total_count += len(lines)
                self.progress['value'] = i + 1
                self.master.update_idletasks() # 更新进度条
            
            self.uploaded_log_content = "".join(all_lines) # 使用 join 保持原始换行
            
            # 更新UI显示合并的文件名和总日志条数
            if hasattr(self, 'preview_text'): # 确保 preview_text 已创建
                self.preview_text.config(state=tk.NORMAL)
                if len(file_paths) > 1:
                    merge_name = self.merge_name_var.get()
                    if not merge_name.endswith('.gz'):
                        merge_name += '.gz'
                    # 显示总文件大小
                    if total_size < 1024:
                        size_str = f"{total_size} B"
                    elif total_size < 1024 * 1024:
                        size_str = f"{total_size/1024:.2f} KB"
                    elif total_size < 1024 * 1024 * 1024:
                        size_str = f"{total_size/(1024*1024):.2f} MB"
                    else:
                        size_str = f"{total_size/(1024*1024*1024):.2f} GB"
                    self.preview_text.insert(tk.END, f"\n将合并为 {merge_name}，共 {total_count} 条日志，总大小: {size_str}，保存在 {os.path.dirname(file_paths[0])}\n")
                else:
                    self.preview_text.insert(tk.END, f"\n共加载 {total_count} 条日志\n")
                self.preview_text.config(state=tk.DISABLED)
                elapsed = time.time() - start_time
                self.preview_text.config(state=tk.NORMAL)
                self.preview_text.insert(tk.END, f"\n本次日志加载耗时: {elapsed:.2f} 秒\n")
                self.preview_text.config(state=tk.DISABLED)
            else: # 如果 preview_text 不存在，则在状态栏显示
                self.file_path_var.set(f"已加载 {len(file_paths)} 个文件, 总行数: {total_count}")

            self.progress['value'] = self.progress['maximum'] # 确保进度条满
            
            # 启用校验按钮
            self.validate_upload_btn.config(state=tk.NORMAL)
            
        except Exception as e:
            self.file_path_var.set(f"加载或合并文件失败: {str(e)}")
            self.progress['value'] = 0
            if hasattr(self, 'preview_text'): # 确保 preview_text 已创建
                self.preview_text.config(state=tk.NORMAL)
                self.preview_text.insert(tk.END, f"\n错误: {str(e)}\n")
                self.preview_text.config(state=tk.DISABLED)
            # 禁用校验按钮
            self.validate_upload_btn.config(state=tk.DISABLED)
    
    def _update_upload_status(self, message, is_error=False):
        """更新上传状态标签或消息框。"""
        # 这个方法可以用来更新UI上的状态标签，如果还没有实现，可以暂时用print
        print(f"校验状态: {message}")
        if is_error:
            messagebox.showerror("校验错误", message)
        # else:
        #     messagebox.showinfo("校验信息", message) # 可以选择是否为普通消息也弹窗

    def _execute_upload_validation(self, log_content):
        """执行上传日志校验的核心逻辑（后台线程）"""
        try:
            lines = log_content.splitlines()
            total_log_count = len(lines)
            date_counts = defaultdict(int)
            
            # 不清空预览区域，而是添加分隔线
            self.master.after(0, lambda: self.preview_text.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.preview_text.insert(tk.END, "\n" + "="*50 + "\n"))
            self.master.after(0, lambda: self.preview_text.insert(tk.END, "--- 开始校验日志 ---\n"))
            
            # 显示日志前3行和后3行
            self.master.after(0, lambda: self.preview_text.insert(tk.END, "--- 日志预览 ---\n"))
            if total_log_count > 0:
                # 显示前3行
                for i in range(min(3, total_log_count)):
                    self.master.after(0, lambda line=lines[i]: self.preview_text.insert(tk.END, line + "\n"))
                
                if total_log_count > 6:
                    self.master.after(0, lambda: self.preview_text.insert(tk.END, "... (中间内容已省略) ...\n"))
                
                # 显示后3行
                for i in range(max(3, total_log_count-3), total_log_count):
                    self.master.after(0, lambda line=lines[i]: self.preview_text.insert(tk.END, line + "\n"))
            
            self.master.after(0, lambda: self.preview_text.insert(tk.END, "\n--- 日志统计信息 ---\n"))
            
            # 匹配 YYYY-MM-DD<SP>HH:MM:SS 格式
            date_pattern = re.compile(r'(\d{4}-\d{2}-\d{2})<SP>')
            
            for line in lines:
                match = date_pattern.search(line)
                if match:
                    date_str = match.group(1)
                    date_counts[date_str] += 1
            
            if date_counts:
                self.master.after(0, lambda: self.preview_text.insert(tk.END, "按日期统计日志条数:\n"))
                for date, count in sorted(date_counts.items()):
                    self.master.after(0, lambda d=date, c=count: self.preview_text.insert(tk.END, f"  {d}: {c} 条\n"))
            else:
                self.master.after(0, lambda: self.preview_text.insert(tk.END, "未能在日志中提取到日期信息。\n"))
                # 显示前几行日志内容以帮助调试
                self.master.after(0, lambda: self.preview_text.insert(tk.END, "\n日志前几行内容（用于调试）:\n"))
                for i in range(min(5, total_log_count)):
                    self.master.after(0, lambda line=lines[i]: self.preview_text.insert(tk.END, f"  {line}\n"))
            
            self.master.after(0, lambda: self.preview_text.insert(tk.END, f"\n已校验总日志条数: {total_log_count}\n"))
            self.master.after(0, lambda: self.preview_text.insert(tk.END, "--- 日志校验完毕 ---\n"))
            
            # 设置预览文本为只读
            self.master.after(0, lambda: self.preview_text.config(state=tk.DISABLED))
            # 滚动到底部
            self.master.after(0, lambda: self.preview_text.see(tk.END))

        except Exception as e:
            self.master.after(0, lambda: self.preview_text.config(state=tk.NORMAL))
            self.master.after(0, lambda: self.preview_text.insert(tk.END, f"校验过程中发生错误: {str(e)}\n"))
            self.master.after(0, lambda: self.preview_text.config(state=tk.DISABLED))
        finally:
            # 确保在主线程中重新启用校验按钮
            if hasattr(self, 'validate_upload_btn'):
                self.master.after(0, lambda: self.validate_upload_btn.config(state=tk.NORMAL))

    def _validate_uploaded_log(self):
        """校验上传的日志文件（在单独的线程中）。"""
        if not self.uploaded_log_content:
            messagebox.showwarning("校验警告", "请先上传日志文件后再进行校验。")
            return

        if hasattr(self, 'validate_upload_btn'): # 确保按钮存在
            self.validate_upload_btn.config(state=tk.DISABLED) # 禁用按钮防止重复点击
        
        # 在新线程中运行校验，以避免UI冻结
        validation_thread = threading.Thread(target=self._execute_upload_validation, args=(self.uploaded_log_content,), daemon=True)
        validation_thread.start()
    # --- 以上是需要粘贴的三个方法 ---

    def create_custom_analysis_tab(self):
        """创建自定义分析标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="自定义分析")
        
        # 字段中文名列表
        self.custom_fields = [
            '预留1', '请求时间', '请求耗时', '攻击类型', '拦截类型', '客户端IP', '代理IP',
            '预留2', '域名', 'URL', '请求方法', 'Referer', '缓存命中状态', '预留3',
            '状态码', '页面大小', '预留4', 'User-Agent', '预留5', '端口+协议类型',
            '预留6', '预留7', '规则ID', '客户端源端口', '预留8', '预留9'
        ]

        # 时间过滤区
        filter_frame = ttk.LabelFrame(frame, text="时间过滤", padding=10)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        self.enable_time_filter = tk.BooleanVar(value=False)
        time_filter_cb = ttk.Checkbutton(filter_frame, text="启用时间过滤", variable=self.enable_time_filter, command=self._on_time_filter_toggle)
        time_filter_cb.pack(side=tk.LEFT)
        # 起始和结束时间控件（精确到秒）
        self.start_time_var = tk.StringVar()
        self.end_time_var = tk.StringVar()
        self.start_time_entry = ttk.Entry(filter_frame, textvariable=self.start_time_var, width=20, state=tk.DISABLED)
        self.end_time_entry = ttk.Entry(filter_frame, textvariable=self.end_time_var, width=20, state=tk.DISABLED)
        ttk.Label(filter_frame, text="起始时间:").pack(side=tk.LEFT, padx=5)
        self.start_time_entry.pack(side=tk.LEFT)
        ttk.Label(filter_frame, text="结束时间:").pack(side=tk.LEFT, padx=5)
        self.end_time_entry.pack(side=tk.LEFT)
        # 时间选择按钮
        self.start_time_btn = ttk.Button(filter_frame, text="选择", command=lambda: self._pick_time(self.start_time_var), state=tk.DISABLED)
        self.start_time_btn.pack(side=tk.LEFT, padx=2)
        self.end_time_btn = ttk.Button(filter_frame, text="选择", command=lambda: self._pick_time(self.end_time_var), state=tk.DISABLED)
        self.end_time_btn.pack(side=tk.LEFT, padx=2)

        # 字段选择区
        fields_frame = ttk.LabelFrame(frame, text="日志输出字段选择", padding=10)
        fields_frame.pack(fill=tk.X, padx=10, pady=5)
        self.custom_field_vars = []
        for i, field in enumerate(self.custom_fields):
            var = tk.BooleanVar(value=False)
            self.custom_field_vars.append(var)
            cb = ttk.Checkbutton(fields_frame, text=field, variable=var)
            cb.grid(row=i//7, column=i%7, sticky='w', padx=3, pady=2)

        # 模糊匹配区
        match_frame = ttk.LabelFrame(frame, text="模糊匹配（每行一个条件，支持包含/不包含，支持自定义选择多个条件之间的逻辑关系）", padding=10)
        match_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 创建顶部选项框架
        options_frame = ttk.Frame(match_frame)
        options_frame.pack(fill=tk.X, pady=(0, 5))
        
        # 匹配模式选项
        match_mode_frame = ttk.Frame(options_frame)
        match_mode_frame.pack(side=tk.LEFT, padx=10)
        ttk.Label(match_mode_frame, text="匹配模式:").pack(side=tk.LEFT)
        self.match_mode = tk.StringVar(value="include")
        ttk.Radiobutton(match_mode_frame, text="包含", variable=self.match_mode, value="include").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(match_mode_frame, text="不包含", variable=self.match_mode, value="exclude").pack(side=tk.LEFT, padx=5)
        
        # 逻辑关系选项
        logic_frame = ttk.Frame(options_frame)
        logic_frame.pack(side=tk.LEFT, padx=10)
        ttk.Label(logic_frame, text="条件逻辑:").pack(side=tk.LEFT)
        self.logic_relation = tk.StringVar(value="and")
        ttk.Radiobutton(logic_frame, text="逻辑且(AND)", variable=self.logic_relation, value="and").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(logic_frame, text="逻辑或(OR)", variable=self.logic_relation, value="or").pack(side=tk.LEFT, padx=5)
        
        # 文本输入区域
        text_frame = ttk.Frame(match_frame)
        text_frame.pack(fill=tk.X, padx=5)
        
        self.match_text = tk.Text(text_frame, height=5, width=100)
        self.match_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.match_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.match_text.configure(yscrollcommand=scrollbar.set)

        # 输出行数和去重
        options_frame = ttk.Frame(frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(options_frame, text="输出行数:").pack(side=tk.LEFT, padx=5)
        self.output_lines_var = tk.StringVar(value="20")  # 修改默认值为20
        ttk.Entry(options_frame, textvariable=self.output_lines_var, width=8).pack(side=tk.LEFT)
        self.dedup_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="去重统计", variable=self.dedup_var).pack(side=tk.LEFT, padx=10)

        # 分析和清空按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        self.custom_analyze_btn = ttk.Button(btn_frame, text="开始分析", command=self._start_custom_analysis, bootstyle=SUCCESS)
        self.custom_analyze_btn.pack(side=tk.LEFT, padx=5)
        self.custom_clear_btn = ttk.Button(btn_frame, text="清空已加载日志", command=self._clear_log_source, bootstyle=DANGER)
        self.custom_clear_btn.pack(side=tk.LEFT, padx=5)

        # 结果输出区
        result_frame = ttk.LabelFrame(frame, text="分析结果", padding=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.custom_result_text = tk.Text(result_frame, height=20, wrap=tk.WORD, state=tk.DISABLED)
        self.custom_result_text.pack(fill=tk.BOTH, expand=True)

    def _on_time_filter_toggle(self):
        state = tk.NORMAL if self.enable_time_filter.get() else tk.DISABLED
        self.start_time_entry.config(state=state)
        self.end_time_entry.config(state=state)
        self.start_time_btn.config(state=state)
        self.end_time_btn.config(state=state)

    def _pick_time(self, target_var):
        # 这里可以弹出自定义时间选择器，暂时用简单输入框模拟
        import tkinter.simpledialog
        value = tkinter.simpledialog.askstring("选择时间", "请输入时间 (格式: YYYY-MM-DD HH:MM:SS)")
        if value:
            target_var.set(value)

    def _start_custom_analysis(self):
        """开始自定义分析"""
        if not hasattr(self, 'uploaded_log_content') and not hasattr(self, 'latest_downloaded_log_path'):
            messagebox.showwarning("警告", "请先上传或下载日志文件")
            return

        try:
            # 获取日志内容
            log_content = self._get_log_content()
            if not log_content:
                messagebox.showerror("错误", "无法获取日志内容")
                return

            # 解析日志行
            log_lines = log_content.splitlines()
            if not log_lines:
                messagebox.showwarning("警告", "日志内容为空")
                return

            # 获取用户设置
            selected_fields = [i for i, var in enumerate(self.custom_field_vars, 1) if var.get()]
            output_lines = int(self.output_lines_var.get())
            dedup = self.dedup_var.get()
            match_conditions = [line.strip() for line in self.match_text.get("1.0", tk.END).splitlines() if line.strip()]
            match_mode = self.match_mode.get()

            # 时间过滤
            if self.enable_time_filter.get():
                start_time = self.start_time_var.get()
                end_time = self.end_time_var.get()
                if not start_time or not end_time:
                    messagebox.showwarning("警告", "请设置完整的时间范围")
                    return
                try:
                    # 转换时间格式
                    start_time = start_time.replace(" ", "<SP>")
                    end_time = end_time.replace(" ", "<SP>")
                    # 过滤时间范围内的日志
                    filtered_lines = []
                    for line in log_lines:
                        parts = line.split()
                        if len(parts) >= 2:
                            time_str = parts[1]
                            if start_time <= time_str <= end_time:
                                filtered_lines.append(line)
                    log_lines = filtered_lines
                except Exception as e:
                    messagebox.showerror("错误", f"时间过滤失败: {str(e)}")
                    return

            # 字段选择和模糊匹配
            result_lines = []
            for line in log_lines:
                parts = line.split()
                if len(parts) < 26:  # 确保日志格式正确
                    continue

                # 字段选择
                if selected_fields:
                    selected_parts = [parts[i-1] for i in selected_fields]
                    output_line = " ".join(selected_parts)
                else:
                    output_line = line

                # 模糊匹配
                if match_conditions:
                    match_result = True
                    if self.logic_relation.get() == "and":
                        # 逻辑且：所有条件都必须满足
                        for condition in match_conditions:
                            if match_mode == "include":
                                if condition not in output_line:
                                    match_result = False
                                    break
                            else:  # exclude
                                if condition in output_line:
                                    match_result = False
                                    break
                    else:  # logic_relation == "or"
                        # 逻辑或：任一条件满足即可
                        match_result = False
                        for condition in match_conditions:
                            if match_mode == "include":
                                if condition in output_line:
                                    match_result = True
                                    break
                            else:  # exclude
                                if condition not in output_line:
                                    match_result = True
                                    break
                    if not match_result:
                        continue

                result_lines.append(output_line)

            # 去重统计
            if dedup:
                from collections import Counter
                counter = Counter(result_lines)
                result_lines = [f"{count} {line}" for line, count in counter.most_common()]

            # 限制输出行数
            result_lines = result_lines[:output_lines]

            # 显示结果
            self.custom_result_text.config(state=tk.NORMAL)
            self.custom_result_text.delete(1.0, tk.END)
            if result_lines:
                self.custom_result_text.insert(tk.END, "\n".join(result_lines))
            else:
                self.custom_result_text.insert(tk.END, "没有匹配的日志记录")
            self.custom_result_text.config(state=tk.DISABLED)

        except ValueError as e:
            messagebox.showerror("错误", f"输入格式错误: {str(e)}")
        except Exception as e:
            messagebox.showerror("错误", f"分析过程中发生错误: {str(e)}")
            print(f"分析错误: {str(e)}")  # 打印到控制台
        
    def create_common_analysis_tab(self):
        """创建常见分析标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="常用日志分析")
        
        # 创建上下分栏
        top_frame = ttk.Frame(frame)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        bottom_frame = ttk.Frame(frame)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 上方：分析选项
        options_frame = ttk.LabelFrame(top_frame, text="分析选项", padding=10)
        options_frame.pack(fill=tk.X)
        
        # 创建复选框变量
        self.analysis_vars = {
            'url_top': tk.BooleanVar(value=False),
            'url_top_no_param': tk.BooleanVar(value=False),  # 新增 URL TOP(去参)
            'ip_top': tk.BooleanVar(value=False),
            'ua_top': tk.BooleanVar(value=False),
            'status_top': tk.BooleanVar(value=False),
            'url_ip_top': tk.BooleanVar(value=False),
            'domain_url_top': tk.BooleanVar(value=False),
            'domain_url_no_param_top': tk.BooleanVar(value=False),
            'error_status_top': tk.BooleanVar(value=False),
            'response_time_dist': tk.BooleanVar(value=False),
            'traffic_ip_top': tk.BooleanVar(value=False),
            'traffic_url_no_param_top': tk.BooleanVar(value=False),
            'traffic_domain_top': tk.BooleanVar(value=False),
            'concurrent_top': tk.BooleanVar(value=False)
        }
        
        # 创建复选框，每行4个
        row = 0
        col = 0
        for key, var in self.analysis_vars.items():
            display_text = self._get_analysis_name(key)  # 使用 _get_analysis_name 获取显示文本
            cb = ttk.Checkbutton(
                options_frame,
                text=display_text,  # 使用获取到的显示文本
                variable=var,
                command=lambda k=key: self._on_analysis_option_changed(k)
            )
            cb.grid(row=row, column=col, sticky='w', padx=5, pady=2)
            
            col += 1
            if col >= 4:  # 每行4个
                col = 0
                row += 1
        
        # TOP N 设置和按钮
        control_frame = ttk.Frame(top_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        # TOP N 设置
        top_frame = ttk.LabelFrame(control_frame, text="TOP N 设置", padding=10)
        top_frame.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(top_frame, text="TOP N:").pack(side=tk.LEFT, padx=5)
        self.top_n_var = tk.StringVar(value="10")
        top_n_entry = ttk.Entry(top_frame, textvariable=self.top_n_var, width=10)
        top_n_entry.pack(side=tk.LEFT, padx=5)
        
        # 分析按钮
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(side=tk.RIGHT, padx=5)
        
        self.analyze_btn = ttk.Button(
            button_frame,
            text="开始分析",
            command=self._start_analysis,
            bootstyle=SUCCESS
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=5)
        
        self.chart_btn = ttk.Button(
            button_frame,
            text="显示图表",
            command=self._show_current_chart,
            bootstyle=INFO
        )
        self.chart_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(
            button_frame,
            text="清空日志源",
            command=self._clear_log_source,
            bootstyle=DANGER
        )
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # 下方：结果显示（使用Notebook）
        self.result_notebook = ttk.Notebook(bottom_frame)
        self.result_notebook.pack(fill=tk.BOTH, expand=True)
        
        # 存储标签页的字典
        self.result_tabs = {}

    def _on_analysis_option_changed(self, key):
        """处理分析选项变更"""
        # 移除自动删除标签页的逻辑，只在开始分析时处理标签页
        pass

    def _start_analysis(self):
        """开始分析日志"""
        if not hasattr(self, 'uploaded_log_content') and not hasattr(self, 'latest_downloaded_log_path'):
            messagebox.showwarning("警告", "请先上传或下载日志文件")
            return

        # 获取选中的分析选项
        selected_options = [key for key, var in self.analysis_vars.items() if var.get()]
        if not selected_options:
            messagebox.showwarning("警告", "请至少选择一个分析选项")
            return

        try:
            top_n = int(self.top_n_var.get())
            if top_n <= 0:
                raise ValueError("TOP N 必须大于0")
        except ValueError as e:
            messagebox.showerror("错误", f"TOP N 设置无效: {str(e)}")
            return

        # 禁用分析按钮
        self.analyze_btn.config(state=tk.DISABLED)

        # 清理未选中的选项对应的标签页
        for key in list(self.result_tabs.keys()):
            if key not in selected_options:
                # 获取标签页的索引
                tab_id = None
                for i in range(self.result_notebook.index('end')):
                    if self.result_notebook.tab(i, "text") == self._get_analysis_name(key):
                        tab_id = i
                        break
                
                if tab_id is not None:
                    self.result_notebook.forget(tab_id)
                    del self.result_tabs[key]

        # 在新线程中执行分析
        threading.Thread(
            target=self._execute_analysis,
            args=(selected_options, top_n),
            daemon=True
        ).start()

    def _execute_analysis(self, selected_options, top_n):
        """执行日志分析"""
        try:
            # 获取日志内容
            log_content = self._get_log_content()
            if not log_content:
                self.master.after(0, lambda: messagebox.showerror("错误", "无法获取日志内容"))
                self.master.after(0, lambda: self.analyze_btn.config(state=tk.NORMAL))
                return
            # 解析日志
            log_lines = log_content.splitlines()
            # 执行选中的分析
            for option in selected_options:
                self._analyze_option(option, log_lines, top_n)
        except Exception as e:
            self.master.after(0, lambda: messagebox.showerror("错误", f"分析过程中发生错误: {str(e)}"))
            print(f"分析错误: {str(e)}")  # 打印到控制台
        finally:
            self.master.after(0, lambda: self.analyze_btn.config(state=tk.NORMAL))

    def _analyze_url_top(self, log_lines, top_n, text_widget):
        """分析URL TOP"""
        url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:  # 确保有足够的字段
                url = parts[9]  # URL在第10个字段
                url_counts[url] += 1
        
        self._display_top_results("URL TOP", url_counts, top_n, text_widget)

    def _analyze_ip_top(self, log_lines, top_n, text_widget):
        """分析访问IP TOP"""
        ip_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 6:  # 确保有足够的字段
                ip = parts[5]  # 客户端IP在第6个字段
                ip_counts[ip] += 1
        
        self._display_top_results("访问IP TOP", ip_counts, top_n, text_widget)

    def _analyze_ua_top(self, log_lines, top_n, text_widget):
        """分析请求UA TOP"""
        ua_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 18:  # 确保有足够的字段
                ua = parts[17]  # User-Agent在第18个字段
                ua_counts[ua] += 1
        
        self._display_top_results("请求UA TOP", ua_counts, top_n, text_widget)

    def _analyze_status_top(self, log_lines, top_n, text_widget):
        """分析状态码 TOP"""
        status_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 15:  # 确保有足够的字段
                status = parts[14]  # 状态码在第15个字段
                status_counts[status] += 1
        
        self._display_top_results("状态码 TOP", status_counts, top_n, text_widget)

    def _analyze_url_ip_top(self, log_lines, top_n, text_widget):
        """分析URL TOP IP统计"""
        # 首先获取URL TOP
        url_counts = Counter()
        url_ip_counts = defaultdict(Counter)
        
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                url = parts[9]
                ip = parts[5] if len(parts) >= 6 else "unknown"
                url_counts[url] += 1
                url_ip_counts[url][ip] += 1
        
        # 显示URL TOP
        self._display_top_results("URL TOP", url_counts, top_n, text_widget)
        
        # 显示每个URL的IP TOP
        text_widget.insert(tk.END, "\n各URL的访问IP TOP:\n")
        for url, count in url_counts.most_common(top_n):
            text_widget.insert(tk.END, f"\nURL: {url}\n")
            self._display_top_results("", url_ip_counts[url], top_n, text_widget, indent=2)

    def _analyze_domain_url_top(self, log_lines, top_n, text_widget):
        """分析域名及URL TOP"""
        domain_url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                domain = parts[8]
                url = parts[9]
                domain_url_counts[f"{domain} {url}"] += 1
        
        self._display_top_results("域名及URL TOP", domain_url_counts, top_n, text_widget)

    def _analyze_domain_url_no_param_top(self, log_lines, top_n, text_widget):
        """分析域名及URL TOP(去参)"""
        domain_url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                domain = parts[8]
                url = parts[9].split('?')[0]  # 去掉URL参数
                domain_url_counts[f"{domain} {url}"] += 1
        
        self._display_top_results("域名及URL TOP(去参)", domain_url_counts, top_n, text_widget)

    def _analyze_error_status_top(self, log_lines, top_n, text_widget):
        """分析40X/50X异常状态码 TOP"""
        error_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 15:
                status = parts[14]
                if status.startswith('4') or status.startswith('5'):
                    error_counts[status] += 1
        
        self._display_top_results("40X/50X异常状态码 TOP", error_counts, top_n, text_widget)

    def _analyze_response_time_dist(self, log_lines, text_widget):
        """分析响应时间分布"""
        time_ranges = {
            '<1s': 0,
            '1-3s': 0,
            '3-5s': 0,
            '5-10s': 0,
            '>10s': 0
        }
        
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    response_time = float(parts[2])
                    if response_time < 1:
                        time_ranges['<1s'] += 1
                    elif response_time < 3:
                        time_ranges['1-3s'] += 1
                    elif response_time < 5:
                        time_ranges['3-5s'] += 1
                    elif response_time < 10:
                        time_ranges['5-10s'] += 1
                    else:
                        time_ranges['>10s'] += 1
                except ValueError:
                    continue
        
        text_widget.insert(tk.END, "响应时间分布:\n")
        for range_name, count in time_ranges.items():
            text_widget.insert(tk.END, f"{count} {range_name}\n")

    def _analyze_traffic_ip_top(self, log_lines, top_n, text_widget):
        """分析消耗流量TOP IP"""
        ip_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    ip = parts[5]
                    size = int(parts[15])
                    ip_traffic[ip] += size
                except (ValueError, IndexError):
                    continue
        # 转换为MB并排序
        ip_traffic_mb = {ip: size/1024/1024 for ip, size in ip_traffic.items()}
        sorted_traffic = sorted(ip_traffic_mb.items(), key=lambda x: x[1], reverse=True)
        text_widget.insert(tk.END, "消耗流量TOP IP:\n")
        for ip, size in sorted_traffic[:top_n]:
            text_widget.insert(tk.END, f"{size:.2f}MB {ip}\n")

    def _analyze_traffic_url_no_param_top(self, log_lines, top_n, text_widget):
        """分析流量TOP URL(去参)"""
        url_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    url = parts[9].split('?')[0]
                    size = int(parts[15])
                    url_traffic[url] += size
                except (ValueError, IndexError):
                    continue
        # 转换为MB并排序
        url_traffic_mb = {url: size/1024/1024 for url, size in url_traffic.items()}
        sorted_traffic = sorted(url_traffic_mb.items(), key=lambda x: x[1], reverse=True)
        text_widget.insert(tk.END, "流量TOP URL(去参):\n")
        for url, size in sorted_traffic[:top_n]:
            text_widget.insert(tk.END, f"{size:.2f}MB {url}\n")

    def _analyze_traffic_domain_top(self, log_lines, top_n, text_widget):
        """分析流量TOP域名"""
        domain_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    domain = parts[8]
                    size = int(parts[15])
                    domain_traffic[domain] += size
                except (ValueError, IndexError):
                    continue
        # 转换为MB并排序
        domain_traffic_mb = {domain: size/1024/1024 for domain, size in domain_traffic.items()}
        sorted_traffic = sorted(domain_traffic_mb.items(), key=lambda x: x[1], reverse=True)
        text_widget.insert(tk.END, "流量TOP域名:\n")
        for domain, size in sorted_traffic[:top_n]:
            text_widget.insert(tk.END, f"{size:.2f}MB {domain}\n")

    def _analyze_concurrent_top(self, log_lines, top_n, text_widget):
        """分析并发TOP统计"""
        time_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    time_str = parts[1].split('.')[0]
                    time_counts[time_str] += 1
                except (ValueError, IndexError):
                    continue
        
        self._display_top_results("并发TOP统计", time_counts, top_n, text_widget)

    def _visualize_analysis(self, option):
        """可视化分析结果"""
        if not hasattr(self, 'uploaded_log_content') and not hasattr(self, 'latest_downloaded_log_path'):
            messagebox.showwarning("警告", "请先上传或下载日志文件")
            return
        try:
            # 获取当前标签页的文本内容
            current_tab = self.result_notebook.select()
            if not current_tab:
                messagebox.showwarning("警告", "请先选择要显示图表的分析结果")
                return
            tab_text = self.result_notebook.tab(current_tab, "text")
            text_widget = self.result_tabs[option].text_widget
            
            # 获取日志内容
            log_content = self._get_log_content()
            if not log_content:
                messagebox.showerror("错误", "无法获取日志内容")
                return
            log_lines = log_content.splitlines()
            try:
                top_n = int(self.top_n_var.get())
                if top_n <= 0:
                    raise ValueError("TOP N 必须大于0")
            except ValueError as e:
                messagebox.showerror("错误", f"TOP N 设置无效: {str(e)}")
                return
            
            viz_window = tk.Toplevel(self.master)
            viz_window.title(f"{self._get_analysis_name(option)} - 可视化")
            fig = plt.figure(figsize=(12, 7))
            
            if option == 'url_top':
                self._visualize_url_top(log_lines, top_n, fig)
            elif option == 'url_top_no_param':
                self._visualize_url_top_no_param(log_lines, top_n, fig)
            elif option == 'ip_top':
                self._visualize_ip_top(log_lines, top_n, fig)
            elif option == 'ua_top':
                self._visualize_ua_top(log_lines, top_n, fig)
            elif option == 'status_top':
                self._visualize_status_top(log_lines, top_n, fig)
            elif option == 'url_ip_top':
                self._visualize_url_ip_top(log_lines, top_n, fig)
            elif option == 'domain_url_top':
                self._visualize_domain_url_top(log_lines, top_n, fig)
            elif option == 'domain_url_no_param_top':
                self._visualize_domain_url_no_param_top(log_lines, top_n, fig)
            elif option == 'error_status_top':
                self._visualize_error_status_top(log_lines, top_n, fig)
            elif option == 'response_time_dist':
                self._visualize_response_time_dist(log_lines, fig)
            elif option == 'traffic_ip_top':
                self._visualize_traffic_ip_top(log_lines, top_n, fig)
            elif option == 'traffic_url_no_param_top':
                self._visualize_traffic_url_no_param_top(log_lines, top_n, fig)
            elif option == 'traffic_domain_top':
                self._visualize_traffic_domain_top(log_lines, top_n, fig)
            elif option == 'concurrent_top':
                self._visualize_concurrent_top(log_lines, top_n, fig)
            
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            canvas = FigureCanvasTkAgg(fig, master=viz_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # 设置窗口大小
            fig_w, fig_h = fig.get_size_inches()
            dpi = fig.dpi
            win_w = int(fig_w * dpi)
            win_h = int(fig_h * dpi)
            viz_window.geometry(f"{win_w}x{win_h}")
            
            # 延迟设置窗口大小，确保自适应
            def resize_to_fit():
                fig_w, fig_h = fig.get_size_inches()
                dpi = fig.dpi
                win_w = int(fig_w * dpi)
                win_h = int(fig_h * dpi)
                viz_window.geometry(f"{win_w}x{win_h}")
            viz_window.after(150, resize_to_fit)
            
        except Exception as e:
            messagebox.showerror("错误", f"生成图表时发生错误: {str(e)}")
            print(f"可视化错误: {str(e)}")  # 打印到控制台

    def _visualize_ua_top(self, log_lines, top_n, fig):
        """可视化UA TOP"""
        ua_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 18:
                ua = parts[17]  # User-Agent在第18个字段
                ua_counts[ua] += 1
        
        # 获取TOP N的数据
        top_uas = ua_counts.most_common(top_n)
        uas = [ua for ua, _ in top_uas]
        counts = [count for _, count in top_uas]
        
        # 创建水平条形图
        ax = fig.add_subplot(111)
        y_pos = range(len(uas))
        ax.barh(y_pos, counts)
        ax.set_yticks(y_pos)
        
        # 处理UA字符串，使其更易读
        readable_uas = []
        for ua in uas:
            # 如果UA太长，截取主要部分
            if len(ua) > 50:
                parts = ua.split()
                if len(parts) > 0:
                    readable_uas.append(parts[0] + "...")
                else:
                    readable_uas.append(ua[:50] + "...")
            else:
                readable_uas.append(ua)
        
        ax.set_yticklabels(readable_uas, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('请求UA TOP 统计', fontproperties=self.font)
        
        # 调整布局以适应长文本
        fig.tight_layout()

    def _visualize_url_top(self, log_lines, top_n, fig):
        """可视化URL TOP"""
        url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                url = parts[9]  # URL在第10个字段
                url_counts[url] += 1
        
        # 获取TOP N的数据
        top_urls = url_counts.most_common(top_n)
        urls = [url for url, _ in top_urls]
        counts = [count for _, count in top_urls]
        
        # 创建水平条形图
        ax = fig.add_subplot(111)
        y_pos = range(len(urls))
        ax.barh(y_pos, counts)
        ax.set_yticks(y_pos)
        
        # 处理URL字符串，使其更易读
        readable_urls = []
        for url in urls:
            # 如果URL太长，截取主要部分
            if len(url) > 50:
                readable_urls.append(url[:50] + "...")
            else:
                readable_urls.append(url)
        
        ax.set_yticklabels(readable_urls, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('URL TOP 统计', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        # 调整布局以适应长文本
        fig.tight_layout()

    def _visualize_url_top_no_param(self, log_lines, top_n, fig):
        """可视化URL TOP(去参)"""
        url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                url = parts[9]  # URL在第10个字段
                # 去掉URL参数
                url = url.split('?')[0]
                url_counts[url] += 1
        
        # 获取TOP N的数据
        top_urls = url_counts.most_common(top_n)
        urls = [url for url, _ in top_urls]
        counts = [count for _, count in top_urls]
        
        # 创建水平条形图
        ax = fig.add_subplot(111)
        y_pos = range(len(urls))
        ax.barh(y_pos, counts)
        ax.set_yticks(y_pos)
        
        # 处理URL字符串，使其更易读
        readable_urls = []
        for url in urls:
            # 如果URL太长，截取主要部分
            if len(url) > 50:
                readable_urls.append(url[:50] + "...")
            else:
                readable_urls.append(url)
        
        ax.set_yticklabels(readable_urls, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('URL TOP(去参) 统计', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        # 调整布局以适应长文本
        fig.tight_layout()

    def _visualize_ip_top(self, log_lines, top_n, fig):
        """可视化IP TOP"""
        ip_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[5]  # 客户端IP在第6个字段
                ip_counts[ip] += 1
        
        # 获取TOP N的数据
        top_ips = ip_counts.most_common(top_n)
        ips = [ip for ip, _ in top_ips]
        counts = [count for _, count in top_ips]
        
        # 创建水平条形图
        ax = fig.add_subplot(111)
        y_pos = range(len(ips))
        ax.barh(y_pos, counts)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(ips, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('访问IP TOP 统计', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        # 调整布局
        fig.tight_layout()

    def _visualize_status_top(self, log_lines, top_n, fig):
        """可视化状态码 TOP"""
        status_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 15:
                status = parts[14]  # 状态码在第15个字段
                status_counts[status] += 1
        
        # 获取TOP N的数据
        top_status = status_counts.most_common(top_n)
        statuses = [status for status, _ in top_status]
        counts = [count for _, count in top_status]
        
        # 创建饼图
        ax = fig.add_subplot(111)
        ax.pie(counts, labels=statuses, autopct='%1.1f%%')
        ax.set_title('状态码分布', fontproperties=self.font)
        
        # 调整布局
        fig.tight_layout()

    def _visualize_error_status_top(self, log_lines, top_n, fig):
        """可视化错误状态码 TOP"""
        error_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 15:
                status = parts[14]
                if status.startswith('4') or status.startswith('5'):
                    error_counts[status] += 1
        
        top_errors = error_counts.most_common(top_n)
        errors = [error for error, _ in top_errors]
        counts = [count for _, count in top_errors]
        
        ax = fig.add_subplot(111)
        ax.pie(counts, labels=errors, autopct='%1.1f%%')
        ax.set_title('错误状态码分布', fontproperties=self.font)
        fig.tight_layout()

    def _visualize_response_time_dist(self, log_lines, fig):
        """可视化响应时间分布"""
        time_ranges = {
            '<1s': 0,
            '1-3s': 0,
            '3-5s': 0,
            '5-10s': 0,
            '>10s': 0
        }
        
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    response_time = float(parts[2])
                    if response_time < 1:
                        time_ranges['<1s'] += 1
                    elif response_time < 3:
                        time_ranges['1-3s'] += 1
                    elif response_time < 5:
                        time_ranges['3-5s'] += 1
                    elif response_time < 10:
                        time_ranges['5-10s'] += 1
                    else:
                        time_ranges['>10s'] += 1
                except ValueError:
                    continue
        
        ranges = list(time_ranges.keys())
        counts = list(time_ranges.values())
        
        ax = fig.add_subplot(111)
        ax.bar(ranges, counts)
        ax.set_xlabel('响应时间范围', fontproperties=self.font)
        ax.set_ylabel('请求数量', fontproperties=self.font)
        ax.set_title('响应时间分布', fontproperties=self.font)
        plt.xticks(rotation=45)
        fig.tight_layout()

    def _visualize_traffic_ip_top(self, log_lines, top_n, fig):
        """可视化流量TOP IP"""
        ip_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    ip = parts[5]
                    size = int(parts[15])
                    ip_traffic[ip] += size
                except (ValueError, IndexError):
                    continue
        
        # 转换为MB并排序
        ip_traffic_mb = {ip: size/1024/1024 for ip, size in ip_traffic.items()}
        sorted_traffic = sorted(ip_traffic_mb.items(), key=lambda x: x[1], reverse=True)[:top_n]
        
        ips = [ip for ip, _ in sorted_traffic]
        sizes = [size for _, size in sorted_traffic]
        
        ax = fig.add_subplot(111)
        y_pos = range(len(ips))
        ax.barh(y_pos, sizes)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(ips, fontproperties=self.font)
        ax.set_xlabel('流量 (MB)', fontproperties=self.font)
        ax.set_title('IP流量TOP统计', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout()

    def _visualize_traffic_url_no_param_top(self, log_lines, top_n, fig):
        """可视化流量TOP URL(去参)"""
        url_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    url = parts[9].split('?')[0]
                    size = int(parts[15])
                    url_traffic[url] += size
                except (ValueError, IndexError):
                    continue
        
        # 转换为MB并排序
        url_traffic_mb = {url: size/1024/1024 for url, size in url_traffic.items()}
        sorted_traffic = sorted(url_traffic_mb.items(), key=lambda x: x[1], reverse=True)[:top_n]
        
        urls = [url for url, _ in sorted_traffic]
        sizes = [size for _, size in sorted_traffic]
        
        ax = fig.add_subplot(111)
        y_pos = range(len(urls))
        ax.barh(y_pos, sizes)
        ax.set_yticks(y_pos)
        
        # 处理URL显示
        readable_urls = []
        for url in urls:
            if len(url) > 50:
                readable_urls.append(url[:50] + "...")
            else:
                readable_urls.append(url)
        
        ax.set_yticklabels(readable_urls, fontproperties=self.font)
        ax.set_xlabel('流量 (MB)', fontproperties=self.font)
        ax.set_title('URL流量TOP统计(去参)', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout()

    def _visualize_traffic_domain_top(self, log_lines, top_n, fig):
        """可视化流量TOP域名"""
        domain_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    domain = parts[8]
                    size = int(parts[15])
                    domain_traffic[domain] += size
                except (ValueError, IndexError):
                    continue
        
        # 转换为MB并排序
        domain_traffic_mb = {domain: size/1024/1024 for domain, size in domain_traffic.items()}
        sorted_traffic = sorted(domain_traffic_mb.items(), key=lambda x: x[1], reverse=True)[:top_n]
        
        domains = [domain for domain, _ in sorted_traffic]
        sizes = [size for _, size in sorted_traffic]
        
        ax = fig.add_subplot(111)
        y_pos = range(len(domains))
        ax.barh(y_pos, sizes)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(domains, fontproperties=self.font)
        ax.set_xlabel('流量 (MB)', fontproperties=self.font)
        ax.set_title('域名流量TOP统计', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout()

    def _visualize_concurrent_top(self, log_lines, top_n, fig):
        """可视化并发TOP统计"""
        time_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    time_str = parts[1].split('.')[0]  # 去掉毫秒部分
                    time_counts[time_str] += 1
                except (ValueError, IndexError):
                    continue
        
        # 获取TOP N的数据
        top_times = time_counts.most_common(top_n)
        times = [time for time, _ in top_times]
        counts = [count for _, count in top_times]
        
        # 创建折线图
        ax = fig.add_subplot(111)
        ax.plot(range(len(times)), counts, marker='o')
        ax.set_xticks(range(len(times)))
        ax.set_xticklabels(times, rotation=45)
        ax.set_xlabel('时间', fontproperties=self.font)
        ax.set_ylabel('并发请求数', fontproperties=self.font)
        ax.set_title('并发请求TOP统计', fontproperties=self.font)
        
        # 设置y轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='y')
        
        fig.tight_layout()

    def _visualize_domain_url_top(self, log_lines, top_n, fig):
        """可视化域名及URL TOP"""
        domain_url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                domain = parts[8]
                url = parts[9]
                domain_url_counts[f"{domain} {url}"] += 1
        
        # 获取TOP N的数据
        top_items = domain_url_counts.most_common(top_n)
        items = [item for item, _ in top_items]
        counts = [count for _, count in top_items]
        
        ax = fig.add_subplot(111)
        y_pos = range(len(items))
        ax.barh(y_pos, counts)
        
        # 处理长文本
        readable_items = [item if len(item) <= 50 else item[:50] + "..." for item in items]
        ax.set_yticks(y_pos)
        ax.set_yticklabels(readable_items, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('域名及URL TOP', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout()

    def _visualize_domain_url_no_param_top(self, log_lines, top_n, fig):
        """可视化域名及URL TOP(去参)"""
        domain_url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                domain = parts[8]
                url = parts[9].split('?')[0]
                domain_url_counts[f"{domain} {url}"] += 1
        
        # 获取TOP N的数据
        top_items = domain_url_counts.most_common(top_n)
        items = [item for item, _ in top_items]
        counts = [count for _, count in top_items]
        
        ax = fig.add_subplot(111)
        y_pos = range(len(items))
        ax.barh(y_pos, counts)
        
        # 处理长文本
        readable_items = [item if len(item) <= 50 else item[:50] + "..." for item in items]
        ax.set_yticks(y_pos)
        ax.set_yticklabels(readable_items, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('域名及URL TOP(去参)', fontproperties=self.font)
        
        # 设置x轴不使用科学计数法
        ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout()

    def _visualize_url_ip_top(self, log_lines, top_n, fig):
        """可视化URL TOP及其IP TOP"""
        from math import ceil
        url_counts = Counter()
        url_ip_counts = defaultdict(Counter)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                url = parts[9]
                ip = parts[5] if len(parts) >= 6 else "unknown"
                url_counts[url] += 1
                url_ip_counts[url][ip] += 1
        
        # 只取TOP N的URL
        top_urls = url_counts.most_common(top_n)
        n_urls = len(top_urls)
        if n_urls == 0:
            fig.suptitle("无数据", fontproperties=self.font)
            return
        
        # 动态布局
        ncols = 1
        nrows = n_urls
        fig.clear()
        for i, (url, _) in enumerate(top_urls):
            ax = fig.add_subplot(nrows, ncols, i+1)
            ip_counts = url_ip_counts[url].most_common(top_n)
            ips = [ip for ip, _ in ip_counts]
            counts = [count for _, count in ip_counts]
            y_pos = range(len(ips))
            ax.barh(y_pos, counts)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(ips, fontproperties=self.font)
            ax.set_xlabel('访问次数', fontproperties=self.font)
            display_url = url if len(url) <= 50 else url[:50] + "..."
            ax.set_title(f'URL: {display_url}', fontproperties=self.font, fontsize=10)
            
            # 设置x轴不使用科学计数法
            ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout(rect=[0, 0, 1, 0.97])

    def _clear_log_source(self):
        """清空日志源"""
        if hasattr(self, 'uploaded_log_content'):
            delattr(self, 'uploaded_log_content')
        if hasattr(self, 'latest_downloaded_log_path'):
            delattr(self, 'latest_downloaded_log_path')
        
        # 清空缓存
        self._log_content_cache = None
        
        # 清空显示
        self.preview_text.config(state=tk.NORMAL)
        self.preview_text.delete(1.0, tk.END)
        self.preview_text.config(state=tk.DISABLED)
        
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        
        # 禁用校验按钮
        self.validate_upload_btn.config(state=tk.DISABLED)
        
        messagebox.showinfo("提示", "日志源已清空")

    def create_download_tab(self):
        """创建日志下载标签页"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="日志下载")
        
        # 下载区域
        download_frame = ttk.LabelFrame(frame, text="下载日志文件", padding=10)
        download_frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
        
        # URL输入框
        url_label = ttk.Label(download_frame, text="下载URL(每行一个):")
        url_label.pack(pady=5)
        
        self.url_text = tk.Text(download_frame, height=5, width=80)
        self.url_text.pack(pady=5)
        
        # 保存路径选择
        path_frame = ttk.Frame(download_frame)
        path_frame.pack(pady=5)
        
        path_label = ttk.Label(path_frame, text="保存路径:")
        path_label.pack(side=tk.LEFT)
        
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, width=50)
        path_entry.pack(side=tk.LEFT, padx=5)
        
        browse_btn = ttk.Button(
            path_frame, 
            text="浏览", 
            command=self._select_download_dir
        )
        browse_btn.pack(side=tk.LEFT)
        
        # 合并选项
        self.merge_var = tk.BooleanVar(value=True)
        merge_check = ttk.Checkbutton(
            download_frame, 
            text="合并为一个文件", 
            variable=self.merge_var
        )
        merge_check.pack(pady=5)
        
        # 合并文件名
        merge_name_frame = ttk.Frame(download_frame)
        merge_name_frame.pack(pady=5)
        
        merge_name_label = ttk.Label(merge_name_frame, text="合并文件名:")
        merge_name_label.pack(side=tk.LEFT)
        
        merge_name_entry = ttk.Entry(merge_name_frame, textvariable=self.merge_name_var)
        merge_name_entry.pack(side=tk.LEFT, padx=5)
        
        # 下载按钮
        self.download_btn = ttk.Button(
            download_frame,
            text="下载日志",
            command=self._start_download,
            style="primary.TButton"
        )
        self.download_btn.pack(pady=10)
        
        # 日志校验按钮
        self.validate_download_btn = ttk.Button(
            download_frame,
            text="校验下载日志",
            command=self._validate_downloaded_log,
            style="info.TButton",
            state=tk.DISABLED
        )
        self.validate_download_btn.pack(pady=5)

        # 进度条
        self.download_progress = ttk.Progressbar(
            download_frame, 
            orient=tk.HORIZONTAL, 
            length=400, 
            mode='determinate'
        )
        self.download_progress.pack(pady=10)
        
        # 结果展示
        self.result_text = tk.Text(
            download_frame, 
            height=10, 
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # 初始化下载器
        self.log_downloader = LogDownloader(
            self.master,
            self.result_text,
            self.download_progress,
            self.validate_download_btn
        )

    def _select_download_dir(self):
        """选择下载目录"""
        dir_path = filedialog.askdirectory(title="选择保存目录")
        if dir_path:
            self.path_var.set(dir_path)

    def _start_download(self):
        """开始下载按钮的回调函数"""
        # 检查是否已有加载的日志
        has_uploaded_log = hasattr(self, 'uploaded_log_content') and self.uploaded_log_content is not None
        has_downloaded_log = hasattr(self, 'latest_downloaded_log_path') and self.latest_downloaded_log_path is not None
        
        if has_uploaded_log or has_downloaded_log:
            if messagebox.askyesno("提示", "当前已有加载的日志，是否先清空已加载的日志？"):
                self._clear_log_source()
            else:
                return

        if not hasattr(self, 'log_downloader') or self.log_downloader is None:
            messagebox.showerror("错误", "下载器未正确初始化")
            return

        urls = [url.strip() for url in self.url_text.get("1.0", tk.END).strip().split('\n') if url.strip()]
        if not urls:
            messagebox.showerror("错误", "请输入至少一个日志URL")
            return
        
        save_dir = self.path_var.get()
        if not save_dir:
            messagebox.showerror("错误", "请选择保存目录")
            return
        
        # 清空输出区域
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        
        self.download_btn.config(state=tk.DISABLED)
        
        def download_thread():
            start_time = time.time()
            try:
                self.validate_download_btn.config(state=tk.DISABLED)
                success_count, failed_urls = self.log_downloader.download_logs(
                    urls, 
                    save_dir,
                    self.merge_var,
                    self.merge_name_var.get()
                )
                
                self.log_downloader._update_status(f"下载完成! 成功: {success_count}, 失败: {len(failed_urls)}")
                
                if self.log_downloader.downloaded_file:
                    # 确保文件存在且可读
                    if os.path.exists(self.log_downloader.downloaded_file):
                        try:
                            # 尝试读取文件的前几个字节来验证文件是否可读
                            with open(self.log_downloader.downloaded_file, 'rb') as f:
                                f.read(1)
                            # 设置下载的日志路径
                            self.latest_downloaded_log_path = self.log_downloader.downloaded_file
                            
                            # 验证文件内容
                            try:
                                # 尝试读取文件内容
                                with open(self.latest_downloaded_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read(1024)  # 读取前1KB内容
                                    if content:
                                        self.validate_download_btn.config(state=tk.NORMAL)
                                    else:
                                        messagebox.showerror("错误", "下载的文件内容为空")
                            except Exception as e:
                                messagebox.showerror("错误", f"无法读取下载的文件内容: {str(e)}")
                        except Exception as e:
                            messagebox.showerror("错误", f"下载的文件无法读取: {str(e)}")
                    else:
                        messagebox.showerror("错误", "下载的文件不存在")
                
            except Exception as e:
                self.log_downloader._update_status(f"下载过程出错: {str(e)}")
            finally:
                elapsed = time.time() - start_time
                self.log_downloader._update_status(f"本次下载总耗时: {elapsed:.2f} 秒")
                self.master.after(0, lambda: self.download_btn.config(state=tk.NORMAL))
        
        threading.Thread(target=download_thread, daemon=True).start()

    def _format_size(self, size_bytes):
        """格式化文件大小显示"""
        if size_bytes < 1024:
            return f"{size_bytes:.1f} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"

    def _update_download_status(self, message):
        """更新下载状态显示 (确保在主线程中调用)"""
        def update_text():
            self.result_text.config(state=tk.NORMAL)
            self.result_text.insert(tk.END, message + "\n")
            self.result_text.see(tk.END)
            self.result_text.config(state=tk.DISABLED)
        self.master.after(0, update_text) # 使用after确保线程安全

    def _validate_downloaded_log(self):
        """校验最新下载的日志文件（在单独线程中执行核心逻辑）"""
        if not self.latest_downloaded_log_path or not os.path.exists(self.latest_downloaded_log_path):
            messagebox.showwarning("校验失败", "未找到有效的已下载日志文件。请先下载日志。")
            return

        self.validate_download_btn.config(state=tk.DISABLED)
        self._update_download_status(f"--- 开始校验日志: {os.path.basename(self.latest_downloaded_log_path)} ---") # 修正拼写错误

        threading.Thread(
            target=self._execute_validation,
            args=(self.latest_downloaded_log_path,),
            daemon=True
        ).start()

    def _execute_validation(self, log_path):
        """执行校验的核心逻辑"""
        try:
            # 1. 显示日志片段 (调整到前面)
            self._update_download_status("开始加载日志预览...") # 添加提示信息
            self._show_log_samples(log_path, "当前校验日志")
            
            # 2. 统计日志量
            self._update_download_status("开始统计日志中的日期信息...")
            date_counts = self._parse_log_dates(log_path)
            if date_counts:
                self._update_download_status("按日期统计日志条数:")
                for date, count in date_counts:
                    self._update_download_status(f"{date}: {count} 条")
            elif os.path.exists(log_path) and os.path.getsize(log_path) > 0:
                 self._update_download_status("未能在日志中找到符合 'YYYY-MM-DD<SP>...' 格式的日期信息。")
            elif not os.path.exists(log_path):
                 self._update_download_status(f"错误: 日志文件 {log_path} 未找到。")
            else: # 文件存在但大小为0
                 self._update_download_status(f"提示: 日志文件 {os.path.basename(log_path)} 为空。")
            
            self._update_download_status("--- 日志校验完毕 ---")
        except Exception as e:
            self._update_download_status(f"校验过程中发生错误: {str(e)}")
        finally:
            # 确保在主线程中更新UI组件的状态
            self.master.after(0, lambda: self.validate_download_btn.config(state=tk.NORMAL))

    def _parse_log_dates(self, filepath):
        date_counts = defaultdict(int)
        
        if not os.path.exists(filepath):
            return [] 
        
        if os.path.getsize(filepath) == 0:
            return [] 
        
        opener = gzip.open if filepath.endswith('.gz') else open
        try:
            with opener(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                for line_number, line in enumerate(f, 1):
                    try:
                        # 1. 按空格分割整行日志
                        line_parts = line.strip().split(' ')
                        if len(line_parts) > 1: # 确保至少有两个字段
                            time_field = line_parts[1] # 第二个字段是时间字段
                            
                            # 2. 在时间字段中按 <SP> 分割
                            if '<SP>' in time_field:
                                date_parts = time_field.split('<SP>', 1) # 最多分割一次
                                date_part = date_parts[0].strip()
                                
                                # 3. 校验日期格式并统计
                                if len(date_part) == 10: # YYYY-MM-DD
                                    if date_part.count('-') == 2:
                                        try:
                                            datetime.datetime.strptime(date_part, '%Y-%m-%d') # 校验日期格式
                                            date_counts[date_part] += 1
                                        except ValueError:
                                            pass # 静默处理格式错误的日期
                    except Exception as e_line:
                        # 确保这个 except 块与内部的 try 对齐
                        # self._update_download_status(f"解析第 {line_number} 行失败: {e_line}") 
                        pass # 忽略单行解析错误
        except Exception as e_file: # 这个 except 与外部的 try 对齐
            self._update_download_status(f"错误: 读取日志文件 {os.path.basename(filepath)} 时发生错误: {str(e_file)}")
            return [] 
        
        return sorted(date_counts.items())

    def _show_log_samples(self, filepath, log_type_name="日志"):
        """显示日志文件的前3行和后3行"""
        if not filepath or not os.path.exists(filepath):
            self._update_download_status(f"{log_type_name}文件路径无效或文件不存在: {filepath}")
            return

        try:
            opener = gzip.open if filepath.endswith('.gz') else open
            lines_to_show_top = []
            lines_to_show_bottom = []
            line_count = 0
            lines_to_display = 3

            # 读取前 lines_to_display 行
            with opener(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i < lines_to_display:
                        lines_to_show_top.append(line.strip())
                    line_count += 1
            
            # 读取后 lines_to_display 行
            if line_count > lines_to_display: 
                with opener(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                    # 使用缓冲区读取最后几行
                    buffer_size = 8192  # 8KB 缓冲区
                    f.seek(0, 2)  # 移动到文件末尾
                    file_size = f.tell()
                    position = file_size
                    buffer = ""
                    lines_found = 0
                    
                    while position > 0 and lines_found < lines_to_display:
                        # 计算要读取的大小
                        read_size = min(buffer_size, position)
                        position -= read_size
                        f.seek(position)
                        
                        # 读取数据并添加到缓冲区
                        chunk = f.read(read_size)
                        buffer = chunk + buffer
                        
                        # 处理缓冲区中的行
                        lines = buffer.splitlines()
                        if len(lines) > 1:  # 确保有完整的行
                            # 保留最后几行
                            lines_to_show_bottom = lines[-lines_to_display:]
                            lines_found = len(lines_to_show_bottom)
                            buffer = lines[0]  # 保留第一行（可能不完整）
                    else: 
                            buffer = lines[0] if lines else ""
                    
                    # 如果找到的行数不足，从文件开头重新读取
                    if lines_found < lines_to_display:
                        with opener(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
                            all_lines = f.readlines()
                            lines_to_show_bottom = [line.strip() for line in all_lines[-lines_to_display:]]
            
            self._update_download_status(f"--- {log_type_name}: {os.path.basename(filepath)} (前{len(lines_to_show_top)}行) ---")
            for line in lines_to_show_top:
                self._update_download_status(line)
            
            if line_count > (lines_to_display * 2):
                self._update_download_status("... (中间内容已省略) ...")
            
            if line_count > lines_to_display:
                self._update_download_status(f"--- {log_type_name}: {os.path.basename(filepath)} (后{len(lines_to_show_bottom)}行) ---")
                for line in lines_to_show_bottom:
                    self._update_download_status(line)
            
            self._update_download_status(f"--- {log_type_name} (共 {line_count} 行) 片段显示完毕 ---")

        except Exception as e:
            self._update_download_status(f"显示{log_type_name}文件样本时出错: {str(e)}")

    def _start_process_uploaded_files(self):
        if not hasattr(self, 'uploaded_file_paths') or not self.uploaded_file_paths:
            messagebox.showwarning("提示", "请先选择要上传的日志文件。")
            return

        self.process_upload_btn.config(state=tk.DISABLED)
        self.validate_upload_btn.config(state=tk.DISABLED)
        self._update_upload_status("开始处理上传的文件...", clear=True)
        self.latest_uploaded_log_path = None

        # 临时目录用于存放上传过程中可能产生的临时gz文件
        # 使用 self.path_var.get() (下载路径) 作为基础目录，或提供一个专门的临时目录选择
        # 这里我们简单地在选择的第一个文件的目录下创建一个temp_upload文件夹
        # 更健壮的做法是使用 tempfile 模块
        base_dir_for_temp = os.path.dirname(self.uploaded_file_paths[0])
        self.upload_temp_dir = os.path.join(base_dir_for_temp, "temp_upload_processing")
        os.makedirs(self.upload_temp_dir, exist_ok=True)

        threading.Thread(
            target=self._execute_upload_processing,
            args=(list(self.uploaded_file_paths), self.upload_merge_var.get(), self.upload_merge_name_var.get(), self.upload_temp_dir),
            daemon=True
        ).start()

    def _execute_upload_processing(self, file_paths, should_merge, merge_name, temp_dir):
        start_time = time.time()
        processed_files_for_merging = []
        success_count = 0
        processed_log_path_for_validation = None

        try:
            for original_path in file_paths:
                filename = os.path.basename(original_path)
                # 检查文件是否已经是gz格式
                if original_path.endswith('.gz'):
                    # 如果已经是gz文件，直接使用
                    processed_files_for_merging.append(original_path)
                    file_size = os.path.getsize(original_path)
                    if file_size < 1024:
                        size_str = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_str = f"{file_size/1024:.2f} KB"
                    elif file_size < 1024 * 1024 * 1024:
                        size_str = f"{file_size/(1024*1024):.2f} MB"
                    else:
                        size_str = f"{file_size/(1024*1024*1024):.2f} GB"
                    self._update_upload_status(f"文件 {filename} 已经是gz格式，直接使用 (大小: {size_str})")
                    success_count += 1
                else:
                    # 如果不是gz文件，先检查文件内容
                    try:
                        with open(original_path, 'rb') as f:
                            # 读取文件头部来检查是否已经是压缩文件
                            header = f.read(2)
                            f.seek(0)  # 重置文件指针
                            
                            if header.startswith(b'\x1f\x8b'):  # gzip文件头
                                # 文件已经是gz格式，只是扩展名不是.gz
                                temp_gz_path = os.path.join(temp_dir, f"{os.path.splitext(filename)[0]}.gz")
                                with open(temp_gz_path, 'wb') as f_out:
                                    f_out.write(f.read())
                                processed_files_for_merging.append(temp_gz_path)
                                file_size = os.path.getsize(temp_gz_path)
                                if file_size < 1024:
                                    size_str = f"{file_size} B"
                                elif file_size < 1024 * 1024:
                                    size_str = f"{file_size/1024:.2f} KB"
                                elif file_size < 1024 * 1024 * 1024:
                                    size_str = f"{file_size/(1024*1024):.2f} MB"
                                else:
                                    size_str = f"{file_size/(1024*1024*1024):.2f} GB"
                                self._update_upload_status(f"文件 {filename} 已经是gz格式，已重命名 (大小: {size_str})")
                            else:
                                # 文件不是gz格式，需要压缩
                                temp_gz_path = os.path.join(temp_dir, f"{os.path.splitext(filename)[0]}.gz")
                                with gzip.open(temp_gz_path, 'wb') as f_out:
                                    f_out.write(f.read())
                                processed_files_for_merging.append(temp_gz_path)
                                file_size = os.path.getsize(temp_gz_path)
                                if file_size < 1024:
                                    size_str = f"{file_size} B"
                                elif file_size < 1024 * 1024:
                                    size_str = f"{file_size/1024:.2f} KB"
                                elif file_size < 1024 * 1024 * 1024:
                                    size_str = f"{file_size/(1024*1024):.2f} MB"
                                else:
                                    size_str = f"{file_size/(1024*1024*1024):.2f} GB"
                                self._update_upload_status(f"成功压缩: {filename} (大小: {size_str})")
                            success_count += 1
                    except Exception as e_compress:
                        self._update_upload_status(f"处理文件 {filename} 失败: {e_compress}")
                        continue
            
            if not processed_files_for_merging:
                self._update_upload_status("没有文件成功处理或准备好进行合并。")
                return

            if should_merge and len(processed_files_for_merging) > 0:
                if not merge_name.endswith('.gz'):
                    merge_name += '.gz'
                # 合并后的文件也放在临时处理目录下，或用户指定的其他位置
                # 为简单起见，我们将其放在第一个上传文件的目录
                output_merge_dir = os.path.dirname(file_paths[0]) 
                merged_output_path = os.path.join(output_merge_dir, merge_name)
                
                self._update_upload_status(f"开始合并 {len(processed_files_for_merging)} 个文件到 {merge_name}...")
                # 使用修改后的 _merge_gz_files，它现在可以接受一个 target_widget_name
                if self._merge_gz_files(processed_files_for_merging, merged_output_path, result_widget_name="upload_result_text", status_prefix="上传模块合并"):
                    # 显示合并后的文件大小
                    merged_size = os.path.getsize(merged_output_path)
                    if merged_size < 1024:
                        size_str = f"{merged_size} B"
                    elif merged_size < 1024 * 1024:
                        size_str = f"{merged_size/1024:.2f} KB"
                    elif merged_size < 1024 * 1024 * 1024:
                        size_str = f"{merged_size/(1024*1024):.2f} MB"
                    else:
                        size_str = f"{merged_size/(1024*1024*1024):.2f} GB"
                    self._update_upload_status(f"成功合并文件到: {merge_name} (大小: {size_str})")
                    processed_log_path_for_validation = merged_output_path
                    # 在预览区域显示合并后的文件名
                    self.master.after(0, lambda: self.preview_text.config(state=tk.NORMAL))
                    self.master.after(0, lambda: self.preview_text.insert(tk.END, f"\n合并后的文件名: {merge_name} (大小: {size_str})\n"))
                    self.master.after(0, lambda: self.preview_text.config(state=tk.DISABLED))
                    # 清理掉用于合并的临时 .gz 文件 (如果它们是在 temp_dir 中创建的)
                    for temp_f in processed_files_for_merging:
                        if temp_dir in temp_f and os.path.exists(temp_f):
                            try:
                                os.remove(temp_f)
                            except Exception as e_remove_temp:
                                self._update_upload_status(f"删除临时压缩文件 {os.path.basename(temp_f)} 失败: {e_remove_temp}")
                else:
                    self._update_upload_status(f"合并文件失败。")
            elif len(processed_files_for_merging) == 1:
                # 如果只有一个文件被处理（可能压缩过），则它就是最终文件
                processed_log_path_for_validation = processed_files_for_merging[0]
                # 显示文件大小
                file_size = os.path.getsize(processed_log_path_for_validation)
                if file_size < 1024:
                    size_str = f"{file_size} B"
                elif file_size < 1024 * 1024:
                    size_str = f"{file_size/1024:.2f} KB"
                elif file_size < 1024 * 1024 * 1024:
                    size_str = f"{file_size/(1024*1024):.2f} MB"
                else:
                    size_str = f"{file_size/(1024*1024*1024):.2f} GB"
                self._update_upload_status(f"单个文件处理完成: {os.path.basename(processed_log_path_for_validation)} (大小: {size_str})")
            elif not should_merge and len(processed_files_for_merging) > 0:
                # 不合并，但有多个文件成功处理。校验按钮将对第一个处理成功的文件生效。
                processed_log_path_for_validation = processed_files_for_merging[0]
                # 显示文件大小
                file_size = os.path.getsize(processed_log_path_for_validation)
                if file_size < 1024:
                    size_str = f"{file_size} B"
                elif file_size < 1024 * 1024:
                    size_str = f"{file_size/1024:.2f} KB"
                elif file_size < 1024 * 1024 * 1024:
                    size_str = f"{file_size/(1024*1024):.2f} MB"
                else:
                    size_str = f"{file_size/(1024*1024*1024):.2f} GB"
                self._update_upload_status(f"{len(processed_files_for_merging)} 个文件处理完成（未合并）。校验将针对: {os.path.basename(processed_log_path_for_validation)} (大小: {size_str})")
            
            self.latest_uploaded_log_path = processed_log_path_for_validation

            if self.latest_uploaded_log_path and os.path.exists(self.latest_uploaded_log_path):
                # 统计日志条数
                self._update_upload_status(f"开始统计日志条数: {os.path.basename(self.latest_uploaded_log_path)}")
                date_counts = self._parse_log_dates(self.latest_uploaded_log_path)
                total_lines = sum(count for _, count in date_counts)
                if total_lines > 0:
                    self._update_upload_status(f"在 {os.path.basename(self.latest_uploaded_log_path)} 中总共统计到 {total_lines} 条有效日期日志。")
                else:
                    self._update_upload_status(f"未在 {os.path.basename(self.latest_uploaded_log_path)} 中统计到有效日期日志。")
                self.master.after(0, lambda: self.validate_upload_btn.config(state=tk.NORMAL))
            else:
                self._update_upload_status("没有可供校验的最终日志文件。")
                self.master.after(0, lambda: self.validate_upload_btn.config(state=tk.DISABLED))

            self._update_upload_status("--- 上传文件处理完毕 ---")
            elapsed = time.time() - start_time
            self._update_upload_status(f"本次上传处理总耗时: {elapsed:.2f} 秒")
        except Exception as e:
            self._update_upload_status(f"处理上传文件过程中发生错误: {str(e)}")
        finally:
            self.master.after(0, lambda: self.process_upload_btn.config(state=tk.NORMAL))
            # 清理临时上传目录
            if os.path.exists(temp_dir):
                try:
                    # Be careful with rmtree, ensure it's the correct directory
                    import shutil
                    shutil.rmtree(temp_dir)
                    self._update_upload_status(f"已清理临时处理目录: {temp_dir}")
                except Exception as e_rm_tempdir:
                    self._update_upload_status(f"清理临时处理目录 {temp_dir} 失败: {e_rm_tempdir}")

    def _analyze_option(self, option, log_lines, top_n):
        """分析单个选项"""
        try:
            # 如果标签页不存在，创建一个新的
            if option not in self.result_tabs:
                tab_frame = ttk.Frame(self.result_notebook)
                self.result_notebook.add(tab_frame, text=self._get_analysis_name(option))
                # 创建文本显示区域
                text_widget = tk.Text(
                    tab_frame,
                    wrap=tk.WORD,
                    state=tk.DISABLED
                )
                text_widget.pack(fill=tk.BOTH, expand=True)
                # 添加滚动条
                scrollbar = ttk.Scrollbar(text_widget, command=text_widget.yview)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                text_widget.config(yscrollcommand=scrollbar.set)
                # 存储标签页的引用
                self.result_tabs[option] = tab_frame
                
                # 将text_widget作为属性存储在tab_frame中，以便后续访问
                tab_frame.text_widget = text_widget
            
            # 获取对应的文本显示区域
            text_widget = self.result_tabs[option].text_widget
            text_widget.config(state=tk.NORMAL)
            text_widget.delete(1.0, tk.END)
            
            # 检查日志内容是否有效
            if not log_lines:
                text_widget.insert(tk.END, "没有可分析的日志内容\n")
                text_widget.config(state=tk.DISABLED)
                return
            
            # 执行相应的分析
            if option == 'url_top':
                self._analyze_url_top(log_lines, top_n, text_widget)
            elif option == 'url_top_no_param':
                self._analyze_url_top_no_param(log_lines, top_n, text_widget)
            elif option == 'ip_top':
                self._analyze_ip_top(log_lines, top_n, text_widget)
            elif option == 'ua_top':
                self._analyze_ua_top(log_lines, top_n, text_widget)
            elif option == 'status_top':
                self._analyze_status_top(log_lines, top_n, text_widget)
            elif option == 'url_ip_top':
                self._analyze_url_ip_top(log_lines, top_n, text_widget)
            elif option == 'domain_url_top':
                self._analyze_domain_url_top(log_lines, top_n, text_widget)
            elif option == 'domain_url_no_param_top':
                self._analyze_domain_url_no_param_top(log_lines, top_n, text_widget)
            elif option == 'error_status_top':
                self._analyze_error_status_top(log_lines, top_n, text_widget)
            elif option == 'response_time_dist':
                self._analyze_response_time_dist(log_lines, text_widget)
            elif option == 'traffic_ip_top':
                self._analyze_traffic_ip_top(log_lines, top_n, text_widget)
            elif option == 'traffic_url_no_param_top':
                self._analyze_traffic_url_no_param_top(log_lines, top_n, text_widget)
            elif option == 'traffic_domain_top':
                self._analyze_traffic_domain_top(log_lines, top_n, text_widget)
            elif option == 'concurrent_top':
                self._analyze_concurrent_top(log_lines, top_n, text_widget)
            
            text_widget.config(state=tk.DISABLED)
        except Exception as e:
            error_msg = f"分析 {self._get_analysis_name(option)} 时发生错误: {str(e)}"
            if 'text_widget' in locals():
                text_widget.insert(tk.END, f"\n{error_msg}\n")
                text_widget.config(state=tk.DISABLED)
            messagebox.showerror("分析错误", error_msg)

    def _display_top_results(self, title, counter, top_n, text_widget, indent=0):
        """显示TOP结果"""
        if title:
            text_widget.insert(tk.END, f"{title}\n")
        
        indent_str = " " * indent
        for item, count in counter.most_common(top_n):
            text_widget.insert(tk.END, f"{indent_str}{count} {item}\n")

    def _get_analysis_name_dict(self):
        """获取分析选项名称字典"""
        return {
            'url_top': 'URL TOP',
            'url_top_no_param': 'URL TOP(去参)',  # 使用中文括号
            'ip_top': '访问IP TOP',
            'ua_top': '请求UA TOP',
            'status_top': '状态码 TOP',
            'url_ip_top': 'URL TOP IP统计',
            'domain_url_top': '域名及URL TOP',
            'domain_url_no_param_top': '域名及URL TOP(去参)',
            'error_status_top': '40X/50X异常状态码 TOP',
            'response_time_dist': '响应时间分布',
            'traffic_ip_top': '消耗流量TOP IP',
            'traffic_url_no_param_top': '流量TOP URL(去参)',
            'traffic_domain_top': '流量TOP域名',
            'concurrent_top': '并发TOP统计'
        }

    def _show_current_chart(self):
        """显示当前标签页对应的图表"""
        current_tab = self.result_notebook.select()
        if not current_tab:
            messagebox.showwarning("警告", "请先选择要显示图表的分析结果")
            return
            
        tab_text = self.result_notebook.tab(current_tab, "text")
        
        # 根据标签页文本找到对应的分析选项
        option = None
        for key, name in self._get_analysis_name_dict().items():
            if name == tab_text:
                option = key
                break
        
        if option:
            self._visualize_analysis(option)
        else:
            messagebox.showwarning("警告", "请先选择要显示图表的分析结果")

    def _visualize_url_ip_top(self, log_lines, top_n, fig):
        """可视化URL TOP及其IP TOP"""
        from math import ceil
        url_counts = Counter()
        url_ip_counts = defaultdict(Counter)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                url = parts[9]
                ip = parts[5] if len(parts) >= 6 else "unknown"
                url_counts[url] += 1
                url_ip_counts[url][ip] += 1
        
        # 只取TOP N的URL
        top_urls = url_counts.most_common(top_n)
        n_urls = len(top_urls)
        if n_urls == 0:
            fig.suptitle("无数据", fontproperties=self.font)
            return
        
        # 动态布局
        ncols = 1
        nrows = n_urls
        fig.clear()
        for i, (url, _) in enumerate(top_urls):
            ax = fig.add_subplot(nrows, ncols, i+1)
            ip_counts = url_ip_counts[url].most_common(top_n)
            ips = [ip for ip, _ in ip_counts]
            counts = [count for _, count in ip_counts]
            y_pos = range(len(ips))
            ax.barh(y_pos, counts)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(ips, fontproperties=self.font)
            ax.set_xlabel('访问次数', fontproperties=self.font)
            display_url = url if len(url) <= 50 else url[:50] + "..."
            ax.set_title(f'URL: {display_url}', fontproperties=self.font, fontsize=10)
            
            # 设置x轴不使用科学计数法
            ax.ticklabel_format(style='plain', axis='x')
        
        fig.tight_layout(rect=[0, 0, 1, 0.97])

    def _visualize_domain_url_no_param_top(self, log_lines, top_n, fig):
        """可视化域名及URL TOP(去参)"""
        domain_url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                domain = parts[8]
                url = parts[9].split('?')[0]
                domain_url_counts[f"{domain} {url}"] += 1
        # 获取TOP N的数据
        top_items = domain_url_counts.most_common(top_n)
        items = [item for item, _ in top_items]
        counts = [count for _, count in top_items]
        ax = fig.add_subplot(111)
        y_pos = range(len(items))
        ax.barh(y_pos, counts)
        # 处理长文本
        readable_items = [item if len(item) <= 50 else item[:50] + "..." for item in items]
        ax.set_yticks(y_pos)
        ax.set_yticklabels(readable_items, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('域名及URL TOP(去参)', fontproperties=self.font)
        fig.tight_layout()

    def _visualize_domain_url_top(self, log_lines, top_n, fig):
        """可视化域名及URL TOP"""
        domain_url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                domain = parts[8]
                url = parts[9]
                domain_url_counts[f"{domain} {url}"] += 1
        # 获取TOP N的数据
        top_items = domain_url_counts.most_common(top_n)
        items = [item for item, _ in top_items]
        counts = [count for _, count in top_items]
        ax = fig.add_subplot(111)
        y_pos = range(len(items))
        ax.barh(y_pos, counts)
        # 处理长文本
        readable_items = [item if len(item) <= 50 else item[:50] + "..." for item in items]
        ax.set_yticks(y_pos)
        ax.set_yticklabels(readable_items, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('域名及URL TOP', fontproperties=self.font)
        fig.tight_layout()

    def _analyze_traffic_ip_top(self, log_lines, top_n, text_widget):
        """分析消耗流量TOP IP"""
        ip_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    ip = parts[5]
                    size = int(parts[15])
                    ip_traffic[ip] += size
                except (ValueError, IndexError):
                    continue
        # 转换为MB并排序
        ip_traffic_mb = {ip: size/1024/1024 for ip, size in ip_traffic.items()}
        sorted_traffic = sorted(ip_traffic_mb.items(), key=lambda x: x[1], reverse=True)
        text_widget.insert(tk.END, "消耗流量TOP IP:\n")
        for ip, size in sorted_traffic[:top_n]:
            text_widget.insert(tk.END, f"{size:.2f}MB {ip}\n")

    def _analyze_traffic_url_no_param_top(self, log_lines, top_n, text_widget):
        """分析流量TOP URL(去参)"""
        url_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    url = parts[9].split('?')[0]
                    size = int(parts[15])
                    url_traffic[url] += size
                except (ValueError, IndexError):
                    continue
        # 转换为MB并排序
        url_traffic_mb = {url: size/1024/1024 for url, size in url_traffic.items()}
        sorted_traffic = sorted(url_traffic_mb.items(), key=lambda x: x[1], reverse=True)
        text_widget.insert(tk.END, "流量TOP URL(去参):\n")
        for url, size in sorted_traffic[:top_n]:
            text_widget.insert(tk.END, f"{size:.2f}MB {url}\n")

    def _analyze_traffic_domain_top(self, log_lines, top_n, text_widget):
        """分析流量TOP域名"""
        domain_traffic = defaultdict(int)
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 16:
                try:
                    domain = parts[8]
                    size = int(parts[15])
                    domain_traffic[domain] += size
                except (ValueError, IndexError):
                    continue
        # 转换为MB并排序
        domain_traffic_mb = {domain: size/1024/1024 for domain, size in domain_traffic.items()}
        sorted_traffic = sorted(domain_traffic_mb.items(), key=lambda x: x[1], reverse=True)
        text_widget.insert(tk.END, "流量TOP域名:\n")
        for domain, size in sorted_traffic[:top_n]:
            text_widget.insert(tk.END, f"{size:.2f}MB {domain}\n")

    def _analyze_concurrent_top(self, log_lines, top_n, text_widget):
        """分析并发TOP统计"""
        time_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 2:
                try:
                    time_str = parts[1].split('.')[0]
                    time_counts[time_str] += 1
                except (ValueError, IndexError):
                    continue
        
        self._display_top_results("并发TOP统计", time_counts, top_n, text_widget)

    def analyze_large_log(self, file_path, process_line_func):
        opener = gzip.open if file_path.endswith('.gz') else open
        with opener(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                process_line_func(line)

    def _analyze_url_top_no_param(self, log_lines, top_n, text_widget):
        """分析URL TOP(去参)"""
        url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:  # 确保有足够的字段
                url = parts[9]  # URL在第10个字段
                # 去掉URL参数
                url = url.split('?')[0]
                url_counts[url] += 1
        
        self._display_top_results("URL TOP(去参)", url_counts, top_n, text_widget)

    def _visualize_url_top_no_param(self, log_lines, top_n, fig):
        """可视化URL TOP(去参)"""
        url_counts = Counter()
        for line in log_lines:
            parts = line.split()
            if len(parts) >= 10:
                url = parts[9]  # URL在第10个字段
                # 去掉URL参数
                url = url.split('?')[0]
                url_counts[url] += 1
        
        # 获取TOP N的数据
        top_urls = url_counts.most_common(top_n)
        urls = [url for url, _ in top_urls]
        counts = [count for _, count in top_urls]
        
        # 创建水平条形图
        ax = fig.add_subplot(111)
        y_pos = range(len(urls))
        ax.barh(y_pos, counts)
        ax.set_yticks(y_pos)
        
        # 处理URL字符串，使其更易读
        readable_urls = []
        for url in urls:
            # 如果URL太长，截取主要部分
            if len(url) > 50:
                readable_urls.append(url[:50] + "...")
            else:
                readable_urls.append(url)
        
        ax.set_yticklabels(readable_urls, fontproperties=self.font)
        ax.set_xlabel('访问次数', fontproperties=self.font)
        ax.set_title('URL TOP(去参) 统计', fontproperties=self.font)
        
        # 调整布局以适应长文本
        fig.tight_layout()

class LogDownloader:
    """日志下载器类，处理所有下载相关的操作"""
    def __init__(self, master, result_text, progress_bar, validate_btn):
        self.master = master
        self.result_text = result_text
        self.progress_bar = progress_bar
        self.validate_btn = validate_btn
        self.downloaded_file = None
        
        # 定义常用的 User-Agent
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]

    def _update_status(self, message):
        """更新状态显示"""
        def update():
            self.result_text.config(state=tk.NORMAL)
            self.result_text.insert(tk.END, message + "\n")
            self.result_text.see(tk.END)
            self.result_text.config(state=tk.DISABLED)
        self.master.after(0, update)

    def _format_size(self, size_bytes):
        """格式化文件大小显示"""
        if size_bytes < 1024:
            return f"{size_bytes:.1f} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes/(1024*1024):.1f} MB"
        else:
            return f"{size_bytes/(1024*1024*1024):.1f} GB"

    def _download_single_file(self, url, index, save_dir):
        """下载单个文件的方法"""
        try:
            # 使用索引作为文件名
            filename = f"log_{index}.gz"
            filepath = os.path.join(save_dir, filename)
            
            # 随机选择一个 User-Agent
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # 尝试下载，最多重试3次
            for attempt in range(3):
                try:
                    # 设置连接超时和读取超时
                    connect_timeout = 10  # 连接超时10秒
                    read_timeout = 30     # 读取超时30秒
                    
                    # 发送请求获取文件
                    with requests.get(url, stream=True, timeout=(connect_timeout, read_timeout), headers=headers) as r:
                        r.raise_for_status()
                        
                        # 获取文件大小（如果服务器提供）
                        total_size = int(r.headers.get('content-length', 0))
                        block_size = 8192
                        downloaded_size = 0
                        last_progress = -1  # 用于跟踪上次显示的进度
                        
                        with open(filepath, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=block_size):
                                if chunk:
                                    f.write(chunk)
                                    downloaded_size += len(chunk)
                                    
                                    # 如果有总大小信息，计算并显示下载进度
                                    if total_size > 0:
                                        progress = int((downloaded_size / total_size) * 100)
                                        # 只在进度变化超过1%时更新显示
                                        if progress > last_progress:
                                            self._update_status(
                                                f"下载进度: {progress}% ({self._format_size(downloaded_size)}/{self._format_size(total_size)})"
                                            )
                                            last_progress = progress
                    
                    # 验证下载的文件
                    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                        return filepath
                    else:
                        raise Exception("下载的文件为空或不存在")
                        
                except requests.exceptions.Timeout:
                    if attempt == 2:
                        raise
                    time.sleep(2)
                except requests.exceptions.RequestException as e:
                    if attempt == 2:
                        raise
                    time.sleep(2)
                except Exception as e:
                    if attempt == 2:
                        raise
                    time.sleep(2)
                    
        except Exception as e:
            # 清理可能存在的部分下载文件
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except:
                    pass
            return None

    def _merge_gz_files(self, input_files, output_file):
        """合并gz文件的方法"""
        try:
            self._update_status(f"开始合并 {len(input_files)} 个文件到: {os.path.basename(output_file)}")
            
            # 确保输出目录存在
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with gzip.open(output_file, 'wb') as f_out:
                for file_idx, file_path in enumerate(input_files):
                    if not os.path.exists(file_path):
                        self._update_status(f"警告: 文件不存在，跳过: {os.path.basename(file_path)}")
                        continue
                        
                    try:
                        self._update_status(f"正在合并: {os.path.basename(file_path)} ({file_idx + 1}/{len(input_files)})")
                        
                        # 尝试作为gz文件读取
                        try:
                            with gzip.open(file_path, 'rb') as f_in:
                                while True:
                                    chunk = f_in.read(8192)
                                    if not chunk:
                                        break
                                    f_out.write(chunk)
                        except Exception as gz_error:
                            # 如果不是gz格式，尝试作为普通文件读取
                            self._update_status(f"文件不是gz格式，尝试作为普通文件读取: {os.path.basename(file_path)}")
                            with open(file_path, 'rb') as f_in:
                                while True:
                                    chunk = f_in.read(8192)
                                    if not chunk:
                                        break
                                    f_out.write(chunk)
                        
                        # 每合并完一个文件，更新进度条
                        current_progress = self.progress_bar['value']
                        self.progress_bar['value'] = current_progress + (1.0 / len(input_files))
                        self.master.update_idletasks()
                            
                    except Exception as e_merge:
                        self._update_status(f"合并文件时出错: {os.path.basename(file_path)} - {str(e_merge)}")
                        continue
            
            # 获取合并后文件的大小
            merged_size = os.path.getsize(output_file)
            self._update_status(f"成功合并文件: {os.path.basename(output_file)} (大小: {self._format_size(merged_size)})")
            
            return True
            
        except Exception as e:
            self._update_status(f"合并文件失败: {str(e)}")
            return False

    def download_logs(self, urls, save_dir, merge_var, merge_name):
        """下载并处理日志文件"""
        temp_files = []
        success_count = 0
        failed_urls = []
        
        # 计算总任务数（下载 + 可能的合并）
        total_tasks = len(urls)
        if merge_var.get() and len(urls) > 1:
            total_tasks += 1  # 添加合并任务
        
        # 重置进度条
        self.progress_bar['value'] = 0
        self.progress_bar['maximum'] = total_tasks

        # 顺序处理每个URL
        for i, url in enumerate(urls):
            # 显示当前下载的链接
            self._update_status(f"下载链接: {url}")
            
            # 记录开始时间
            start_time = time.time()
            
            # 下载文件
            result = self._download_single_file(url, i, save_dir)
            
            # 计算耗时
            elapsed_time = time.time() - start_time
            
            if result:
                temp_files.append(result)
                success_count += 1
                # 显示下载结果（在同一行）
                file_size = os.path.getsize(result)
                self._update_status(f"下载结果: 成功 | 文件名: {os.path.basename(result)} | 文件大小: {self._format_size(file_size)} | 耗时: {elapsed_time:.2f}秒\n---")
            else:
                failed_urls.append(url)
                self._update_status(f"\n下载结果: 失败 | 耗时: {elapsed_time:.2f}秒\n---")
            
            # 更新总体进度
            self.progress_bar['value'] = i + 1
            self.master.update_idletasks()

        # 处理文件合并
        if len(temp_files) > 1 and merge_var.get():
            # 确保合并文件名以.gz结尾
            if not merge_name.endswith('.gz'):
                merge_name += '.gz'
                
            merged_file_path = os.path.join(save_dir, merge_name)
            
            # 更新状态显示合并开始
            self._update_status(f"\n开始合并 {len(temp_files)} 个文件到: {merge_name}")
            
            # 执行合并
            if self._merge_gz_files(temp_files, merged_file_path):
                self.downloaded_file = merged_file_path
                # 更新进度条到完成状态
                self.progress_bar['value'] = total_tasks
                self.master.update_idletasks()
            else:
                self.downloaded_file = None
        elif len(temp_files) == 1:
            self.downloaded_file = temp_files[0]
        else:
            self.downloaded_file = None

        # 显示最终结果
        self._update_status("\n--- 下载完成 ---")
        self._update_status(f"成功下载: {success_count} 个文件")
        if failed_urls:
            self._update_status(f"失败: {len(failed_urls)} 个文件")
            self._update_status("失败的URL:")
            for url in failed_urls:
                self._update_status(f"- {url}")

        return success_count, failed_urls

# 修改主程序入口部分
if __name__ == "__main__":
    # 使用ttkbootstrap的Window类创建主窗口
    root = ttk.Window(title="日志分析工具", themename="flatly")
    root.geometry("1800x1400")
    
    # 创建应用实例
    app = LogAnalyzerApp(root)
    
    # 启动主循环
    root.mainloop()