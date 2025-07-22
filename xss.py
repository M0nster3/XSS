import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import requests
import re
import threading
from urllib.parse import urljoin, urlparse
from queue import Queue
import json
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException

# 🚨 高危 API/属性关键字
DANGEROUS_PATTERNS = [
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(.*['\"]",
    r"setInterval\s*\(.*['\"]",
    r"new Function\s*\(",
    r"\.src\s*=",
    r"\.href\s*=",
    r"\.action\s*=",
    r"\.onerror\s*=",
    r"\.onclick\s*=",
    r"\.onload\s*=",
    r"jQuery\.html\s*\(",
    r"jQuery\.append\s*\(",
    r"jQuery\.attr\s*\(",
    r"on\w+\s*=",
    r"javascript\s*:",
    r"<input\b[^>]*>",
]

# API端点常见路径
API_PATHS = [
    'api', 'graphql', 'rest', 'v1', 'v2', 
    'oauth', 'auth', 'login', 'logout',
    'user', 'users', 'account', 'admin'
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS-Scanner)"
}

results = []
crawled_urls = []
lock = threading.Lock()

class Crawler:
    def __init__(self, base_url, log, max_depth=3, max_pages=50, dynamic=False):
        self.base_url = base_url
        self.log = log
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.dynamic = dynamic
        self.visited = set()
        self.queue = Queue()
        self.domain = urlparse(base_url).netloc
        self.driver = None
        
        if dynamic:
            self.init_selenium()
            
    def deep_dom_scan(self, url):
        if not self.driver:
            return []
        
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )

            # 核心JS探测脚本
            scan_js = """
            // 1. 获取所有隐藏输入字段
            const hiddenInputs = Array.from(document.querySelectorAll('input[type=hidden]')).map(el => ({
                name: el.name,
                value: el.value,
                id: el.id,
                outerHTML: el.outerHTML
            }));

            // 2. 探测动态生成的DOM
            const dynamicElements = Array.from(document.querySelectorAll('[data-*]')).map(el => ({
                tag: el.tagName,
                attributes: Array.from(el.attributes).map(attr => ({
                    name: attr.name,
                    value: attr.value
                }))
            }));

            // 3. 检查Shadow DOM
            const shadowContent = [];
            document.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) {
                    shadowContent.push({
                        host: el.tagName,
                        html: el.shadowRoot.innerHTML
                    });
                }
            });

            return {
                hiddenInputs,
                dynamicElements,
                shadowContent
            };
            """
            
            # 执行探测
            dom_data = self.driver.execute_script(scan_js)
            
            # 处理结果
            risks = []
            for inp in dom_data['hiddenInputs']:
                if inp['name'] == 'etd':  # 针对您的用例
                    risks.append({
                        'type': 'Hidden Input',
                        'field': inp
                    })
            
            return risks

        except Exception as e:
            print(f"深度扫描失败: {str(e)}")
            return []

    def init_selenium(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--allow-running-insecure-content')
        self.driver = webdriver.Chrome(options=chrome_options)
    
    def close_selenium(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def crawl(self):
        self.queue.put((self.base_url, 0))
        
        while not self.queue.empty() and len(self.visited) < self.max_pages:
            url, depth = self.queue.get()
            
            if url in self.visited or depth > self.max_depth:
                continue
                
            self.visited.add(url)
            
            try:
                if self.dynamic:
                    content, links = self.crawl_dynamic(url)
                else:
                    content, links = self.crawl_static(url)
                
                crawled_urls.append(url)
                with lock:
                    self.log.insert(tk.END, f"🔗 深度 {depth}: {url}\n")
                
                # 发现API端点
                api_endpoints = self.find_api_endpoints(url, content)
                for api in api_endpoints:
                    if api not in self.visited:
                        self.queue.put((api, depth + 1))
                        with lock:
                            self.log.insert(tk.END, f"   ➤ 发现API端点: {api}\n")
                
                # 添加新链接到队列
                for link in links:
                    if link not in self.visited and link not in [q[0] for q in self.queue.queue]:
                        self.queue.put((link, depth + 1))
            
            except Exception as e:
                with lock:
                    self.log.insert(tk.END, f"⚠️ 抓取 {url} 出错: {str(e)[:100]}\n")
        
        self.close_selenium()
        return list(self.visited)
    
    def crawl_static(self, url):
        res = requests.get(url, headers=HEADERS, timeout=10)
        content = res.text
        
        # 提取所有链接
        links = set()
        soup = BeautifulSoup(content, 'html.parser')
        
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
            attr = 'href' if tag.name in ['a', 'link'] else 'src'
            if attr in tag.attrs:
                link = urljoin(url, tag[attr])
                if self.is_valid_url(link):
                    links.add(link)
        
        return content, list(links)
    
    def crawl_dynamic(self, url):
        if not self.driver:
            return "", []
            
        try:
            self.driver.get(url)
            time.sleep(2)  # 更智能的等待方式
            WebDriverWait(self.driver, 10).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            
            content = self.driver.page_source
            
            # 修复点1：使用新的find_elements API
            elements = self.driver.find_elements(By.XPATH, "//*[@href or @src]")
            links = set()
            
            for el in elements:
                try:
                    link = el.get_attribute('href') or el.get_attribute('src')
                    if link and self.is_valid_url(link):
                        links.add(link)
                except:
                    continue
                    
            return content, list(links)
            
        except WebDriverException as e:
            with lock:
                self.log.insert(tk.END, f"⚠️ 动态抓取 {url} 出错: {str(e)[:100]}\n")
            return "", []
    
    def is_valid_url(self, url):
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        if parsed.netloc != self.domain:
            return False
        if parsed.path.endswith(('.jpg', '.png', '.gif', '.css', '.pdf')):
            return False
        return True
    
    def find_api_endpoints(self, url, content):
        endpoints = set()
        
        # 从HTML内容中查找API路径
        api_pattern = r'["\'](/[^"\']*?(?:{})(?:/[^"\']*)?)["\']'.format('|'.join(API_PATHS))
        matches = re.findall(api_pattern, content, re.IGNORECASE)
        
        for match in matches:
            endpoint = urljoin(url, match)
            if self.is_valid_url(endpoint):
                endpoints.add(endpoint)
        
        # 从JavaScript代码中查找API调用
        js_pattern = r'(?:fetch|axios|ajax|XMLHttpRequest)\s*\(\s*["\']([^"\']*?)["\']'
        js_matches = re.findall(js_pattern, content, re.IGNORECASE)
        
        for match in js_matches:
            endpoint = urljoin(url, match)
            if self.is_valid_url(endpoint):
                endpoints.add(endpoint)
        
        return list(endpoints)

class Scanner:
    def __init__(self, log, progress, total_urls):
        self.log = log
        self.progress = progress
        self.total = total_urls
        self.current = 0
    
    def scan_all(self, urls):
        threads = []
        
        for url in urls:
            t = threading.Thread(target=self.scan_url, args=(url,), daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
    
    def scan_url(self, url):
        try:
            content_type = self.get_content_type(url)
            
            if "text/html" in content_type:
                self.scan_html(url)
            elif "application/javascript" in content_type:
                self.scan_js(url)
            elif "application/json" in content_type:
                self.scan_json(url)
            
        except Exception as e:
            with lock:
                self.log.insert(tk.END, f"❌ 扫描 {url} 出错: {str(e)[:100]}\n")
        finally:
            with lock:
                self.current += 1
                self.progress["value"] = (self.current / self.total) * 100
    
    def get_content_type(self, url):
        try:
            res = requests.head(url, headers=HEADERS, timeout=5)
            return res.headers.get("Content-Type", "").lower()
        except:
            return ""
    
    def scan_html(self, url):
        res = requests.get(url, headers=HEADERS, timeout=10)
        content = res.text
        
        findings = []
        for pattern in DANGEROUS_PATTERNS:
            matches = re.findall(pattern, content, flags=re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append((pattern, matches))
        
        if findings:
            with lock:
                self.log.insert(tk.END, f"🚨 HTML XSS风险: {url}\n", "alert")
                for pattern, matches in findings:
                    self.log.insert(tk.END, f"  🔸 模式: {pattern}\n")
                    for match in matches[:3]:
                        self.log.insert(tk.END, f"     ➡ {match[:80]}...\n")
            
            results.append({
                "url": url,
                "type": "HTML",
                "issues": [{"pattern": p, "examples": m[:5]} for p, m in findings]
            })
    
    def scan_js(self, url):
        res = requests.get(url, headers=HEADERS, timeout=10)
        content = res.text
        
        findings = []
        js_patterns = [
            r"\.innerHTML\s*=",
            r"document\.write\s*\(",
            r"eval\s*\(",
            r"new Function\s*\(",
            r"setTimeout\s*\(.*['\"]",
            r"setInterval\s*\(.*['\"]",
            r"location\.(href|assign|replace)\s*=",
            r"window\.open\s*\(",
            r"\.src\s*=",
            r"\.postMessage\s*\("
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, flags=re.IGNORECASE)
            if matches:
                findings.append((pattern, matches))
        
        if findings:
            with lock:
                self.log.insert(tk.END, f"🚨 JS文件XSS风险: {url}\n", "alert")
                for pattern, matches in findings:
                    self.log.insert(tk.END, f"  🔸 模式: {pattern}\n")
                    for match in matches[:3]:
                        self.log.insert(tk.END, f"     ➡ {match[:80]}...\n")
            
            results.append({
                "url": url,
                "type": "JavaScript",
                "issues": [{"pattern": p, "examples": m[:5]} for p, m in findings]
            })
    
    def scan_json(self, url):
        res = requests.get(url, headers=HEADERS, timeout=10)
        try:
            data = res.json()
            json_str = json.dumps(data)
            
            findings = []
            for pattern in DANGEROUS_PATTERNS:
                matches = re.findall(pattern, json_str, flags=re.IGNORECASE)
                if matches:
                    findings.append((pattern, matches))
            
            if findings:
                with lock:
                    self.log.insert(tk.END, f"🚨 JSON API XSS风险: {url}\n", "alert")
                    for pattern, matches in findings:
                        self.log.insert(tk.END, f"  🔸 模式: {pattern}\n")
                        for match in matches[:3]:
                            self.log.insert(tk.END, f"     ➡ {match[:80]}...\n")
                
                results.append({
                    "url": url,
                    "type": "JSON API",
                    "issues": [{"pattern": p, "examples": m[:5]} for p, m in findings]
                })
        except:
            pass

def save_report(results, filename="xss_scan_report.html"):
    html = """
    <html><head><title>XSS扫描报告</title>
    <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; }
    h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    h2 { color: #d9534f; margin-top: 30px; }
    .url { color: #337ab7; font-weight: bold; }
    .issue { background: #f9f9f9; border-left: 4px solid #d9534f; padding: 10px; margin: 10px 0; }
    .pattern { color: #5bc0de; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style></head><body>
    <h1>XSS漏洞扫描报告</h1>
    <p>扫描时间: {time}</p>
    """
    
    from datetime import datetime
    html = html.format(time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    for r in results:
        html += f"""
        <div class="result">
            <h2>{r['type']}</h2>
            <p class="url">{r['url']}</p>
        """
        
        for issue in r["issues"]:
            html += f"""
            <div class="issue">
                <p class="pattern">危险模式: {issue['pattern']}</p>
                <p>示例:</p>
                <pre>{'\n'.join(issue['examples'])}</pre>
            </div>
            """
        
        html += "</div>"
    
    html += "</body></html>"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return os.path.abspath(filename)

def create_gui():
    root = tk.Tk()
    root.title("高级XSS扫描器 v2.0")
    root.geometry("900x700")
    
    # 配置区域
    config_frame = tk.Frame(root)
    config_frame.pack(pady=10, fill=tk.X)
    
    tk.Label(config_frame, text="🌐 目标URL列表 (每行一个URL):").grid(row=0, column=0, sticky='nw')
    
    # 创建带滚动条的URL输入框
    url_frame = tk.Frame(config_frame)
    url_frame.grid(row=1, column=0, columnspan=3, sticky='ew')
    
    url_text = scrolledtext.ScrolledText(url_frame, height=8, wrap=tk.WORD)
    url_text.pack(fill=tk.BOTH, expand=True)
    
    # 添加示例URL按钮
    def add_example_urls():
        example_urls = """http://example.com
https://test-site.com
http://demo.org/admin"""
        url_text.delete(1.0, tk.END)
        url_text.insert(tk.END, example_urls)
    
    example_btn = tk.Button(config_frame, text="添加示例URL", command=add_example_urls)
    example_btn.grid(row=2, column=0, sticky='w', pady=5)
    
    # 其他配置选项
    tk.Label(config_frame, text="爬取深度:").grid(row=3, column=0, sticky='w')
    depth_spin = tk.Spinbox(config_frame, from_=1, to=5, width=5)
    depth_spin.grid(row=3, column=1, sticky='w', padx=5)
    
    tk.Label(config_frame, text="最大页面数:").grid(row=4, column=0, sticky='w')
    max_pages_spin = tk.Spinbox(config_frame, from_=10, to=500, width=5)
    max_pages_spin.grid(row=4, column=1, sticky='w', padx=5)
    
    dynamic_var = tk.IntVar()
    tk.Checkbutton(config_frame, text="动态内容分析(Selenium)", variable=dynamic_var).grid(row=5, column=0, columnspan=2, sticky='w')
    
    # 进度条
    progress = ttk.Progressbar(root, length=800)
    progress.pack(pady=5)
    
    # 日志区域
    log_frame = tk.Frame(root)
    log_frame.pack(pady=10, fill=tk.BOTH, expand=True)
    
    log = scrolledtext.ScrolledText(log_frame, height=25)
    log.pack(fill=tk.BOTH, expand=True)
    log.tag_config("alert", foreground="red")
    log.tag_config("success", foreground="green")
    
    # 按钮区域
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)
    
    def run_crawl():
        url_list = url_text.get(1.0, tk.END).strip().split('\n')
        url_list = [url.strip() for url in url_list if url.strip()]
        
        if not url_list:
            messagebox.showerror("错误", "请输入至少一个有效的URL！")
            return
            
        # 检查并修正URL格式
        processed_urls = []
        for url in url_list:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            processed_urls.append(url)
        
        # 清空之前的结果
        global results, crawled_urls
        results = []
        crawled_urls = []
        
        log.delete(1.0, tk.END)
        log.insert(tk.END, f"🕷 开始爬取 {len(processed_urls)} 个网站...\n")
        
        def crawl_thread():
            try:
                for url in processed_urls:
                    log.insert(tk.END, f"\n=== 开始处理: {url} ===\n")
                    crawler = Crawler(
                        base_url=url,
                        log=log,
                        max_depth=int(depth_spin.get()),
                        max_pages=int(max_pages_spin.get()),
                        dynamic=bool(dynamic_var.get())
                    )
                    crawled_urls.extend(crawler.crawl())
                
                log.insert(tk.END, "\n✅ 所有URL爬取完成！\n", "success")
                log.insert(tk.END, f"共找到 {len(crawled_urls)} 个URL\n")
                
                # 启用扫描按钮
                scan_btn.config(state=tk.NORMAL)
            except Exception as e:
                log.insert(tk.END, f"❌ 爬取过程中出错: {str(e)}\n")
        
        threading.Thread(target=crawl_thread, daemon=True).start()
    
    def run_scan():
        if not crawled_urls:
            messagebox.showerror("错误", "请先爬取URL！")
            return
            
        log.insert(tk.END, "\n⚡ 开始扫描漏洞...\n")
        
        def scan_thread():
            try:
                scanner = Scanner(log, progress, len(crawled_urls))
                scanner.scan_all(crawled_urls)
                
                log.insert(tk.END, "\n✅ 扫描完成！\n", "success")
                log.insert(tk.END, f"共发现 {len(results)} 处潜在漏洞\n")
                
                # 生成报告
                report_path = save_report(results)
                log.insert(tk.END, f"\n📄 报告已保存到: {report_path}\n", "success")
                
                # 显示报告按钮
                report_btn.config(state=tk.NORMAL)
            except Exception as e:
                log.insert(tk.END, f"❌ 扫描过程中出错: {str(e)}\n")
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def show_report():
        report_path = save_report(results)
        os.startfile(report_path)
    
    crawl_btn = tk.Button(button_frame, text="开始爬取", command=run_crawl, bg="#5bc0de", fg="white")
    crawl_btn.pack(side=tk.LEFT, padx=5)
    
    scan_btn = tk.Button(button_frame, text="开始扫描", command=run_scan, bg="#5cb85c", fg="white", state=tk.DISABLED)
    scan_btn.pack(side=tk.LEFT, padx=5)
    
    report_btn = tk.Button(button_frame, text="查看报告", command=show_report, bg="#f0ad4e", fg="white", state=tk.DISABLED)
    report_btn.pack(side=tk.LEFT, padx=5)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
