import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import requests
import re
import threading
from urllib.parse import urljoin, urlparse
from queue import Queue
import json
import os

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
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS-Scanner)"
}

results = []
lock = threading.Lock()


# 🕷 自动爬取站点页面
def crawl_site(base_url, log, max_pages=100):
    visited = set()
    queue = Queue()
    queue.put(base_url)
    found_urls = []

    log.insert(tk.END, f"🌐 Crawling site: {base_url}\n")
    while not queue.empty() and len(visited) < max_pages:
        url = queue.get()
        if url in visited:
            continue
        visited.add(url)

        try:
            res = requests.get(url, headers=HEADERS, timeout=10)
            if "text/html" not in res.headers.get("Content-Type", ""):
                continue  # 只爬 HTML 页面

            found_urls.append(url)
            log.insert(tk.END, f"🔗 Found: {url}\n")

            links = re.findall(r'href=["\'](.*?)["\']', res.text, flags=re.IGNORECASE)
            for link in links:
                full_url = urljoin(url, link)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    if full_url not in visited:
                        queue.put(full_url)
        except Exception as e:
            log.insert(tk.END, f"⚠️ Error fetching {url}: {e}\n")
    log.insert(tk.END, f"✅ Total pages found: {len(found_urls)}\n")
    return found_urls


# ⚡ 多线程扫描 HTML 页面
def scan_html_page(url, log, progress, total, current):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        content = res.text

        findings = []
        for pattern in DANGEROUS_PATTERNS:
            matches = re.findall(pattern, content, flags=re.IGNORECASE | re.DOTALL)
            if matches:
                findings.append((pattern, matches))

        if findings:
            with lock:
                log.insert(tk.END, f"🚨 XSS risks found on {url}\n", "alert")
                for pattern, matches in findings:
                    log.insert(tk.END, f"  🔸 Pattern: {pattern}\n")
                    for match in matches[:3]:
                        log.insert(tk.END, f"     ➡ {match[:80]}...\n")
            results.append({
                "url": url,
                "type": "HTML",
                "issues": [{"pattern": p, "examples": m[:5]} for p, m in findings]
            })
        else:
            with lock:
                log.insert(tk.END, f"✅ No obvious XSS patterns found on {url}\n")
    except Exception as e:
        with lock:
            log.insert(tk.END, f"❌ Error scanning {url}: {e}\n")
    finally:
        with lock:
            current[0] += 1
            progress["value"] = (current[0] / total[0]) * 100


# 📤 扫描 JSON API 响应
def scan_json_api(url, log, progress, total, current):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        if "application/json" in res.headers.get("Content-Type", ""):
            data = res.json()
            json_str = json.dumps(data)
            findings = []
            for pattern in DANGEROUS_PATTERNS:
                matches = re.findall(pattern, json_str, flags=re.IGNORECASE)
                if matches:
                    findings.append((pattern, matches))

            if findings:
                with lock:
                    log.insert(tk.END, f"🚨 XSS risks found in JSON API {url}\n", "alert")
                    for pattern, matches in findings:
                        log.insert(tk.END, f"  🔸 Pattern: {pattern}\n")
                        for match in matches[:3]:
                            log.insert(tk.END, f"     ➡ {match[:80]}...\n")
                results.append({
                    "url": url,
                    "type": "JSON API",
                    "issues": [{"pattern": p, "examples": m[:5]} for p, m in findings]
                })
    except:
        pass
    finally:
        with lock:
            current[0] += 1
            progress["value"] = (current[0] / total[0]) * 100


# 📄 保存 HTML 报告
def save_report(results, filename="xss_scan_report.html"):
    html = """
    <html><head><title>XSS Scan Report</title>
    <style>
    body { font-family: Arial, sans-serif; }
    h2 { color: #d9534f; }
    pre { background: #f9f9f9; padding: 10px; border: 1px solid #ccc; }
    </style></head><body>
    <h1>XSS Scan Report</h1>
    """
    for r in results:
        html += f"<h2>{r['type']} - {r['url']}</h2>"
        for issue in r["issues"]:
            html += f"<p><b>Pattern:</b> {issue['pattern']}</p>"
            html += "<pre>" + "\n".join(issue["examples"]) + "</pre>"
    html += "</body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return os.path.abspath(filename)


# 🖥 GUI 主界面
def create_gui():
    root = tk.Tk()
    root.title("XSS 全功能扫描器")
    root.geometry("800x600")

    tk.Label(root, text="📂 URL 列表文件 (.txt 每行一个 URL):").pack(pady=5)
    entry = tk.Entry(root, width=80)
    entry.pack()
    tk.Button(root, text="浏览", command=lambda: load_url_file(entry)).pack(pady=5)

    progress = ttk.Progressbar(root, length=700)
    progress.pack(pady=5)

    log = scrolledtext.ScrolledText(root, height=20)
    log.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    log.tag_config("alert", foreground="red")
    log.tag_config("title", foreground="blue", font=("Arial", 10, "bold"))

    def run_scan():
        url_file = entry.get().strip()
        if not os.path.isfile(url_file):
            messagebox.showerror("Error", "请先选择有效的 URL 列表文件！")
            return
        with open(url_file, "r", encoding="utf-8") as f:
            url_list = [line.strip() for line in f if line.strip()]
        if not url_list:
            messagebox.showerror("Error", "URL 列表为空！")
            return

        total = [len(url_list) * 2]  # HTML + JSON
        current = [0]
        progress["maximum"] = 100
        progress["value"] = 0

        # 多线程扫描 HTML
        for url in url_list:
            threading.Thread(target=scan_html_page, args=(url, log, progress, total, current), daemon=True).start()
        # 多线程扫描 JSON
        for url in url_list:
            threading.Thread(target=scan_json_api, args=(url, log, progress, total, current), daemon=True).start()

    tk.Button(root, text="开始扫描", command=run_scan, bg="green", fg="white").pack(pady=10)
    root.mainloop()


# 打开文件选择
def load_url_file(entry):
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)


if __name__ == "__main__":
    create_gui()
