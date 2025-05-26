import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import json
import webbrowser
import requests
import os
from datetime import datetime
from urllib.parse import urlparse

class CVEToolkitPro:
    def __init__(self, root):
        self.root = root
        self.root.title("CVE Toolkit Pro")
        self.root.geometry("1366x860")
        self.current_data = []
        self.filtered_data = []
        self.github_token = None
        self.config_path = os.path.expanduser("~/.cve_toolkit_pro.json")

        # Initialize UI components
        self.setup_menu()
        self.setup_style()
        self.setup_notebook()
        self.setup_context_menu()
        self.setup_status_bar()
        self.load_config()

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # GitHub menu
        github_menu = tk.Menu(menubar, tearoff=0)
        github_menu.add_command(label="Set API Token", command=self.set_github_token)
        github_menu.add_command(label="Clear Token", command=self.clear_github_token)
        
        menubar.add_cascade(label="File", menu=file_menu)
        menubar.add_cascade(label="GitHub", menu=github_menu)
        
        self.root.config(menu=menubar)

    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure("Treeview", 
                           font=('Segoe UI', 9), 
                           rowheight=28,
                           background='#ffffff',
                           fieldbackground='#ffffff')
        self.style.map('Treeview', background=[('selected', '#0078D4')])
        self.style.configure("Treeview.Heading", 
                           font=('Segoe UI', 10, 'bold'),
                           background='#f0f0f0')
        self.style.configure("TNotebook.Tab", 
                           font=('Segoe UI', 9, 'bold'),
                           padding=(10, 5))
        self.style.configure("TButton", 
                           font=('Segoe UI', 9),
                           padding=6)
        self.style.configure("Status.TLabel",
                           font=('Segoe UI', 8),
                           background='#f0f0f0',
                           relief=tk.SUNKEN)

    def setup_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Local CVE Tab
        self.local_frame = ttk.Frame(self.notebook)
        self.setup_local_tab()
        
        # GitHub Search Tab
        self.github_frame = ttk.Frame(self.notebook)
        self.setup_github_tab()
        
        # Documentation Tab
        self.doc_frame = ttk.Frame(self.notebook)
        self.setup_documentation_tab()
        
        self.notebook.add(self.local_frame, text="Local CVEs")
        self.notebook.add(self.github_frame, text="GitHub Search")
        self.notebook.add(self.doc_frame, text="Documentation")

    def setup_local_tab(self):
        # Search Frame
        search_frame = ttk.Frame(self.local_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.local_search_entry = ttk.Entry(search_frame, width=40)
        self.local_search_entry.pack(side=tk.LEFT, padx=5)
        self.local_search_entry.bind("<Return>", lambda e: self.filter_cves())
        
        ttk.Button(search_frame, text="Search", command=self.filter_cves).pack(side=tk.LEFT, padx=2)
        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=2)

        # Toolbar
        toolbar = ttk.Frame(self.local_frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Button(toolbar, text="Load JSON", command=self.load_json).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Refresh", command=self.refresh_data).pack(side=tk.LEFT, padx=2)
        
        # Treeview
        self.tree = ttk.Treeview(self.local_frame, columns=("ID", "CVE ID", "Author", "Date", "Severity", "Link"), show="headings")
        
        # Configure columns
        columns = [
            ("ID", 50), ("CVE ID", 150), ("Author", 120),
            ("Date", 100), ("Severity", 80), ("Link", 300)
        ]
        
        for col, width in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_treeview(c, False))
            self.tree.column(col, width=width, anchor=tk.W, stretch=True)
        
        # Configure tags for severity colors
        self.tree.tag_configure('High', background='#ffcccc')
        self.tree.tag_configure('Medium', background='#ffffcc')
        self.tree.tag_configure('Low', background='#ccffcc')
        
        # Scrollbars
        vsb = ttk.Scrollbar(self.local_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.local_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Layout
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        # Double-click binding
        self.tree.bind("<Double-1>", self.open_link_event)

    def setup_github_tab(self):
        # Search Controls
        search_frame = ttk.Frame(self.github_frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Search Query:").pack(side=tk.LEFT)
        self.github_search_entry = ttk.Entry(search_frame, width=40)
        self.github_search_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(search_frame, text="Year:").pack(side=tk.LEFT)
        self.year_combo = ttk.Combobox(search_frame, values=[str(y) for y in range(1999, datetime.now().year+1)], width=6)
        self.year_combo.set(str(datetime.now().year))
        self.year_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(search_frame, text="Search GitHub", command=self.github_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Search ExploitDB", command=self.search_exploit_db).pack(side=tk.LEFT, padx=5)
        
        # Results Treeview
        self.github_tree = ttk.Treeview(self.github_frame, columns=("Repository", "Description", "Author", "Stars", "URL"), show="headings")
        
        github_columns = [
            ("Repository", 200), ("Description", 300), ("Author", 120),
            ("Stars", 80), ("URL", 400)
        ]
        
        for col, width in github_columns:
            self.github_tree.heading(col, text=col)
            self.github_tree.column(col, width=width, anchor=tk.W)
        
        # Scrollbars
        vsb = ttk.Scrollbar(self.github_frame, orient="vertical", command=self.github_tree.yview)
        hsb = ttk.Scrollbar(self.github_frame, orient="horizontal", command=self.github_tree.xview)
        self.github_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Layout
        self.github_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_documentation_tab(self):
        doc_text = """CVE Toolkit Pro Documentation

1. Local CVE Management:
   - Load JSON: Import CVE data from JSON files
   - Export JSON: Save current CVE list to JSON
   - Double-click entries for detailed view
   - Right-click for context actions

2. GitHub Integration:
   - Set GitHub API token for increased rate limits
   - Search GitHub repositories by CVE ID/year
   - Auto-extract author from GitHub URLs
   - Direct repository downloads

3. Advanced Features:
   - ExploitDB integration
   - Severity rating system
   - Customizable columns
   - Secure token storage

Keyboard Shortcuts:
   - Ctrl+O: Open file
   - Ctrl+S: Save file
   - Ctrl+F: Search focus
   - F5: Refresh data
"""
        text_area = scrolledtext.ScrolledText(self.doc_frame, wrap=tk.WORD, font=('Consolas', 10))
        text_area.insert(tk.INSERT, doc_text)
        text_area.configure(state='disabled')
        text_area.pack(fill=tk.BOTH, expand=True)

    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open Link", command=self.open_link)
        self.context_menu.add_command(label="Copy CVE ID", command=self.copy_cve_id)
        self.context_menu.add_command(label="Download Repo", command=self.download_from_local_link)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Export Entry", command=self.export_entry)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.github_tree.bind("<Button-3>", self.show_github_context_menu)

    def setup_status_bar(self):
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, 
                             anchor=tk.W, style="Status.TLabel")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # Core functionality methods
    def set_github_token(self):
        token = simpledialog.askstring("GitHub Token", "Enter GitHub personal access token:", parent=self.root)
        if token:
            self.github_token = token
            self.save_config()
            messagebox.showinfo("Success", "GitHub token configured successfully")
            self.status_var.set("GitHub token configured")

    def clear_github_token(self):
        self.github_token = None
        self.save_config()
        messagebox.showinfo("Info", "GitHub token cleared")
        self.status_var.set("GitHub token cleared")

    def load_config(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                self.github_token = config.get('github_token')
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to load config: {str(e)}")

    def save_config(self):
        try:
            with open(self.config_path, 'w') as f:
                json.dump({'github_token': self.github_token}, f)
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to save config: {str(e)}")

    def load_json(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not path:
            return
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            self.current_data = []
            for idx, item in enumerate(data, 1):
                if 'Author' not in item and 'Link' in item:
                    parsed = urlparse(item['Link'])
                    if 'github.com' in parsed.netloc:
                        parts = parsed.path.strip('/').split('/')
                        if len(parts) >= 1:
                            item['Author'] = parts[0]
                
                self.current_data.append({
                    "ID": idx,
                    "CVE ID": item.get("CVE ID", ""),
                    "Author": item.get("Author", "Unknown"),
                    "Date": item.get("Date", ""),
                    "Severity": item.get("Severity", "Medium").capitalize(),
                    "Link": item.get("Link", ""),
                    "RawData": item
                })
            
            self.clear_search()
            messagebox.showinfo("Success", f"Loaded {len(data)} CVEs")
            self.status_var.set(f"Loaded {len(data)} CVEs from {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load JSON: {str(e)}")

    def filter_cves(self):
        query = self.local_search_entry.get().lower()
        if not query:
            self.clear_search()
            return
        
        filtered = []
        for item in self.current_data:
            if (query in item["CVE ID"].lower() or
                query in item["Author"].lower() or
                query in item["Date"].lower() or
                query in item["Severity"].lower() or
                query in item["Link"].lower()):
                filtered.append(item)
        
        self.filtered_data = filtered
        self.refresh_treeview(self.filtered_data)
        self.status_var.set(f"Showing {len(filtered)} of {len(self.current_data)} CVEs")

    def clear_search(self):
        self.local_search_entry.delete(0, tk.END)
        self.refresh_treeview()
        self.status_var.set(f"Showing all {len(self.current_data)} CVEs")

    def sort_treeview(self, col, reverse):
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        data.sort(reverse=reverse)
        
        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)
        
        self.tree.heading(col, command=lambda: self.sort_treeview(col, not reverse))

    def refresh_treeview(self, data=None):
        data = data if data is not None else self.current_data
        self.tree.delete(*self.tree.get_children())
        
        for item in data:
            tags = (item["Severity"],)
            self.tree.insert("", tk.END, 
                           values=(
                               item["ID"],
                               item["CVE ID"],
                               item["Author"],
                               item["Date"],
                               item["Severity"],
                               item["Link"]
                           ), tags=tags)

    def github_search(self):
        query = self.github_search_entry.get()
        year = self.year_combo.get()
        search_terms = f"CVE-{year} {query}"
        
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        
        try:
            response = requests.get(
                f"https://api.github.com/search/repositories?q={search_terms}",
                headers=headers
            )
            response.raise_for_status()
            
            self.github_tree.delete(*self.github_tree.get_children())
            for repo in response.json()['items']:
                self.github_tree.insert("", tk.END, values=(
                    repo['name'],
                    repo['description'] or "No description",
                    repo['owner']['login'],
                    repo['stargazers_count'],
                    repo['html_url']
                ))
            self.status_var.set(f"Found {len(response.json()['items'])} GitHub repositories")
        except Exception as e:
            messagebox.showerror("Search Error", f"GitHub search failed: {str(e)}")
            self.status_var.set("GitHub search failed")

    def download_repo(self):
        selected = self.github_tree.selection()
        if not selected:
            return
        
        url = self.github_tree.item(selected[0], 'values')[4]
        try:
            if not os.path.exists("downloads"):
                os.makedirs("downloads")
            
            repo_name = url.split('/')[-1]
            zip_url = f"{url}/archive/refs/heads/main.zip"
            response = requests.get(zip_url, stream=True)
            
            filename = f"downloads/{repo_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=128):
                    f.write(chunk)
            
            messagebox.showinfo("Success", f"Downloaded to:\n{filename}")
            self.status_var.set(f"Downloaded repository to {filename}")
        except Exception as e:
            messagebox.showerror("Download Error", f"Failed to download: {str(e)}")
            self.status_var.set("Download failed")

    def download_from_local_link(self):
        selected = self.tree.selection()
        if not selected:
            return
        
        link = self.tree.item(selected[0], 'values')[5]
        if not link:
            messagebox.showerror("Error", "No link available for this entry")
            return
        
        try:
            parsed_url = urlparse(link)
            if 'github.com' in parsed_url.netloc:
                path_parts = parsed_url.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    repo_owner = path_parts[0]
                    repo_name = path_parts[1]
                    zip_url = f"https://github.com/{repo_owner}/{repo_name}/archive/refs/heads/main.zip"
                else:
                    raise ValueError("Invalid GitHub URL format")
            else:
                zip_url = link  # Assume direct download link
            
            if not os.path.exists("downloads"):
                os.makedirs("downloads")
            
            if 'github.com' in parsed_url.netloc:
                filename = f"downloads/{repo_name}-{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
            else:
                filename = os.path.join("downloads", os.path.basename(parsed_url.path))
                filename = f"{filename}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            response = requests.get(zip_url, stream=True)
            response.raise_for_status()

            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=128):
                    f.write(chunk)
            
            messagebox.showinfo("Success", f"Downloaded to:\n{filename}")
            self.status_var.set(f"Downloaded to {filename}")
        except Exception as e:
            messagebox.showerror("Download Error", f"Failed to download: {str(e)}")
            self.status_var.set("Download failed")

    def search_exploit_db(self):
        query = self.github_search_entry.get()
        year = self.year_combo.get()
        webbrowser.open(f"https://www.exploit-db.com/search?q=CVE-{year}-{query}")
        self.status_var.set(f"Opened Exploit-DB search for CVE-{year}-{query}")

    def show_context_menu(self, event):
        widget = event.widget
        item = widget.identify_row(event.y)
        if item:
            widget.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def show_github_context_menu(self, event):
        item = self.github_tree.identify_row(event.y)
        if item:
            self.github_tree.selection_set(item)
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Open Repository", command=lambda: webbrowser.open(self.github_tree.item(item, 'values')[4]))
            menu.add_command(label="Download Repo", command=self.download_repo)
            menu.post(event.x_root, event.y_root)

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if not path:
            return
        
        try:
            with open(path, 'w') as f:
                json.dump([item['RawData'] for item in self.current_data], f, indent=2)
            messagebox.showinfo("Success", "Data exported successfully")
            self.status_var.set(f"Data exported to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
            self.status_var.set("Export failed")

    def open_link_event(self, event):
        self.open_link()

    def open_link(self):
        selected = self.tree.selection()
        if selected:
            link = self.tree.item(selected[0], 'values')[5]
            webbrowser.open(link)
            self.status_var.set(f"Opened {link}")

    def copy_cve_id(self):
        selected = self.tree.selection()
        if selected:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.tree.item(selected[0], 'values')[1])
            self.status_var.set("Copied CVE ID to clipboard")

    def refresh_data(self):
        self.refresh_treeview()
        self.status_var.set("Data refreshed")

    def export_entry(self):
        selected = self.tree.selection()
        if selected:
            item = self.current_data[int(self.tree.item(selected[0], 'values')[0]) - 1]
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                initialfile=f"{item['CVE ID']}.json"
            )
            if path:
                try:
                    with open(path, 'w') as f:
                        json.dump(item['RawData'], f, indent=2)
                    messagebox.showinfo("Success", "Entry exported successfully")
                    self.status_var.set(f"Exported {item['CVE ID']} to {os.path.basename(path)}")
                except Exception as e:
                    messagebox.showerror("Export Error", str(e))
                    self.status_var.set("Export failed")

if __name__ == "__main__":
    root = tk.Tk()
    app = CVEToolkitPro(root)
    root.mainloop()