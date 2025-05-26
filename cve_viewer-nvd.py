import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import webbrowser

class CVEViewerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CVE Viewer")
        self.cve_data = []
        
        # Create main container
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Create controls frame
        self.controls_frame = ttk.Frame(self.main_frame)
        self.controls_frame.pack(fill='x', pady=5)
        
        # Load JSON button
        self.load_btn = ttk.Button(
            self.controls_frame, 
            text="Load JSON File",
            command=self.load_json
        )
        self.load_btn.pack(side='left', padx=5)
        
        # Search entry
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            self.controls_frame,
            textvariable=self.search_var,
            width=30
        )
        self.search_entry.pack(side='right', padx=5)
        self.search_entry.bind('<KeyRelease>', self.filter_data)
        ttk.Label(self.controls_frame, text="Search:").pack(side='right', padx=5)
        
        # Create Treeview with scrollbars
        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.pack(fill='both', expand=True)
        
        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=('cve_id', 'date_updated', 'cve_link', 'github_link'),
            show='headings'
        )
        
        # Configure columns
        self.tree.heading('cve_id', text='CVE ID')
        self.tree.heading('date_updated', text='Date Updated')
        self.tree.heading('cve_link', text='CVE Link')
        self.tree.heading('github_link', text='GitHub Link')
        
        self.tree.column('cve_id', width=120, anchor='w')
        self.tree.column('date_updated', width=180, anchor='w')
        self.tree.column('cve_link', width=250, anchor='w')
        self.tree.column('github_link', width=250, anchor='w')
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(self.tree_frame, orient='vertical', command=self.tree.yview)
        x_scroll = ttk.Scrollbar(self.tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        
        # Configure grid resizing
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind double click event
        self.tree.bind('<Double-1>', self.open_link)

    def load_json(self):
        file_path = filedialog.askopenfilename(
            title="Select CVE JSON File",
            filetypes=[("JSON files", "*.json")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                    # Clear previous data
                    self.cve_data = []
                    
                    # Process array of report objects
                    for report in data:
                        # Collect entries from both new and updated sections
                        self.cve_data.extend(report.get('new', []))
                        self.cve_data.extend(report.get('updated', []))
                    
                    if not self.cve_data:
                        messagebox.showinfo("Info", "No CVE entries found in the file")
                        return
                        
                    self.populate_treeview(self.cve_data)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")

    def populate_treeview(self, data):
        self.tree.delete(*self.tree.get_children())
        
        for entry in data:
            self.tree.insert('', 'end', values=(
                entry.get('cveId', 'N/A'),
                entry.get('dateUpdated', 'N/A'),
                entry.get('cveOrgLink', 'N/A'),
                entry.get('githubLink', 'N/A')
            ))

    def filter_data(self, event=None):
        search_term = self.search_var.get().lower()
        filtered_data = [
            entry for entry in self.cve_data
            if search_term in entry.get('cveId', '').lower()
        ]
        self.populate_treeview(filtered_data)

    def open_link(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item[0])
            col = self.tree.identify_column(event.x)
            
            # Get both links from the row
            cve_link = item['values'][2]
            github_link = item['values'][3]
            
            # Open link based on clicked column
            if col == '#3' and cve_link.startswith('http'):
                webbrowser.open(cve_link)
            elif col == '#4' and github_link.startswith('http'):
                webbrowser.open(github_link)

if __name__ == '__main__':
    root = tk.Tk()
    app = CVEViewerApp(root)
    root.mainloop()