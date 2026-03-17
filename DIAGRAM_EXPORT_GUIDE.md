# 📊 How to Export Diagrams to Images

Your two Mermaid diagrams have been saved as `.mmd` files:
- `diagram-1-ip-blocking-flow.mmd`
- `diagram-2-three-blocking-options.mmd`

## Option 1: Using Mermaid Live Editor (Easiest) ✅

1. Go to: https://mermaid.live/
2. Click "File" → "Open from file"
3. Select one of the `.mmd` files
4. Click the download icon (bottom left)
5. Choose format: PNG, SVG, or PDF

## Option 2: Using VS Code Extension

1. Install "Markdown Preview Mermaid Support" extension
2. Right-click on `.mmd` file
3. Click "Preview"
4. Right-click diagram → "Export as PNG/SVG"

## Option 3: Using Command Line Tools

### macOS/Linux with Docker:
```bash
# Install mermaid-cli via npm
npm install -g @mermaid-js/mermaid-cli

# Convert to PNG
mmdc -i diagram-1-ip-blocking-flow.mmd -o diagram-1.png

# Convert to SVG
mmdc -i diagram-1-ip-blocking-flow.mmd -o diagram-1.svg -t default
```

### Without Docker:
```bash
# Using brew (macOS)
brew install mermaid-cli

# Convert files
mmdc -i diagram-1-ip-blocking-flow.mmd -o diagram-1.png
mmdc -i diagram-2-three-blocking-options.mmd -o diagram-2.png
```

## Option 4: Using Online Tools

These websites convert Mermaid diagrams to images:
- https://mermaid.live/ (Recommended)
- https://kroki.io/
- https://dreampuf.github.io/GraphvizOnline/

## Quickest Method:

1. Open: https://mermaid.live/
2. Paste content of `.mmd` file
3. Click download icon
4. Done!

---

## File Locations:

All files are in your project directory:
```
/Users/pankajkumarrana/Desktop/major-project/Thread-Intelligence-and-Response-Framework-for-Malicious-IPs-Dashboard/
├── diagram-1-ip-blocking-flow.mmd
├── diagram-2-three-blocking-options.mmd
└── DIAGRAM_EXPORT_GUIDE.md (this file)
```

## What Each Diagram Shows:

📊 **Diagram 1: IP Blocking Flow Architecture**
- Shows how the block request flows through the system
- From dashboard UI → backend → firewall → response

🔄 **Diagram 2: Three Blocking Options**
- Compares the three implementation levels
- Option 1 (app-only), Option 2 (firewall), Option 3 (persistent)

---

Prefer online tool? → https://mermaid.live/
