#!/usr/bin/env python3
"""Convert Markdown report to PDF using weasyprint."""

import sys
import markdown
from weasyprint import HTML

def md_to_pdf(md_path: str, pdf_path: str):
    with open(md_path, "r", encoding="utf-8") as f:
        md_content = f.read()

    html_body = markdown.markdown(
        md_content,
        extensions=["extra", "codehilite", "toc", "tables", "fenced_code"],
    )

    css = """
    @page {
        size: A4;
        margin: 2.5cm 2cm;
        @bottom-center {
            content: counter(page);
            font-family: 'DejaVu Sans', sans-serif;
            font-size: 9pt;
            color: #666;
        }
    }
    body {
        font-family: 'DejaVu Sans', sans-serif;
        font-size: 11pt;
        line-height: 1.5;
        color: #222;
    }
    h1 { font-size: 18pt; margin-top: 0; page-break-before: avoid; }
    h2 { font-size: 14pt; border-bottom: 1px solid #999; padding-bottom: 3px; }
    h3 { font-size: 12pt; }
    h4 { font-size: 11pt; }
    pre, code {
        font-family: 'DejaVu Sans Mono', monospace;
        font-size: 8pt;
        background: #f4f4f4;
        border: 1px solid #ddd;
        border-radius: 3px;
    }
    pre {
        padding: 8px;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }
    code { padding: 2px 4px; }
    pre code { padding: 0; background: none; border: none; }
    table {
        border-collapse: collapse;
        width: 100%;
        margin: 10px 0;
    }
    th, td {
        border: 1px solid #999;
        padding: 6px 8px;
        text-align: left;
    }
    th { background-color: #e0e0e0; }
    img {
        max-width: 100%;
        height: auto;
    }
    blockquote {
        border-left: 4px solid #ccc;
        margin: 10px 0;
        padding: 5px 15px;
        color: #555;
        background: #f9f9f9;
    }
    .placeholder {
        border: 2px dashed #cc0000;
        padding: 15px;
        margin: 15px 0;
        background: #fff0f0;
        color: #cc0000;
        font-style: italic;
    }
    """

    html_doc = f"""<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <style>{css}</style>
</head>
<body>
{html_body}
</body>
</html>"""

    HTML(string=html_doc, base_url=".").write_pdf(pdf_path)
    print(f"PDF saved to: {pdf_path}")

if __name__ == "__main__":
    md_to_pdf(sys.argv[1], sys.argv[2])
