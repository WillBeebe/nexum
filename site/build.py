"""Build the dependency-free public documentation surface only."""
from pathlib import Path
import shutil
import html
root = Path(__file__).resolve().parent
out = root / "dist"
out.mkdir(exist_ok=True)
source = (root / "index.html").read_text()
marker = "<!-- AGENT_INSTRUCTIONS -->"
if source.count(marker) != 1:
    raise ValueError("Expected one agent instructions placeholder")
brief = (root / "agents.md").read_text()
(out / "index.html").write_text(source.replace(marker, html.escape(brief)))
for name in ("style.css", "site.js", "agents.md", "favicon.png", "favicon.ico"):
    shutil.copyfile(root / name, out / name)
print(f"Built {out}")
