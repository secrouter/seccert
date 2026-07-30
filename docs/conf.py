"""Sphinx configuration for the SecCert documentation."""

project = "SecCert"
author = "Austin Probe"
copyright = "2026, Austin Probe"
release = "1.0.0"

extensions = ["myst_parser"]
myst_enable_extensions = ["colon_fence", "deflist"]

html_theme = "furo"
html_title = "SecCert"
html_static_path = []
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

source_suffix = {".md": "markdown", ".rst": "restructuredtext"}
