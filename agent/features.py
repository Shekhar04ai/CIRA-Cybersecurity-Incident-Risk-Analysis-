"""The feature list shared by the scanner, the trainer and the model."""

FEATURES = [
    "ext_executable",
    "ext_script",
    "ext_macro_doc",
    "double_ext",
    "mz_mismatch",
    "entropy",
    "size_log",
    "in_risky_location",
    "is_hidden",
    "is_pe",
    "wx_section",
    "susp_imports",
    "max_section_entropy",
]

# Plain-language names shown next to each score contribution.
LABELS = {
    "ext_executable": "Program file type (.exe, .dll, .scr)",
    "ext_script": "Script file type (.bat, .ps1, .vbs, .js)",
    "ext_macro_doc": "Document that can run macros",
    "double_ext": "Double extension (looks like one file type, is another)",
    "mz_mismatch": "Program disguised as another file type",
    "entropy": "Content looks packed or encrypted",
    "size_log": "File size",
    "in_risky_location": "Stored in Downloads or a temp folder",
    "is_hidden": "Hidden file",
    "is_pe": "Has the structure of a Windows program",
    "wx_section": "Memory section that is both writable and executable",
    "susp_imports": "Calls to functions often used by malware",
    "max_section_entropy": "Packed section inside the program",
}
