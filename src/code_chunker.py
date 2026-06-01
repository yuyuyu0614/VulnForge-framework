"""Code chunker — splits source files by function/class boundaries via tree-sitter AST.

Each chunk preserves identity (file, function name, signature, line range)
for selective retrieval in the context engineering pipeline.
"""

import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, field

from feature_extractor import (
    _detect_language, _load_grammar, EXT_TO_LANG,
)


# --- Node types that define chunk boundaries ---

BOUNDARY_TYPES = {
    # Python
    "function_definition", "class_definition",
    "decorated_definition",
    # JavaScript / TypeScript
    "function_declaration", "class_declaration", "method_definition",
    "arrow_function", "function",
    # Go
    "function_declaration", "method_declaration", "type_declaration",
    # Java
    "method_declaration", "class_declaration", "constructor_declaration",
    "interface_declaration",
    # C/C++
    "function_definition", "class_specifier", "struct_specifier",
}


def _extract_name_and_sig(node, source: bytes) -> tuple[str, str]:
    """Extract the name and signature text from a boundary node."""
    name = "<unknown>"
    sig_byte_range = (node.start_byte, node.end_byte)

    for child in node.children:
        if child.type in ("identifier", "name", "property_identifier"):
            name = source[child.start_byte:child.end_byte].decode()
            break
        # Nested name lookup (e.g., function_declaration > declarator > identifier)
        if child.type in ("declarator", "function_declarator"):
            for gc in child.children:
                if gc.type in ("identifier", "name", "field_identifier",
                               "property_identifier"):
                    name = source[gc.start_byte:gc.end_byte].decode()
                    break

    # Get the full signature snippet (first line(s) up to opening brace or '->')
    sig_text = source[node.start_byte:node.end_byte].decode(errors="replace")
    # Trim to signature only (up to first '{' or ':' in Python class)
    sig_line = sig_text.split("\n")[0].strip()
    return name, sig_line


def _node_body_text(node, source: bytes) -> str:
    """Get the body text of a function/class node."""
    body_node = None
    for child in node.children:
        if child.type in ("block", "body", "statement_list",
                          "compound_statement", "class_body"):
            body_node = child
            break
    if body_node:
        return source[body_node.start_byte:body_node.end_byte].decode(errors="replace")
    # Fallback: whole node
    return source[node.start_byte:node.end_byte].decode(errors="replace")


@dataclass
class Chunk:
    chunk_id: str
    file_path: str
    language: str
    name: str                     # function/class name
    signature: str                # first line of declaration
    node_type: str                # 'function','class','method'
    line_start: int
    line_end: int
    body: str                     # the actual code body
    parent_name: str | None = None  # enclosing class for methods


@dataclass
class ChunkResult:
    file_path: str
    language: str
    chunks: list[Chunk] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    full_source: str = ""


def chunk_file(file_path: str | Path) -> ChunkResult:
    """Parse a source file and split it into function/class chunks.

    Returns a ChunkResult with all identified chunks.
    """
    file_path = Path(file_path)
    result = ChunkResult(file_path=str(file_path), language="unknown")

    lang = _detect_language(file_path)
    if lang is None:
        result.errors.append(f"Unsupported file type: {file_path.suffix}")
        return result

    result.language = lang
    grammar = _load_grammar(lang)
    if grammar is None:
        result.errors.append(f"Tree-sitter grammar not installed for: {lang}")
        return result

    try:
        source_bytes = file_path.read_bytes()
        result.full_source = source_bytes.decode(errors="replace")
    except Exception as e:
        result.errors.append(f"Failed to read file: {e}")
        return result

    try:
        from tree_sitter import Parser, Language
        lang_obj = Language(grammar.language())
        parser = Parser(lang_obj)
        tree = parser.parse(source_bytes)
    except Exception as e:
        result.errors.append(f"Parse error: {e}")
        return result

    # Collect chunks
    _collect_chunks(tree.root_node, source_bytes, result, parent_name=None)

    return result


def _collect_chunks(node, source: bytes, result: ChunkResult,
                    parent_name: str | None = None):
    """Recursively collect function/class boundary nodes as chunks."""
    if node.type in BOUNDARY_TYPES:
        name, sig = _extract_name_and_sig(node, source)
        body = _node_body_text(node, source)

        chunk_type = "class" if "class" in node.type else "function"
        if "method" in node.type or "constructor" in node.type:
            chunk_type = "method"

        chunk = Chunk(
            chunk_id=hashlib.sha256(
                f"{result.file_path}:{name}:{node.start_point[0]+1}".encode()
            ).hexdigest()[:12],
            file_path=result.file_path,
            language=result.language,
            name=name,
            signature=sig,
            node_type=chunk_type,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            body=body,
            parent_name=parent_name,
        )
        result.chunks.append(chunk)

        # Recurse into this boundary to find nested functions/methods
        new_parent = name if chunk_type == "class" else parent_name
        for child in node.children:
            _collect_chunks(child, source, result, parent_name=new_parent)
    else:
        # Recurse into children
        for child in node.children:
            _collect_chunks(child, source, result, parent_name=parent_name)


def chunk_directory(root_dir: str | Path,
                    extensions: set[str] | None = None) -> list[ChunkResult]:
    """Walk a directory tree and chunk all supported files."""
    root_dir = Path(root_dir)
    results = []
    for file_path in root_dir.rglob("*"):
        if file_path.is_file():
            ext = file_path.suffix.lower()
            if extensions and ext not in extensions:
                continue
            if ext in EXT_TO_LANG:
                r = chunk_file(file_path)
                if r.chunks or r.errors:
                    results.append(r)
    return results


def to_context_json(result: ChunkResult, include_body: bool = True) -> list[dict]:
    """Convert chunks to standardized JSON context summaries for agent consumption.

    This is the format that gets fed into the selective retrieval pipeline.
    """
    summaries = []
    imports = _extract_imports(result)
    for chunk in result.chunks:
        entry = {
            "chunk_id": chunk.chunk_id,
            "file": chunk.file_path,
            "language": chunk.language,
            "name": chunk.name,
            "signature": chunk.signature,
            "type": chunk.node_type,
            "lines": f"{chunk.line_start}-{chunk.line_end}",
            "parent": chunk.parent_name,
            "imports": imports,
        }
        if include_body:
            entry["body"] = chunk.body
        summaries.append(entry)
    return summaries


def _extract_imports(result: ChunkResult) -> list[str]:
    """Extract import/include statements as context for chunks."""
    imports = []
    for line in result.full_source.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if result.language == "python":
            if stripped.startswith(("import ", "from ")):
                imports.append(stripped)
        elif result.language == "javascript":
            if stripped.startswith(("import ", "const ", "var ", "let ")) and "require" in stripped:
                imports.append(stripped)
        elif result.language == "go":
            if stripped.startswith("import ") or stripped.startswith('"'):
                imports.append(stripped)
        elif result.language in ("cpp", ):
            if stripped.startswith("#include"):
                imports.append(stripped)
        elif result.language == "java":
            if stripped.startswith("import "):
                imports.append(stripped)
    return imports


def chunk_summary(results: list[ChunkResult]) -> dict:
    """Generate aggregate statistics for chunking results."""
    total_chunks = 0
    total_errors = 0
    files_with_chunks = 0
    by_type = {"function": 0, "method": 0, "class": 0}
    by_lang: dict[str, int] = {}

    for r in results:
        if r.chunks:
            files_with_chunks += 1
        total_chunks += len(r.chunks)
        total_errors += len(r.errors)
        for c in r.chunks:
            by_type[c.node_type] = by_type.get(c.node_type, 0) + 1
            by_lang[r.language] = by_lang.get(r.language, 0) + 1

    return {
        "files_processed": len(results),
        "files_with_chunks": files_with_chunks,
        "total_chunks": total_chunks,
        "total_errors": total_errors,
        "by_type": by_type,
        "by_language": by_lang,
    }
