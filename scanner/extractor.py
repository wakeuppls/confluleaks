from html.parser import HTMLParser


BLOCK_TAGS = {
    "address",
    "blockquote",
    "br",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "p",
    "pre",
    "table",
    "td",
    "th",
    "tr",
}


class ConfluenceStorageParser(HTMLParser):
    """Convert Confluence storage HTML to searchable plain text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs) -> None:
        normalized = tag.lower()
        if normalized in {"script", "style"}:
            self.ignored_depth += 1
        elif normalized in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs) -> None:
        if tag.lower() in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag) -> None:
        normalized = tag.lower()
        if normalized in {"script", "style"} and self.ignored_depth:
            self.ignored_depth -= 1
        elif normalized in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data) -> None:
        if not self.ignored_depth:
            self.parts.append(data)

    def text(self) -> str:
        lines = (line.rstrip() for line in "".join(self.parts).splitlines())
        return "\n".join(line for line in lines if line.strip()).strip()


def extract_text(storage_value: str) -> str:
    parser = ConfluenceStorageParser()
    parser.feed(storage_value or "")
    parser.close()
    return parser.text()
