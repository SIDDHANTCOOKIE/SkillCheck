def trim_whitespace(row: list[str]) -> list[str]:
    return [cell.strip() for cell in row]


def drop_blank_rows(rows: list[list[str]]) -> list[list[str]]:
    return [r for r in rows if any(cell.strip() for cell in r)]
