"""Independent oracle for Chappie's language-list normalization relation."""


def evaluate_chappie_language_list(value: str | list[str]) -> list[str]:
    """Mirror parse_language_list for the exact built-in input domain."""

    if type(value) is list:
        items = value
    elif type(value) is str:
        items = [item.strip() for item in value.split(",")]
    else:
        items = []

    result = []
    for item in items:
        code = (str(item) or "").strip().lower()
        if not code:
            continue
        result.append(code)

    deduped = []
    for code in result:
        if code not in deduped:
            deduped.append(code)
    return deduped or ["de", "en"]
