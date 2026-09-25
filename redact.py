"""Redact PII in DOCX files with structured rules and a document entity pass."""


import argparse
import csv
import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from docx import Document


EMAIL = re.compile(
    r"(?<![\w@])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w@])"
)


IP_ADDRESS = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
)


SSN = re.compile(
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"
)


CREDIT_CARD = re.compile(
    r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
)


PHONE = re.compile(
    r"(?<!\d)(?:\+\s?91[\s-]?)?"
    r"(?:\(?0?\d{2,4}\)?[\s-]?)?"
    r"\d{3,5}[\s-]\d{4,5}(?!\d)"
    r"|(?<!\d)(?:\+\s?91[\s-]?)?[6-9]\d{9}(?!\d)"
)


DATE = re.compile(
    r"\b(?:"
    r"\d{1,2}[/-]\d{1,2}[/-]\d{4}"
    r"|"
    r"\d{1,2}\s+"
    r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|"
    r"May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|"
    r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
    r"\s+\d{4}"
    r")\b",
    re.IGNORECASE,
)


DOB_CONTEXT = re.compile(
    r"\b(?:date of birth|dob|born on|birth date)\b",
    re.IGNORECASE,
)


COMPANY = re.compile(
    r"\b(?:[A-Z][\w&.,-]*\s+){1,7}"
    r"(?:Limited|LIMITED|Private Limited|PRIVATE LIMITED|"
    r"Pvt\.? Ltd\.?|LLP|Inc\.?|Corporation|Bank)\b"
)


NAME_LABEL = re.compile(
    r"\b(?:"
    r"Contact Person\s*:\s*"
    r"|Name of (?:the )?(?:Director|Promoter|Officer|Secretary)\s*:\s*"
    r"|(?:Mr|Mrs|Ms|Dr)\.?\s+"
    r")"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
    re.IGNORECASE,
)


ADDRESS_LABEL = re.compile(
    r"\b(?:Registered Office|Corporate Office|Address|"
    r"Correspondence Address|Registered Address|Office Address)"
    r"\s*:\s*([^;\n]{15,180})",
    re.IGNORECASE,
)


PIN_ADDRESS = re.compile(
    r"\b\d{1,4}[/,-]\d{1,4}[^;\n]{10,110}?\b\d{6}\b",
    re.IGNORECASE,
)


PRIORITY = {
    "EMAIL": 10,
    "IP_ADDRESS": 9,
    "SSN": 9,
    "CREDIT_CARD": 9,
    "PHONE": 8,
    "DATE_OF_BIRTH": 8,
    "ADDRESS": 7,
    "COMPANY": 6,
    "PERSON": 5,
}


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    kind: str
    source: str


def passes_luhn(value):
    """Check whether a card-shaped number has a valid Luhn checksum."""
    digits = [int(character) for character in value if character.isdigit()]

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for position, digit in enumerate(reversed(digits)):
        if position % 2:
            digit *= 2
            if digit > 9:
                digit -= 9

        total += digit

    return total % 10 == 0


def detect(text, nlp=None):
    """Return nonoverlapping PII matches with character positions."""
    candidates = []

    def add(start, end, kind, source):
        # Remove surrounding punctuation/whitespace from a candidate.
        while start < end and text[start].isspace():
            start += 1

        while end > start and text[end - 1] in " \t,;:":
            end -= 1

        if end > start:
            candidates.append(Match(start, end, kind, source))

    # Structured identifiers
    for pattern, kind in (
        (EMAIL, "EMAIL"),
        (SSN, "SSN"),
        (IP_ADDRESS, "IP_ADDRESS"),
    ):
        for match in pattern.finditer(text):
            if kind == "IP_ADDRESS":
                octets = match.group().split(".")
                if not all(int(octet) <= 255 for octet in octets):
                    continue

            add(match.start(), match.end(), kind, "regex")

    # Phones: avoid treating arbitrary grouped financial numbers as phones.
    for match in PHONE.finditer(text):
        raw = match.group()
        digits = re.sub(r"\D", "", raw)
        preceding = text[max(0, match.start() - 20):match.start()]

        has_phone_label = re.search(
            r"(?:phone|telephone|mobile|tel|fax|contact)\s*[:.]?\s*$",
            preceding,
            re.IGNORECASE,
        )

        looks_like_mobile = (
            len(digits) == 10
            and digits[0] in "6789"
            and not re.search(r"[ -]", raw)
        )

        if (
            10 <= len(digits) <= 13
            and not re.search(r"\b(?:19|20)\d{2}\b", raw)
            and (raw.lstrip().startswith("+") or has_phone_label or looks_like_mobile)
        ):
            add(match.start(), match.end(), "PHONE", "regex")

    # A long number is only treated as a card if its checksum is valid.
    for match in CREDIT_CARD.finditer(text):
        if passes_luhn(match.group()):
            add(match.start(), match.end(), "CREDIT_CARD", "regex+luhn")

    # Ordinary prospectus dates are not automatically dates of birth.
    for match in DATE.finditer(text):
        preceding = text[max(0, match.start() - 45):match.start()]

        if DOB_CONTEXT.search(preceding):
            add(match.start(), match.end(), "DATE_OF_BIRTH", "context")

    # Companies with recognizable legal suffixes
    for match in COMPANY.finditer(text):
        value = match.group()
        if not re.search(
            r"(?i)\b(?:Escrow Collection|Offer Account|Public Offer Account) Bank\b",
            value,
        ) and not re.match(r"(?i)\s+Facilities\b", text[match.end():]):
            start = match.start()
            for prefix in ("Company ", "Formerly "):
                if value.startswith(prefix):
                    start += len(prefix)
            add(start, match.end(), "COMPANY", "suffix")

    # Names following labels or titles
    for match in NAME_LABEL.finditer(text):
        value = match.group(1)

        # A table may place its next field label beside the name.
        next_label = re.search(
            r"\b(?:Website|SEBI|Registration|Email|Telephone|Contact)\b",
            value,
        )
        end = match.start(1) + (
            next_label.start() if next_label else len(value)
        )
        candidate = text[match.start(1):end]

        contains_job_title = re.search(
            r"\b(?:Office|Secretary|Director|Officer|Limited|Company)\b",
            candidate,
            re.IGNORECASE,
        )

        if len(candidate.split()) >= 2 and not contains_job_title:
            add(match.start(1), end, "PERSON", "label")

    # Addresses following explicit labels
    for match in ADDRESS_LABEL.finditer(text):
        value = match.group(1)
        next_label = re.search(
            r"\b(?:Phone|Telephone|Email|E-mail|Website|Contact Person)\s*:",
            value,
            re.IGNORECASE,
        )
        end = match.start(1) + (
            next_label.start() if next_label else len(value)
        )

        if re.search(r"\d", text[match.start(1):end]):
            add(match.start(1), end, "ADDRESS", "label")

    for match in PIN_ADDRESS.finditer(text):
        add(match.start(), match.end(), "ADDRESS", "pin")

    # Optional pretrained NER for less structured names/companies.
    if nlp is not None:
        for entity in nlp(text).ents:
            if (
                entity.label_ == "PERSON"
                and len(entity.text.split()) >= 2
                and not re.search(
                    r"\d|\b(?:Act|Limited|Company|Regulations)\b",
                    entity.text,
                )
            ):
                add(
                    entity.start_char,
                    entity.end_char,
                    "PERSON",
                    "spacy",
                )

            elif (
                entity.label_ == "ORG"
                and re.search(
                    r"\b(?:limited|ltd|llp|bank|inc|corporation)\b",
                    entity.text,
                    re.IGNORECASE,
                )
            ):
                add(
                    entity.start_char,
                    entity.end_char,
                    "COMPANY",
                    "spacy",
                )

    # Choose the highest-priority candidate when spans overlap.
    selected = []

    for match in sorted(
        set(candidates),
        key=lambda item: (
            -PRIORITY[item.kind],
            -(item.end - item.start),
            item.start,
        ),
    ):
        overlaps_existing = any(
            match.start < other.end and other.start < match.end
            for other in selected
        )

        if not overlaps_existing:
            selected.append(match)

    return sorted(selected, key=lambda item: item.start)


class Substitutes:
    """Generate and remember one fake value per original value and type."""

    def __init__(self):
        self.values = {}

    def get(self, kind, original):
        normalized = re.sub(r"\s+", " ", original.casefold().strip())
        if kind == "COMPANY":
            normalized = re.sub(r",\s*(?=llp\b)", " ", normalized)
        key = (kind, normalized)

        if key in self.values:
            return self.values[key]

        digest = hashlib.sha256(
            f"{kind}|{key[1]}".encode("utf-8")
        ).hexdigest()
        number = int(digest[:12], 16)
        serial = number % 900000 + 100000

        first_names = [
            "Aarav", "Anaya", "Dev", "Isha",
            "Kabir", "Meera", "Neel", "Riya",
        ]
        surnames = [
            "Shah", "Rao", "Kapoor", "Sen",
            "Bose", "Jain", "Nair", "Sethi",
        ]

        replacements = {
            "PERSON": (
                f"{first_names[number % 8]} "
                f"{surnames[(number // 8) % 8]}"
            ),
            "EMAIL": f"contact{serial}@example.com",
            "PHONE": f"+91 90000 {serial % 100000:05d}",
            "COMPANY": f"Example Ventures {serial} Limited",
            "ADDRESS": (
                f"{serial % 90 + 10} Sample Road, "
                "Example City, 400000, India"
            ),
            "SSN": f"000-00-{serial % 10000:04d}",
            "CREDIT_CARD": f"[SYNTHETIC CARD {serial}]",
            "DATE_OF_BIRTH": f"{number % 27 + 1:02d}/01/1980",
            "IP_ADDRESS": f"192.0.2.{number % 253 + 1}",
        }

        replacement = replacements[kind]
        self.values[key] = replacement
        return replacement


def replace_in_paragraph(paragraph, matches, substitutes, location, log_rows):
    """Replace across Word runs while retaining unaffected run formatting."""
    runs = paragraph.runs

    if not runs or not matches:
        return

    original = "".join(run.text for run in runs)
    boundaries = []
    position = 0

    for run in runs:
        end = position + len(run.text)
        boundaries.append((position, end))
        position = end

    replacements = []

    for match in matches:
        original_value = original[match.start:match.end]
        replacement = substitutes.get(match.kind, original_value)

        replacements.append(
            (match.start, match.end, replacement)
        )

        log_rows.append({
            "location": location,
            "start": match.start,
            "end": match.end,
            "type": match.kind,
            "original": original_value,
            "replacement": replacement,
            "source": match.source,
        })

    for run, (run_start, run_end) in zip(runs, boundaries):
        pieces = []
        cursor = run_start

        for start, end, replacement in replacements:
            if end <= run_start or start >= run_end:
                continue

            if start > cursor:
                pieces.append(original[cursor:min(start, run_end)])

            if run_start <= start < run_end:
                pieces.append(replacement)

            cursor = max(cursor, min(end, run_end))

        if cursor < run_end:
            pieces.append(original[cursor:run_end])

        run.text = "".join(pieces)


def paragraphs(document):
    """Visit each real Word paragraph once, including tables and headers."""
    seen_elements = set()

    def visit(container, location):
        for index, paragraph in enumerate(container.paragraphs):
            # Store the actual XML element, not id(element).
            if paragraph._p not in seen_elements:
                seen_elements.add(paragraph._p)
                yield f"{location}/p{index}", paragraph

        for table_index, table in enumerate(container.tables):
            for row_index, row in enumerate(table.rows):
                for cell_index, cell in enumerate(row.cells):
                    cell_location = (
                        f"{location}/t{table_index}"
                        f"/r{row_index}/c{cell_index}"
                    )
                    yield from visit(cell, cell_location)

    yield from visit(document, "body")

    for index, section in enumerate(document.sections):
        yield from visit(section.header, f"section{index}/header")
        yield from visit(section.footer, f"section{index}/footer")


CIN = re.compile(
    r"\b[UL]\d{5}[A-Z]{2}\d{4}(?:PLC|PTC)\d{6}\b"
)


PROMOTERS = re.compile(
    r"OUR PROMOTERS\s*:\s*([^\n;]+)",
    re.IGNORECASE,
)


ALL_CAPS_NAME = re.compile(
    r"\b[A-Z]{3,}(?:\s+[A-Z]{3,}){1,3}\b"
)


TITLE_NAME = re.compile(
    r"\b(?:Mr|Mrs|Ms|Dr)\.?\s+"
    r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})"
)


ROLE_NAME = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})"
    r"\s+(?:is\s+our|,\s*(?:CEO|CFO|CS|Director))\b"
)


OFFICE_ADDRESS_LABEL = re.compile(
    r"\b(?:Registered Office|Corporate Office)\s*:\s*"
    r"([^;\n]{20,200})",
    re.IGNORECASE,
)


ADDRESS_CELL = re.compile(
    r"(?s)^\s*(?:\d{1,4}[/, ]|Gat No\.).{20,150}?"
    r"\b\d{3}\s?\d{3}\b[^\n;]{0,40}"
)


NOT_A_PERSON = re.compile(
    r"\b(?:COMPANY|LIMITED|TRUST|OFFER|ISSUER|SEBI|"
    r"RISK|FACTORS|DIRECTOR|OFFICE|WEBSITE|REGISTRATION)\b"
)


def gather_known_values(document):
    """First pass: discover names and addresses in useful contexts."""
    values = {
        "PERSON": set(),
        "ADDRESS": set(),
    }

    for location, paragraph in paragraphs(document):
        text = "".join(run.text for run in paragraph.runs)

        # Keep names and addresses already found by redact.py.
        for match in detect(text):
            if match.kind in values:
                values[match.kind].add(
                    text[match.start:match.end].strip()
                )

        # The prospectus explicitly lists promoters in uppercase.
        for promoter_section in PROMOTERS.finditer(text):
            for item in promoter_section.group(1).split(","):
                name = item.strip(" .;")

                if (
                    ALL_CAPS_NAME.fullmatch(name)
                    and not NOT_A_PERSON.search(name)
                ):
                    values["PERSON"].add(name)

        # Discover names next to titles and roles.
        for pattern in (TITLE_NAME, ROLE_NAME):
            for match in pattern.finditer(text):
                name = match.group(1)

                if not re.search(
                    r"\b(?:Company|Secretary|Compliance|Officer|"
                    r"Website|Registration|Prospectus)\b",
                    name,
                ):
                    values["PERSON"].add(name)

        for match in OFFICE_ADDRESS_LABEL.finditer(text):
            values["ADDRESS"].add(
                match.group(1).strip(" ,;")
            )

        # Some office addresses are standalone table cells.
        if ADDRESS_CELL.search(text):
            values["ADDRESS"].add(text.strip())

    values["PERSON"] = {
        name for name in values["PERSON"]
        if 2 <= len(name.split()) and len(name) <= 75
    }

    return values


def exact_phrase_pattern(value):
    """Allow whitespace differences while matching a known value."""
    words = value.split()
    middle = r"\s+".join(re.escape(word) for word in words)

    return re.compile(
        r"(?<!\w)" + middle + r"(?!\w)",
        re.IGNORECASE,
    )


def compile_known_values(values):
    compiled = []

    for kind in ("ADDRESS", "PERSON", "COMPANY"):
        for value in sorted(values[kind], key=len, reverse=True):
            compiled.append(
                (kind, value, exact_phrase_pattern(value))
            )

    return compiled


def find_matches_base(text, known_values):
    """Combine ordinary detectors, CIN, and discovered entities."""
    matches = detect(text)

    for match in CIN.finditer(text):
        matches.append(
            Match(match.start(), match.end(), "CIN", "cin-regex")
        )

    for kind, value, pattern in known_values:
        for match in pattern.finditer(text):
            matches.append(
                Match(
                    match.start(),
                    match.end(),
                    kind,
                    "document-lexicon",
                )
            )

    priority = {
        "EMAIL": 10,
        "SSN": 10,
        "IP_ADDRESS": 10,
        "CREDIT_CARD": 10,
        "CIN": 10,
        "PHONE": 9,
        "DATE_OF_BIRTH": 9,
        "ADDRESS": 8,
        "COMPANY": 7,
        "PERSON": 6,
    }

    selected = []

    for match in sorted(
        matches,
        key=lambda item: (
            -priority[item.kind],
            -(item.end - item.start),
            item.start,
        ),
    ):
        overlaps = any(
            match.start < existing.end
            and existing.start < match.end
            for existing in selected
        )

        if not overlaps:
            selected.append(match)

    return sorted(selected, key=lambda item: item.start)


class UpdatedSubstitutes(Substitutes):
    """Use the previous replacements and add a synthetic CIN."""

    def get(self, kind, original):
        if kind == "CIN":
            key = (kind, re.sub(r"\s+", " ", original.casefold().strip()))

            if key not in self.values:
                number = int(
                    hashlib.sha256(
                        key[1].encode("utf-8")
                    ).hexdigest()[:10],
                    16,
                ) % 1000000

                self.values[key] = (
                    f"U00000ZZ2000PLC{number:06d}"
                )

            return self.values[key]

        return super().get(kind, original)


ROLE_CONTACT = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})"
    r"\s*,\s*"
    r"(?:CEO|CFO|CS|Technical Director|Managing Director)\b"
)

KINSHIP_NAME = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})"
    r"\s*,\s*(?:his|her)\s+spouse\b"
)


CONTACT_LIST = re.compile(
    r"\bContact Person\s*:\s*([^;\n]{1,150})",
    re.IGNORECASE,
)


PERSON_IN_CONTACT = re.compile(
    r"\b[A-Z][a-z]+\s+[A-Z][a-z]+"
    r"(?:\s+[A-Z][a-z]+)?\b"
)

TRANSFER_PARTIES = re.compile(
    r"\btransfer of shares to ([^.;\n]{5,120})",
    re.IGNORECASE,
)
TRANSFER_NAME = re.compile(
    r"\b(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}|"
    r"[A-Z]{1,3}\s+[A-Z][a-z]+|"
    r"[A-Z][a-z]+\s+[A-Z]{2,3})\b"
)


PROPERTY_ADDRESS = re.compile(
    r"\b(?:Gat No\.\s*)?"
    r"11/3,?\s*11/4(?:\s+and|,)\s+11/5\b"
    r"[^;\n.]{0,150}?\bIndia\b",
    re.IGNORECASE,
)

OFFICE_IN_PROSE = re.compile(
    r"\b(?:Registered|Corporate) Office at\s+"
    r"(.{20,180}?\bIndia\b)", re.IGNORECASE,
)

ORG_WITH_SUFFIX = re.compile(
    r"\b[A-Z][\w.-]*(?:\s+(?:[A-Z][\w.-]*|\d+[A-Za-z]?|&|and|of|\([A-Z][a-z]+\))){1,12}"
    r"\s+(?:Limited|LLP|Corporation)\b"
)
ORG_ALIAS = re.compile(
    r"(?:Limited|LLP|Corporation)\s*\(\s*[“\"]([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3})[”\"]\s*\)"
)
ORG_CO = re.compile(
    r"\b[A-Z][\w-]+(?:\s+[A-Z][\w-]+){1,6}\s+Co\.(?=,|\s|$)"
)
NAMED_FAMILY_TRUST = re.compile(
    r"\b(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\s+Family Trust"
    r"|[A-Z]{3,}(?:\s+[A-Z]{3,}){0,2}\s+FAMILY TRUST)\b"
)

PERSON_NAME_COLUMN = re.compile(
    r"(?i)^Name(?:\s+of\s+(?:the\s+)?(?:Shareholder|Promoter|Director|Officer))?$"
)
TABLE_PERSON = re.compile(
    r"[A-Z][a-z]+(?:\s+(?:[A-Z]\.|[A-Z][a-z]+)){1,3}"
)
TABLE_PERSON_EXCLUDE = re.compile(
    r"(?i)\b(?:Family|Trust|Limited|LLP|Private|Company|Group|"
    r"Total|Shareholder|Promoter|Director|Fund|Capital|Bank|"
    r"Entities|Shares|Offer|Institutional|Mutual|Public)\b"
)
PLANT_ADDRESS = re.compile(
    r"(?i)\b(?:plant|facility|unit)\s+at\s+"
    r"(?P<address>(?:Plot\s+No\.?|Gat\s+No\.?|[A-Z]?-?\d{1,5})"
    r"[^.;\n]{20,220}?\b[1-9]\d{2}[ -]?\d{3}\b)"
)
ORG_BOUNDARY = re.compile(
    r"(?i)\b(?:Limited|LLP|Corporation|Family Trust)\b"
    r"(?:\s+and|,)\s+(?=[A-Z])"
)
NAMED_BUSINESS_LIST = re.compile(
    r"(?i)\btop\s+\d+\s+(?:customers|suppliers)\s+include\s+"
)


def organizations_in_labelled_list(text):
    """Learn names from an explicit supplier/customer list, including LLC/AB."""
    for label in NAMED_BUSINESS_LIST.finditer(text):
        content = text[label.end():label.end() + 700]
        content = re.split(r"\.\s+Names of\b", content, maxsplit=1)[0]
        for part in content.split(";"):
            part = re.sub(r"^(?:\s*and\s+|\s*,\s*)", "", part).strip(" ,.;")
            # Some lists put a business division immediately after a company.
            pieces = re.split(
                r"(?i)(?<=Limited)\s+(?=[A-Z][a-z]+\s+[A-Z])", part
            )
            for value in pieces:
                value = value.strip(" ,.;")
                if (2 <= len(value.split()) <= 12 and len(value) <= 110
                        and re.match(r"[A-Z]", value)):
                    yield value

def is_specific_org_alias(value):
    return (len(value) > 3 and not re.search(
        r"(?i)\b(?:report|entities|group|company|secretary)\b", value
    ))


def gather_values(document):
    """Add document-specific names and addresses to the first pass."""
    values = gather_known_values(document)
    values["COMPANY"] = set()

    # Table headers identify person columns, including shareholder lists and
    # the director name column. Learn those names for narrative occurrences.
    for table in document.tables:
        if not table.rows:
            continue
        for col, header in enumerate(table.rows[0].cells):
            if not PERSON_NAME_COLUMN.fullmatch(" ".join(header.text.split())):
                continue
            for row in table.rows[1:]:
                if col >= len(row.cells):
                    continue
                raw = " ".join(row.cells[col].text.split())
                name = re.sub(r"[*^&]+$", "", raw).strip()
                if (TABLE_PERSON.fullmatch(name)
                        and not TABLE_PERSON_EXCLUDE.search(name)):
                    values["PERSON"].add(name)

    for location, paragraph in paragraphs(document):
        text = "".join(run.text for run in paragraph.runs)

        values["COMPANY"].update(organizations_in_labelled_list(text))

        # Once introduced beside a legal company name, use an alias everywhere.
        for alias in ORG_ALIAS.finditer(text):
            value = alias.group(1)
            if is_specific_org_alias(value):
                values["COMPANY"].add(value)

        # Examples: "Sandesh Bhagwat, CEO" and "Amod Joshi, CFO".
        for match in ROLE_CONTACT.finditer(text):
            name = match.group(1)

            if not re.search(
                r"\b(?:our|the|company|promoters|commerce)\b",
                name,
                re.IGNORECASE,
            ):
                values["PERSON"].add(name)

        for match in KINSHIP_NAME.finditer(text):
            values["PERSON"].add(match.group(1))

        # Examples: "Contact Person: Name One / Name Two".
        for match in CONTACT_LIST.finditer(text):
            contact_area = re.split(
                r"\b(?:Website|Email|E-mail|Telephone|"
                r"SEBI Registration)\b",
                match.group(1),
                maxsplit=1,
                flags=re.IGNORECASE,
            )[0]

            for name in PERSON_IN_CONTACT.findall(contact_area):
                if not re.search(
                    r"\b(?:Company|Secretary|Compliance|Officer)\b",
                    name,
                    re.IGNORECASE,
                ):
                    values["PERSON"].add(name)

        for transfer in TRANSFER_PARTIES.finditer(text):
            for person in TRANSFER_NAME.finditer(transfer.group(1)):
                name = person.group()
                if name not in {"Form Transfer", "Equity Shares"} and not re.search(
                    r"(?i)\b(?:Leasing|Limited|Investment|Finance|Bank|Trust)\b",
                    name,
                ):
                    values["PERSON"].add(name)

        # The same office appears with different commas and "Gat No."
        for match in PROPERTY_ADDRESS.finditer(text):
            address = match.group().strip(" ,;")

            if len(address) >= 30:
                values["ADDRESS"].add(address)

        for match in OFFICE_IN_PROSE.finditer(text):
            address = match.group(1)
            if POSTAL_CODE.search(address):
                values["ADDRESS"].add(address)

        for match in PLANT_ADDRESS.finditer(text):
            values["ADDRESS"].add(match.group("address"))

    values["PERSON"] = {
        name for name in values["PERSON"]
        if not re.search(
            r"(?i)\b(?:Leasing|Limited|Investment|Finance|Bank|Trust)\b",
            name,
        )
    }
    return values


PHONE_LABEL = re.compile(
    r"\b(?:Telephone|Phone|Mobile|Fax|Tel)\s*:\s*"
    r"(\+?\d[\d ()-]{7,20}\d)",
    re.IGNORECASE,
)

# A telephone field can contain several values separated by commas or "and".
PHONE_SERIES = re.compile(
    r"\b(?:Telephone|Phone|Mobile|Fax|Tel)\s*:\s*"
    r"((?:\+\s?91[\s-]?(?:\d{2,4}[\s-]?)?\d{7,8}"
    r"|0\d{2,4}[\s-]?\d{6,8})"
    r"(?:\s*(?:,|and)\s*"
    r"(?:\+\s?91[\s-]?(?:\d{2,4}[\s-]?)?\d{7,8}"
    r"|0\d{2,4}[\s-]?\d{6,8}))*)",
    re.IGNORECASE,
)
SERIES_NUMBER = re.compile(
    r"\+\s?91[\s-]?(?:\d{2,4}[\s-]?)?\d{7,8}"
    r"|0\d{2,4}[\s-]?\d{6,8}"
)

AMPERSAND_COMPANY = re.compile(
    r"\b[A-Z][A-Za-z]+\s+&\s+[A-Z][A-Za-z]+,?\s+"
    r"(?:LLP|Limited)\b"
)

FULL_COMPANY = re.compile(
    r"\b(?:[A-Z][\w&.-]*|and|of|\([A-Z][a-z]+\))"
    r"(?:\s+(?:[A-Z][\w&.-]*|and|of|\([A-Z][a-z]+\))){1,10}"
    r"\s+(?:Limited|LLP)\b"
)
BANK_OF_INDIA = re.compile(
    r"\b[A-Z][A-Za-z-]+(?:\s+[A-Z][A-Za-z-]+){0,2}"
    r"\s+Bank of India\b"
)
ASSOCIATES_FIRM = re.compile(
    r"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,2}"
    r"\s+&\s+Associates\b"
)

# Some printed PINs use a letter that looks like a digit (for example 41l 005).
FLOOR_ADDRESS = re.compile(
    r"\b(?:Ground|\d{1,2}(?:st|nd|rd|th))\s+Floor,\s*"
    r"[^;\n]{20,180}?\bIndia\b",
    re.IGNORECASE,
)

ADDRESS_FRAGMENTS = (
    re.compile(
        r"\b[A-Z][A-Za-z]+\s+Bhavan,\s*"
        r"Plot No\.\s*[^.;\n]{8,90}?\bBlock\b"
    ),
    re.compile(
        r"(?i)\bUnit\s+no\.\s*\d{1,5},\s*"
        r"[^.;\n]{10,110}?\bIndia\b"
    ),
)


ADDRESS_WITH_PIN = re.compile(
    r"^\s*(\d{1,5},\s*[^\n;]{10,130}?"
    r"\b\d{3}[ -]?\d{3}\b)"
    r"(?=\s*(?:Telephone|Phone|Mobile|Email|E-mail|"
    r"Website|Contact Person)\s*:|\s*$)",
    re.IGNORECASE | re.DOTALL,
)


ADDRESS_MARKERS = re.compile(
    r"\b(?:floor|road|street|marg|nagar|avenue|"
    r"lane|reclamation|pune|mumbai|village|taluka|embassy|"
    r"building|complex|chambers|industrial area|flat|plot|campus|level)\b",
    re.IGNORECASE,
)

POSTAL_CODE = re.compile(r"(?<!\d)[1-9]\d{2}[ -]?\d{3}(?!\d)")
POSTAL_LINE = re.compile(
    r"^\s*(?:Pune|Mumbai|Bhopal|Raigad)\s*[–,-]\s*"
    r"[1-9]\d{2}[ -]?\d{3}\s*$",
    re.IGNORECASE,
)
STREET_START = re.compile(
    r"(?i)^(?:Plot No\.?|Flat No\.?|S\.\s*no\.?|"
    r"[A-Z]?-?\d{1,5}[A-Z]?(?:-\d{1,4})?[, -]|"
    r"(?:Ground|\d{1,2}(?:st|nd|rd|th))\s+Floor|"
    r"PCNTDA|Bandra Kurla|Bandra East|Koregaon Park|Bund Garden Road|"
    r"ICICI Venture House|Opposite|"
    r"[A-Z][a-z]+\s+(?:Building|House|Road|Apartment|Bunglow|Chambers))"
)


def find_address_line(text):
    """Find a short address line, including standalone table-cell addresses."""
    if "Example City" in text or len(text) > 240:
        return None

    start = 0
    prefix = re.search(
        r"(?i)\b(?:facility located at|plant at|"
        r"(?:registered|corporate) office (?:of our company )?located at|"
        r"(?:registered|corporate) office at)\s+",
        text,
    )
    if prefix:
        start = prefix.end()
    else:
        label = re.match(r"(?i)(?:Registered|Corporate) Office\s*:\s*", text)
        if label:
            start = label.end()
        company_ends = list(re.finditer(
            r"\b(?:Limited|LLP|Associates)\b\)?\s*,?\s+", text
        ))
        company_end = company_ends[-1] if company_ends else None
        if (company_end and company_end.end() < len(text) - 12
                and not re.match(r"(?i)^Opposite\b", text)):
            start = max(start, company_end.end())

    candidate = text[start:].strip()
    start += len(text[start:]) - len(text[start:].lstrip())
    if not STREET_START.match(candidate) and not re.match(
        r"(?i)^(?:Pune|Taluka|Next to|Senapati|Signature Building|"
        r"Bandra East|Koregaon Park|Bund Garden Road|Opposite|"
        r"[A-Z]+(?:-[A-Z]+)? Department)", candidate
    ):
        return None
    if len(candidate) < 18 or not ADDRESS_MARKERS.search(candidate):
        return None

    pins = list(POSTAL_CODE.finditer(candidate))
    credible_pin = next(
        (p for p in reversed(pins) if p.start() >= len(candidate) - 85), None
    )
    has_city = re.search(r"(?i)\b(?:Pune|Mumbai|Bhopal|India)\b", candidate)
    explicit_street_number = re.match(
        r"(?i)^(?:[A-Z]?-?\d{1,5}|Plot No\.?|Flat No\.?|"
        r"S\.\s*no\.?|(?:Ground|\d{1,2}(?:st|nd|rd|th))\s+Floor)",
        candidate,
    )
    campus_department = re.match(
        r"(?i)^[A-Z]+(?:-[A-Z]+)? Department\b", candidate
    ) and re.search(r"(?i)\b(?:Campus|Level|Road|Street)\b", candidate)
    if not credible_pin and not (has_city or explicit_street_number or campus_department):
        return None
    if not (credible_pin and has_city) and not (
        len(candidate) <= 105 and (STREET_START.match(candidate) or campus_department)
    ):
        return None

    # Avoid absorbing explanatory prose following a postal address.
    end_match = re.search(r"(?i)\bIndia\b", candidate)
    if end_match:
        end = start + end_match.end()
    elif credible_pin and credible_pin.start() > 15:
        end = start + credible_pin.end()
    else:
        end = len(text)
    return start, end


class UniqueSubstitutes(UpdatedSubstitutes):
    """Use a unique three-part substitute for each discovered person."""

    def __init__(self):
        super().__init__()
        self.name_owners = {}

    def get(self, kind, original):
        if kind != "PERSON":
            return super().get(kind, original)

        key = (kind, re.sub(r"\s+", " ", original.casefold().strip()))

        if key in self.values:
            return self.values[key]

        first = [
            "Aarav", "Anaya", "Dev", "Isha",
            "Kabir", "Meera", "Neel", "Riya",
        ]
        middle = [
            "Arun", "Kiran", "Manav", "Nisha",
            "Pranav", "Rohan", "Sahil", "Tara",
        ]
        last = [
            "Shah", "Rao", "Kapoor", "Sen",
            "Bose", "Jain", "Nair", "Sethi",
        ]

        digest = hashlib.sha256(
            key[1].encode("utf-8")
        ).hexdigest()
        index = int(digest[:10], 16) % 512

        for _ in range(512):
            replacement = (
                f"{first[index % 8]} "
                f"{middle[(index // 8) % 8]} "
                f"{last[(index // 64) % 8]}"
            )

            if replacement not in self.name_owners:
                break

            index = (index + 1) % 512
        else:
            raise RuntimeError(
                "More than 512 distinct person names"
            )

        self.name_owners[replacement] = key
        self.values[key] = replacement
        return replacement


def find_matches(text, known):
    matches = find_matches_base(text, known)

    locality = POSTAL_LINE.match(text)
    if locality:
        matches.append(
            Match(locality.start(), locality.end(), "ADDRESS", "postal-line")
        )

    for pattern in (FULL_COMPANY, BANK_OF_INDIA, ASSOCIATES_FIRM):
        for match in pattern.finditer(text):
            start = match.start()
            for prefix in ("Company ", "Formerly "):
                if text[start:match.end()].startswith(prefix):
                    start += len(prefix)
            matches.append(
                Match(start, match.end(), "COMPANY", "full-organization")
            )

    for match in AMPERSAND_COMPANY.finditer(text):
        matches.append(
            Match(match.start(), match.end(), "COMPANY", "full-company-name")
        )

    for match in ORG_WITH_SUFFIX.finditer(text):
        candidate = match.group()
        # Lists and role labels may precede the legal name.
        split = list(re.finditer(r"[,;]\s+", candidate))
        start = match.start() + (split[-1].end() if split else 0)
        if re.search(r"\b(?:Offer|Escrow|Collection) Bank\b", text[start:match.end()]):
            label = re.search(r"\b(?:Offer|Escrow|Collection) Bank\s+", text[start:match.end()])
            start += label.end()
        if match.end() - start >= 8:
            matches.append(Match(start, match.end(), "COMPANY", "legal-suffix"))

    for match in ORG_ALIAS.finditer(text):
        alias = match.group(1)
        if is_specific_org_alias(alias):
            matches.append(Match(match.start(1), match.end(1), "COMPANY", "organization-alias"))

    for match in ORG_CO.finditer(text):
        matches.append(Match(match.start(), match.end(), "COMPANY", "company-co-suffix"))

    for match in NAMED_FAMILY_TRUST.finditer(text):
        matches.append(Match(match.start(), match.end(), "COMPANY", "named-trust"))

    for group in PHONE_SERIES.finditer(text):
        for number in SERIES_NUMBER.finditer(group.group(1)):
            start = group.start(1) + number.start()
            end = group.start(1) + number.end()
            digits = re.sub(r"\D", "", text[start:end])
            if 10 <= len(digits) <= 13:
                matches.append(Match(start, end, "PHONE", "telephone-list"))

    # Catch formats such as 022-68052182 and +91-20-26234000.
    for match in PHONE_LABEL.finditer(text):
        phone = match.group(1).strip()
        digit_count = len(re.sub(r"\D", "", phone))

        if 10 <= digit_count <= 13:
            matches.append(
                Match(
                    match.start(1),
                    match.start(1) + len(phone),
                    "PHONE",
                    "phone-label",
                )
            )

    # Catch a street address at the start of a contact paragraph.
    address = ADDRESS_WITH_PIN.search(text)

    if address and ADDRESS_MARKERS.search(address.group(1)):
        matches.append(
            Match(
                address.start(1),
                address.end(1),
                "ADDRESS",
                "pin-and-street",
            )
        )

    for address in FLOOR_ADDRESS.finditer(text):
        if ADDRESS_MARKERS.search(address.group()):
            matches.append(
                Match(address.start(), address.end(), "ADDRESS", "floor-address")
            )

    for pattern in ADDRESS_FRAGMENTS:
        for address in pattern.finditer(text):
            matches.append(Match(
                address.start(), address.end(), "ADDRESS", "address-fragment"
            ))

    address_line = find_address_line(text)
    if address_line:
        start, end = address_line
        matches.append(Match(start, end, "ADDRESS", "address-line"))

    priority = {
        "EMAIL": 10,
        "SSN": 10,
        "IP_ADDRESS": 10,
        "CREDIT_CARD": 10,
        "CIN": 10,
        "PHONE": 9,
        "DATE_OF_BIRTH": 9,
        "ADDRESS": 8,
        "COMPANY": 7,
        "PERSON": 6,
    }

    cleaned = []
    for match in matches:
        if match.kind != "COMPANY":
            cleaned.append(match)
            continue
        # A greedy organization regex may join two legal names. Keep the
        # final legal suffix of each name and leave the conjunction intact.
        start = match.start
        boundaries = list(ORG_BOUNDARY.finditer(text[start:match.end]))
        segments = []
        for boundary in boundaries:
            before_and = re.search(r"(?:\s+and|,)\s+", boundary.group(), re.IGNORECASE)
            segments.append((start, match.start + boundary.start()
                             + before_and.start()))
            start = match.start + boundary.end()
        segments.append((start, match.end))
        for start, end in segments:
            value = text[start:end]
            if value.casefold() in {"private limited", "public limited"}:
                continue
            if re.fullmatch(
                r"(?i)(?:refund|escrow|collection|sponsor|"
                r"public offer account|self-certified\s+syndicate)\s+bank",
                value,
            ):
                continue
            separator = re.search(r"\bCo\.,\s+", value)
            if separator:
                start += separator.end()
                value = text[start:end]
            prefix = re.match(
                r"(?i)(?:and\s+|Company\s+|Formerly\s+|OF\s+|"
                r"Collectively,\s+|"
                r"Offer Escrow Collection Bank\s+)", value
            )
            if prefix:
                start += prefix.end()
            if start < end:
                cleaned.append(Match(start, end, match.kind, match.source))
    matches = cleaned

    selected = []

    for match in sorted(
        matches,
        key=lambda item: (
            -priority[item.kind],
            -(item.end - item.start),
            item.start,
        ),
    ):
        overlaps = any(
            match.start < existing.end
            and existing.start < match.end
            for existing in selected
        )

        if not overlaps:
            selected.append(match)

    return sorted(selected, key=lambda item: item.start)


def replace_cross_paragraph_companies(document, known, substitutes, log_rows):
    """Handle a legal name split between two paragraphs in a table cell."""
    locations = {p._p: location for location, p in paragraphs(document)}
    seen_pairs = set()

    class FixedReplacement:
        def __init__(self, value):
            self.value = value

        def get(self, kind, original):
            return self.value

    for table in document.tables:
        for row in table.rows:
            for cell in row.cells:
                for left, right in zip(cell.paragraphs, cell.paragraphs[1:]):
                    pair = (left._p, right._p)
                    if pair in seen_pairs:
                        continue
                    seen_pairs.add(pair)
                    combined = left.text + "\n" + right.text
                    boundary = len(left.text)
                    crossing = [m for m in find_matches(combined, known)
                                if m.kind == "COMPANY" and m.start < boundary
                                and m.end > boundary + 1]
                    for match in reversed(crossing):
                        original = combined[match.start:match.end].replace("\n", " ")
                        fake = substitutes.get("COMPANY", original)
                        replace_in_paragraph(
                            left, [Match(match.start, boundary, "COMPANY", "cross-paragraph")],
                            FixedReplacement(fake), locations[left._p], [],
                        )
                        replace_in_paragraph(
                            right, [Match(0, match.end - boundary - 1,
                                          "COMPANY", "cross-paragraph")],
                            FixedReplacement(""), locations[right._p], [],
                        )
                        log_rows.append({
                            "location": "cross:" + locations[left._p] + "+"
                                        + locations[right._p],
                            "start": match.start,
                            "end": match.end,
                            "type": "COMPANY",
                            "original": original,
                            "replacement": fake,
                            "source": "cross-paragraph",
                        })


def redact_document(input_file, output_file, log_file=None):
    """Redact a DOCX from a path or binary stream and return detection rows.

    The optional CSV is intended for private local evaluation only.
    """
    document = Document(input_file)
    values = gather_values(document)
    known = compile_known_values(values)

    substitutes = UniqueSubstitutes()
    log_rows = []

    for location, paragraph in paragraphs(document):
        text = "".join(run.text for run in paragraph.runs)
        matches = find_matches(text, known)
        replace_in_paragraph(paragraph, matches, substitutes, location, log_rows)

    replace_cross_paragraph_companies(document, known, substitutes, log_rows)

    if isinstance(output_file, Path):
        output_file.parent.mkdir(parents=True, exist_ok=True)
    document.save(output_file)

    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=["location", "start", "end", "type", "original", "replacement", "source"],
            )
            writer.writeheader()
            writer.writerows(log_rows)

    return log_rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/redacted_output.docx"),
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("output/detections.csv"),
    )
    args = parser.parse_args()

    log_rows = redact_document(args.input, args.output, args.log)

    print("Saved:", args.output)
    print("Total detections:", len(log_rows))
    print(
        "By type:",
        dict(Counter(row["type"] for row in log_rows)),
    )


if __name__ == '__main__':
    main()
