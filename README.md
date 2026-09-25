# PII Redaction Tool — KSH prospectus

**Aaditya Raj Dixit** · SAP ID: **500122014** · Aaditya.122014@stu.upes.ac.in

This tool reads the supplied Red Herring Prospectus DOCX and replaces detected PII with consistent synthetic values in a new DOCX. It uses regex, context rules and a list of entities learned from the document; **no NER model or API** is required. The assignment mentions a “ticket log,” but the provided input is a prospectus with tables and ordinary financial dates.

## Setup and run

Requirements: **Python 3.10+**; install dependencies from `requirements.txt`. In PowerShell, from the project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python redact.py "input\Red Herring Prospectus.docx" --output "output\redacted_output.docx" --log "output\detections.csv"
python test_detectors.py
python evaluate.py --gold final_frozen_labels.json --log "output\detections.csv"
```

Place the supplied original at `input/Red Herring Prospectus.docx` first; skip virtual-environment setup if it is already active. Close the output file in Word before rerunning on Windows. The deliverable is `output/redacted_output.docx`. The CSV logs source values, types, offsets and replacements; **it contains original PII** and should be handled privately.

## Browser demo and deployment

Run `python app.py` locally and visit `http://127.0.0.1:5000` to upload a DOCX and download its redacted copy. The browser app uses the same pipeline as the CLI. It processes uploads in memory and does not create the private CSV. Review the downloaded DOCX before sharing it.

For a public demo, push the project files to GitHub, then create a Python Web Service on Render from that repository. Set build command to `pip install -r requirements.txt` and start command to `gunicorn app:app`. Use the resulting service URL for the form's cloud link. Never commit the source prospectus or detection logs: `.gitignore` excludes `input/`, `output/`, CSV files and virtual environments. The redacted DOCX is supplied separately from the public repository.

## Approach

- **Emails, Indian phones, US-style SSNs, IPv4 addresses and Indian CINs:** format patterns with checks appropriate to each type. Card-shaped numbers additionally need a valid Luhn checksum.
- **Dates of birth:** a date is replaced only near an explicit birth label; ordinary offer and incorporation dates stay intact.
- **People:** contact/role cues, promoter lists and shareholder/director table columns supply names reused elsewhere in the document.
- **Companies and addresses:** legal suffixes, named trusts, labelled supplier/customer lists, aliases, office/contact fields, street/floor/postal patterns and plant context.

The script visits paragraphs, tables, headers and footers, resolves overlapping matches, and replaces text inside DOCX runs. A pass also handles company names split between table paragraphs. Identical values, including case/whitespace variants, receive the same deterministic fake value; CINs are an extra category beyond the nine required types. To extend the tool, add a detector and overlap priority in `redact.py`, a synthetic replacement in `Substitutes.get`, and labelled evaluation examples.

## Limits and evaluation

Publicly named people, companies and trusts are in scope because the assignment requests them. Context reduces false positives on financial numbers and generic role words, but unusual names (including some with middle initials), unlabelled birthdays, irregular phones and fragmented addresses can be missed. Unprocessed images, drawings, comments or footnotes may retain information. Substitutes are **pseudonyms, not guaranteed irreversible anonymization**; an alias and its legal company name may get different fake labels.

`evaluation_report.md` defines exact-span precision/recall/F1 and character-level accuracy, reports **0.930 F1 on a frozen 28-paragraph sample**, and explains why earlier `1.000` scores are regression checks. The source had no detected SSN, valid card, explicitly labelled DOB or IPv4 examples; constructed checks cover basic behavior but cannot establish real-document accuracy for those types.
