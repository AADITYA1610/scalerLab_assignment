"""Small browser interface for the same DOCX redaction pipeline as redact.py."""

from io import BytesIO
from zipfile import BadZipFile, is_zipfile

from docx.opc.exceptions import PackageNotFoundError
from flask import Flask, render_template_string, request, send_file

from redact import redact_document

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prospectus PII Redactor</title>
<style>body{font:16px/1.55 system-ui,sans-serif;background:#f4f6fa;color:#17243b;margin:0;padding:3rem 1rem}
main{max-width:650px;margin:auto;padding:2rem;background:white;border-radius:14px;box-shadow:0 5px 25px #17243b12}
h1{line-height:1.2}input{display:block;margin:1rem 0}button{background:#155abd;color:white;border:0;border-radius:7px;padding:.8rem 1.2rem;font:inherit;cursor:pointer}
.error{color:#9c1824}small{color:#526079}</style></head><body><main>
<h1>Prospectus PII Redactor</h1>
<p>Upload a Word <strong>.docx</strong> file to download a copy with detected personal and company information replaced by consistent synthetic values.</p>
{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
<form action="/redact" method="post" enctype="multipart/form-data">
<label for="document">Choose a DOCX file (up to 12 MB)</label>
<input id="document" name="document" type="file" accept=".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document" required>
<button type="submit">Redact and download</button></form>
<p><small>Files are processed in memory during the request and are not intentionally stored by this app. Detection can miss information; review the downloaded document before sharing it.</small></p>
</main></body></html>"""


@app.get("/")
def index():
    return render_template_string(PAGE)


@app.post("/redact")
def redact_upload():
    upload = request.files.get("document")
    if upload is None or not upload.filename or not upload.filename.lower().endswith(".docx"):
        return render_template_string(PAGE, error="Choose a .docx file."), 400

    source = BytesIO(upload.read())
    if not is_zipfile(source):
        return render_template_string(PAGE, error="This is not a valid DOCX file."), 400

    source.seek(0)
    result = BytesIO()
    try:
        redact_document(source, result)
    except (BadZipFile, PackageNotFoundError, ValueError, KeyError):
        return render_template_string(PAGE, error="Could not read this DOCX file."), 400

    result.seek(0)
    response = send_file(
        result,
        mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        as_attachment=True,
        download_name="redacted_output.docx",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def too_large(_):
    return render_template_string(PAGE, error="File exceeds the 12 MB limit."), 413


if __name__ == "__main__":
    app.run(debug=False)
