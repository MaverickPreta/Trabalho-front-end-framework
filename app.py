"""Backend Flask que consulta o VirusTotal (API v3)."""
import hashlib
import io
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
DOWNLOADS_DIR = Path(os.getenv("DOWNLOADS_DIR", Path.home() / "Downloads")).resolve()
IGNORED_EXT = {".crdownload", ".part", ".tmp", ".download", ".partial"}
SMALL_LIMIT = 32 * 1024 * 1024        # acima disso o VT exige upload_url especial
MAX_UPLOAD = 100 * 1024 * 1024        # limite que escolhi para este app

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD
CORS(app)  # libera o Flutter web (outra porta) a chamar a API


class VTError(Exception):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.message = message
        self.status = status


@app.errorhandler(VTError)
def handle_vt_error(e):
    return jsonify({"error": e.message}), e.status


def vt(method, path_or_url, **kwargs):
    if not VT_API_KEY:
        raise VTError("VT_API_KEY não configurada no arquivo .env", 500)
    url = path_or_url if path_or_url.startswith("http") else VT_BASE + path_or_url
    try:
        r = requests.request(
            method, url, headers={"x-apikey": VT_API_KEY}, timeout=kwargs.pop("timeout", 30), **kwargs
        )
    except requests.RequestException as exc:
        raise VTError(f"Falha de conexão com o VirusTotal: {exc}")
    if r.status_code == 429:
        raise VTError("Limite de requisições do VirusTotal atingido (plano gratuito: 4/min). Aguarde um pouco.", 429)
    if r.status_code in (401, 403):
        raise VTError("Chave de API inválida ou sem permissão.", 401)
    return r


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def report_link(sha256):
    return f"https://www.virustotal.com/gui/file/{sha256}"


def lookup_or_submit(sha256, filename, open_fn, size):
    """Procura pelo hash; se o VT não conhece o arquivo, envia para análise."""
    r = vt("GET", f"/files/{sha256}")
    if r.status_code == 200:
        attrs = r.json()["data"]["attributes"]
        return {
            "status": "done",
            "sha256": sha256,
            "stats": attrs.get("last_analysis_stats", {}),
            "link": report_link(sha256),
            "submitted": False,
        }
    if r.status_code != 404:
        raise VTError(f"VirusTotal respondeu {r.status_code}")

    # Arquivo desconhecido -> upload
    upload_url = VT_BASE + "/files"
    if size > SMALL_LIMIT:
        u = vt("GET", "/files/upload_url")
        if u.status_code != 200:
            raise VTError("Não foi possível obter a URL de upload para arquivo grande.")
        upload_url = u.json()["data"]

    with open_fn() as f:
        up = vt("POST", upload_url, files={"file": (filename, f)}, timeout=300)
    if up.status_code != 200:
        raise VTError(f"Falha no upload ao VirusTotal ({up.status_code}).")
    return {
        "status": "queued",
        "sha256": sha256,
        "analysis_id": up.json()["data"]["id"],
        "link": report_link(sha256),
        "submitted": True,
    }


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "key_configured": bool(VT_API_KEY), "downloads_dir": str(DOWNLOADS_DIR)})


@app.get("/api/downloads")
def list_downloads():
    """Arquivos modificados recentemente na pasta de downloads desta máquina."""
    minutes = request.args.get("minutes", default=60, type=int)
    cutoff = time.time() - minutes * 60
    if not DOWNLOADS_DIR.is_dir():
        raise VTError(f"Pasta de downloads não encontrada: {DOWNLOADS_DIR}", 404)
    items = []
    for p in DOWNLOADS_DIR.iterdir():
        if not p.is_file() or p.suffix.lower() in IGNORED_EXT or p.name.startswith("."):
            continue
        st = p.stat()
        if st.st_mtime >= cutoff:
            items.append({"name": p.name, "size": st.st_size, "modified": st.st_mtime})
    items.sort(key=lambda i: i["modified"], reverse=True)
    return jsonify(items[:50])


@app.post("/api/scan/download")
def scan_download():
    """Escaneia um arquivo da pasta de downloads, pelo nome."""
    filename = (request.get_json(silent=True) or {}).get("filename", "")
    target = (DOWNLOADS_DIR / filename).resolve()
    # impede path traversal (../../algo)
    if target.parent != DOWNLOADS_DIR or not target.is_file():
        raise VTError("Arquivo não encontrado na pasta de downloads.", 404)
    size = target.stat().st_size
    if size > MAX_UPLOAD:
        raise VTError("Arquivo grande demais para este app (limite 100 MB).", 413)
    sha = sha256_of(target)
    return jsonify(lookup_or_submit(sha, target.name, lambda: target.open("rb"), size))


@app.post("/api/scan/upload")
def scan_upload():
    """Escaneia um arquivo enviado pelo navegador."""
    f = request.files.get("file")
    if not f:
        raise VTError("Nenhum arquivo enviado.", 400)
    data = f.read()
    sha = hashlib.sha256(data).hexdigest()
    return jsonify(lookup_or_submit(sha, f.filename or "arquivo", lambda: io.BytesIO(data), len(data)))


@app.get("/api/analysis/<analysis_id>")
def analysis(analysis_id):
    """Consulta o andamento de uma análise enviada."""
    r = vt("GET", f"/analyses/{analysis_id}")
    if r.status_code != 200:
        raise VTError(f"VirusTotal respondeu {r.status_code}")
    body = r.json()
    attrs = body["data"]["attributes"]
    sha = body.get("meta", {}).get("file_info", {}).get("sha256")
    out = {"status": "done" if attrs.get("status") == "completed" else "queued"}
    if out["status"] == "done":
        out["stats"] = attrs.get("stats", {})
        out["sha256"] = sha
        out["link"] = report_link(sha) if sha else None
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
