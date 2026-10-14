from __future__ import annotations
import hashlib, math, mimetypes, platform, re, tempfile
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
MAX_FILE_BYTES = 100 * 1024 * 1024
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES

def human_size(size):
    value, units = float(size), ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return (str(size) + " B") if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024

def detect_type(data, filename):
    signatures = [
        (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png"),
        (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
        (b"GIF87a", "GIF image", "image/gif"), (b"GIF89a", "GIF image", "image/gif"),
        (b"%PDF-", "PDF document", "application/pdf"),
        (b"PK\x03\x04", "ZIP-based archive (ZIP/DOCX/XLSX/APK)", "application/zip"),
        (b"Rar!\x1a\x07", "RAR archive", "application/vnd.rar"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "application/x-7z-compressed"),
        (b"\x1f\x8b", "GZIP archive", "application/gzip"), (b"ID3", "MP3 audio", "audio/mpeg"),
        (b"OggS", "Ogg media", "application/ogg"), (b"fLaC", "FLAC audio", "audio/flac"),
        (b"BM", "BMP image", "image/bmp"), (b"MZ", "Windows executable (PE candidate)", "application/vnd.microsoft.portable-executable"),
        (b"\x7fELF", "ELF executable", "application/x-elf"), (b"SQLite format 3\x00", "SQLite database", "application/vnd.sqlite3"),
    ]
    for sig, label, mime in signatures:
        if data.startswith(sig): return label, mime
    if len(data) >= 12 and data[4:8] == b"ftyp": return "MP4/ISO Base Media video", "video/mp4"
    if data.startswith(b"RIFF") and len(data) >= 12:
        if data[8:12] == b"WAVE": return "WAV audio", "audio/wav"
        if data[8:12] == b"AVI ": return "AVI video", "video/x-msvideo"
        if data[8:12] == b"WEBP": return "WebP image", "image/webp"
    guessed, _ = mimetypes.guess_type(filename)
    if guessed: return "Firma non riconosciuta; tipo stimato dall'estensione", guessed
    try: data[:8192].decode("utf-8"); return "Testo o dati compatibili con UTF-8", "text/plain"
    except UnicodeDecodeError: return "File binario non identificato", "application/octet-stream"

def entropy(data):
    if not data: return 0.0
    counts = [0] * 256
    for byte in data: counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)

def printable_strings(data, minimum=5, limit=500):
    return [item.decode("ascii", errors="replace") for item in re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)[:limit]]

def analyze_file(path, original_name):
    data = path.read_bytes()
    sha256, sha1, md5 = hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.md5(data).hexdigest()
    detected_name, detected_mime = detect_type(data[:64], original_name)
    metadata = [
        {"group":"File","key":"Nome","value":original_name,"explanation":"Nome originale ricevuto dal browser; non prova il contenuto reale."},
        {"group":"File","key":"Estensione","value":Path(original_name).suffix.lower() or "(nessuna)","explanation":"L'estensione può essere cambiata e non garantisce il formato."},
        {"group":"File","key":"Dimensione","value":human_size(len(data)),"explanation":f"Dimensione esatta: {len(data)} byte."},
        {"group":"File","key":"MIME type","value":detected_mime,"explanation":"Tipo stimato dai byte iniziali o, in fallback, dall'estensione."},
        {"group":"File","key":"Firma rilevata","value":detected_name,"explanation":"Riconoscimento euristico dei byte iniziali, non una validazione completa."},
        {"group":"Hashes","key":"SHA-256","value":sha256,"explanation":"Impronta crittografica utile per confrontare file."},
        {"group":"Hashes","key":"SHA-1","value":sha1,"explanation":"Impronta storica; non garantisce protezione moderna dalle collisioni."},
        {"group":"Hashes","key":"MD5","value":md5,"explanation":"Utile per confronti non critici, non per sicurezza contro collisioni."},
        {"group":"Tecnico","key":"Entropia","value":f"{entropy(data):.4f} bit/byte","explanation":"Distribuzione dei byte: valori alti possono dipendere da compressione o cifratura, ma non lo provano."},
        {"group":"Tecnico","key":"Byte nulli","value":str(data.count(b"\x00")),"explanation":"Numero di byte con valore zero."},
        {"group":"Tecnico","key":"Valori di byte distinti","value":f"{len(set(data))} / 256","explanation":"Quanti valori diversi da 0 a 255 sono presenti."},
    ]
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        import io
        with Image.open(io.BytesIO(data)) as im:
            metadata += [
                {"group":"Immagine","key":"Formato","value":str(im.format),"explanation":"Formato riconosciuto da Pillow."},
                {"group":"Immagine","key":"Dimensioni","value":f"{im.width} × {im.height}","explanation":"Larghezza e altezza in pixel."},
                {"group":"Immagine","key":"Modalità colore","value":str(im.mode),"explanation":"Rappresentazione del colore, ad esempio RGB o RGBA."},
            ]
            exif = im.getexif()
            for tag_id, value in exif.items():
                metadata.append({"group":"EXIF","key":TAGS.get(tag_id,str(tag_id)),"value":str(value)[:300],"explanation":"Dato incorporato nell'immagine, potenzialmente assente o modificabile."})
            try:
                gps_raw = exif.get_ifd(34853) if 34853 in exif else {}
                gps = {GPSTAGS.get(tag_id, str(tag_id)): value for tag_id, value in gps_raw.items()}
                def as_float(number):
                    if hasattr(number, "numerator") and hasattr(number, "denominator"):
                        return float(number.numerator) / float(number.denominator) if number.denominator else 0.0
                    return float(number)
                def gps_decimal(parts, reference):
                    degrees, minutes, seconds = [as_float(part) for part in parts]
                    result = degrees + minutes / 60.0 + seconds / 3600.0
                    return -result if str(reference).upper() in ("S", "W") else result
                if gps.get("GPSLatitude") and gps.get("GPSLongitude"):
                    latitude = gps_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
                    longitude = gps_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
                    coordinates = f"{latitude:.6f}, {longitude:.6f}"
                    map_url = f"https://www.google.com/maps?q={latitude:.6f},{longitude:.6f}"
                    metadata.append({"group":"Posizione","key":"Coordinate GPS","value":coordinates,"explanation":"Coordinate salvate nei metadati della foto. Possono indicare dove è stata scattata, ma potrebbero essere state modificate."})
                    metadata.append({"group":"Posizione","key":"Apri sulla mappa","value":map_url,"explanation":"Apri il link per vedere queste coordinate su Google Maps."})
            except Exception:
                pass
    except Exception: pass
    if data.startswith(b"%PDF-"):
        try:
            from pypdf import PdfReader
            import io
            reader = PdfReader(io.BytesIO(data), strict=False)
            metadata += [
                {"group":"PDF","key":"Numero pagine","value":str(len(reader.pages)),"explanation":"Numero di pagine rilevato dal parser."},
                {"group":"PDF","key":"Cifrato","value":str(reader.is_encrypted),"explanation":"Indica se il documento risulta protetto da cifratura."},
            ]
            if not reader.is_encrypted:
                for key,value in (reader.metadata or {}).items():
                    metadata.append({"group":"PDF","key":str(key).lstrip("/"),"value":str(value)[:500],"explanation":"Metadato dichiarato nel documento, non prova dell'identità dell'autore."})
        except Exception as exc:
            metadata.append({"group":"PDF","key":"Nota parser","value":str(exc)[:250],"explanation":"Il parser non ha letto tutti i dati del PDF."})
    def metadata_value(*names):
        wanted = {name.lower() for name in names}
        for item in metadata:
            if item["key"].lower() in wanted and item["value"] and item["value"] != "(nessuna)":
                return item["value"]
        return None
    camera_make = metadata_value("Make")
    camera_model = metadata_value("Model")
    camera = " ".join(part for part in (camera_make, camera_model) if part) or None
    photo_date = metadata_value("DateTimeOriginal", "DateTimeDigitized", "DateTime")
    highlights = {"location": metadata_value("Coordinate GPS"), "map_url": metadata_value("Apri sulla mappa"), "photo_date": photo_date, "camera": camera}
    return {"name":original_name,"size_bytes":len(data),"size_human":human_size(len(data)),"detected_type":detected_name,"mime":detected_mime,"sha256":sha256,"metadata":metadata,"highlights":highlights,"strings":printable_strings(data),"hex_preview":" ".join(f"{b:02X}" for b in data[:512]),"analyzed_at":datetime.now().astimezone().isoformat(timespec="seconds"),"analysis_note":"Analisi euristica locale. I metadati possono essere incompleti o falsificati."}

@app.get("/")
def index(): return send_from_directory(BASE_DIR, "index.html")
@app.get("/style.css")
def style(): return send_from_directory(BASE_DIR, "style.css")
@app.get("/script.js")
def script(): return send_from_directory(BASE_DIR, "script.js")
@app.get("/api/status")
def status(): return jsonify({"name":"Meta Search","version":"0.2","platform":platform.system(),"max_file_bytes":MAX_FILE_BYTES})
@app.post("/api/analyze")
def analyze():
    if "file" not in request.files: return jsonify({"error":"Nessun file ricevuto."}), 400
    uploaded = request.files["file"]
    if not uploaded.filename: return jsonify({"error":"Seleziona un file prima dell'analisi."}), 400
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="metasearch_", delete=False) as temp:
            temp_path = Path(temp.name)
            total = 0
            while True:
                chunk = uploaded.stream.read(1024 * 1024)
                if not chunk: break
                total += len(chunk)
                if total > MAX_FILE_BYTES: return jsonify({"error":"Il file supera il limite di 100 MB della versione 0.2."}), 413
                temp.write(chunk)
        return jsonify(analyze_file(temp_path, uploaded.filename))
    except Exception as exc:
        app.logger.exception("Analisi non riuscita")
        return jsonify({"error":"Analisi non riuscita: " + str(exc)[:250]}), 500
    finally:
        if temp_path:
            try: temp_path.unlink(missing_ok=True)
            except OSError: pass
@app.errorhandler(413)
def too_large(_error): return jsonify({"error":"Il file supera il limite di 100 MB."}), 413

if __name__ == "__main__":
    print("Meta Search 0.2 — apri http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
