"""
╔══════════════════════════════════════════════════════════════════════╗
║   SURGIX v1.12 Web GoldenEye — Version Streamlit (Cloud)            ║
║   CHU Mohammed VI · Oujda · Service Ophtalmologie                   ║
║   Stockage persistant : Google Drive — compatible version PC v1.12  ║
╚══════════════════════════════════════════════════════════════════════╝

Déploiement gratuit : https://streamlit.io/cloud

Les fichiers Drive utilisés sont LES MÊMES que la version PC :
  patients_A1.json / patients_B1.json / patients_B2.json / patients_A2.json
  users.json  /  ttt_memory.json

── Configuration requise (Streamlit Cloud > Secrets) ─────────────────
[gcp_service_account]
type = "service_account"
project_id = "..."
private_key_id = "..."
private_key = "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----\\n"
client_email = "surgix@...iam.gserviceaccount.com"
client_id = "..."
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
──────────────────────────────────────────────────────────────────────

⚠️  Partagez chaque fichier JSON Drive avec l'email du service account
    (rôle Éditeur). Les fichiers sont détectés automatiquement par nom.

    Pour lire les fichiers chiffrés v1.12 PC, ajoutez dans les Secrets :
    crypto_password = "DJIRE6p"  (ou tout mot de passe v1.12 valide)
"""

import streamlit as st
import json, hashlib, secrets, os, datetime, unicodedata, calendar
from difflib import SequenceMatcher
from datetime import date, timedelta

# ═══════════════════════════════════════════════════════════════
# CHIFFREMENT FERNET — compatible v1.12 PC (GoldenEye)
# Même algo PC : PBKDF2HMAC SHA-256, sel fixe, 100k itérations
# ═══════════════════════════════════════════════════════════════
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

@st.cache_resource
def _get_fernet():
    """
    Dérive la clé Fernet depuis les secrets Streamlit.
    Mode 1 : secrets["crypto_password"] → PBKDF2 identique à v1.12 PC ← RECOMMANDÉ
    Mode 2 : secrets["fernet_key"]      → clé Fernet brute base64
    Retourne None si non configuré (mode non-chiffré rétrocompat v1.09).
    """
    if not _CRYPTO_AVAILABLE:
        return None
    try:
        if "fernet_key" in st.secrets:
            return Fernet(st.secrets["fernet_key"].encode())
        if "crypto_password" in st.secrets:
            password = st.secrets["crypto_password"]
            salt = b"SURGIX_CHU_OUJDA_2024"   # sel identique v1.12 PC
            kdf  = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=32,
                salt=salt, iterations=100_000
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return Fernet(key)
    except Exception:
        pass
    return None

def _decrypt_bytes(raw: bytes) -> str:
    """
    Déchiffre des données brutes Drive.
    1. Tente Fernet (fichiers chiffrés v1.12 PC)
    2. Fallback UTF-8 brut (anciens fichiers v1.09 non-chiffrés)
    """
    fernet = _get_fernet()
    if fernet and raw:
        try:
            return fernet.decrypt(raw).decode("utf-8")
        except Exception:
            pass  # Pas chiffré ou mauvaise clé → fallback
    try:
        return raw.decode("utf-8")
    except Exception:
        return "{}"

def _encrypt_str(data: str) -> bytes:
    """Chiffre pour l'écriture Drive. UTF-8 brut si pas de Fernet configuré."""
    fernet = _get_fernet()
    if fernet:
        return fernet.encrypt(data.encode("utf-8"))
    return data.encode("utf-8")

# ── Google Drive ────────────────────────────────────────────────────
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
    import io as _io
    _DRIVE_AVAILABLE = True
except ImportError:
    _DRIVE_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════
# COUCHE GOOGLE DRIVE — compatible fichiers version PC
# ═══════════════════════════════════════════════════════════════
_DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive"]

# Noms de fichiers identiques à la version PC
_DRIVE_FILES = {
    "A1":   "patients_A1.json",
    "B1":   "patients_B1.json",
    "B2":   "patients_B2.json",
    "A2":   "patients_A2.json",
    "users": "users.json",
    "ttt":   "ttt_memory.json",
}

@st.cache_resource
def _drive_service():
    """Retourne un client Drive authentifié via Service Account (mis en cache)."""
    if not _DRIVE_AVAILABLE:
        return None
    try:
        creds_info = dict(st.secrets["gcp_service_account"])
        creds_info["private_key"] = creds_info["private_key"].replace("\\n", "\n")
        creds = service_account.Credentials.from_service_account_info(
            creds_info, scopes=_DRIVE_SCOPES
        )
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception:
        return None

def _find_file_id(svc, name: str) -> str:
    """Cherche un fichier Drive par nom (comme la version PC)."""
    try:
        q   = f"name='{name}' and trashed=false"
        res = svc.files().list(q=q, fields="files(id)", pageSize=5).execute()
        files = res.get("files", [])
        return files[0]["id"] if files else ""
    except Exception:
        return ""

def _drive_download_json(name: str) -> dict:
    """
    Télécharge depuis Drive et déchiffre automatiquement.
    Compatible v1.12 PC (Fernet) ET v1.09 (JSON brut).
    """
    svc = _drive_service()
    if not svc:
        return {}
    try:
        fid = _find_file_id(svc, name)
        if not fid:
            return {}
        req = svc.files().get_media(fileId=fid)
        buf = _io.BytesIO()
        dl  = MediaIoBaseDownload(buf, req)
        done = False
        while not done:
            _, done = dl.next_chunk()
        buf.seek(0)
        raw  = buf.read()
        text = _decrypt_bytes(raw)   # Fernet si chiffré, UTF-8 sinon
        return json.loads(text)
    except Exception:
        return {}

def _drive_upload_json(name: str, data):
    """
    Chiffre et uploade sur Drive.
    Compatible v1.12 PC : Fernet si configuré, UTF-8 brut sinon.
    """
    svc = _drive_service()
    if not svc:
        return
    try:
        json_str = json.dumps(data, ensure_ascii=False, indent=2)
        raw      = _encrypt_str(json_str)   # Fernet si configuré
        media    = MediaIoBaseUpload(_io.BytesIO(raw), mimetype="application/octet-stream")
        fid      = _find_file_id(svc, name)
        if fid:
            svc.files().update(fileId=fid, media_body=media).execute()
        else:
            svc.files().create(
                body={"name": name}, media_body=media, fields="id"
            ).execute()
    except Exception:
        pass  # Silencieux — ne jamais bloquer l'interface

def drive_load_all() -> dict:
    """
    Charge tous les fichiers depuis Drive et retourne un snapshot complet.
    Compatible avec la structure de fichiers de la version PC.
    """
    db = {}
    for eq in ["A1", "B1", "B2", "A2"]:
        eq_data = _drive_download_json(_DRIVE_FILES[eq])
        if isinstance(eq_data, dict):
            db.update(eq_data)
    return {
        "db":    db,
        "users": _drive_download_json(_DRIVE_FILES["users"]),
        "ttt":   _drive_download_json(_DRIVE_FILES["ttt"]),
    }

def drive_save_patients():
    """
    Sauvegarde les patients sur Drive en respectant la séparation par équipe
    (identique à la version PC : patients_A1.json, patients_B1.json, etc.)
    """
    db = st.session_state.get("db", {})
    # Répartition par équipe
    buckets = {"A1": {}, "B1": {}, "B2": {}, "A2": {}, "admin": {}}
    eq_membres = {
        "A1": ["ACHERGUI","HALHOUL","LABYAD","BOUTAIB","JABRI","MOUSSA","HEYOUNI"],
        "B1": ["HIDA","OUSMANE","NOUR","ELMEHDI","KOUEUI","DJIRE"],
        "B2": ["SKIKER","NADO","HAMDI","BOULAGHCHA","HABOUCHA","BOUCHAREB","BENALI","ELHACHEMI"],
        "A2": ["BADI","DHAOUI","YAMANI","MOHAMMEDHASSAN","SERJI","CHEIKH","TIJANIH","ELHADDI","ELMASSRI"],
    }
    for ip, patient in db.items():
        medecin = patient.get("medecin", "")
        placed  = False
        for eq, membres in eq_membres.items():
            # On cherche si le médecin traitant appartient à cette équipe
            for m in membres:
                if m.lower() in medecin.lower():
                    buckets[eq][ip] = patient
                    placed = True
                    break
            if placed:
                break
        if not placed:
            buckets["admin"][ip] = patient
    # Upload de chaque bucket
    for eq in ["A1", "B1", "B2", "A2"]:
        _drive_upload_json(_DRIVE_FILES[eq], buckets[eq])

def drive_save_users():
    _drive_upload_json(_DRIVE_FILES["users"], st.session_state.get("users", {}))

def drive_save_ttt():
    _drive_upload_json(_DRIVE_FILES["ttt"], st.session_state.get("ttt_fiches", []))

def _apply_snapshot(snap: dict):
    """Injecte les données chargées depuis Drive dans session_state."""
    if snap.get("db"):
        st.session_state.db = snap["db"]
    if snap.get("users"):
        st.session_state.users = snap["users"]
    if snap.get("ttt"):
        st.session_state.ttt_fiches = snap["ttt"]

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION PAGE
# ═══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="SURGIX v1.12 Web GoldenEye",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════
# CSS GLOBAL
# ═══════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* Topbar */
.surgix-header {
    background: linear-gradient(90deg, #1A3355 0%, #1565C0 100%);
    padding: 14px 24px; border-radius: 8px; margin-bottom: 16px;
    display: flex; align-items: center; gap: 16px;
}
.surgix-header h1 { color: #fff; margin: 0; font-size: 1.5rem; }
.surgix-header p  { color: #B0C4DE; margin: 0; font-size: 0.8rem; }

/* Cards */
.card {
    background: #fff; border-radius: 8px; padding: 16px;
    border: 1px solid #E2E8F0; margin-bottom: 12px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.card-accent { border-left: 4px solid #1565C0; }
.card-success { border-left: 4px solid #2E7D32; }
.card-warn   { border-left: 4px solid #E65100; }
.card-teal   { border-left: 4px solid #00695C; }

/* Badges */
.badge { display:inline-block; padding:2px 10px; border-radius:12px;
         font-size:0.72rem; font-weight:700; margin:2px; }
.badge-blue  { background:#E3F2FD; color:#1565C0; }
.badge-green { background:#E8F5E9; color:#2E7D32; }
.badge-orange{ background:#FFF3E0; color:#E65100; }
.badge-red   { background:#FFEBEE; color:#C62828; }
.badge-teal  { background:#E0F2F1; color:#00695C; }
.badge-gold  { background:#FFFDE7; color:#F57F17; }

/* Table fiche impression */
.fiche-table { width:100%; border-collapse:collapse; font-size:0.78rem; }
.fiche-table th { background:#1565C0; color:#fff; padding:6px 4px; text-align:center; }
.fiche-table td { border:1px solid #B0C4DE; padding:5px 6px; }
.fiche-hdr-blue  { background:#DDEEFF; }
.fiche-hdr-we    { background:#FFE8C0; }
.fiche-sec-col   { background:#D6EAF8; font-weight:700; }
.fiche-sec-iv    { background:#D5F5E3; font-weight:700; }
.fiche-sec-bol   { background:#FFF3E0; font-weight:700; }
.fiche-row-alt   { background:#F8FAFC; }
.fiche-bolus-sym { color:#E65100; font-weight:900; font-size:1rem; text-align:center; }

/* Nav sidebar */
[data-testid="stSidebar"] { background: #1A3355 !important; }
[data-testid="stSidebar"] .stButton button {
    background: transparent !important; color: #B0C4DE !important;
    border: none !important; text-align: left !important;
    font-size: 0.9rem !important; padding: 8px 16px !important;
    width: 100% !important; border-radius: 6px !important;
}
[data-testid="stSidebar"] .stButton button:hover {
    background: #1565C0 !important; color: #fff !important;
}

/* Misc */
.stat-card { text-align:center; padding:18px; background:#fff;
             border-radius:8px; border:1px solid #E2E8F0; }
.stat-card .num { font-size:2rem; font-weight:900; color:#1565C0; }
.stat-card .lbl { font-size:0.8rem; color:#546E7A; }
.alert-row { background:#FFECEC !important; }
.patient-name { font-weight:700; color:#1A1A2E; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# CONSTANTES
# ═══════════════════════════════════════════════════════════════
ROLE_ADMIN   = "admin"
ROLE_USER    = "utilisateur"
SUPER_ADMIN  = "DJIRE"
TYPE_HOSPIT  = "Hospitalisé"
TYPE_BLOC    = "Bloc"
ALERT_JOURS  = 14

COLONNES     = ["Nom","Prénom","IP","Âge","Diagnostic","Mutuelle","Ville",
                "Date prog.","Médecin","Prof","Matériel","Téléphone","CIN","Type"]
CLES_PATIENT = ("nom","prenom","ip","age","diagnostic","mutuelle","ville",
                "date_prog","medecin","prof","materiel","telephone","cin","type_patient")

EQUIPES = {
    "A1": {"couleur": "#00695C", "membres": ["ACHERGUI","HALHOUL","LABYAD","BOUTAIB","JABRI","MOUSSA","HEYOUNI"]},
    "B1": {"couleur": "#1565C0", "membres": ["HIDA","OUSMANE","NOUR","ELMEHDI","KOUEUI","DJIRE"]},
    "B2": {"couleur": "#E65100", "membres": ["SKIKER","NADO","HAMDI","BOULAGHCHA","HABOUCHA","BOUCHAREB","BENALI","ELHACHEMI"]},
    "A2": {"couleur": "#AD1457", "membres": ["BADI","DHAOUI","YAMANI","MOHAMMEDHASSAN","SERJI","CHEIKH","TIJANIH","ELHADDI","ELMASSRI"]},
}

COMPTES_DEFAUT = [
    ("DJIRE","DJIRE6p",ROLE_ADMIN,"Dr. DJIRE"),
    ("ACHERGUI","ACHERGUI7k",ROLE_USER,"Dr. ACHERGUI"),
    ("HALHOUL","HALHOUL3p",ROLE_USER,"Dr. HALHOUL"),
    ("LABYAD","LABYAD9x",ROLE_USER,"Dr. LABYAD"),
    ("BOUTAIB","BOUTAIB4m",ROLE_USER,"Dr. BOUTAIB"),
    ("JABRI","JABRI6t",ROLE_USER,"Dr. JABRI"),
    ("MOUSSA","MOUSSA2r",ROLE_USER,"Dr. MOUSSA"),
    ("HEYOUNI","HEYOUNI8q",ROLE_USER,"Dr. HEYOUNI"),
    ("HIDA","HIDA5n",ROLE_USER,"Dr. HIDA"),
    ("OUSMANE","OUSMANE7d",ROLE_USER,"Dr. OUSMANE"),
    ("NOUR","NOUR4z",ROLE_USER,"Dr. NOUR"),
    ("ELMEHDI","ELMEHDI9a",ROLE_USER,"Dr. EL MEHDI"),
    ("KOUEUI","KOUEUI3k",ROLE_USER,"Dr. KOUEUI"),
    ("SKIKER","SKIKER2v",ROLE_USER,"Dr. SKIKER"),
    ("NADO","NADO8m",ROLE_USER,"Dr. NADO"),
    ("HAMDI","HAMDI5x",ROLE_USER,"Dr. HAMDI"),
    ("BOULAGHCHA","BOULAGHCHA7r",ROLE_USER,"Dr. BOULAGHCHA"),
    ("HABOUCHA","HABOUCHA4t",ROLE_USER,"Dr. HABOUCHA"),
    ("BOUCHAREB","BOUCHAREB9p",ROLE_USER,"Dr. BOUCHAREB"),
    ("BENALI","BENALI3q",ROLE_USER,"Dr. BENALI"),
    ("ELHACHEMI","ELHACHEMI6z",ROLE_USER,"Dr. EL HACHEMI"),
    ("BADI","BADI2x",ROLE_USER,"Dr. BADI"),
    ("DHAOUI","DHAOUI5m",ROLE_USER,"Dr. DHAOUI"),
    ("YAMANI","YAMANI8k",ROLE_USER,"Dr. YAMANI"),
    ("MOHAMMEDHASSAN","MOHAMMEDHASSAN3p",ROLE_USER,"Dr. MOHAMMED HASSAN"),
    ("SERJI","SERJI7t",ROLE_USER,"Dr. SERJI"),
    ("CHEIKH","CHEIKH4n",ROLE_USER,"Dr. CHEIKH"),
    ("TIJANIH","TIJANIH6r",ROLE_USER,"Dr. TIJANIH"),
    ("ELHADDI","ELHADDI9v",ROLE_USER,"Dr. EL HADDI"),
    ("ELMASSRI","ELMASSRI2q",ROLE_USER,"Dr. EL MASSRI"),
]

DIAG_NORMALIZE = {
    "cataract": "Cataracte", "cataracte": "Cataracte", "cataractes": "Cataracte",
    "glaucome": "Glaucome", "glaucôme": "Glaucome",
    "pterygion": "Ptérygion", "ptérygion": "Ptérygion", "pterigion": "Ptérygion",
    "uveite": "Uvéite", "uvéite": "Uvéite",
    "crosslinking": "Crosslinking", "cross-linking": "Crosslinking",
    "kératocône": "Kératocône", "keratocone": "Kératocône",
    "dacryocystite": "Dacryocystite", "dacryo": "Dacryocystite",
    "decollement retine": "Décollement de rétine", "décollement rétine": "Décollement de rétine",
    "dr": "Décollement de rétine", "dmla": "DMLA",
    "strabisme": "Strabisme", "chalazion": "Chalazion",
    "implantation secondaire": "Implantation secondaire",
    "glaucome aigu": "Glaucome aigu",
    "uvéite antérieure": "Uvéite antérieure",
    "occlusion veineuse": "Occlusion veineuse rétinienne",
    "conjonctivite": "Conjonctivite",
    "examen sous sédation": "Examen sous sédation",
    "ablation de fil": "Ablation de fil",
    "cataracte extra": "Cataracte extra",
}
DIAG_SUGGESTIONS = sorted(set(DIAG_NORMALIZE.values()))

POSOLOGIES_COLLYRE = ["1 gtte x 1/j","1 gtte x 2/j","1 gtte x 3/j","1 gtte x 4/j",
                      "1 gtte x 6/j","1 gtte x 8/j","1 gtte horaire","2 gttes x 4/j"]
POSOLOGIES_POMMADE = ["applic x 1/j","applic x 2/j","applic x 3/j",
                      "applic matin","applic soir","applic matin + soir"]
POSOLOGIES_IV      = ["1 inj/j","1 inj x 2/j","1 inj x 3/j","perf/j","1 inj/sem"]
POSOLOGIES_PEROS   = ["1 cp/j","1 cp x 2/j","1 cp x 3/j","2 cp/j","1 gel/j","1 gel x 2/j"]
POSOLOGIES_SIROP   = ["1 c.a.s x 1/j","1 c.a.s x 2/j","1 c.a.s x 3/j","1 c.a.m x 2/j"]

# ═══════════════════════════════════════════════════════════════
# UTILITAIRES
# ═══════════════════════════════════════════════════════════════
def _hash(pw, salt=None):
    if salt is None: salt = secrets.token_hex(16)
    return hashlib.sha256((salt + pw).encode()).hexdigest(), salt

def _verify(pw, h, s): return _hash(pw, s)[0] == h

def _normalize_str(s):
    s = s.lower().strip()
    s = unicodedata.normalize("NFD", s)
    return "".join(c for c in s if unicodedata.category(c) != "Mn")

def normaliser_diagnostic(texte):
    if not texte or not texte.strip(): return texte
    key = _normalize_str(texte)
    for k, v in DIAG_NORMALIZE.items():
        if _normalize_str(k) == key: return v
    for k, v in DIAG_NORMALIZE.items():
        if _normalize_str(k) in key or key in _normalize_str(k): return v
    best_score, best_val = 0, texte
    for k, v in DIAG_NORMALIZE.items():
        score = SequenceMatcher(None, key, _normalize_str(k)).ratio()
        if score > best_score: best_score, best_val = score, v
    if best_score >= 0.82: return best_val
    return texte.strip().capitalize()

def equipe_de(login):
    for eq, cfg in EQUIPES.items():
        if login in cfg["membres"]: return eq
    return ""

def completude_dossier(p):
    champs = ["nom","prenom","ip","age","diagnostic","mutuelle","ville","date_prog","medecin","telephone","cin"]
    remplis = sum(1 for k in champs if str(p.get(k,"")).strip())
    base = round(100 * remplis / len(champs))
    if p.get("consultations"): base = min(100, base + 5)
    return base

def parse_date(ds):
    if not ds: return None
    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y"):
        try: return datetime.datetime.strptime(ds.strip(), fmt)
        except: pass
    return None

def est_alerte(ds):
    d = parse_date(ds)
    if d is None: return False
    delta = (d - datetime.datetime.now()).days
    return 0 <= delta <= ALERT_JOURS

def est_attente(ds):
    if not ds or not ds.strip(): return True
    d = parse_date(ds)
    if d is None: return True
    return d.date() >= date.today()

def est_ancien(ds):
    d = parse_date(ds)
    return d is not None and d.date() < date.today()

def est_semaine(ds):
    d = parse_date(ds)
    if d is None: return False
    auj   = date.today()
    lundi = auj - timedelta(days=auj.weekday())
    return lundi <= d.date() <= lundi + timedelta(days=6)

def nouveau_patient(ip, nom, prenom, age="", equipe=""):
    return {
        "ip": ip, "nom": nom, "prenom": prenom, "age": age,
        "diagnostic": "", "mutuelle": "", "ville": "",
        "date_prog": "", "medecin": "", "prof": "NON",
        "materiel": "NON PRÉCISÉ", "telephone": "", "cin": "",
        "type_patient": TYPE_HOSPIT, "equipe": equipe,
        "date_creation": datetime.datetime.now().isoformat(timespec="seconds"),
        "consultations": [], "historique": []
    }

# ═══════════════════════════════════════════════════════════════
# STOCKAGE SESSION STATE (base patients + users en mémoire)
# ═══════════════════════════════════════════════════════════════
def _init_state():
    # ── Chargement Drive une seule fois par session ──────────────
    if "drive_loaded" not in st.session_state:
        st.session_state.drive_loaded = True
        snap = drive_load_all()
        if snap:
            _apply_snapshot(snap)

    # ── Valeurs par défaut si Drive vide ou inaccessible ─────────
    if "users" not in st.session_state:
        users = {}
        for login, pw, role, nom in COMPTES_DEFAUT:
            h, s = _hash(pw)
            users[login] = {"hash": h, "salt": s, "role": role, "nom_complet": nom}
        st.session_state.users = users

    if "db" not in st.session_state:
        st.session_state.db = {}           # ip → patient dict

    if "logged_in" not in st.session_state:
        st.session_state.logged_in    = False
        st.session_state.current_user = None

    if "page" not in st.session_state:
        st.session_state.page = "patients"

    if "ttt_fiches" not in st.session_state:
        st.session_state.ttt_fiches = []   # mémoire fiches traitement

    if "log" not in st.session_state:
        st.session_state.log = []

    if "nav" not in st.session_state:
        st.session_state.nav = "tous"

    if "selected_ip" not in st.session_state:
        st.session_state.selected_ip = None

    if "edit_ip" not in st.session_state:
        st.session_state.edit_ip = None

    if "_drive_save_counter" not in st.session_state:
        st.session_state._drive_save_counter = 0

_init_state()

def log_action(user, action, detail=""):
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user, "action": action, "detail": detail
    }
    st.session_state.log.append(entry)
    if len(st.session_state.log) > 500:
        st.session_state.log = st.session_state.log[-500:]

def get_db():
    return st.session_state.db

def save_patient(patient):
    ip = patient["ip"]
    st.session_state.db[ip] = patient
    drive_save_patients()  # Sauvegarde immédiate dans le bon fichier d'équipe

def current_user():  return st.session_state.current_user
def current_nom():
    u = st.session_state.users.get(current_user(), {})
    return u.get("nom_complet", current_user())
def current_role():
    u = st.session_state.users.get(current_user(), {})
    return u.get("role", ROLE_USER)
def current_equipe(): return equipe_de(current_user())
def eq_membres():
    eq = current_equipe()
    if eq: return EQUIPES[eq]["membres"]
    return list(st.session_state.users.keys())
def eq_medecins():
    return [st.session_state.users[l].get("nom_complet", l)
            for l in eq_membres() if l in st.session_state.users]

# ═══════════════════════════════════════════════════════════════
# PAGE CONNEXION
# ═══════════════════════════════════════════════════════════════
def page_login():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("""
        <div style="text-align:center; padding:40px 0 20px 0;">
            <div style="font-size:3.5rem;">🏥</div>
            <h1 style="color:#1565C0; margin:8px 0 4px 0;">SURGIX</h1>
            <p style="color:#546E7A; font-size:0.9rem;">CHU Mohammed VI · Oujda</p>
            <p style="color:#90A4AE; font-size:0.75rem;">v1.12 Web GoldenEye · Service Ophtalmologie</p>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form"):
            login = st.text_input("Identifiant", placeholder="Login...")
            pw    = st.text_input("Mot de passe", type="password", placeholder="••••••••")
            submitted = st.form_submit_button("CONNEXION", use_container_width=True)

        if submitted:
            u = st.session_state.users.get(login.strip())
            if u and _verify(pw, u["hash"], u["salt"]):
                st.session_state.logged_in    = True
                st.session_state.current_user = login.strip()
                log_action(login, "CONNEXION", "OK")
                st.rerun()
            else:
                log_action(login, "ÉCHEC CONNEXION", "")
                st.error("Identifiant ou mot de passe incorrect.")

# ═══════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════
def render_sidebar():
    with st.sidebar:
        eq   = current_equipe()
        col  = EQUIPES.get(eq, {}).get("couleur", "#1565C0")
        st.markdown(f"""
        <div style="padding:16px 0 8px 0; text-align:center;">
            <div style="font-size:2rem;">🏥</div>
            <div style="color:#FFFFFF; font-weight:700; font-size:1.1rem;">SURGIX</div>
            <div style="color:#B0C4DE; font-size:0.72rem;">CHU Mohammed VI · Oujda</div>
            <div style="margin-top:8px; background:{col}; height:3px; border-radius:2px;"></div>
            <div style="color:#ECEFF1; font-size:0.8rem; margin-top:10px; font-weight:600;">
                👤 {current_nom()}
            </div>
            <div style="color:#90A4AE; font-size:0.72rem;">
                {'Équipe ' + eq if eq else 'Administration'}
                &nbsp;·&nbsp;
                {'🔑 Admin' if current_role()==ROLE_ADMIN else ''}
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='color:#4A6FA5;font-size:0.72rem;padding:8px 16px 4px;font-weight:700;'>NAVIGATION</div>", unsafe_allow_html=True)
        nav_items = [
            ("🏠 Tous les patients", "tous"),
            ("⏳ En attente",        "attente"),
            ("📅 Cette semaine",     "semaine"),
            ("🗂 Anciens patients",  "anciens"),
            ("🏥 Hospitalisés",      "hospit"),
            ("⚔ Patients Bloc",     "bloc"),
        ]
        for label, key in nav_items:
            if st.button(label, key=f"nav_{key}", use_container_width=True):
                st.session_state.nav  = key
                st.session_state.page = "patients"
                st.rerun()

        st.markdown("<div style='border-top:1px solid #2A4F7F;margin:8px 0;'></div>", unsafe_allow_html=True)
        st.markdown("<div style='color:#4A6FA5;font-size:0.72rem;padding:4px 16px;font-weight:700;'>OUTILS</div>", unsafe_allow_html=True)

        if st.button("📊 Statistiques",     use_container_width=True): st.session_state.page = "stats";      st.rerun()
        if st.button("💊 Fiche traitement", use_container_width=True): st.session_state.page = "fiche_ttt";  st.rerun()
        if st.button("📅 Planning semaine", use_container_width=True): st.session_state.page = "planning";   st.rerun()

        if current_role() == ROLE_ADMIN or current_user() == SUPER_ADMIN:
            st.markdown("<div style='border-top:1px solid #2A4F7F;margin:8px 0;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='color:#4A6FA5;font-size:0.72rem;padding:4px 16px;font-weight:700;'>ADMIN</div>", unsafe_allow_html=True)
            if st.button("👥 Utilisateurs", use_container_width=True): st.session_state.page = "users";   st.rerun()
            if st.button("📝 Journal",      use_container_width=True): st.session_state.page = "journal"; st.rerun()

        st.markdown("<div style='border-top:1px solid #2A4F7F;margin:8px 0;'></div>", unsafe_allow_html=True)
        if st.button("🔒 Déconnexion", use_container_width=True):
            log_action(current_user(), "DÉCONNEXION", "")
            st.session_state.logged_in    = False
            st.session_state.current_user = None
            st.rerun()

# ═══════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════
def render_header(subtitle=""):
    db   = get_db()
    nb   = len(db)
    al   = sum(1 for p in db.values() if est_alerte(p.get("date_prog","")))
    eq   = current_equipe()
    col  = EQUIPES.get(eq, {}).get("couleur", "#1565C0")
    alerte_badge = f'<span class="badge badge-red">⚠ {al} alertes</span>' if al else ''
    equipe_label = f'Équipe {eq}' if eq else 'Admin'
    st.markdown(f"""
    <div class="surgix-header">
        <div style="font-size:2rem;">🏥</div>
        <div>
            <h1>SURGIX&nbsp;&nbsp;<span style='font-size:0.9rem;color:#90CAF9;'>v1.12 Web GoldenEye</span></h1>
            <p>{subtitle or 'CHU Mohammed VI · Service Ophtalmologie · Oujda'}</p>
        </div>
        <div style="margin-left:auto; text-align:right;">
            <span class="badge badge-blue">{nb} patients</span>
            {alerte_badge}
            <span class="badge" style="background:{col}20;color:{col};">
                {equipe_label}
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# PAGE PATIENTS — liste
# ═══════════════════════════════════════════════════════════════
def filtrer_patients(nav, search="", filtre="tous"):
    db = get_db()
    result = []
    for ip, p in db.items():
        ds     = p.get("date_prog", "")
        type_p = p.get("type_patient", TYPE_HOSPIT)
        if nav == "attente" and not est_attente(ds):    continue
        if nav == "anciens" and not est_ancien(ds):     continue
        if nav == "semaine" and not est_semaine(ds):    continue
        if nav == "hospit"  and type_p != TYPE_HOSPIT:  continue
        if nav == "bloc"    and type_p != TYPE_BLOC:    continue
        if filtre == "moi"   and p.get("medecin","") != current_nom():  continue
        if filtre == "prof"  and p.get("prof","NON").upper() != "OUI":  continue
        if search:
            s = search.lower()
            if not any(s in str(v).lower() for v in list(p.values())[:14]): continue
        result.append((ip, p))
    return result

def page_patients():
    render_header()
    nav   = st.session_state.nav
    nav_labels = {"tous":"Tous les patients","attente":"En attente","semaine":"Cette semaine",
                  "anciens":"Anciens patients","hospit":"Hospitalisés","bloc":"Patients Bloc"}

    st.markdown(f"### {nav_labels.get(nav,'Patients')}")

    # ── Barre d'outils ─────────────────────────────────────────
    c1, c2, c3, c4 = st.columns([3, 2, 1.5, 1.5])
    with c1:
        search = st.text_input("🔍 Recherche", placeholder="Nom, IP, diagnostic...", label_visibility="collapsed")
    with c2:
        filtre = st.selectbox("Filtre", ["tous","moi","prof","hospit","bloc"],
                              format_func=lambda x: {"tous":"Tous","moi":"Mes patients",
                                                      "prof":"Prof seulement","hospit":"Hospitalisés","bloc":"Bloc"}[x],
                              label_visibility="collapsed")
    with c3:
        if st.button("➕ Nouveau patient", use_container_width=True):
            st.session_state.page = "add_patient"; st.rerun()
    with c4:
        if st.button("🔄 Actualiser", use_container_width=True):
            st.rerun()

    rows = filtrer_patients(nav, search, filtre)
    nb   = len(rows)
    al   = sum(1 for _, p in rows if est_alerte(p.get("date_prog","")))

    st.markdown(f"""
    <div style="margin:8px 0; color:#546E7A; font-size:0.85rem;">
        <b>{nb}</b> patient(s) affiché(s)
        {'&nbsp;·&nbsp;<span style="color:#C62828;font-weight:700;">⚠ ' + str(al) + ' alerte(s)</span>' if al else ''}
    </div>
    """, unsafe_allow_html=True)

    if not rows:
        st.info("Aucun patient trouvé dans cette vue.")
        return

    # ── Tableau ─────────────────────────────────────────────────
    for ip, p in rows:
        ds      = p.get("date_prog","")
        type_p  = p.get("type_patient", TYPE_HOSPIT)
        is_prof = p.get("prof","NON").upper() == "OUI"
        is_al   = est_alerte(ds)
        comp    = completude_dossier(p)
        nb_c    = len(p.get("consultations",[]))

        # couleur de ligne
        if is_al:
            bg = "#FFF0F0"
        elif type_p == TYPE_BLOC:
            bg = "#FFF8E1"
        elif is_prof:
            bg = "#E8F5E9"
        else:
            bg = "#FFFFFF"

        with st.container():
            st.markdown(f'<div style="background:{bg};border-radius:6px;padding:10px 14px;margin-bottom:6px;border:1px solid #E2E8F0;">', unsafe_allow_html=True)
            cols = st.columns([3, 2, 2, 2, 1.5, 1, 1.5, 1.2])
            with cols[0]:
                icons = ("🩺 " if nb_c > 0 else "") + ("⚠ " if comp < 50 else "")
                st.markdown(f"**{icons}{p.get('prenom','')} {p.get('nom','')}**  \n`IP: {ip}`", unsafe_allow_html=False)
            with cols[1]:
                st.markdown(f"🔬 {p.get('diagnostic','—')}")
            with cols[2]:
                st.markdown(f"📅 {p.get('date_prog','—')}")
            with cols[3]:
                st.markdown(f"👨‍⚕️ {p.get('medecin','—')}")
            with cols[4]:
                badge_type = "badge-orange" if type_p == TYPE_BLOC else "badge-blue"
                badge_icon = "⚔" if type_p == TYPE_BLOC else "🏥"
                st.markdown(f'<span class="badge {badge_type}">{badge_icon} {type_p}</span>', unsafe_allow_html=True)
            with cols[5]:
                bar_col = "#2E7D32" if comp >= 80 else ("#E65100" if comp >= 50 else "#C62828")
                st.markdown(f'<div style="font-size:0.7rem;color:{bar_col};font-weight:700;">{comp}%</div>', unsafe_allow_html=True)
            with cols[6]:
                if st.button("📋 Dossier", key=f"dos_{ip}", use_container_width=True):
                    st.session_state.selected_ip = ip
                    st.session_state.page = "dossier"; st.rerun()
            with cols[7]:
                if st.button("✏️ Modifier", key=f"edit_{ip}", use_container_width=True):
                    st.session_state.edit_ip = ip
                    st.session_state.page = "edit_patient"; st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# PAGE AJOUTER PATIENT
# ═══════════════════════════════════════════════════════════════
def page_add_patient():
    render_header("Nouveau patient")
    st.markdown("### ➕ Ajouter un patient")

    if st.button("← Retour à la liste"):
        st.session_state.page = "patients"; st.rerun()

    with st.form("form_add"):
        st.markdown("#### 👤 Identité")
        c1, c2, c3 = st.columns(3)
        with c1: nom    = st.text_input("Nom *")
        with c2: prenom = st.text_input("Prénom *")
        with c3: ip     = st.text_input("IP (optionnel)", placeholder="Laissez vide si inconnu")

        c4, c5, c6 = st.columns(3)
        with c4: age      = st.text_input("Âge")
        with c5: cin      = st.text_input("CIN")
        with c6: tel      = st.text_input("Téléphone")

        st.markdown("#### 🔬 Informations cliniques")
        c7, c8 = st.columns(2)
        with c7:
            diag_input  = st.text_input("Diagnostic", placeholder="Commencez à taper...")
            diag_sugg   = []
            if diag_input and len(diag_input) >= 2:
                key = _normalize_str(diag_input)
                diag_sugg = [d for d in DIAG_SUGGESTIONS if key in _normalize_str(d)][:6]
            if diag_sugg:
                diag_sel = st.selectbox("Suggestion", [""] + diag_sugg, label_visibility="collapsed")
                if diag_sel: diag_input = diag_sel
        with c8:
            mutuelle = st.text_input("Mutuelle")

        c9, c10 = st.columns(2)
        with c9: ville = st.text_input("Ville")
        with c10: pass

        st.markdown("#### 📅 Programmation")
        c11, c12, c13 = st.columns(3)
        with c11: date_prog = st.text_input("Date programmée (JJ/MM/AAAA)", placeholder="01/06/2025")
        with c12:
            medecins_equipe = eq_medecins()
            medecin = st.selectbox("Médecin opérateur", medecins_equipe) if medecins_equipe else st.text_input("Médecin opérateur")
        with c13:
            prof       = st.radio("Consultation Prof ?", ["NON", "OUI"], horizontal=True)
            type_pt    = st.radio("Type patient", [TYPE_HOSPIT, TYPE_BLOC], horizontal=True)

        materiel = st.radio("Matériel prescrit", ["NON PRÉCISÉ", "OUI", "NON"], horizontal=True)
        mat_detail = ""
        if materiel == "OUI":
            mat_detail = st.text_input("Détail du matériel")

        submitted = st.form_submit_button("＋ Ajouter le patient", use_container_width=True)

    if submitted:
        nom    = nom.strip()
        prenom = prenom.strip()
        ip     = ip.strip()

        if not nom or not prenom:
            st.error("Nom et Prénom sont obligatoires.")
            return

        db = get_db()
        if ip and ip in db:
            st.error(f"IP « {ip} » déjà utilisée.")
            return

        if not ip:
            import random, string
            existing = set(db.keys())
            while True:
                ip = "SANS-IP-" + "".join(random.choices(string.digits, k=6))
                if ip not in existing: break

        diag_norm = normaliser_diagnostic(diag_input.strip())
        mat_val   = (f"OUI — {mat_detail}".strip() if materiel == "OUI" and mat_detail
                     else materiel)

        p = nouveau_patient(ip, nom, prenom, age, current_equipe())
        p.update({
            "diagnostic": diag_norm, "mutuelle": mutuelle, "ville": ville,
            "date_prog": date_prog, "medecin": medecin, "prof": prof,
            "materiel": mat_val, "telephone": tel, "cin": cin,
            "type_patient": type_pt,
        })
        save_patient(p)
        log_action(current_user(), "AJOUT PATIENT", f"{prenom} {nom} — IP {ip}")
        st.success(f"✅ Patient {prenom} {nom} ajouté (IP: {ip})")
        st.session_state.page = "patients"
        st.rerun()

# ═══════════════════════════════════════════════════════════════
# PAGE MODIFIER PATIENT
# ═══════════════════════════════════════════════════════════════
def page_edit_patient():
    ip = st.session_state.edit_ip
    db = get_db()
    p  = db.get(ip, {})
    if not p:
        st.error("Patient introuvable."); return

    render_header(f"Modifier — {p.get('prenom','')} {p.get('nom','')}")
    st.markdown(f"### ✏️ Modifier — {p.get('prenom','')} {p.get('nom','')}  `IP: {ip}`")

    if st.button("← Retour à la liste"):
        st.session_state.page = "patients"; st.rerun()

    with st.form("form_edit"):
        c1, c2, c3 = st.columns(3)
        with c1: nom    = st.text_input("Nom *",    value=p.get("nom",""))
        with c2: prenom = st.text_input("Prénom *", value=p.get("prenom",""))
        with c3: age    = st.text_input("Âge",      value=p.get("age",""))

        c4, c5, c6 = st.columns(3)
        with c4: cin = st.text_input("CIN",       value=p.get("cin",""))
        with c5: tel = st.text_input("Téléphone", value=p.get("telephone",""))
        with c6: ville = st.text_input("Ville",   value=p.get("ville",""))

        st.markdown("#### 🔬 Clinique")
        c7, c8 = st.columns(2)
        with c7: diag     = st.text_input("Diagnostic",  value=p.get("diagnostic",""))
        with c8: mutuelle = st.text_input("Mutuelle",    value=p.get("mutuelle",""))

        st.markdown("#### 📅 Programmation")
        c9, c10, c11 = st.columns(3)
        with c9:  date_prog = st.text_input("Date programmée", value=p.get("date_prog",""))
        with c10:
            medecins_equipe = eq_medecins()
            cur_med = p.get("medecin","")
            idx = medecins_equipe.index(cur_med) if cur_med in medecins_equipe else 0
            medecin = st.selectbox("Médecin", medecins_equipe, index=idx)
        with c11:
            prof    = st.radio("Prof ?", ["NON","OUI"], horizontal=True,
                               index=0 if p.get("prof","NON")=="NON" else 1)
            type_pt = st.radio("Type", [TYPE_HOSPIT, TYPE_BLOC], horizontal=True,
                               index=0 if p.get("type_patient",TYPE_HOSPIT)==TYPE_HOSPIT else 1)

        materiel = st.text_input("Matériel", value=p.get("materiel","NON PRÉCISÉ"))
        submitted = st.form_submit_button("💾 Enregistrer", use_container_width=True)

    if submitted:
        p.update({
            "nom": nom.strip(), "prenom": prenom.strip(), "age": age.strip(),
            "cin": cin.strip(), "telephone": tel.strip(), "ville": ville.strip(),
            "diagnostic": normaliser_diagnostic(diag.strip()),
            "mutuelle": mutuelle.strip(), "date_prog": date_prog.strip(),
            "medecin": medecin, "prof": prof, "type_patient": type_pt,
            "materiel": materiel.strip(),
        })
        save_patient(p)
        log_action(current_user(), "MODIFICATION", f"{prenom} {nom} IP {ip}")
        st.success("✅ Patient mis à jour.")
        st.session_state.page = "patients"; st.rerun()

    # Suppression (admin only)
    if current_role() == ROLE_ADMIN or current_user() == SUPER_ADMIN:
        st.markdown("---")
        st.markdown("#### 🗑 Zone dangereuse")
        if st.checkbox("Je veux supprimer ce patient"):
            if st.button("🗑 Supprimer définitivement", type="primary"):
                del st.session_state.db[ip]
                drive_save_patients()
                log_action(current_user(), "SUPPRESSION", f"IP {ip}")
                st.session_state.page = "patients"; st.rerun()

# ═══════════════════════════════════════════════════════════════
# PAGE DOSSIER CLINIQUE
# ═══════════════════════════════════════════════════════════════
def page_dossier():
    ip = st.session_state.selected_ip
    db = get_db()
    p  = db.get(ip, {})
    if not p:
        st.error("Patient introuvable."); return

    nom_aff = f"{p.get('prenom','')} {p.get('nom','')}".strip() or "Patient"
    comp    = completude_dossier(p)
    eq      = p.get("equipe","")
    col     = EQUIPES.get(eq, {}).get("couleur", "#1565C0")

    render_header(f"Dossier clinique — {nom_aff}")
    st.markdown(f"### 🩺 Dossier — {nom_aff}")

    c_back, c_edit = st.columns([8, 2])
    with c_back:
        if st.button("← Retour à la liste"): st.session_state.page = "patients"; st.rerun()
    with c_edit:
        if st.button("✏️ Modifier patient"):
            st.session_state.edit_ip = ip; st.session_state.page = "edit_patient"; st.rerun()

    # Info résumée
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""<div class="stat-card">
            <div class="num" style="font-size:1.4rem;">{comp}%</div>
            <div class="lbl">Complétude</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div class="stat-card">
            <div class="num" style="font-size:1.4rem;">{len(p.get('consultations',[]))}</div>
            <div class="lbl">Consultations</div></div>""", unsafe_allow_html=True)
    with c3:
        tp = p.get("type_patient", TYPE_HOSPIT)
        st.markdown(f"""<div class="stat-card">
            <div class="num" style="font-size:1.1rem;">{'⚔' if tp==TYPE_BLOC else '🏥'}</div>
            <div class="lbl">{tp}</div></div>""", unsafe_allow_html=True)
    with c4:
        al_str = "⚠ Alerte" if est_alerte(p.get("date_prog","")) else "✅ OK"
        al_col = "#C62828" if est_alerte(p.get("date_prog","")) else "#2E7D32"
        st.markdown(f"""<div class="stat-card">
            <div class="num" style="font-size:1.1rem;color:{al_col};">{al_str}</div>
            <div class="lbl">Date prog.</div></div>""", unsafe_allow_html=True)

    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["✏️ Nouvelle consultation", "🗂 Historique", "ℹ️ Informations"])

    # ── Onglet nouvelle consultation ──
    with tab1:
        st.markdown("#### Ajouter une consultation")
        with st.form("form_consult"):
            c_date, c_med = st.columns(2)
            with c_date:
                date_c = st.text_input("Date", value=datetime.datetime.now().strftime("%d/%m/%Y"))
            with c_med:
                med_c = st.text_input("Médecin", value=current_nom())

            motif = st.text_area("Motif / Plainte", height=80)
            examen = st.text_area("Examen clinique (AV, TO, fond d'œil...)", height=100)
            conclusion = st.text_area("Conclusion / Plan", height=80)

            sub = st.form_submit_button("💾 Enregistrer la consultation")

        if sub:
            if not motif and not examen and not conclusion:
                st.warning("Remplissez au moins un champ.")
            else:
                consult = {
                    "date": date_c, "medecin": med_c,
                    "motif": motif, "examen": examen, "conclusion": conclusion,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                if "consultations" not in p: p["consultations"] = []
                p["consultations"].insert(0, consult)
                save_patient(p)
                log_action(current_user(), "CONSULTATION", f"IP {ip}")
                st.success("✅ Consultation enregistrée.")
                st.rerun()

    # ── Onglet historique ──
    with tab2:
        consultations = p.get("consultations", [])
        if not consultations:
            st.info("Aucune consultation enregistrée.")
        else:
            for i, c in enumerate(consultations):
                with st.expander(f"📋 {c.get('date','?')} — {c.get('medecin','?')} ({i+1}/{len(consultations)})"):
                    if c.get("motif"):      st.markdown(f"**Motif :** {c['motif']}")
                    if c.get("examen"):     st.markdown(f"**Examen :** {c['examen']}")
                    if c.get("conclusion"): st.markdown(f"**Conclusion :** {c['conclusion']}")

    # ── Onglet infos ──
    with tab3:
        st.markdown("#### Informations du patient")
        col_pairs = [
            ("Nom", p.get("nom","")),         ("Prénom", p.get("prenom","")),
            ("IP", p.get("ip","")),           ("Âge", p.get("age","")),
            ("Diagnostic", p.get("diagnostic","")), ("Mutuelle", p.get("mutuelle","")),
            ("Ville", p.get("ville","")),     ("CIN", p.get("cin","")),
            ("Téléphone", p.get("telephone","")), ("Médecin", p.get("medecin","")),
            ("Date prog.", p.get("date_prog","")), ("Type patient", p.get("type_patient","")),
            ("Prof", p.get("prof","")),       ("Matériel", p.get("materiel","")),
        ]
        c1, c2 = st.columns(2)
        for i, (lbl, val) in enumerate(col_pairs):
            with (c1 if i % 2 == 0 else c2):
                st.markdown(f"**{lbl}:** {val or '—'}")

# ═══════════════════════════════════════════════════════════════
# PAGE STATISTIQUES
# ═══════════════════════════════════════════════════════════════
def page_stats():
    render_header("Statistiques")
    st.markdown("### 📊 Tableau de bord")

    db  = get_db()
    pts = list(db.values())
    nb  = len(pts)

    if nb == 0:
        st.info("Aucun patient enregistré."); return

    # KPIs
    c1, c2, c3, c4, c5 = st.columns(5)
    metrics = [
        (str(nb),                                         "Total patients",   c1),
        (str(sum(1 for p in pts if est_attente(p.get("date_prog","")))), "En attente", c2),
        (str(sum(1 for p in pts if est_semaine(p.get("date_prog","")))), "Cette semaine", c3),
        (str(sum(1 for p in pts if p.get("type_patient")==TYPE_HOSPIT)), "Hospitalisés", c4),
        (str(sum(1 for p in pts if est_alerte(p.get("date_prog","")))),  "Alertes",      c5),
    ]
    for val, lbl, col in metrics:
        with col:
            st.markdown(f"""<div class="stat-card">
                <div class="num">{val}</div>
                <div class="lbl">{lbl}</div></div>""", unsafe_allow_html=True)

    st.markdown("---")
    c_left, c_right = st.columns(2)

    # Diagnostics
    with c_left:
        st.markdown("#### 🔬 Top 10 diagnostics")
        from collections import Counter
        diags = Counter(p.get("diagnostic","—") or "—" for p in pts)
        top10 = diags.most_common(10)
        for d, n in top10:
            pct = round(100 * n / nb)
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                <div style="flex:1;font-size:0.85rem;">{d}</div>
                <div style="width:120px;background:#E3F2FD;border-radius:4px;height:10px;">
                    <div style="width:{pct}%;background:#1565C0;border-radius:4px;height:10px;"></div>
                </div>
                <div style="font-size:0.8rem;color:#546E7A;width:40px;text-align:right;">{n}</div>
            </div>
            """, unsafe_allow_html=True)

    # Répartition par équipe / médecin
    with c_right:
        st.markdown("#### 👨‍⚕️ Répartition par médecin")
        meds = Counter(p.get("medecin","—") or "—" for p in pts)
        top_med = meds.most_common(10)
        for m, n in top_med:
            pct = round(100 * n / nb)
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
                <div style="flex:1;font-size:0.85rem;">{m}</div>
                <div style="width:120px;background:#E0F2F1;border-radius:4px;height:10px;">
                    <div style="width:{pct}%;background:#00695C;border-radius:4px;height:10px;"></div>
                </div>
                <div style="font-size:0.8rem;color:#546E7A;width:40px;text-align:right;">{n}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 📋 Répartition par type patient")
    hospit = sum(1 for p in pts if p.get("type_patient")==TYPE_HOSPIT)
    bloc   = sum(1 for p in pts if p.get("type_patient")==TYPE_BLOC)
    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown(f"""<div class="stat-card card-accent">
            <div class="num">{hospit}</div>
            <div class="lbl">🏥 Hospitalisés</div></div>""", unsafe_allow_html=True)
    with cc2:
        st.markdown(f"""<div class="stat-card card-warn">
            <div class="num">{bloc}</div>
            <div class="lbl">⚔ Bloc</div></div>""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# PAGE PLANNING SEMAINE
# ═══════════════════════════════════════════════════════════════
def page_planning():
    render_header("Planning semaine")
    st.markdown("### 📅 Planning de la semaine")

    auj   = date.today()
    lundi = auj - timedelta(days=auj.weekday())
    jours = ["Lun","Mar","Mer","Jeu","Ven","Sam","Dim"]
    semaine = [lundi + timedelta(days=i) for i in range(7)]

    db  = get_db()
    pts = list(db.values())

    cols = st.columns(7)
    for i, (j, d) in enumerate(zip(jours, semaine)):
        patients_j = [p for p in pts if parse_date(p.get("date_prog","")) and
                      parse_date(p.get("date_prog","")).date() == d]
        is_today = d == auj
        bg = "#E3F2FD" if is_today else ("#FFF8E1" if i >= 5 else "#F8FAFC")
        border = "2px solid #1565C0" if is_today else "1px solid #E2E8F0"
        with cols[i]:
            st.markdown(f"""
            <div style="background:{bg};border:{border};border-radius:8px;padding:10px;min-height:160px;">
                <div style="font-weight:700;font-size:0.85rem;color:{'#1565C0' if is_today else '#546E7A'};">
                    {j}<br>{d.strftime('%d/%m')}
                </div>
                <div style="margin-top:8px;font-size:0.75rem;">
                    {''.join(f'<div style="background:#fff;border-radius:4px;padding:3px 5px;margin-bottom:4px;border-left:3px solid #1565C0;">'
                              f'{p.get("prenom","")[0]}. {p.get("nom","")}'
                              f'</div>' for p in patients_j[:6])}
                    {'<div style="color:#90A4AE;">+' + str(len(patients_j)-6) + ' autres</div>' if len(patients_j)>6 else ''}
                    {'<div style="color:#90A4AE;font-size:0.7rem;">—</div>' if not patients_j else ''}
                </div>
            </div>
            """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# PAGE FICHE DE TRAITEMENT
# ═══════════════════════════════════════════════════════════════
def page_fiche_ttt():
    render_header("Fiche de traitement")
    st.markdown("### 💊 Fiche de surveillance et de traitement")

    # Mémoire fiches récentes
    fiches_rec = [f for f in st.session_state.ttt_fiches
                  if (datetime.datetime.now().timestamp() - f.get("timestamp",0)) < 14*86400]
    st.session_state.ttt_fiches = fiches_rec

    # Charger depuis mémoire
    if fiches_rec:
        with st.expander(f"🕐 Fiches récentes ({len(fiches_rec)})"):
            for fi in fiches_rec:
                nom_p = f"{fi.get('nom','')} {fi.get('prenom','')}".strip() or "—"
                nb_col = len([c for c in fi.get("collyres",[]) if c.get("nom")])
                nb_iv  = len([c for c in fi.get("iv_peros",[]) if c.get("nom")])
                c_nom, c_btn = st.columns([4,1])
                with c_nom:
                    st.markdown(f"**{nom_p}** `IP:{fi.get('ip','—')}`  ·  {fi.get('date_str','?')}  ·  {nb_col} collyre(s) · {nb_iv} IV/per os")
                with c_btn:
                    if st.button("Charger", key=f"load_{fi.get('timestamp',0)}"):
                        st.session_state["_ttt_load"] = fi; st.rerun()

    load = st.session_state.pop("_ttt_load", None)

    with st.form("form_ttt", clear_on_submit=False):
        st.markdown("#### Informations patient")
        c1, c2, c3, c4 = st.columns(4)
        with c1: nom_t    = st.text_input("Nom",      value=load.get("nom","")    if load else "")
        with c2: prenom_t = st.text_input("Prénom",   value=load.get("prenom","") if load else "")
        with c3: ip_t     = st.text_input("IP",       value=load.get("ip","")     if load else "")
        with c4: date_h   = st.text_input("Date hosp.",value=load.get("date_h", datetime.datetime.now().strftime("%d/%m/%Y")) if load else datetime.datetime.now().strftime("%d/%m/%Y"))

        diag_t = st.text_input("Diagnostic",        value=load.get("diag","") if load else "")
        med_t  = st.text_input("Médecin traitant",  value=load.get("med", current_nom()) if load else current_nom())

        st.markdown("#### Surveillance")
        c5, c6 = st.columns(2)
        with c5: glyc = st.radio("Glycémie",       ["NON","OUI"], horizontal=True,
                                  index=0 if not load else (1 if load.get("glyc")=="OUI" else 0))
        with c6: ta   = st.radio("Tension artérielle",["NON","OUI"], horizontal=True,
                                  index=0 if not load else (1 if load.get("ta")=="OUI" else 0))

        st.markdown("#### Calendrier des prescriptions")
        c7, c8 = st.columns(2)
        with c7: debut_t = st.text_input("Date de début (JJ/MM/AAAA)",
                                          value=load.get("debut", datetime.datetime.now().strftime("%d/%m/%Y")) if load else datetime.datetime.now().strftime("%d/%m/%Y"))
        with c8: nb_j    = st.number_input("Nombre de jours", min_value=1, max_value=30,
                                            value=load.get("nb_j",8) if load else 8)

        st.markdown("#### 💧 Collyres / Pommades")
        nb_col = st.number_input("Nombre de collyres/pommades", min_value=0, max_value=10, value=2)
        collyres = []
        prev_cols = (load.get("collyres",[]) if load else [])
        for i in range(int(nb_col)):
            prev = prev_cols[i] if i < len(prev_cols) else {}
            cc1, cc2, cc3, cc4 = st.columns([1.5, 3, 2, 1.5])
            with cc1:
                type_col = st.selectbox(f"Type#{i+1}", ["Collyre","Pommade"],
                                         index=0 if prev.get("type_col","Collyre")=="Collyre" else 1,
                                         key=f"ttype_{i}")
            with cc2:
                nom_col = st.text_input(f"Médicament#{i+1}", value=prev.get("nom",""), key=f"tnom_{i}")
            with cc3:
                poses = POSOLOGIES_COLLYRE if type_col=="Collyre" else POSOLOGIES_POMMADE
                prev_pos = prev.get("posologie", poses[3] if type_col=="Collyre" else poses[0])
                pos_idx = poses.index(prev_pos) if prev_pos in poses else 0
                posologie = st.selectbox(f"Posologie#{i+1}", poses, index=pos_idx, key=f"tpos_{i}")
            with cc4:
                oeil = st.selectbox(f"Œil#{i+1}", ["ODG","OD","OG"],
                                     index=["ODG","OD","OG"].index(prev.get("oeil","ODG")),
                                     key=f"toeil_{i}")
            if nom_col.strip():
                collyres.append({"type_col": type_col, "nom": nom_col.strip(),
                                  "posologie": posologie, "oeil": oeil})

        st.markdown("#### 💉 IV / Per os / Sirop")
        nb_iv = st.number_input("Nombre de traitements IV/Per os/Sirop", min_value=0, max_value=10, value=2)
        iv_peros = []
        prev_iv = (load.get("iv_peros",[]) if load else [])
        for i in range(int(nb_iv)):
            prev = prev_iv[i] if i < len(prev_iv) else {}
            ic1, ic2, ic3 = st.columns([1.5, 3, 2])
            with ic1:
                type_iv_opts = ["Per os","IV","Sirop"]
                type_iv = st.selectbox(f"TypeIV#{i+1}", type_iv_opts,
                                        index=type_iv_opts.index(prev.get("type_iv","Per os")) if prev.get("type_iv","Per os") in type_iv_opts else 0,
                                        key=f"ivtype_{i}")
            with ic2:
                nom_iv = st.text_input(f"Médicament IV#{i+1}", value=prev.get("nom",""), key=f"ivnom_{i}")
            with ic3:
                poses_iv = {"Per os": POSOLOGIES_PEROS, "IV": POSOLOGIES_IV, "Sirop": POSOLOGIES_SIROP}
                poses = poses_iv.get(type_iv, POSOLOGIES_PEROS)
                prev_p = prev.get("posologie", poses[0])
                pos_idx = poses.index(prev_p) if prev_p in poses else 0
                posologie_iv = st.selectbox(f"Posologie IV#{i+1}", poses, index=pos_idx, key=f"ivpos_{i}")
            if nom_iv.strip():
                iv_peros.append({"type_iv": type_iv, "nom": nom_iv.strip(), "posologie": posologie_iv})

        st.markdown("#### △ Bolus")
        nb_bol = st.number_input("Nombre de bolus", min_value=0, max_value=5, value=1)
        bolus_list = []
        prev_bol = (load.get("bolus",[]) if load else [])
        for i in range(int(nb_bol)):
            prev = prev_bol[i] if i < len(prev_bol) else {}
            bc1, bc2 = st.columns([3, 5])
            with bc1:
                nom_bol = st.text_input(f"Bolus#{i+1}", value=prev.get("nom",""), key=f"bolnom_{i}")
            with bc2:
                jours_sel = st.multiselect(f"Jours △ #{i+1}",
                    options=list(range(1, int(nb_j)+1)),
                    default=[j for j in prev.get("jours",[]) if j <= int(nb_j)],
                    format_func=lambda x: f"J{x}",
                    key=f"boljours_{i}")
            if nom_bol.strip():
                bolus_list.append({"nom": nom_bol.strip(), "jours": jours_sel})

        col_sav, col_pre = st.columns(2)
        with col_sav: btn_save = st.form_submit_button("💾 Sauvegarder la fiche", use_container_width=True)
        with col_pre: btn_prev = st.form_submit_button("👁 Générer & Afficher", use_container_width=True)

    # ── Actions ──────────────────────────────────────────────────
    fiche_data = {
        "nom": nom_t, "prenom": prenom_t, "ip": ip_t, "date_h": date_h,
        "diag": diag_t, "med": med_t, "glyc": glyc, "ta": ta,
        "debut": debut_t, "nb_j": int(nb_j),
        "collyres": collyres, "iv_peros": iv_peros, "bolus": bolus_list,
        "timestamp": datetime.datetime.now().timestamp(),
        "date_str": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
    }

    if btn_save:
        if not nom_t and not ip_t:
            st.warning("Remplissez au moins le Nom ou l'IP.")
        else:
            # Remplacer si même IP
            st.session_state.ttt_fiches = [f for f in st.session_state.ttt_fiches
                                            if f.get("ip","") != ip_t or not ip_t]
            st.session_state.ttt_fiches.insert(0, fiche_data)
            st.session_state.ttt_fiches = st.session_state.ttt_fiches[:20]
            log_action(current_user(), "SAUVEGARDE FICHE TTT", f"{nom_t} {prenom_t}")
            st.success("✅ Fiche sauvegardée (disponible 14 jours).")

    if btn_prev:
        if not collyres and not iv_peros and not bolus_list:
            st.warning("Ajoutez au moins une prescription.")
        else:
            _render_fiche_preview(fiche_data)

def _get_dates_from_fiche(debut_str, nb_j):
    try:   d0 = datetime.datetime.strptime(debut_str.strip(), "%d/%m/%Y")
    except: d0 = datetime.datetime.now()
    fr = ["Lun","Mar","Mer","Jeu","Ven","Sam","Dim"]
    out = []
    for i in range(max(1, min(30, int(nb_j)))):
        d = d0 + timedelta(days=i)
        out.append({"label": f"{fr[d.weekday()]} {d.day:02d}/{d.month:02d}",
                    "is_we": d.weekday() >= 5, "idx": i+1})
    return out

def _render_fiche_preview(f):
    dates    = _get_dates_from_fiche(f["debut"], f["nb_j"])
    collyres = f.get("collyres", [])
    iv_peros = f.get("iv_peros", [])
    bolus    = f.get("bolus",    [])
    nb       = len(dates)

    # ── Génération HTML imprimable ─────────────────────────────
    cb = lambda v: "☑" if v == "OUI" else "☐"

    hdr_cells = "".join(
        f'<th class="{"fiche-hdr-we" if d["is_we"] else "fiche-hdr-blue"}">'
        f'{d["label"]}</th>' for d in dates)

    rows_html = ""

    if collyres:
        rows_html += f'<tr><td class="fiche-sec-col" colspan="{nb+1}">💧 Collyres / Pommades</td></tr>'
        for i, item in enumerate(collyres):
            bg = ' class="fiche-row-alt"' if i % 2 else ""
            badge = "[P]" if item["type_col"] == "Pommade" else "[C]"
            lbl   = f'{badge} {item["nom"]}  [{item["oeil"]}]  {item["posologie"]}'
            cells = "".join(f"<td></td>" for _ in dates)
            rows_html += f'<tr{bg}><td>{lbl}</td>{cells}</tr>'

    if iv_peros:
        rows_html += f'<tr><td class="fiche-sec-iv" colspan="{nb+1}">💉 IV / Per os / Sirop</td></tr>'
        for i, item in enumerate(iv_peros):
            bg = ' class="fiche-row-alt"' if i % 2 else ""
            lbl = f'[{item["type_iv"]}] {item["nom"]}  {item["posologie"]}'
            cells = "".join(f"<td></td>" for _ in dates)
            rows_html += f'<tr{bg}><td>{lbl}</td>{cells}</tr>'

    if bolus:
        rows_html += f'<tr><td class="fiche-sec-bol" colspan="{nb+1}">△ Bolus</td></tr>'
        for i, item in enumerate(bolus):
            bg = ' class="fiche-row-alt"' if i % 2 else ""
            cells = "".join(
                f'<td class="fiche-bolus-sym">{"△" if d["idx"] in item["jours"] else ""}</td>'
                for d in dates)
            rows_html += f'<tr{bg}><td>{item["nom"]}</td>{cells}</tr>'

    html_print = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Fiche TTT — {f["nom"]} {f["prenom"]}</title>
<style>
body {{ font-family: Calibri, Arial, sans-serif; font-size: 9pt; margin: 12mm; }}
.hosp {{ text-align:center; color:#1A2B6B; }}
.hosp h1 {{ font-size:13pt; margin:0; }} .hosp h2 {{ font-size:10pt; margin:0; }}
hr {{ border: 1px solid #1565C0; margin:4px 0; }}
.info-bloc {{ width:100%; border-collapse:collapse; border:1px solid #1565C0; margin:6px 0; }}
.info-bloc td {{ border:1px solid #1565C0; padding:5px 8px; vertical-align:top; font-size:8.5pt; }}
.titre {{ text-align:center; font-style:italic; font-weight:bold; font-size:10pt; margin:6px 0; }}
table.fiche {{ width:100%; border-collapse:collapse; }}
table.fiche th {{ background:#1565C0; color:#fff; padding:5px 3px; font-size:8pt; border:1px solid #1565C0; }}
table.fiche td {{ border:1px solid #B0C4DE; padding:5px 4px; font-size:8pt; }}
.fiche-hdr-blue {{ background:#DDEEFF; color:#000; font-weight:bold; }}
.fiche-hdr-we   {{ background:#FFE8C0; color:#000; font-weight:bold; }}
.fiche-sec-col  {{ background:#D6EAF8; font-weight:bold; }}
.fiche-sec-iv   {{ background:#D5F5E3; font-weight:bold; }}
.fiche-sec-bol  {{ background:#FFF3E0; font-weight:bold; }}
.fiche-row-alt  {{ background:#F8FAFC; }}
.fiche-bolus-sym{{ text-align:center; font-weight:900; color:#E65100; font-size:11pt; }}
.footer {{ font-size:6.5pt; color:#999; text-align:right; margin-top:8px; }}
@media print {{ .no-print {{ display:none; }} }}
</style></head><body>
<div class="no-print" style="margin-bottom:12px;">
  <button onclick="window.print()" style="padding:8px 22px;background:#1565C0;color:white;
    border:none;border-radius:5px;cursor:pointer;font-size:10pt;font-weight:bold;">
    🖨️  Imprimer / PDF
  </button>
</div>
<div class="hosp"><h1>CHU MOHAMMED VI &nbsp;&nbsp; OUJDA</h1><h2>SERVICE D'OPHTALMOLOGIE</h2><hr></div>
<table class="info-bloc"><tr>
  <td style="width:28%"><b>Nom / Prénom :</b><br>{f["nom"]} {f["prenom"]}<br><br><b>Date hosp. :</b> {f["date_h"]}</td>
  <td style="width:22%"><b>IP :</b> {f["ip"]}<br><br><b>Diagnostic :</b><br>{f["diag"]}</td>
  <td style="width:28%"><b>Surveillance :</b><br>Glycémie : {cb(f["glyc"])} OUI &nbsp; {cb("OUI" if f["glyc"]=="NON" else "NON")} NON<br>T.A. : {cb(f["ta"])} OUI &nbsp; {cb("OUI" if f["ta"]=="NON" else "NON")} NON</td>
  <td style="width:22%;text-align:center;vertical-align:middle"><b>Médecin traitant :</b><br><br><b style="color:#1A2B6B">{f["med"]}</b></td>
</tr></table>
<div class="titre">Fiche de surveillance et de traitement &ndash; Service d'Ophtalmologie</div>
<table class="fiche">
  <thead><tr><th style="text-align:left;padding:5px 8px;">Prescriptions</th>{hdr_cells}</tr></thead>
  <tbody>{rows_html}</tbody>
</table>
<div class="footer">Généré le {datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")} &nbsp;•&nbsp;
{f["med"]} &nbsp;•&nbsp; SURGIX v1.12 Web GoldenEye</div>
</body></html>"""

    # Affichage inline + bouton téléchargement
    st.markdown("---")
    st.markdown("#### 📋 Aperçu de la fiche")

    # Aperçu HTML inline
    st.components.v1.html(html_print, height=600, scrolling=True)

    # Téléchargement
    st.download_button(
        label="⬇️ Télécharger la fiche HTML (imprimable)",
        data=html_print.encode("utf-8"),
        file_name=f"fiche_ttt_{f['nom']}_{f['ip'] or 'X'}.html",
        mime="text/html",
    )

# ═══════════════════════════════════════════════════════════════
# PAGE UTILISATEURS (admin)
# ═══════════════════════════════════════════════════════════════
def page_users():
    render_header("Gestion utilisateurs")
    st.markdown("### 👥 Utilisateurs")

    users = st.session_state.users
    col_headers = st.columns([2, 3, 2, 2])
    for h, c in zip(["Login","Nom complet","Rôle","Équipe"], col_headers):
        with c: st.markdown(f"**{h}**")
    st.markdown("---")
    for login, u in users.items():
        c1, c2, c3, c4 = st.columns([2, 3, 2, 2])
        with c1: st.markdown(login)
        with c2: st.markdown(u.get("nom_complet",""))
        with c3:
            badge = "badge-blue" if u.get("role")==ROLE_ADMIN else "badge-teal"
            st.markdown(f'<span class="badge {badge}">{u.get("role","")}</span>',
                        unsafe_allow_html=True)
        with c4: st.markdown(equipe_de(login) or "—")

    st.markdown("---")
    st.markdown("#### 🔑 Réinitialiser un mot de passe")
    with st.form("form_reset_pw"):
        r_login = st.selectbox("Utilisateur", list(users.keys()))
        r_pw    = st.text_input("Nouveau mot de passe", type="password")
        r_pw2   = st.text_input("Confirmer", type="password")
        sub = st.form_submit_button("Réinitialiser")
    if sub:
        if len(r_pw) < 4:
            st.error("Mot de passe trop court (min. 4 caractères).")
        elif r_pw != r_pw2:
            st.error("Les mots de passe ne correspondent pas.")
        else:
            h, s = _hash(r_pw)
            users[r_login]["hash"] = h; users[r_login]["salt"] = s
            drive_save_users()
            log_action(current_user(), "RESET MDP", r_login)
            st.success(f"✅ MDP de {r_login} réinitialisé.")

    st.markdown("#### 🔒 Changer mon mot de passe")
    with st.form("form_change_pw"):
        old_pw  = st.text_input("Ancien mot de passe", type="password")
        new_pw  = st.text_input("Nouveau mot de passe", type="password")
        new_pw2 = st.text_input("Confirmer", type="password")
        sub2 = st.form_submit_button("Changer")
    if sub2:
        u = users.get(current_user(), {})
        if not _verify(old_pw, u["hash"], u["salt"]):
            st.error("Ancien mot de passe incorrect.")
        elif len(new_pw) < 4:
            st.error("Mot de passe trop court.")
        elif new_pw != new_pw2:
            st.error("Les mots de passe ne correspondent pas.")
        else:
            h, s = _hash(new_pw)
            u["hash"] = h; u["salt"] = s
            drive_save_users()
            log_action(current_user(), "CHANGEMENT MDP", current_user())
            st.success("✅ Mot de passe modifié.")

# ═══════════════════════════════════════════════════════════════
# PAGE JOURNAL
# ═══════════════════════════════════════════════════════════════
def page_journal():
    render_header("Journal d'activité")
    st.markdown("### 📝 Journal d'activité")

    logs = list(reversed(st.session_state.log))

    search_log = st.text_input("🔍 Filtrer le journal", placeholder="utilisateur, action...")
    if search_log:
        s = search_log.lower()
        logs = [l for l in logs if any(s in str(v).lower() for v in l.values())]

    st.markdown(f"**{len(logs)} entrée(s)**")
    if not logs:
        st.info("Journal vide.")
        return

    cols = st.columns([2, 1.5, 2, 3])
    for h, c in zip(["Timestamp","Utilisateur","Action","Détail"], cols):
        with c: st.markdown(f"**{h}**")
    st.markdown("---")
    for e in logs[:200]:
        c1, c2, c3, c4 = st.columns([2, 1.5, 2, 3])
        with c1: st.markdown(f'<small>{e.get("timestamp","")}</small>', unsafe_allow_html=True)
        with c2: st.markdown(e.get("user",""))
        with c3: st.markdown(e.get("action",""))
        with c4: st.markdown(e.get("detail",""))

# ═══════════════════════════════════════════════════════════════
# ROUTEUR PRINCIPAL
# ═══════════════════════════════════════════════════════════════
def main():
    _init_state()

    if not st.session_state.logged_in:
        page_login()
        return

    render_sidebar()

    page = st.session_state.page
    if   page == "patients":     page_patients()
    elif page == "add_patient":  page_add_patient()
    elif page == "edit_patient": page_edit_patient()
    elif page == "dossier":      page_dossier()
    elif page == "stats":        page_stats()
    elif page == "fiche_ttt":    page_fiche_ttt()
    elif page == "planning":     page_planning()
    elif page == "users":
        if current_role() == ROLE_ADMIN or current_user() == SUPER_ADMIN:
            page_users()
        else:
            st.error("Accès réservé à l'administrateur.")
    elif page == "journal":
        if current_role() == ROLE_ADMIN or current_user() == SUPER_ADMIN:
            page_journal()
        else:
            st.error("Accès réservé à l'administrateur.")
    else:
        page_patients()


if __name__ == "__main__":
    main()
