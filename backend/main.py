import os
import json
import uuid
import asyncio
import io
import pymysql
from datetime import datetime, date
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, Date, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
from fpdf import FPDF

# --- 1. ŠIFROVACIA LOGIKA ---
def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        # Ak by súbor chýbal, vygeneruje sa nový, ale pozor: stratíš prístup k starým dátam!
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
        return key

cipher_suite = Fernet(load_key())

def encrypt_data(text_to_encrypt: str) -> str:
    if not text_to_encrypt: return ""
    return cipher_suite.encrypt(text_to_encrypt.encode()).decode()

def decrypt_data(cipher_text: str) -> str:
    if not cipher_text: return ""
    try:
        return cipher_suite.decrypt(cipher_text.encode()).decode()
    except Exception:
        # Ak dáta nie sú zašifrované (staré záznamy), vráti ich v pôvodnom stave
        return cipher_text

# --- 2. DATABÁZOVÁ KONFIGURÁCIA ---
temp_engine = create_engine("mysql+pymysql://root:@127.0.0.1:3306")
with temp_engine.connect() as conn:
    conn.execute(text("CREATE DATABASE IF NOT EXISTS last_link_db"))
    conn.execute(text("COMMIT"))

DATABASE_URL = "mysql+pymysql://root:@127.0.0.1:3306/last_link_db?charset=utf8mb4"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_type = Column(String(50))  # "LEKAR" alebo "RODINA"
    identifier = Column(String(255))  # Meno lekára alebo kód rodiny
    family_code = Column(String(255))
    attempt_date = Column(DateTime, default=datetime.now)
    ip_address = Column(String(255))
    status = Column(String(50))  # "SUCCESS" alebo "FAILED"

class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = {
        'mysql_charset': 'utf8mb4',
        'mysql_collate': 'utf8mb4_unicode_ci'
    }

    id = Column(Integer, primary_key=True, index=True)
    family_code = Column(String(10), unique=True, nullable=False)
    doctor_id = Column(String(255))
    
    # Šifrované polia budú v DB ako String(Text)
    deceased_name = Column(Text) 
    maiden_name = Column(Text)
    deceased_rc = Column(Text, index=False) # Index na zašifrovanom poli nedáva zmysel pre vyhľadávanie
    
    marital_status = Column(String(50))
    birth_date = Column(Date)
    death_date = Column(DateTime)
    place_of_death = Column(String(255))
    permanent_residence = Column(Text)
    cause_of_death = Column(Text)
    status = Column(String(50), default="PENDING")
    notifications_json = Column(Text)
    created_at = Column(DateTime, default=datetime.now)

Base.metadata.create_all(bind=engine)

# --- 3. SCHÉMY (Pydantic) ---
class DeathReport(BaseModel):
    deceased_rc: str
    deceased_name: str
    doctor_id: str
    maiden_name: str
    marital_status: str
    birth_date: date
    death_date: datetime
    permanent_residence: str
    place_of_death: str
    cause_of_death: str
    status: str = "PENDING"

# --- 4. POMOCNÉ FUNKCIE ---
DOCTOR_TOKENS = {
    "key-mudr-123": "MUDr. Ján Štastný",
    "key-mudr-456": "MUDr. Anna Veselá"
}

async def simulate_processing(family_code: str):
    await asyncio.sleep(1)
    print(f"--- [START] Simulácia pre kód: {family_code} ---")
    await asyncio.sleep(30) # Skrátené pre testovanie
    
    db = SessionLocal()
    try:
        incident = db.query(Incident).filter(Incident.family_code == family_code).first()
        if incident:
            updated_notifs = [
                {"target": "Sociálna poisťovňa", "state": "DONE"},
                {"target": "Tatra Banka", "state": "DONE"},
                {"target": "Zdravotná poisťovňa", "state": "DONE"}
            ]
            incident.status = "COMPLETED"
            incident.notifications_json = json.dumps(updated_notifs)
            db.commit()
            print(f"--- [OK] Aktualizované pre {family_code} ---")
    except Exception as e:
        print(f"--- [ERROR] {e} ---")
        db.rollback()
    finally:
        db.close()

# --- 5. FASTAPI SETUP ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 6. ENDPOINTY ---

@app.get("/api/v1/verify-doctor")
async def verify_doctor(request: Request, x_auth_token: str = Header(None)):
    db = SessionLocal()
    ip = request.client.host if request else "127.0.0.1"
    
    try:
        # 1. Kontrola, či token existuje v tvojom slovníku DOCTOR_TOKENS
        if x_auth_token in DOCTOR_TOKENS:
            doctor_name = DOCTOR_TOKENS[x_auth_token]
            
            # LOG: Úspešné overenie lekára
            new_log = AccessLog(
                user_type="LEKAR", 
                identifier=doctor_name, 
                ip_address=ip, 
                status="VERIFIED_SUCCESS"
            )
            db.add(new_log)
            db.commit()
            
            return {"status": "authorized", "doctor_name": doctor_name}
        
        # 2. Ak token nesedí (Neautorizovaný pokus)
        new_log = AccessLog(
            user_type="LEKAR", 
            identifier=f"Unknown Token: {x_auth_token[:8]}...", # Zapíšeme aspoň začiatok zlého tokenu
            ip_address=ip, 
            status="VERIFIED_FAILED"
        )
        db.add(new_log)
        db.commit()
        
        raise HTTPException(status_code=401, detail="Neautorizovaný prístup")

    finally:
        db.close()

@app.get("/status/{code}")
async def get_status(code: str, dob: str = None, request: Request = None):

    db = SessionLocal()
    
    # 1. DEFINUJEME IP HNEĎ NA ZAČIATKU
    ip = request.client.host if request else "127.0.0.1"

    if not dob:
        raise HTTPException(status_code=400, detail="Chýba dátum narodenia.")

    db = SessionLocal()
    try:
        # 1. Vyhľadanie podľa kódu (veľkými písmenami)
        incident = db.query(Incident).filter(Incident.family_code == code.upper().strip()).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Kód neexistuje")

        # 2. Porovnanie NEŠIFROVANÉHO dátumu
        # .strip() odstráni prípadné náhodné medzery na začiatku/konci
        db_dob = str(incident.birth_date).strip()
        user_dob = str(dob).strip()

        print(f"--- [AUTH CHECK] Kód: {code} | DB: '{db_dob}' vs USER: '{user_dob}' ---")

        if db_dob != user_dob:
            raise HTTPException(status_code=401, detail="Nesprávny dátum narodenia.")


        incident = db.query(Incident).filter(Incident.family_code == code.upper().strip()).first()
        
        # LOGOVANIE: Ak kód neexistuje
        if not incident:
            new_log = AccessLog(family_code=code, ip_address=ip, status="NOT_FOUND", user_type="RODINA")
            db.add(new_log)
            db.commit()
            raise HTTPException(status_code=404, detail="Kód neexistuje")

        # LOGOVANIE: Kontrola dátumu
        db_dob = str(incident.birth_date).strip()
        if db_dob != str(dob).strip():
            new_log = AccessLog(family_code=code, ip_address=ip, status="WRONG_DOB")
            db.add(new_log)
            db.commit()
            raise HTTPException(status_code=401, detail="Nesprávny dátum")

        # LOGOVANIE: Úspešný vstup
        new_log = AccessLog(family_code=code, ip_address=ip, status="SUCCESS",user_type="RODINA")
        db.add(new_log)
        db.commit()

        # 3. Ak sedí, dešifrujeme len meno a vrátime dáta
        return {
            "deceased": decrypt_data(incident.deceased_name),
            "status": incident.status,
            "notifications": json.loads(incident.notifications_json)
        }

    finally:
        db.close()

@app.get("/api/v1/report/pdf/{code}")
async def generate_pdf(code: str):
    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.family_code == code.upper()).first()
    db.close()

    if not incident:
        raise HTTPException(status_code=404, detail="Záznam nenájdený")

    # DEŠIFROVANIE DÁT PRE PDF
    name = decrypt_data(incident.deceased_name).upper()
    rc_raw = decrypt_data(incident.deceased_rc).replace("/", "").replace(" ", "")
    
    # Formátovanie dátumov a času
    def format_date_sk(date_val):
        if not date_val: return ".........."
        if hasattr(date_val, 'strftime'):
            return date_val.strftime("%d-%m-%Y")
        return str(date_val)

    b_date = format_date_sk(incident.birth_date)
    d_date = format_date_sk(incident.death_date)
    d_time = incident.death_date.strftime("%H:%M") if hasattr(incident.death_date, 'strftime') else ".........."

    # TVORBA PDF
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Fonty (Uisti sa, že máš .ttf súbory v priečinku!)
    pdf.add_font('Roboto', '', 'Roboto.ttf')
    pdf.add_font('Roboto', 'B', 'Roboto-Bold.ttf')
    pdf.add_font('Roboto', 'I', 'Roboto-Italic.ttf')

    # Hlavička
    pdf.set_font("Roboto", '', 8)
    pdf.cell(100, 4, txt="ŠTATISTICKÝ ÚRAD SLOVENSKEJ REPUBLIKY", ln=0)
    pdf.set_font("Roboto", 'B', 8)
    pdf.cell(0, 4, txt="Hlásenie pre ŠÚ SR: ÁNO", ln=1, align='R')
    
    # IKF boxy
    pdf.set_xy(150, 15)
    pdf.set_font("Roboto", '', 7)
    pdf.cell(10, 5, "IKF")
    for i in range(6):
        pdf.rect(160 + (i*4), 15, 4, 5)

    pdf.set_xy(10, 25)
    pdf.set_font("Roboto", 'B', 14)
    pdf.cell(0, 8, txt="List o prehliadke mŕtveho a štatistické hlásenie o úmrtí", ln=True, align='C')
    pdf.ln(5)

    def add_section_header(text_title):
        pdf.set_font("Roboto", 'B', 10)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(0, 7, txt=f" {text_title}", ln=True, fill=True, border=1)
        pdf.ln(2)

    # I. ÚMRTIE
    add_section_header("I. ÚMRTIE")
    
    pdf.set_font("Roboto", 'B', 9)
    pdf.cell(8, 8, "01", border=1, align='C')
    pdf.set_font("Roboto", '', 9)
    pdf.cell(45, 8, " Priezvisko a meno:")
    pdf.set_font("Roboto", 'B', 11)
    pdf.cell(0, 8, txt=name, ln=1)

    # Rodné číslo mriežka
    pdf.set_font("Roboto", 'B', 9)
    pdf.cell(8, 8, "02", border=1, align='C')
    pdf.set_font("Roboto", '', 9)
    pdf.cell(45, 8, " Rodné číslo:")
    curr_x = pdf.get_x()
    for i in range(10):
        digit = rc_raw[i] if i < len(rc_raw) else ""
        pdf.rect(curr_x + (i*5), pdf.get_y() + 1, 5, 6)
        pdf.text(curr_x + (i*5) + 1.5, pdf.get_y() + 5.5, digit)
    pdf.ln(10)

    # Dátum a čas
    pdf.set_font("Roboto", 'B', 9)
    pdf.cell(8, 8, "03", border=1, align='C')
    pdf.set_font("Roboto", '', 9)
    pdf.cell(55, 8, " Deň, mesiac, rok a hodina úmrtia:")
    pdf.set_font("Roboto", 'B', 10)
    pdf.cell(0, 8, txt=f"{d_date}      o      {d_time}  hod.", ln=1)

    # Narodenie
    pdf.set_font("Roboto", '', 9)
    pdf.cell(8, 8, "", ln=0)
    pdf.cell(55, 8, " Dátum narodenia:")
    pdf.cell(0, 8, txt=b_date, ln=1)

    # Miesto
    pdf.set_font("Roboto", 'B', 9)
    pdf.cell(8, 8, "04", border=1, align='C')
    pdf.set_font("Roboto", '', 9)
    pdf.cell(45, 8, " Miesto úmrtia:")
    pdf.cell(0, 8, txt=str(incident.place_of_death or ""), ln=1)
    pdf.ln(5)

    # II. PRÍČINA SMRTI
    add_section_header("II. PRÍČINA SMRTI")
    pdf.set_font("Roboto", 'B', 9)
    pdf.cell(8, 18, "05", border=1, align='C')
    pdf.set_font("Roboto", '', 10)
    curr_y = pdf.get_y()
    pdf.rect(18, curr_y, 182, 18)
    pdf.set_xy(20, curr_y + 2)
    pdf.multi_cell(178, 5, txt=str(incident.cause_of_death or ""))
    
    pdf.set_xy(10, curr_y + 22)

    # Päta
    pdf.set_y(-20)
    pdf.set_font("Roboto", 'I', 7)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 4, txt=f"Kinnex System | Kód: {incident.family_code} | Vygenerované: {datetime.now().strftime('%d.%m.%Y %H:%M')}", ln=True, align='C')

    pdf_output = pdf.output()
    return Response(
        content=bytes(pdf_output),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=LPM_{code}.pdf"}
    )

#ZOZNAM UMŔTÍ PRE LEKÁRA

@app.get("/api/v1/doctor/my-reports")
async def get_doctor_reports(x_auth_token: str = Header(None)):
    if x_auth_token not in DOCTOR_TOKENS:
        raise HTTPException(status_code=401, detail="Neautorizovaný prístup")
    
    doctor_name = DOCTOR_TOKENS[x_auth_token]
    db = SessionLocal()
    # Získame posledných 20 záznamov daného lekára
    incidents = db.query(Incident).filter(Incident.doctor_id == doctor_name).order_by(Incident.created_at.desc()).limit(20).all()
    db.close()

    result = []
    now = datetime.now()

    for inc in incidents:
        # Výpočet, či prešlo menej ako 60 minút
        diff = now - inc.created_at
        is_editable = diff.total_seconds() < 3600  # 3600 sekúnd = 1 hodina

        result.append({
            "family_code": inc.family_code,
            "deceased_name": decrypt_data(inc.deceased_name),
            "created_at": inc.created_at.strftime("%H:%M:%S (%d.%m.)"),
            "status": inc.status,
            "is_editable": is_editable,
            "minutes_left": max(0, int((3600 - diff.total_seconds()) / 60))
        })
    
    return result

# --- 1. ENDPOINT NA NAČÍTANIE DÁT DO FORMULÁRA (Toto ti chýbalo) ---
@app.get("/api/v1/report/{code}")
async def get_report_for_edit(code: str, x_auth_token: str = Header(None)):
    if x_auth_token not in DOCTOR_TOKENS:
        raise HTTPException(status_code=401, detail="Neautorizovaný prístup")

    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.family_code == code.upper()).first()
    db.close()

    if not incident:
        raise HTTPException(status_code=404, detail="Záznam sa nenašiel")

    # VRACIAME DEŠIFROVANÉ DÁTA
    return {
        "deceased_name": decrypt_data(incident.deceased_name),
        "deceased_rc": decrypt_data(incident.deceased_rc),
        "maiden_name": decrypt_data(incident.maiden_name),
        "marital_status": incident.marital_status,
        "birth_date": str(incident.birth_date),
        "death_date": incident.death_date.isoformat() if incident.death_date else None,
        "permanent_residence": incident.permanent_residence,
        "place_of_death": incident.place_of_death,
        "cause_of_death": incident.cause_of_death
    }

# --- 2. ENDPOINT NA ULOŽENIE ZMIEN (Zmeň metódu na PUT) ---
@app.put("/api/v1/report/{code}")
async def update_report(
    code: str, 
    updated_data: DeathReport, 
    x_auth_token: str = Header(None)
):
    if x_auth_token not in DOCTOR_TOKENS:
        raise HTTPException(status_code=401, detail="Neautorizovaný prístup")

    db = SessionLocal()
    incident = db.query(Incident).filter(Incident.family_code == code.upper()).first()

    if not incident:
        db.close()
        raise HTTPException(status_code=404, detail="Záznam sa nenašiel")

    # KONTROLA ČASOVÉHO LIMITU (1 hodina)
    now = datetime.now()
    if (now - incident.created_at).total_seconds() > 3600:
        db.close()
        raise HTTPException(status_code=403, detail="Časový limit na úpravu vypršal")

    try:
        # Aktualizácia a šifrovanie
        incident.deceased_name = encrypt_data(updated_data.deceased_name)
        incident.deceased_rc = encrypt_data(updated_data.deceased_rc)
        incident.maiden_name = encrypt_data(updated_data.maiden_name)
        incident.cause_of_death = updated_data.cause_of_death
        incident.place_of_death = updated_data.place_of_death
        incident.permanent_residence = updated_data.permanent_residence
        incident.birth_date = updated_data.birth_date
        incident.death_date = updated_data.death_date
        incident.marital_status = updated_data.marital_status

        # ... pridaj ďalšie polia, ktoré chceš aktualizovať
        
        db.commit()
        return {"status": "updated", "message": "Zmeny boli uložené."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

# --- 7. WEBSOCKET MANAGER (Pre Real-time notifikácie) ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"--- [WS] Nový admin pripojený. Celkovo: {len(self.active_connections)} ---")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"--- [WS] Admin odpojený. Zostáva: {len(self.active_connections)} ---")

    async def broadcast(self, message: dict):
        # Toto pošle dáta všetkým otvoreným Admin oknám
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception as e:
                print(f"--- [WS ERROR] Zlyhalo odoslanie: {e} ---")

manager = ConnectionManager()

# Endpoint pre Admin Panel, na ktorý sa napojí tvoje nové HTML rozhranie
@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Udržujeme spojenie živé, čakáme na ping/pong
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

import logging

# Nastavenie logovania, aby si videl chyby v konzole
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- ENDPOINT PRE REPORT ---
@app.post("/api/v1/report")
async def create_report(
    report: DeathReport,
    background_tasks: BackgroundTasks,
    x_auth_token: str = Header(None)
):
    # 1. Overenie lekára
    if x_auth_token not in DOCTOR_TOKENS:
        raise HTTPException(status_code=401, detail="Neautorizovaný prístup")

    family_code = str(uuid.uuid4())[:6].upper()
    db = SessionLocal()

    initial_notifs = [
         {"target": "Sociálna poisťovňa", "state": "WAITING"},
         {"target": "Tatra Banka", "state": "WAITING"},
         {"target": "Zdravotná poisťovňa", "state": "WAITING"}
     ]

    try:

        # --- TÁTO ČASŤ TI TAM CHÝBALA ALEBO BOLA INAK ---
        # Posielame NEŠIFROVANÉ dáta priamo z objektu 'report', 
        # aby ich Admin panel vedel prečítať
        await manager.broadcast({
            "rc": report.deceased_rc,
            "meno": report.deceased_name,
            "miesto": report.place_of_death,
            "cas": datetime.now().strftime("%H:%M:%S")
        })
        # -----------------------------------------------
        # 2. Príprava záznamu pre DB
        new_entry = Incident(
             family_code=family_code,
             # ŠIFROVANIE PRI ZÁPISE
             deceased_name=encrypt_data(report.deceased_name),
             maiden_name=encrypt_data(report.maiden_name),
             deceased_rc=encrypt_data(report.deceased_rc),
            
             marital_status=report.marital_status,
             birth_date=report.birth_date,
             death_date=report.death_date,
             permanent_residence=report.permanent_residence,
             place_of_death=report.place_of_death,
             cause_of_death=report.cause_of_death,
             doctor_id=DOCTOR_TOKENS[x_auth_token],
             status=report.status,
             notifications_json=json.dumps(initial_notifs),
             created_at=datetime.now()
        )
        
        db.add(new_entry)
        db.commit() # Uloženie do MySQL

        background_tasks.add_task(simulate_processing, family_code)
        return {"status": "success", "family_code": family_code}

    except Exception as e:
        db.rollback()
        print(f"CHYBA PRI REPORTE: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()
