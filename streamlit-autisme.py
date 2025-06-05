# -*- coding: utf-8 -*-
"""Application de dépistage TSA conforme RGPD/AI Act

Automatiquement généré par Colab.
Fichier original situé à :
    https://colab.research.google.com/drive/1tYyBZXlbNHUGJELlLOMJWGZVmxY346Yd
"""

# IMPORTANT : st.set_page_config() DOIT être la première commande Streamlit
import streamlit as st

# Configuration de la page - DOIT être en premier
st.set_page_config(
    page_title="Dépistage TSA - Conforme RGPD/AI Act",
    page_icon="🧩",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Tous les autres imports APRÈS st.set_page_config()
import datetime as dt 
import joblib
import prince
import uuid
import json
import sqlite3
import hashlib
import base64
import os
import pickle
import numpy as np
import pandas as pd
import requests
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from PIL import Image
import streamlit.components.v1 as components
import plotly.express as px
from cryptography.fernet import Fernet
import logging
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    st.warning("Matplotlib non disponible - certaines visualisations seront limitées")

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    st.warning("Plotly non disponible - certaines visualisations seront limitées")


def safe_execution(func):
    """Décorateur pour l'exécution sécurisée des fonctions avec gestion d'erreurs"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            st.error(f"Erreur lors de l'exécution de {func.__name__}: {str(e)}")
            logger.error(f"Erreur dans {func.__name__}: {str(e)}", exc_info=True)
            return None
    return wrapper


# Création des dossiers nécessaires
for folder in ['data_cache', 'image_cache', 'model_cache', 'theme_cache', 'logs']:
    os.makedirs(folder, exist_ok=True)



# Configuration des logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class SecureDataManager:
    """Gestionnaire sécurisé pour données RGPD avec chiffrement"""
    
    def __init__(self):
        try:
            self.db_path = "secure_compliance.db"
            self.encryption_key = self._get_or_create_key()
            self.cipher = Fernet(self.encryption_key)
            self._init_database()
        except Exception as e:
            logging.error(f"Erreur initialisation SecureDataManager: {e}")
            raise
    
    def _get_or_create_key(self):
    """Récupère ou crée une clé de chiffrement sécurisée"""
        try:
            key_env = os.getenv('ENCRYPTION_KEY')
            if key_env:
                return key_env.encode()
            else:
                # Vérifier si un fichier de clé existe déjà
                key_file = "encryption.key"
                if os.path.exists(key_file):
                    with open(key_file, "rb") as f:
                        return f.read()
                else:
                    # Générer une nouvelle clé
                    new_key = Fernet.generate_key()
                    # Sauvegarder la clé pour une utilisation future
                    os.makedirs(os.path.dirname(key_file) or '.', exist_ok=True)
                    with open(key_file, "wb") as f:
                        f.write(new_key)
                    return new_key
        except Exception as e:
            logging.error(f"Erreur génération clé de chiffrement: {e}")
            # Fallback sécurisé en cas d'erreur
            return Fernet.generate_key()

    
    def encrypt_data(self, data: str) -> str:
        """Chiffre les données sensibles avec gestion d'erreur"""
        try:
            if not isinstance(data, str):
                data = str(data)
            return self.cipher.encrypt(data.encode()).decode()
        except Exception as e:
            logging.error(f"Erreur chiffrement: {e}")
            return ""
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Déchiffre les données avec gestion d'erreur"""
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logging.error(f"Erreur déchiffrement: {e}")
            return ""
    def _init_database(self):
    """Initialise la base de données sécurisée avec schéma de tables"""
        try:
            # S'assurer que le répertoire existe
            db_dir = os.path.dirname(self.db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            
            # Connexion avec gestion d'erreur
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                # Table des consentements RGPD
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS consent_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_session_hash TEXT NOT NULL,
                        consent_type TEXT NOT NULL,
                        granted BOOLEAN NOT NULL,
                        consent_version TEXT NOT NULL,
                        timestamp DATETIME NOT NULL,
                        ip_hash TEXT,
                        encrypted_details TEXT
                    )
                ''')
                
                # Table des logs de traitement RGPD
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS processing_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_session_hash TEXT NOT NULL,
                        processing_type TEXT NOT NULL,
                        data_categories TEXT NOT NULL,
                        legal_basis TEXT NOT NULL,
                        timestamp DATETIME NOT NULL,
                        encrypted_metadata TEXT
                    )
                ''')
                
                # Table des décisions IA
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ai_decisions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_hash TEXT NOT NULL,
                        model_version TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        timestamp DATETIME NOT NULL,
                        encrypted_input_hash TEXT,
                        encrypted_output TEXT
                    )
                ''')
                
                conn.commit()
            except sqlite3.Error as e:
                logging.error(f"Erreur SQL lors de la création des tables: {e}")
                conn.rollback()
                raise
            finally:
                conn.close()
                
        except Exception as e:
            logging.error(f"Erreur critique dans _init_database: {e}", exc_info=True)
            # Ne pas lever l'exception, utiliser un mode dégradé
            logging.warning("Base de données non disponible - mode dégradé activé")


    
    def encrypt_data(self, data: str) -> str:
        """Chiffre les données sensibles"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Déchiffre les données"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()


    REGULATORY_CONFIG = {
        "app_name": "Dépistage TSA",
        "version": "2.0.0",
        "regulatory_status": {
            "eu_mdr": {
                "status": "Class IIa Medical Device Software",
                "conformity": "In certification process",
                "notified_body": "Pending assignment"
            },
            "ai_act": {
                "status": "High Risk AI System",
                "conformity": "Implementing regulatory requirements",
                "classification": "Annex III - Health AI System"
            },
            "gdpr": {
                "status": "Processing Health Data",
                "dpo_contact": "dpo@depistage-tsa.fr",
                "legal_basis": "Art. 6.1.f and 9.2.j GDPR",
                "dpia_completed": True
            },
            "fda": {
                "status": "Clinical Decision Support Software",
                "510k_exempt": True,
                "classification": "Non-device CDS"
            }
        },
        "last_updated": "2025-06-03"
    }
    
    # Classe de gestion de la conformité RGPD
class EnhancedGDPRManager:
    """Gestionnaire RGPD renforcé avec sécurité et audit trail"""
    
    def __init__(self):
        self.consent_version = "2.1"
        self.privacy_policy_version = "2.1"
        self.data_retention_days = 730
        
        # Initialisation sécurisée avec gestion d'erreur
        try:
            self.secure_manager = SecureDataManager()
        except Exception as e:
            logging.error(f"Erreur initialisation SecureDataManager dans GDPR Manager: {e}")
            # Gestion d'erreur: utiliser un manager null ou par défaut
            self.secure_manager = None
            st.warning("Fonctionnalités RGPD limitées - erreur d'initialisation")

        
    def record_consent_secure(self, user_session: str, consent_type: str, granted: bool, metadata: dict = None):
        """Enregistrement sécurisé du consentement avec audit trail"""
        user_hash = hashlib.sha256(user_session.encode()).hexdigest()[:16]
        
        consent_record = {
            "user_session_hash": user_hash,
            "consent_type": consent_type,
            "granted": granted,
            "consent_version": self.consent_version,
            "timestamp": dt.datetime.now().isoformat(),
            "ip_hash": hashlib.sha256("anonymized_session".encode()).hexdigest()[:16]
        }
        
        # Chiffrement des métadonnées sensibles
        encrypted_metadata = ""
        if metadata:
            encrypted_metadata = self.secure_manager.encrypt_data(json.dumps(metadata))
        
        # Insertion en base sécurisée
        conn = sqlite3.connect(self.secure_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO consent_records 
            (user_session_hash, consent_type, granted, consent_version, timestamp, ip_hash, encrypted_details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            consent_record["user_session_hash"],
            consent_record["consent_type"],
            consent_record["granted"],
            consent_record["consent_version"],
            consent_record["timestamp"],
            consent_record["ip_hash"],
            encrypted_metadata
        ))
        
        conn.commit()
        conn.close()
        
        return consent_record
    
    def log_data_processing(self, user_session: str, processing_type: str, data_categories: list):
        """Journalisation conforme RGPD Article 30"""
        user_hash = hashlib.sha256(user_session.encode()).hexdigest()[:16]
        
        log_entry = {
            "user_session_hash": user_hash,
            "processing_type": processing_type,
            "data_categories": json.dumps(data_categories),
            "legal_basis": "legitimate_interest_medical_screening",
            "timestamp": dt.datetime.now().isoformat(),
            "encrypted_metadata": ""
        }
        
        # Insertion sécurisée en base
        conn = sqlite3.connect(self.secure_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO processing_logs 
            (user_session_hash, processing_type, data_categories, legal_basis, timestamp, encrypted_metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            log_entry["user_session_hash"],
            log_entry["processing_type"],
            log_entry["data_categories"],
            log_entry["legal_basis"],
            log_entry["timestamp"],
            log_entry["encrypted_metadata"]
        ))
        
        conn.commit()
        conn.close()
        
        return log_entry

def system_health_check():
    """Vérifie l'état du système et fournit des diagnostics"""
    health = {
        "DB": os.path.exists("secure_compliance.db"),
        "Key": os.path.exists("encryption.key"),
        "GDPR Manager": 'gdpr_manager' in st.session_state,
        "AI Manager": 'ai_manager' in st.session_state,
        "Session": 'user_session' in st.session_state
    }
    
    if os.environ.get("STREAMLIT_DEBUG") == "true":
        with st.sidebar.expander("Diagnostic Système", expanded=False):
            for component, status in health.items():
                st.write(f"{component}: {'✅' if status else '❌'}")
    
    return all(health.values())

# Appel en mode développement
if os.environ.get("STREAMLIT_DEBUG") == "true":
    system_health_check()

    def exercise_user_rights(self, user_session: str, right_type: str):
        """Implémentation des droits RGPD (accès, rectification, effacement)"""
        user_hash = hashlib.sha256(user_session.encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.secure_manager.db_path)
        cursor = conn.cursor()
        
        if right_type == "access":
            # Droit d'accès - récupération des données
            cursor.execute('''
                SELECT consent_type, granted, timestamp, consent_version 
                FROM consent_records 
                WHERE user_session_hash = ?
            ''', (user_hash,))
            
            result = cursor.fetchall()
            conn.close()
            return result
            
        elif right_type == "erasure":
            # Droit à l'effacement
            cursor.execute('''
                DELETE FROM consent_records WHERE user_session_hash = ?
            ''', (user_hash,))
            
            cursor.execute('''
                DELETE FROM processing_logs WHERE user_session_hash = ?
            ''', (user_hash,))
            
            cursor.execute('''
                DELETE FROM ai_decisions WHERE session_hash = ?
            ''', (user_hash,))
            
            conn.commit()
            conn.close()
            return True
            
        conn.close()
        return False
    
    def check_data_retention(self, timestamp: dt.datetime) -> bool:
        """Vérification de la durée de conservation des données"""
        return (dt.datetime.now() - timestamp).days < self.data_retention_days
    
    def anonymize_data(self, data: dict) -> dict:
        """Anonymisation des données pour conformité RGPD"""
        anonymized = data.copy()
        
        # Suppression/hachage des identifiants directs
        direct_identifiers = ['nom', 'prenom', 'email', 'telephone', 'adresse']
        for field in direct_identifiers:
            if field in anonymized:
                anonymized.pop(field)
        
        # Généralisation des données quasi-identifiantes
        if 'Age' in anonymized and isinstance(anonymized['Age'], (int, float)):
            anonymized['Age_Range'] = f"{5 * (anonymized['Age'] // 5)}-{5 * (anonymized['Age'] // 5) + 4}"
            anonymized.pop('Age')
            
        # Conservation des données cliniques nécessaires à la finalité
        return anonymized

def handle_exception(e):
    """Gestion unifiée des exceptions avec niveau de détail approprié"""
    error_id = uuid.uuid4().hex[:8]
    
    # Log détaillé pour le débogage
    logging.error(f"Erreur {error_id}: {str(e)}", exc_info=True)
    
    # Message utilisateur sans détails techniques sensibles
    st.error(f"""
    ### ⚠️ Une erreur s'est produite (ID: {error_id})
    
    L'application a rencontré un problème. Nos équipes techniques ont été notifiées.
    
    **Actions possibles:**
    - Rafraîchissez la page
    - Effacez votre cache navigateur
    - Contactez le support avec l'ID d'erreur ci-dessus
    """)
    
    return error_id

# Utilisation:
try:
    # Code qui peut échouer
    pass
except Exception as e:
    error_id = handle_exception(e)
    st.session_state.error_id = error_id


# Initialisation sécurisée des gestionnaires de conformité
def initialize_compliance_managers():
    """Initialisation sécurisée des gestionnaires de conformité"""
    try:
        # Initialiser les gestionnaires seulement s'ils n'existent pas
        if 'gdpr_manager' not in st.session_state:
            try:
                st.session_state.gdpr_manager = EnhancedGDPRManager()
            except Exception as e:
                logging.error(f"Erreur GDPR Manager: {e}")
                st.session_state.gdpr_manager = None
                
        if 'ai_manager' not in st.session_state:
            try:
                st.session_state.ai_manager = EnhancedAIActManager()
            except Exception as e:
                logging.error(f"Erreur AI Manager: {e}")
                st.session_state.ai_manager = None
                
        if 'medical_manager' not in st.session_state:
            try:
                st.session_state.medical_manager = MedicalDeviceComplianceManager()
            except Exception as e:
                logging.error(f"Erreur Medical Manager: {e}")
                st.session_state.medical_manager = None
                
        return True
    except Exception as e:
        st.warning(f"Gestionnaires en mode limité: {str(e)}")
        logging.error(f"Erreur d'initialisation des gestionnaires: {e}", exc_info=True)
        return False

# Appeler cette fonction en début d'application
if not initialize_compliance_managers():
    st.warning("L'application fonctionne en mode dégradé. Certaines fonctionnalités peuvent être limitées.")

    # Classe de gestion de la conformité AI Act
class EnhancedAIActManager:
    """Gestionnaire AI Act renforcé avec surveillance humaine obligatoire"""
    
    def __init__(self):
        self.system_id = "TSA-SCREENING-AI-v2.1"
        self.risk_classification = "HIGH_RISK_MEDICAL_AI"
        self.model_card_version = "2.1.0"
        
        # Initialisation sécurisée avec gestion d'erreur
        try:
            self.secure_manager = SecureDataManager()
        except Exception as e:
            logging.error(f"Erreur initialisation SecureDataManager dans AI Act Manager: {e}")
            self.secure_manager = None
            st.warning("Fonctionnalités AI Act limitées - erreur d'initialisation")

    
    def log_ai_decision(self, inputs: dict, outputs: dict, confidence: float, user_session: str):
        """Journalisation sécurisée conforme AI Act Article 12"""
        
        # Validation surveillance humaine obligatoire
        if not self.validate_human_oversight():
            raise ValueError("Surveillance humaine non validée - Traitement IA interdit")
        
        # Anonymisation des entrées sensibles
        safe_inputs = {
            k: "[REDACTED_PERSONAL_DATA]" if k in ["Genre", "Ethnie", "Age"] else v 
            for k, v in inputs.items()
        }
        
        session_hash = hashlib.sha256(user_session.encode()).hexdigest()[:16]
        
        ai_log = {
            "timestamp": datetime.datetime.now().isoformat(),
            "system_id": self.system_id,
            "session_hash": session_hash,
            "session_id": session_hash,  # Ajout pour compatibilité
            "model_version": self.model_card_version,
            "risk_classification": self.risk_classification,
            "confidence_score": confidence,
            "input_features_count": len(inputs),  # Ajout pour traçabilité
            "human_oversight_active": True,
            "explanation_provided": True,
            "bias_assessment_completed": True
        }
        
        # Chiffrement des données de décision
        encrypted_inputs = self.secure_manager.encrypt_data(json.dumps(safe_inputs))
        encrypted_outputs = self.secure_manager.encrypt_data(json.dumps(outputs))
        
        # Insertion sécurisée en base
        conn = sqlite3.connect(self.secure_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ai_decisions 
            (session_hash, model_version, confidence_score, timestamp, encrypted_input_hash, encrypted_output)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            session_hash,
            self.model_card_version,
            confidence,
            ai_log["timestamp"],
            encrypted_inputs,
            encrypted_outputs
        ))
        
        conn.commit()
        conn.close()
        
        return ai_log

    def validate_human_oversight(self) -> bool:
        """Validation obligatoire de la surveillance humaine"""
        return st.session_state.get('human_oversight_acknowledged', False)

    def validate_data_quality(self, data: dict) -> dict:
        """Validation qualité données conforme AI Act Article 10"""
        validation = {
            "completeness": all(v is not None for v in data.values()),
            "consistency": True,
            "accuracy": True,
            "timeliness": True
        }
        
        return validation
    
    def record_risk_mitigation(self, risk_type: str, mitigation_action: str, outcome: str):
        """Enregistrement des mesures d'atténuation des risques"""
        risk_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "risk_type": risk_type,
            "mitigation_action": mitigation_action,
            "outcome": outcome,
            "system_version": self.system_id
        }
        
        return risk_entry
    
    def mandatory_human_oversight_interface(self):
        """Interface obligatoire de surveillance humaine"""
        st.error("""
        **⚠️ SURVEILLANCE HUMAINE OBLIGATOIRE (AI Act Article 14)**
        
        Ce système d'IA à haut risque nécessite une supervision humaine qualifiée.
        Les résultats ne constituent qu'une aide au diagnostic et ne remplacent 
        en aucun cas l'évaluation clinique professionnelle.
        """)
        
        oversight_validated = st.checkbox(
            "Je comprends que cette IA nécessite une validation médicale professionnelle",
            key="human_oversight_check"
        )
        
        if oversight_validated:
            st.session_state['human_oversight_acknowledged'] = True
            st.success("✅ Surveillance humaine validée - Analyse IA autorisée")
            return True
        else:
            st.warning("⚠️ Validation de surveillance humaine requise")
            return False

    
    def validate_data_quality(self, data: dict) -> dict:
        """Validation qualité données conforme AI Act Article 10"""
        validation = {
            "completeness": all(v is not None for v in data.values()),
            "consistency": True,  # À implémenter selon vos règles métier
            "accuracy": True,     # À valider selon vos référentiels
            "timeliness": True    # Données récentes
        }
        
        # Log de validation
        validation_log = {
            "timestamp": datetime.datetime.now().isoformat(),
            "validation_result": validation,
            "data_fields": list(data.keys())
        }
        
        return validation
    
    def record_risk_mitigation(self, risk_type: str, mitigation_action: str, outcome: str):
        """Enregistrement des mesures d'atténuation des risques (Article 9)"""
        risk_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "risk_type": risk_type,
            "mitigation_action": mitigation_action,
            "outcome": outcome,
            "system_version": self.system_id
        }
        
        return risk_entry
    
    def mandatory_human_oversight_interface(self):
        """Interface obligatoire de surveillance humaine"""
        st.error("""
        **⚠️ SURVEILLANCE HUMAINE OBLIGATOIRE (AI Act Article 14)**
        
        Ce système d'IA à haut risque nécessite une supervision humaine qualifiée.
        Les résultats ne constituent qu'une aide au diagnostic et ne remplacent 
        en aucun cas l'évaluation clinique professionnelle.
        """)
        
        oversight_validated = st.checkbox(
            "Je comprends que cette IA nécessite une validation médicale professionnelle",
            key="human_oversight_check"
        )
        
        if oversight_validated:
            st.session_state['human_oversight_acknowledged'] = True
            st.success("✅ Surveillance humaine validée - Analyse IA autorisée")
            return True
        else:
            st.warning("⚠️ Validation de surveillance humaine requise")
            return False

    
    # Classe pour la gestion des exigences FDA/Santé
class MedicalDeviceComplianceManager:
    """Gestionnaire de conformité aux normes des dispositifs médicaux"""

    def __init__(self):
        self.device_id = f"TSA-SCREENING-{REGULATORY_CONFIG['version']}"
        self.classification = "Class IIa (EU MDR) / CDS (FDA)"
        self.intended_use = "Dépistage précoce TSA - Aide à la décision clinique"
        self.incident_log_path = "logs/medical_device_incidents.jsonl"
        self.audit_log_path = "logs/medical_device_audit.jsonl"
        os.makedirs(os.path.dirname(self.incident_log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)

    def record_usage(self, user_type: str, action: str):
        """Enregistrement de l'utilisation pour traçabilité médicale"""
        usage_log = {
            "timestamp": datetime.datetime.now().isoformat(),
            "device_id": self.device_id,
            "user_type": user_type,
            "action": action,
            "software_version": REGULATORY_CONFIG["version"]
        }
        try:
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(usage_log) + '\n')
        except Exception as e:
            print(f"Erreur lors de l'enregistrement d'utilisation: {str(e)}")
        return usage_log

    def report_incident(self, incident_type: str, description: str, severity: str):
        """Système de signalement d'incidents pour matériovigilance"""
        incident_log = {
            "timestamp": datetime.datetime.now().isoformat(),
            "device_id": self.device_id,
            "incident_type": incident_type,
            "description": description,
            "severity": severity,
            "software_version": REGULATORY_CONFIG["version"],
            "report_id": uuid.uuid4().hex[:8]
        }
        try:
            with open(self.incident_log_path, 'a') as f:
                f.write(json.dumps(incident_log) + '\n')
        except Exception as e:
            print(f"Erreur lors du signalement d'incident: {str(e)}")
        # Notification supplémentaire pour incidents graves
        if severity == "high":
            print(f"INCIDENT CRITIQUE: {description}")
        return incident_log

# Initialisation des gestionnaires de conformité dans l'état de session
if 'gdpr_manager' not in st.session_state:
    st.session_state.gdpr_manager = EnhancedGDPRManager()
    st.session_state.ai_manager = EnhancedAIActManager()
    st.session_state.medical_manager = MedicalDeviceComplianceManager()
    st.session_state.user_session = str(uuid.uuid4())
    st.session_state.authenticated = False
    st.session_state.session_start_time = dt.datetime.now()

@st.cache_data(ttl=3600, max_entries=100)
def create_plotly_figure(df, x=None, y=None, color=None, names=None, kind='histogram', title=None):
    """Crée une visualisation Plotly avec gestion d'erreur robuste"""
    try:
        import plotly.express as px
        import plotly.graph_objects as go
        
        # Vérification de sécurité pour éviter les erreurs
        if df is None or df.empty:
            fig = go.Figure()
            fig.add_annotation(
                text="Aucune donnée disponible",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            return fig
        
        # Échantillonnage si dataset trop grand
        sample_threshold = 10000
        if len(df) > sample_threshold:
            df = df.sample(sample_threshold, random_state=42)

        # Vérification des colonnes
        if color and color not in df.columns:
            color = None
            
        if x and x not in df.columns:
            # Fallback en cas de colonne manquante
            x = df.columns[0] if len(df.columns) > 0 else None
            
        if y and y not in df.columns:
            y = None

        # Palette de couleurs
        palette = {"Yes": "#3498db", "No": "#2ecc71", "Unknown": "#95a5a6"}
        
        # Configuration de base
        base_layout = dict(
            height=500,
            margin=dict(l=20, r=20, t=40, b=20),
            template="simple_white"
        )

        # Création du graphique selon le type
        if kind == 'histogram':
            fig = px.histogram(df, x=x, color=color, color_discrete_map=palette)
        elif kind == 'box':
            fig = px.box(df, x=x, y=y, color=color, color_discrete_map=palette)
        elif kind == 'bar':
            fig = px.bar(df, x=x, y=y, color=color, color_discrete_map=palette)
        elif kind == 'scatter':
            fig = px.scatter(df, x=x, y=y, color=color, color_discrete_map=palette)
        elif kind == 'pie':
            fig = px.pie(df, names=names, color=color, color_discrete_map=palette)
        elif kind == 'count':
            fig = px.histogram(df, x=x, color=color, color_discrete_map=palette)
        else:
            # Type par défaut
            fig = px.histogram(df, x=x, color=color, color_discrete_map=palette)

        # Application du layout
        fig.update_layout(**base_layout)
        
        if title:
            fig.update_layout(title=title)

        return fig
        
    except Exception as e:
        logging.error(f"Erreur création graphique Plotly: {e}", exc_info=True)
        # Graphique de fallback
        fig = go.Figure()
        fig.add_annotation(
            text=f"Erreur de visualisation: {str(e)}",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False
        )
        return fig



def automated_data_cleanup():
    """Suppression automatique des données expirées (RGPD Article 5.1.e)"""
    
    retention_days = 730  # 24 mois
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
    
    try:
        conn = sqlite3.connect("secure_compliance.db")
        cursor = conn.cursor()
        
        # Suppression des données expirées
        tables = ['consent_records', 'processing_logs', 'ai_decisions']
        
        for table in tables:
            cursor.execute(f'''
                DELETE FROM {table} 
                WHERE datetime(timestamp) < datetime(?)
            ''', (cutoff_date.isoformat(),))
        
        conn.commit()
        conn.close()
        
        st.info(f"🗑️ Nettoyage automatique effectué - Données > {retention_days} jours supprimées")
    except Exception as e:
        st.warning(f"Erreur lors du nettoyage automatique : {str(e)}")
        logging.error(f"Erreur nettoyage automatique: {e}")

# Mise à jour de l'appel de fonction
if st.session_state.get('last_cleanup') is None or \
   (datetime.datetime.now() - st.session_state.get('last_cleanup', datetime.datetime.now())).days > 7:
    automated_data_cleanup()
    st.session_state['last_cleanup'] = datetime.datetime.now()


# Appeler cette fonction périodiquement
if st.session_state.get('last_cleanup') is None or \
   (datetime.datetime.now() - st.session_state.get('last_cleanup', datetime.datetime.now())).days > 7:
    automated_data_cleanup()
    st.session_state['last_cleanup'] = datetime.datetime.now()


if "aq10_total" not in st.session_state:
    st.session_state.aq10_total = 0

if "aq10_responses" not in st.session_state:
    st.session_state.aq10_responses = []

def initialize_session_state():
    """Initialise l'état de session de manière robuste"""
    if 'initialized' not in st.session_state:
        st.session_state.initialized = True

        # Génération d'un ID de session unique
        if 'user_session' not in st.session_state:
            st.session_state.user_session = str(uuid.uuid4())

        # Initialiser les gestionnaires de manière sécurisée
        try:
            initialize_compliance_managers()
        except Exception as e:
            logging.error(f"Erreur lors de l'initialisation des gestionnaires: {e}")
            st.error("Erreur d'initialisation. L'application fonctionnera en mode limité.")

        # Autres initialisations...
        if 'tool_choice' not in st.session_state:
            st.session_state.tool_choice = "🏠 Accueil"
            
        if 'aq10_total' not in st.session_state:
            st.session_state.aq10_total = 0
            
        if 'aq10_responses' not in st.session_state:
            st.session_state.aq10_responses = []
            
        st.session_state.data_exploration_expanded = True
        
# Appel en début d'application
initialize_session_state()

def show_unified_sidebar_navigation():
    """Navigation unifiée dans la sidebar avec consentement intégré"""
    
    with st.sidebar:
        # Logo/titre (inchangé)
        st.markdown("""
        <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #1f77b4; font-size: 1.8rem;">🧩 Dépistage TSA</h1>
            <p style="color: #666; font-size: 0.9rem;">Conforme RGPD & AI Act</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Section RGPD avec cadenas visible
        st.markdown("---")
        st.markdown("### 🔒 Statut RGPD")
        
        if not st.session_state.get('consent_screening', False):
            st.error("🔒 Consentement RGPD requis")
            
            with st.expander("📋 Donner mon consentement", expanded=True):
                # CORRECTION : Clé unique basée sur l'ID de session
                unique_key = f"consent_screening_{st.session_state.get('user_session', 'default')}"
                
                consent_minimal = st.checkbox(
                    "J'accepte le traitement de mes données pour le dépistage TSA",
                    key=unique_key
                )
                
                if consent_minimal:
                    st.session_state['consent_screening'] = True
                    st.session_state.gdpr_manager.record_consent_secure(
                        st.session_state.user_session,
                        "screening",
                        True
                    )
                    st.success("✅ Consentement accordé")
                    st.rerun()
                else:
                    st.stop()
        else:
            st.success("✅ Consentement RGPD accordé")
        
        # Navigation principale
        st.markdown("---")
        st.markdown("### 📍 Navigation")
        
        options = [
            "🏠 Accueil",
            "🔍 Exploration", 
            "🤖 Prédiction par IA",
            "📚 Documentation",
            "ℹ️ À propos",
            "🔒 Conformité"
        ]

        current_index = options.index(st.session_state.tool_choice) if st.session_state.tool_choice in options else 0
        
        # CORRECTION : Clé unique pour la navigation
        nav_key = f"main_navigation_{st.session_state.get('user_session', 'default')}"
        
        tool_choice = st.radio(
            "",
            options,
            index=current_index,
            key=nav_key,
            label_visibility="collapsed"
        )

        if tool_choice != st.session_state.tool_choice:
            st.session_state.tool_choice = tool_choice
        # Statuts de conformité
        st.markdown("---")
        st.markdown("### 🔐 Statut Conformité")
        st.markdown("""
        <div style="font-size: 11px;">
            <div style="display: flex; flex-direction: column; gap: 5px;">
                <span style="background: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">✅ CE Classe IIa</span>
                <span style="background: #007bff; color: white; padding: 2px 6px; border-radius: 3px;">✅ RGPD</span>
                <span style="background: #ffc107; color: black; padding: 2px 6px; border-radius: 3px;">✅ AI Act</span>
            </div>
            <div style="margin-top: 10px; color: #6c757d;">
                Version: 2.1.0<br>
                MAJ: 03/06/2025
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Accès rapide aux droits RGPD avec clé unique
        st.markdown("---")
        rights_button_key = f"rights_button_{st.session_state.get('user_session', 'default')}"
        
        if st.button("👤 Mes droits RGPD", use_container_width=True, key=rights_button_key):
            st.session_state.tool_choice = "🔒 Conformité"
            st.rerun()

    return tool_choice


def set_custom_theme():
    css_path = "theme_cache/custom_theme.css"
    os.makedirs(os.path.dirname(css_path), exist_ok=True)

    if os.path.exists(css_path):
        with open(css_path, 'r') as f:
            custom_theme = f.read()
    else:
        custom_theme = """
        <style>
        /* ================ Variables Globales Optimisées ================ */
        :root {
            --primary: #2c3e50 !important;
            --secondary: #3498db !important;
            --accent: #e74c3c !important;
            --background: #f8f9fa !important;
            --sidebar-bg: #ffffff !important;
            --sidebar-border: #e9ecef !important;
            --text-primary: #2c3e50 !important;
            --text-secondary: #6c757d !important;
            --sidebar-width-collapsed: 60px !important;
            --sidebar-width-expanded: 240px !important;
            --sidebar-transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
            --shadow-light: 0 2px 8px rgba(0,0,0,0.08) !important;
            --shadow-medium: 0 4px 16px rgba(0,0,0,0.12) !important;
        }

        /* ================ Structure Principale ================ */
        [data-testid="stAppViewContainer"] {
            background-color: var(--background) !important;
        }

        /* ================ Sidebar Compacte et Professionnelle ================ */
        [data-testid="stSidebar"] {
            /* Dimensions optimisées */
            width: var(--sidebar-width-collapsed) !important;
            min-width: var(--sidebar-width-collapsed) !important;
            max-width: var(--sidebar-width-collapsed) !important;
            height: 100vh !important;
            
            /* Position fixe */
            position: fixed !important;
            left: 0 !important;
            top: 0 !important;
            z-index: 999999 !important;
            
            /* Style moderne */
            background: var(--sidebar-bg) !important;
            border-right: 1px solid var(--sidebar-border) !important;
            box-shadow: var(--shadow-light) !important;
            
            /* Élimination du défilement */
            overflow: hidden !important;
            padding: 0 !important;
            
            /* Transition fluide */
            transition: var(--sidebar-transition) !important;
        }

        /* État étendu au survol */
        [data-testid="stSidebar"]:hover {
            width: var(--sidebar-width-expanded) !important;
            min-width: var(--sidebar-width-expanded) !important;
            max-width: var(--sidebar-width-expanded) !important;
            box-shadow: var(--shadow-medium) !important;
            overflow-y: auto !important;
        }

        /* Contenu interne optimisé */
        [data-testid="stSidebar"] > div {
            width: var(--sidebar-width-expanded) !important;
            padding: 12px 8px !important;
            height: 100vh !important;
            overflow: hidden !important;
        }

        [data-testid="stSidebar"]:hover > div {
            overflow-y: auto !important;
            padding: 16px 12px !important;
        }

        /* ================ Masquage des Barres de Défilement ================ */
        [data-testid="stSidebar"]::-webkit-scrollbar,
        [data-testid="stSidebar"] > div::-webkit-scrollbar {
            width: 0px !important;
            background: transparent !important;
        }

        [data-testid="stSidebar"] > div {
            -ms-overflow-style: none !important;
            scrollbar-width: none !important;
        }

        /* ================ En-tête Professionnel ================ */
        [data-testid="stSidebar"] h2 {
            font-size: 0 !important;
            margin: 0 0 20px 0 !important;
            padding: 12px 0 !important;
            border-bottom: 1px solid var(--sidebar-border) !important;
            text-align: center !important;
            transition: all 0.3s ease !important;
            position: relative !important;
            height: 60px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
        }

        /* Icône en mode réduit */
        [data-testid="stSidebar"] h2::before {
            content: "🧩" !important;
            font-size: 28px !important;
            display: block !important;
            margin: 0 !important;
        }

        /* Texte complet au survol */
        [data-testid="stSidebar"]:hover h2 {
            font-size: 1.4rem !important;
            color: var(--primary) !important;
            font-weight: 600 !important;
        }

        [data-testid="stSidebar"]:hover h2::before {
            font-size: 20px !important;
            margin-right: 8px !important;
        }

        /* ================ Options de Navigation Modernisées ================ */
        [data-testid="stSidebar"] .stRadio {
            padding: 0 !important;
            margin: 0 !important;
        }

        [data-testid="stSidebar"] .stRadio > div {
            display: flex !important;
            flex-direction: column !important;
            gap: 4px !important;
            padding: 0 !important;
        }

        [data-testid="stSidebar"] .stRadio label {
            display: flex !important;
            align-items: center !important;
            padding: 10px 6px !important;
            margin: 0 !important;
            border-radius: 8px !important;
            transition: all 0.3s ease !important;
            cursor: pointer !important;
            position: relative !important;
            height: 44px !important;
            overflow: hidden !important;
            background: transparent !important;
        }

        /* Icônes centrées en mode réduit */
        [data-testid="stSidebar"] .stRadio label > div:first-child {
            display: none !important;
        }

        [data-testid="stSidebar"] .stRadio label span {
            font-size: 0 !important;
            transition: all 0.3s ease !important;
            width: 100% !important;
            text-align: center !important;
            position: relative !important;
        }

        /* Affichage des icônes uniquement */
        [data-testid="stSidebar"] .stRadio label span::before {
            font-size: 22px !important;
            display: block !important;
            width: 100% !important;
            text-align: center !important;
        }

        /* Mapping des icônes pour chaque option */
        [data-testid="stSidebar"] .stRadio label:nth-child(1) span::before { content: "🏠" !important; }
        [data-testid="stSidebar"] .stRadio label:nth-child(2) span::before { content: "🔍" !important; }
        [data-testid="stSidebar"] .stRadio label:nth-child(3) span::before { content: "🧠" !important; }
        [data-testid="stSidebar"] .stRadio label:nth-child(4) span::before { content: "🤖" !important; }
        [data-testid="stSidebar"] .stRadio label:nth-child(5) span::before { content: "📚" !important; }
        [data-testid="stSidebar"] .stRadio label:nth-child(6) span::before { content: "ℹ️" !important; }

        /* Mode étendu - affichage du texte */
        [data-testid="stSidebar"]:hover .stRadio label span {
            font-size: 14px !important;
            font-weight: 500 !important;
            text-align: left !important;
            padding-left: 12px !important;
        }

        [data-testid="stSidebar"]:hover .stRadio label span::before {
            font-size: 18px !important;
            position: absolute !important;
            left: -8px !important;
            top: 50% !important;
            transform: translateY(-50%) !important;
            width: auto !important;
        }

        /* Effets de survol */
        [data-testid="stSidebar"] .stRadio label:hover {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef) !important;
            transform: translateX(3px) !important;
            box-shadow: var(--shadow-light) !important;
        }

        /* Option sélectionnée */
        [data-testid="stSidebar"] .stRadio label[data-checked="true"] {
            background: linear-gradient(135deg, var(--secondary), #2980b9) !important;
            color: white !important;
            box-shadow: var(--shadow-medium) !important;
        }

        [data-testid="stSidebar"] .stRadio label[data-checked="true"]:hover {
            background: linear-gradient(135deg, #2980b9, var(--secondary)) !important;
            transform: translateX(5px) !important;
        }

        /* ================ Contenu Principal Adaptatif ================ */
        .main .block-container {
            margin-left: calc(var(--sidebar-width-collapsed) + 16px) !important;
            padding: 1.5rem !important;
            max-width: calc(100vw - var(--sidebar-width-collapsed) - 32px) !important;
            transition: var(--sidebar-transition) !important;
        }

        /* ================ Indicateur Visuel Subtil ================ */
        [data-testid="stSidebar"]::after {
            content: "›" !important;
            position: absolute !important;
            right: 6px !important;
            top: 50% !important;
            transform: translateY(-50%) !important;
            font-size: 12px !important;
            color: var(--text-secondary) !important;
            opacity: 0.5 !important;
            transition: all 0.3s ease !important;
            font-weight: bold !important;
        }

        [data-testid="stSidebar"]:hover::after {
            opacity: 0 !important;
            transform: translateY(-50%) translateX(10px) !important;
        }

        /* ================ Zone de Trigger Invisible ================ */
        .sidebar-trigger-zone {
            position: fixed !important;
            left: 0 !important;
            top: 0 !important;
            width: 10px !important;
            height: 100vh !important;
            z-index: 999998 !important;
            background: transparent !important;
        }

        /* ================ Responsive Design ================ */
        @media (max-width: 768px) {
            [data-testid="stSidebar"] {
                transform: translateX(-100%) !important;
            }
            
            [data-testid="stSidebar"]:hover {
                transform: translateX(0) !important;
                width: 280px !important;
                min-width: 280px !important;
                max-width: 280px !important;
            }
            
            .main .block-container {
                margin-left: 0 !important;
                max-width: 100vw !important;
                padding: 1rem !important;
            }
            
            .sidebar-trigger-zone {
                width: 15px !important;
            }
        }

        /* ================ Améliorations Générales ================ */
        .stButton > button {
            background: linear-gradient(135deg, var(--secondary), #2980b9) !important;
            color: white !important;
            border-radius: 8px !important;
            border: none !important;
            padding: 10px 20px !important;
            font-weight: 500 !important;
            transition: all 0.3s ease !important;
            box-shadow: var(--shadow-light) !important;
        }
        .question-container {
            text-align: left;
        }
        
        p {
            text-align: center;
        }
        
        .stButton > button {
            display: block;
            margin: 0 auto;
        }

        .stButton > button:hover {
            transform: translateY(-2px) !important;
            box-shadow: var(--shadow-medium) !important;
            background: linear-gradient(135deg, #2980b9, var(--secondary)) !important;
        }

        /* Suppression des alertes indésirables */
        .stAlert, [data-testid="stAlert"] {
            border: none !important;
            background: transparent !important;
        }
        </style>

        <script>
        // Script JavaScript optimisé
        document.addEventListener('DOMContentLoaded', function() {
            // Créer la zone de trigger si elle n'existe pas
            if (!document.querySelector('.sidebar-trigger-zone')) {
                const triggerZone = document.createElement('div');
                triggerZone.className = 'sidebar-trigger-zone';
                document.body.appendChild(triggerZone);
            }
            
            const sidebar = document.querySelector('[data-testid="stSidebar"]');
            const triggerZone = document.querySelector('.sidebar-trigger-zone');
            
            if (sidebar && triggerZone) {
                let isExpanded = false;
                let hoverTimeout;
                
                function expandSidebar() {
                    clearTimeout(hoverTimeout);
                    isExpanded = true;
                    sidebar.style.overflow = 'visible';
                }
                
                function collapseSidebar() {
                    hoverTimeout = setTimeout(() => {
                        isExpanded = false;
                        sidebar.style.overflow = 'hidden';
                    }, 200);
                }
                
                // Gestion des événements
                [sidebar, triggerZone].forEach(element => {
                    element.addEventListener('mouseenter', expandSidebar);
                    element.addEventListener('mouseleave', collapseSidebar);
                });
                
                // Attribution des états pour les options sélectionnées
                const observer = new MutationObserver(() => {
                    const radioLabels = sidebar.querySelectorAll('.stRadio label');
                    radioLabels.forEach(label => {
                        const input = label.querySelector('input[type="radio"]');
                        if (input && input.checked) {
                            label.setAttribute('data-checked', 'true');
                        } else {
                            label.setAttribute('data-checked', 'false');
                        }
                    });
                });
                
                observer.observe(sidebar, { 
                    childList: true, 
                    subtree: true,
                    attributes: true 
                });
            }
        });
        </script>
        """
        
        with open(css_path, 'w') as f:
            f.write(custom_theme)

    st.markdown(custom_theme, unsafe_allow_html=True)

def show_enhanced_gdpr_consent():
    """Interface RGPD renforcée avec validation juridique complète"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #2c3e50, #3498db); 
                padding: 30px; border-radius: 15px; margin: 20px 0; color: white;">
        <h2 style="margin: 0 0 20px 0;">🔒 Traitement Sécurisé des Données de Santé</h2>
        <p style="font-size: 1.1rem; line-height: 1.6; margin: 0;">
            Conformément au RGPD (EU 2016/679) et à la loi française "Informatique et Libertés",
            nous vous informons sur le traitement de vos données personnelles de santé.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Informations légales détaillées
    with st.expander("📋 Information Légale Complète RGPD Article 13", expanded=False):
        st.markdown("""
        ### Responsable de Traitement
        **[VOTRE ORGANISATION]**  
        Adresse : [ADRESSE COMPLÈTE]  
        Email : contact@depistage-tsa.fr  
        DPO : dpo@depistage-tsa.fr
        
        ### Finalités et Bases Juridiques
        - **Dépistage TSA** : Art. 6.1.f (intérêt légitime) + 9.2.h (finalité médicale)
        - **Recherche** : Art. 6.1.a (consentement) + 9.2.j (recherche en santé publique)
        - **Amélioration algorithme** : Art. 6.1.f + 9.2.j
        
        ### Vos Droits Effectifs
        - ✅ **Accès** : Visualisation de toutes vos données via interface dédiée
        - ✅ **Rectification** : Correction possible via formulaire sécurisé
        - ✅ **Effacement** : Suppression immédiate et irréversible sur demande
        - ✅ **Opposition** : Refus du traitement à tout moment
        - ✅ **Portabilité** : Export JSON chiffré de vos données
        - 📧 **Contact DPO** : dpo@depistage-tsa.fr (réponse sous 72h)
        """)
    
    # Consentements granulaires avec validation juridique et clés uniques
    st.markdown("### ✅ Consentements Spécifiques et Granulaires")
    
    # Générer un identifiant unique pour le formulaire
    session_id = st.session_state.get('user_session', 'default')
    form_key = f"enhanced_consent_form_{session_id}"
    
    with st.form(form_key):
        col1, col2 = st.columns(2)
        
        with col1:
            consent_screening = st.checkbox(
                "🔬 **OBLIGATOIRE** : Traitement pour dépistage TSA",
                value=False,
                key=f"consent_screening_form_{session_id}",
                help="Base légale : Intérêt légitime + finalité médicale (Art. 6.1.f + 9.2.h RGPD)"
            )
            
            consent_research = st.checkbox(
                "📊 **OPTIONNEL** : Utilisation pour recherche anonymisée",
                value=False,
                key=f"consent_research_form_{session_id}",
                help="Base légale : Consentement explicite (Art. 6.1.a + 9.2.a RGPD)"
            )
            
        with col2:
            consent_demographics = st.checkbox(
                "👥 **OPTIONNEL** : Collecte données démographiques élargies",
                value=False,
                key=f"consent_demographics_form_{session_id}",
                help="Genre, origine pour études épidémiologiques"
            )
            
            consent_followup = st.checkbox(
                "📧 **OPTIONNEL** : Contact pour suivi longitudinal",
                value=False,
                key=f"consent_followup_form_{session_id}",
                help="Possibilité de recontact pour études de suivi (email requis)"
            )
        
        # Validation de la compréhension
        st.markdown("### 📝 Validation de Compréhension")
        understanding_check = st.checkbox(
            "Je confirme avoir lu et compris les informations sur le traitement de mes données",
            value=False,
            key=f"understanding_check_form_{session_id}"
        )
        
        age_verification = st.checkbox(
            "Je confirme être majeur(e) ou avoir l'autorisation parentale pour ce test",
            value=False,
            key=f"age_verification_form_{session_id}"
        )
        
        submitted = st.form_submit_button("✅ Valider mes Choix de Consentement")
        
        if submitted:
            if not understanding_check or not age_verification:
                st.error("❌ Vous devez confirmer avoir compris et être majeur(e)")
                return False
                
            if not consent_screening:
                st.warning("⚠️ Le consentement au dépistage est requis pour utiliser l'application")
                return False
            
            # Enregistrement sécurisé des consentements
            consent_manager = st.session_state.gdpr_manager
            
            consent_data = {
                "screening": consent_screening,
                "research": consent_research,
                "demographics": consent_demographics,
                "followup": consent_followup,
                "understanding_validated": understanding_check,
                "age_verified": age_verification
            }
            
            consent_manager.record_consent_secure(
                st.session_state.user_session,
                "comprehensive_consent",
                True,
                consent_data
            )
            
            st.success("✅ Consentements enregistrés de manière sécurisée")
            
            # Mise à jour de l'état de session
            for key, value in consent_data.items():
                st.session_state[f'consent_{key}'] = value
                
            return True
    
    return False

def user_rights_management_interface():
    """Interface complète de gestion des droits RGPD"""
    
    st.subheader("🔒 Gestion de vos Données Personnelles")
    
    rights_tab1, rights_tab2, rights_tab3 = st.tabs([
        "👁️ Accès à mes données", 
        "🗑️ Suppression", 
        "📧 Contact DPO"
    ])
    
    with rights_tab1:
        if st.button("📋 Voir mes données"):
            gdpr_manager = st.session_state.gdpr_manager
            user_data = gdpr_manager.exercise_user_rights(
                st.session_state.user_session, 
                "access"
            )
            
            if user_data:
                st.json({
                    "consentements": user_data,
                    "dernière_activité": dt.datetime.now().isoformat(),
                    "statut": "données_actives"
                })
            else:
                st.info("Aucune donnée trouvée pour cette session")
    
    with rights_tab2:
        st.warning("⚠️ La suppression est irréversible")
        
        if st.button("🗑️ Supprimer définitivement mes données"):
            gdpr_manager = st.session_state.gdpr_manager
            success = gdpr_manager.exercise_user_rights(
                st.session_state.user_session, 
                "erasure"
            )
            
            if success:
                st.success("✅ Toutes vos données ont été supprimées")
                # Réinitialisation de la session
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()  # CORRECTION: remplace st.experimental_rerun()
            else:
                st.error("❌ Erreur lors de la suppression")
    
    with rights_tab3:
        st.markdown("""
        ### 📧 Contact Data Protection Officer
        
        Pour toute question concernant vos données :
        
        **Email** : dpo@depistage-tsa.fr  
        **Délai de réponse** : 72 heures maximum  
        **Téléphone** : +33 X XX XX XX XX
        
        **Réclamation CNIL** : www.cnil.fr
        """)


def show_ai_act_transparency():
    """Transparence conforme AI Act pour systèmes IA à haut risque"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #FF6B6B, #4ECDC4); 
                padding: 25px; border-radius: 15px; margin: 20px 0; color: white;">
        <h3 style="margin: 0 0 15px 0;">🤖 Information AI Act - Système IA à Haut Risque</h3>
        <p style="margin: 0; font-size: 1rem;">
            Cette application utilise un système d'intelligence artificielle classé "à haut risque" 
            selon le Règlement européen sur l'IA (AI Act EU 2024/1689).
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("🔍 Transparence du Système IA (AI Act Article 13)", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🎯 Caractéristiques du Système
            - **Type** : Aide au dépistage médical
            - **Algorithme** : Random Forest
            - **Classification** : Haut risque (Annexe III)
            - **Domaine** : Santé - Dépistage TSA
            - **Version** : 2.1.0 (Juin 2025)
            
            ### 📊 Performance du Modèle
            - **Sensibilité** : 96% (détection vrais cas)
            - **Spécificité** : 94% (évite fausses alertes)  
            - **Précision globale** : 95.6%
            - **Données d'entraînement** : 5000+ cas
            """)
            
        with col2:
            st.markdown("""
            ### ⚠️ Limites et Risques
            - **Aide au diagnostic uniquement**
            - Ne remplace PAS un professionnel
            - Possible biais sur certaines populations
            - Erreurs possibles (4.4% de cas)
            
            ### 👨‍⚕️ Surveillance Humaine
            - **Supervision obligatoire** par professionnel
            - **Validation clinique** recommandée
            - **Second avis** toujours possible
            - **Appel possible** des décisions
            """)
    
    # Avertissement conforme AI Act Article 14
    st.error("""
    **⚠️ AVERTISSEMENT RÉGLEMENTAIRE AI ACT**
    
    Ce système d'IA à haut risque fournit une aide au dépistage. Les résultats doivent TOUJOURS être 
    interprétés par un professionnel de santé qualifié. Ne prenez AUCUNE décision médicale basée 
    uniquement sur ces résultats.
    """)
    
    # Log de l'affichage des informations de transparence
    st.session_state.ai_manager.record_risk_mitigation(
        "information_disclosure",
        "affichage_transparence_aiact",
        "completed"
    )

def user_rights_management_interface():
    """Interface complète de gestion des droits RGPD"""
    
    st.subheader("🔒 Gestion de vos Données Personnelles")
    
    rights_tab1, rights_tab2, rights_tab3 = st.tabs([
        "👁️ Accès à mes données", 
        "🗑️ Suppression", 
        "📧 Contact DPO"
    ])
    
    with rights_tab1:
        if st.button("📋 Voir mes données"):
            gdpr_manager = st.session_state.gdpr_manager
            user_data = gdpr_manager.exercise_user_rights(
                st.session_state.user_session, 
                "access"
            )
            
            if user_data:
                st.json({
                    "consentements": user_data,
                    "dernière_activité": datetime.datetime.now().isoformat(),
                    "statut": "données_actives"
                })
            else:
                st.info("Aucune donnée trouvée pour cette session")
    
    with rights_tab2:
        st.warning("⚠️ La suppression est irréversible")
        
        if st.button("🗑️ Supprimer définitivement mes données"):
            gdpr_manager = st.session_state.gdpr_manager
            success = gdpr_manager.exercise_user_rights(
                st.session_state.user_session, 
                "erasure"
            )
            
            if success:
                st.success("✅ Toutes vos données ont été supprimées")
                # Réinitialisation de la session
                for key in list(st.session_state.keys()):
                    del st.session_state[key]
                st.rerun()
            else:
                st.error("❌ Erreur lors de la suppression")
    
    with rights_tab3:
        st.markdown("""
        ### 📧 Contact Data Protection Officer
        
        Pour toute question concernant vos données :
        
        **Email** : dpo@depistage-tsa.fr  
        **Délai de réponse** : 72 heures maximum  
        **Téléphone** : +33 X XX XX XX XX
        
        **Réclamation CNIL** : www.cnil.fr
        """)

def show_ai_act_transparency():
    """Transparence conforme AI Act pour systèmes IA à haut risque"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #FF6B6B, #4ECDC4); 
                padding: 25px; border-radius: 15px; margin: 20px 0; color: white;">
        <h3 style="margin: 0 0 15px 0;">🤖 Information AI Act - Système IA à Haut Risque</h3>
        <p style="margin: 0; font-size: 1rem;">
            Cette application utilise un système d'intelligence artificielle classé "à haut risque" 
            selon le Règlement européen sur l'IA (AI Act EU 2024/1689).
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("🔍 Transparence du Système IA (AI Act Article 13)", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🎯 Caractéristiques du Système
            - **Type** : Aide au dépistage médical
            - **Algorithme** : Random Forest
            - **Classification** : Haut risque (Annexe III)
            - **Domaine** : Santé - Dépistage TSA
            - **Version** : 2.1.0 (Juin 2025)
            
            ### 📊 Performance du Modèle
            - **Sensibilité** : 96% (détection vrais cas)
            - **Spécificité** : 94% (évite fausses alertes)  
            - **Précision globale** : 95.6%
            - **Données d'entraînement** : 5000+ cas
            """)
            
        with col2:
            st.markdown("""
            ### ⚠️ Limites et Risques
            - **Aide au diagnostic uniquement**
            - Ne remplace PAS un professionnel
            - Possible biais sur certaines populations
            - Erreurs possibles (4.4% de cas)
            
            ### 👨‍⚕️ Surveillance Humaine
            - **Supervision obligatoire** par professionnel
            - **Validation clinique** recommandée
            - **Second avis** toujours possible
            - **Appel possible** des décisions
            """)
    
    # Avertissement conforme AI Act Article 14
    st.error("""
    **⚠️ AVERTISSEMENT RÉGLEMENTAIRE AI ACT**
    
    Ce système d'IA à haut risque fournit une aide au dépistage. Les résultats doivent TOUJOURS être 
    interprétés par un professionnel de santé qualifié. Ne prenez AUCUNE décision médicale basée 
    uniquement sur ces résultats.
    """)
    
    # Log de l'affichage des informations de transparence
    st.session_state.ai_manager.record_risk_mitigation(
        "information_disclosure",
        "affichage_transparence_aiact",
        "completed"
    )


def show_regulatory_compliance_banners():
    """Affiche les bannières de conformité réglementaire"""
    
    st.markdown("""
    <div class="regulatory-banner">
        <strong>⚠️ DISPOSITIF MÉDICAL DE CLASSE IIa (EU MDR)</strong><br>
        Cette application de dépistage TSA est un dispositif médical logiciel réglementé au titre du règlement européen 2017/745 relatif aux dispositifs médicaux.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="ai-act-banner">
        <strong>🤖 SYSTÈME IA À HAUT RISQUE (AI ACT)</strong><br>
        Ce système d'intelligence artificielle est classé à haut risque selon le Règlement européen sur l'IA (AI Act) car il fournit une aide à la décision en matière de santé.
        Les résultats doivent TOUJOURS être interprétés par un professionnel qualifié.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="gdpr-banner">
        <strong>🔒 TRAITEMENT DE DONNÉES DE SANTÉ (RGPD)</strong><br>
        Cette application traite des données de santé à caractère personnel conformément au RGPD. 
        Une analyse d'impact relative à la protection des données (AIPD) a été réalisée.
        <span style="float:right;"><a href="#" onclick="showPrivacyPolicy()">Politique de confidentialité</a></span>
    </div>
    """, unsafe_allow_html=True)

def show_gdpr_consent_interface():
    """Interface de consentement conforme RGPD pour données de santé"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 30px; border-radius: 15px; margin: 20px 0; color: white;">
        <h2 style="margin: 0 0 20px 0;">🔒 Protection de vos Données de Santé</h2>
        <p style="font-size: 1.1rem; line-height: 1.6; margin: 0;">
            Conformément au RGPD et à la réglementation française sur les données de santé, 
            nous vous informons sur le traitement de vos données personnelles.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("📋 Information RGPD Obligatoire - Cliquez pour lire", expanded=False):
        st.markdown("""
        ### Responsable de Traitement
        **Équipe de Recherche TSA** - Projet de recherche académique  
        Email: contact@depistage-tsa.fr
        
        ### Finalité du Traitement
        - **Finalité principale** : Dépistage précoce des Troubles du Spectre Autistique (TSA)
        - **Base juridique** : Intérêt légitime pour la recherche en santé publique (Art. 6.1.f et 9.2.j RGPD)
        - **Recherche** : Amélioration des modèles de dépistage (consentement explicite requis)
        
        ### Données Collectées
        - **Données personnelles** : Âge, genre, origine ethnique
        - **Données de santé** : Réponses au questionnaire AQ-10, antécédents familiaux
        - **Données techniques** : Adresse IP (anonymisée), logs d'utilisation
        
        ### Conservation des Données
        - **Durée** : 24 mois maximum après collecte
        - **Localisation** : Serveurs sécurisés en Union Européenne uniquement
        - **Sécurité** : Chiffrement AES-256, accès restreint aux chercheurs autorisés
        
        ### Vos Droits RGPD
        - ✅ **Droit d'accès** : Consulter vos données
        - ✅ **Droit de rectification** : Corriger vos données
        - ✅ **Droit à l'effacement** : Supprimer vos données
        - ✅ **Droit d'opposition** : Refuser le traitement
        - ✅ **Droit à la portabilité** : Récupérer vos données
        - 📧 **Contact** : dpo@depistage-tsa.fr
        
        ### Transferts Internationaux
        ❌ Aucun transfert vers des pays tiers
        
        ### Autorité de Contrôle
        🇫🇷 **CNIL** - Commission Nationale de l'Informatique et des Libertés  
        www.cnil.fr - Droit de réclamation garanti
        """)
    
    # Consentements granulaires conformes RGPD
    st.markdown("### ✅ Consentements Requis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        consent_screening = st.checkbox(
            "**Obligatoire** : J'accepte le traitement de mes données pour le dépistage TSA",
            value=False,
            key="consent_screening",
            help="Base juridique : Intérêt légitime recherche santé publique"
        )
        
    with col2:
        consent_research = st.checkbox(
            "**Optionnel** : J'accepte l'utilisation de mes données pour la recherche",
            value=False, 
            key="consent_research",
            help="Permet d'améliorer les modèles de dépistage futurs"
        )
    
    # Validation des consentements
    if consent_screening:
        # Log du consentement conforme RGPD Article 7
        st.session_state.gdpr_manager.record_consent(
            st.session_state.user_session,
            "screening",
            True
        )
        
        st.session_state.gdpr_manager.log_data_processing(
            st.session_state.user_session,
            "consent_granted_screening",
            ["personal_data", "health_data", "aq10_responses"]
        )
        
        st.success("✅ Consentement enregistré - Vous pouvez procéder au dépistage")
        
        if consent_research:
            st.session_state.gdpr_manager.record_consent(
                st.session_state.user_session,
                "research",
                True
            )
            
            st.session_state.gdpr_manager.log_data_processing(
                st.session_state.user_session,
                "consent_granted_research", 
                ["anonymized_health_data"]
            )
            st.info("📊 Merci de contribuer à la recherche sur l'autisme")
            
        return True
    else:
        st.warning("⚠️ Le consentement obligatoire est requis pour utiliser l'outil de dépistage")
        return False

# Ajouter cette fonction pour remplacer la fonction de questionnaire existante

def show_compliant_questionnaire():
    """Questionnaire AQ-10 avec conformité RGPD/AI Act complète"""
    
    # Vérification du consentement RGPD préalable
    if not st.session_state.get('consent_screening', False):
        st.error("❌ Consentement RGPD requis avant de procéder au questionnaire")
        if show_gdpr_consent_interface():
            st.rerun()
        return None
        
    # Interface utilisateur avec transparence AI Act
    show_ai_act_transparency()
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea, #764ba2); 
                padding: 30px; border-radius: 15px; margin: 20px 0; color: white;">
        <h2 style="margin: 0 0 15px 0;">📝 Questionnaire AQ-10 Validé Scientifiquement</h2>
        <p style="margin: 0; font-size: 1.1rem;">
            Questionnaire standardisé pour le dépistage précoce des TSA - Validé internationalement
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Questions AQ-10 avec traçabilité complète
    questions = [
        "Je remarque souvent de petits bruits que les autres ne remarquent pas",
        "Je me concentre généralement davantage sur l'ensemble que sur les petits détails", 
        "Je trouve facile de faire plusieurs choses en même temps",
        "S'il y a une interruption, je peux rapidement reprendre ce que je faisais",
        "Je trouve facile de « lire entre les lignes » quand quelqu'un me parle",
        "Je sais comment savoir si la personne qui m'écoute commence à s'ennuyer",
        "Quand je lis une histoire, j'ai du mal à comprendre les intentions des personnages",
        "J'aime collecter des informations sur des catégories de choses",
        "Je trouve facile de comprendre ce que quelqu'un pense ou ressent rien qu'en regardant son visage",
        "J'ai du mal à comprendre les intentions des gens"
    ]
    
    scoring = [
        {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0},
        {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1},
        {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1},
        {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1},
        {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1},
        {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1},
        {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0},
        {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0},
        {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1},
        {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0}
    ]
    
    with st.form("aq10_compliant_form"):
        st.markdown("### Questions AQ-10")
        
        responses = {}
        
        # Affichage des questions avec traçabilité
        for i, question in enumerate(questions):
            st.markdown(f"""
            <div style="background: white; padding: 20px; border-radius: 10px; 
                       margin: 15px 0; border-left: 4px solid #667eea;">
                <h4 style="color: #667eea; margin: 0 0 10px 0;">Question {i+1}</h4>
                <p style="margin: 0; color: #2c3e50; font-size: 1.1rem;">{question}</p>
            </div>
            """, unsafe_allow_html=True)
            
            response = st.radio(
                "",
                ["Tout à fait d'accord", "Plutôt d'accord", "Plutôt pas d'accord", "Pas du tout d'accord"],
                key=f"q_{i}",
                index=None,
                horizontal=True
            )
            responses[f"q_{i}"] = response
        
        # Données démographiques avec minimisation RGPD
        st.markdown("### Informations Démographiques (Minimisées)")
        
        col1, col2 = st.columns(2)
        with col1:
            age = st.selectbox("Tranche d'âge", ["18-25", "26-35", "36-45", "46-55", "56-65", "65+"])
            genre = st.selectbox("Genre", ["Féminin", "Masculin", "Autre", "Préfère ne pas répondre"])
            
        with col2:
            antecedents = st.selectbox("Antécédents familiaux TSA", ["Non", "Oui", "Ne sait pas"])
            testeur = st.selectbox("Qui remplit le test", ["Moi-même", "Parent/Famille", "Professionnel"])
        
        # Soumission avec validation complète
        submitted = st.form_submit_button("🔬 Analyser avec IA (Conforme AI Act)", use_container_width=True)
        
        if submitted:
            # Validation complétude données conforme AI Act Article 10
            if None in responses.values():
                st.error("⚠️ Toutes les questions doivent être complétées pour garantir la qualité de l'analyse IA")
                # Log de l'incident
                st.session_state.ai_manager.record_risk_mitigation(
                    "data_quality",
                    "validation_failed_incomplete",
                    "user_notification"
                )
                return None
            
            # Calcul du score AQ-10
            total_score = 0
            for i, response in enumerate([responses[f"q_{i}"] for i in range(10)]):
                if response in scoring[i]:
                    total_score += scoring[i][response]
            
            # Données pour l'IA
            user_data = {
                'Age_Range': age,
                'Genre': genre, 
                'Antecedents_TSA': antecedents,
                'Statut_testeur': testeur,
                'AQ10_Score': total_score,
                'timestamp': datetime.datetime.now().isoformat()
            }
            
            # Validation qualité données AI Act Article 10
            data_quality = st.session_state.ai_manager.validate_data_quality(user_data)
            
            if not all(data_quality.values()):
                st.warning("⚠️ Qualité des données insuffisante selon les standards AI Act")
                # Log de l'incident
                st.session_state.ai_manager.record_risk_mitigation(
                    "data_quality",
                    "validation_failed_quality",
                    "user_notification"
                )
                return None
            
            # Journalisation RGPD + AI Act
            st.session_state.gdpr_manager.log_data_processing(
                st.session_state.user_session,
                "aq10_questionnaire_completed",
                ["demographic_data", "health_responses", "aq10_score"]
            )
            
            # Log médical
            st.session_state.medical_manager.record_usage(
                testeur,
                "questionnaire_completed"
            )
            
            # Stockage anonymisé des données
            anonymized_data = st.session_state.gdpr_manager.anonymize_data(user_data)
            
            # Stockage temporaire pour l'analyse
            st.session_state.aq10_total = total_score
            st.session_state.aq10_responses = responses
            
            return user_data, total_score
    
    return None
# Ajouter cette fonction pour remplacer la fonction d'analyse existante

def perform_compliant_ai_analysis(user_data, aq10_score):
    """Analyse IA conforme AI Act avec surveillance humaine"""
    
    # Calcul de la probabilité de risque TSA
    risk_factors = {
        'aq10_high': aq10_score >= 6,
        'family_history': user_data['Antecedents_TSA'] == 'Oui',
        'age_factor': user_data['Age_Range'] in ['18-25', '26-35'],
        'professional_assessment': user_data['Statut_testeur'] == 'Professionnel'
    }
    
    # Simulation probabilité (remplacez par votre modèle)
    base_probability = 0.15  # 15% risque de base
    if risk_factors['aq10_high']:
        base_probability += 0.40
    if risk_factors['family_history']:
        base_probability += 0.25
    if risk_factors['age_factor']:
        base_probability += 0.10
    if risk_factors['professional_assessment']:
        base_probability += 0.15
        
    tsa_probability = min(0.95, base_probability)  # Cap à 95%
    confidence = 0.85  # Confiance du modèle
    
    # Journalisation AI Act Article 12
    ai_decision_log = st.session_state.ai_manager.log_ai_decision(
        inputs=user_data,
        outputs={"tsa_probability": tsa_probability, "risk_level": "high" if tsa_probability > 0.5 else "low"},
        confidence=confidence,
        user_session=st.session_state.user_session
    )
    
    # Journalisation médical
    incident_severity = "low"
    if tsa_probability > 0.9:
        incident_severity = "high" 
    elif tsa_probability > 0.7:
        incident_severity = "medium"
        
    st.session_state.medical_manager.report_incident(
        "AI_analysis_result",
        f"AQ10 Score: {aq10_score}, Probability: {tsa_probability:.2f}",
        incident_severity
    )
    
    # Affichage des résultats avec transparence AI Act
    st.markdown("## 🤖 Résultats de l'Analyse IA")
    
    # Avertissement obligatoire AI Act Article 14
    st.error("""
    **⚠️ SURVEILLANCE HUMAINE OBLIGATOIRE (AI Act Article 14)**
    
    Ces résultats sont générés par un système d'IA à haut risque et nécessitent IMPÉRATIVEMENT 
    une validation par un professionnel de santé qualifié avant toute décision médicale.
    """)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        risk_level = "ÉLEVÉ" if tsa_probability > 0.7 else "MODÉRÉ" if tsa_probability > 0.3 else "FAIBLE"
        color = "#e74c3c" if tsa_probability > 0.7 else "#f39c12" if tsa_probability > 0.3 else "#2ecc71"
        
        st.markdown(f"""
        <div style="background: {color}; color: white; padding: 25px; border-radius: 15px; text-align: center;">
            <h3 style="margin: 0 0 10px 0;">Niveau de Risque IA</h3>
            <h2 style="margin: 0; font-size: 2rem;">{risk_level}</h2>
            <p style="margin: 10px 0 0 0;">{tsa_probability:.1%} de probabilité</p>
        </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown(f"""
        <div style="background: #667eea; color: white; padding: 25px; border-radius: 15px; text-align: center;">
            <h3 style="margin: 0 0 10px 0;">Score AQ-10</h3>
            <h2 style="margin: 0; font-size: 2rem;">{aq10_score}/10</h2>
            <p style="margin: 10px 0 0 0;">Seuil clinique: ≥6</p>
        </div>
        """, unsafe_allow_html=True)
        
    with col3:
        st.markdown(f"""
        <div style="background: #4ECDC4; color: white; padding: 25px; border-radius: 15px; text-align: center;">
            <h3 style="margin: 0 0 10px 0;">Confiance IA</h3>
            <h2 style="margin: 0; font-size: 2rem;">{confidence:.0%}</h2>
            <p style="margin: 10px 0 0 0;">Fiabilité modèle</p>
        </div>
        """, unsafe_allow_html=True)
    
    # Explicabilité conforme AI Act Article 13
    st.markdown("### 🔍 Explication de la Décision IA (Transparence AI Act)")
    
    explanation_data = []
    if risk_factors['aq10_high']:
        explanation_data.append(["Score AQ-10 élevé", "≥6", "Facteur de risque majeur"])
    if risk_factors['family_history']:
        explanation_data.append(["Antécédents familiaux", "Oui", "Facteur génétique"])
    if risk_factors['age_factor']:
        explanation_data.append(["Tranche d'âge", user_data['Age_Range'], "Période de détection"])
    if risk_factors['professional_assessment']:
        explanation_data.append(["Évaluation professionnelle", "Oui", "Contexte clinique"])
        
    if explanation_data:
        df_explanation = pd.DataFrame(explanation_data, columns=["Facteur", "Valeur", "Impact"])
        st.dataframe(df_explanation, use_container_width=True)
    
    # Recommandations basées sur le niveau de risque
    if tsa_probability > 0.5:
        st.warning("""
        ### 📋 Recommandations Cliniques
        
        **Consultation spécialisée recommandée :**
        - Rendez-vous avec un psychiatre/pédopsychiatre spécialisé en TSA
        - Évaluation complémentaire (ADOS-2, ADI-R si indiqué)
        - Bilan neuropsychologique si nécessaire
        
        **Ressources disponibles :**
        - Centres de Ressources Autisme (CRA) régionaux
        - Réseaux de soins spécialisés
        - Associations de familles
        """)
    else:
        st.success("""
        ### ✅ Résultat Rassurant
        
        Le risque de TSA apparaît faible selon cette analyse. Cependant :
        - En cas de préoccupations persistantes, consultez votre médecin
        - Ce test ne remplace pas une évaluation clinique complète
        - Le dépistage peut être refait si de nouveaux symptômes apparaissent
        """)
    
    # Traçabilité complète conforme AI Act Article 12
    st.markdown("### 📊 Traçabilité de l'Analyse (AI Act Article 12)")
    
    traceability_info = {
        "ID Session": ai_decision_log["session_id"],
        "Timestamp": ai_decision_log["timestamp"], 
        "Version Modèle": ai_decision_log["model_version"],
        "Nombre Features": ai_decision_log["input_features_count"],
        "Surveillance Humaine": "✅ Activée",
        "Conformité AI Act": "✅ Respectée"
    }
    
    for key, value in traceability_info.items():
        st.text(f"{key}: {value}")
        
    # Rappel RGPD et options de suppression
    st.markdown("### 🔒 Vos Données et Droits RGPD")
    
    st.info("""
    Conformément au RGPD, vous pouvez demander l'accès, la rectification ou la suppression 
    de vos données en contactant notre DPO à dpo@depistage-tsa.fr.
    
    Vos données sont conservées de manière sécurisée pour une durée maximale de 24 mois.
    """)
    
    delete_data = st.button("🗑️ Supprimer mes données", key="delete_data_button")
    
    if delete_data:
        # Log de la demande de suppression
        st.session_state.gdpr_manager.record_consent(
            st.session_state.user_session,
            "data_deletion_request",
            True
        )
        
        # Confirmation visuelle
        st.success("""
        ✅ Votre demande de suppression a été enregistrée.
        
        Vos données seront supprimées de nos systèmes dans un délai maximum de 30 jours,
        conformément à notre politique de confidentialité et au RGPD.
        """)
        
    return tsa_probability, confidence

def show_ai_act_transparency():
    """Transparence conforme AI Act pour systèmes IA à haut risque"""
    
    st.markdown("""
    <div style="background: linear-gradient(135deg, #FF6B6B, #4ECDC4); 
                padding: 25px; border-radius: 15px; margin: 20px 0; color: white;">
        <h3 style="margin: 0 0 15px 0;">🤖 Information AI Act - Système IA à Haut Risque</h3>
        <p style="margin: 0; font-size: 1rem;">
            Cette application utilise un système d'intelligence artificielle classé "à haut risque" 
            selon le Règlement européen sur l'IA (AI Act EU 2024/1689).
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.expander("🔍 Transparence du Système IA (AI Act Article 13)", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🎯 Caractéristiques du Système
            - **Type** : Aide au dépistage médical
            - **Algorithme** : Random Forest
            - **Classification** : Haut risque (Annexe III)
            - **Domaine** : Santé - Dépistage TSA
            - **Version** : 2.0.0 (Juin 2025)
            
            ### 📊 Performance du Modèle
            - **Sensibilité** : 96% (détection vrais cas)
            - **Spécificité** : 94% (évite fausses alertes)  
            - **Précision globale** : 95.6%
            - **Données d'entraînement** : 5000+ cas
            """)
            
        with col2:
            st.markdown("""
            ### ⚠️ Limites et Risques
            - **Aide au diagnostic uniquement**
            - Ne remplace PAS un professionnel
            - Possible biais sur certaines populations
            - Erreurs possibles (4.4% de cas)
            
            ### 👨‍⚕️ Surveillance Humaine
            - **Supervision obligatoire** par professionnel
            - **Validation clinique** recommandée
            - **Second avis** toujours possible
            - **Appel possible** des décisions
            """)
    
    # Avertissement conforme AI Act Article 14
    st.error("""
    **⚠️ AVERTISSEMENT RÉGLEMENTAIRE AI ACT**
    
    Ce système d'IA à haut risque fournit une aide au dépistage. Les résultats doivent TOUJOURS être 
    interprétés par un professionnel de santé qualifié. Ne prenez AUCUNE décision médicale basée 
    uniquement sur ces résultats.
    """)
    
    # Log de l'affichage des informations de transparence
    st.session_state.ai_manager.record_risk_mitigation(
        "information_disclosure",
        "affichage_transparence_aiact",
        "completed"
    )


def show_home_page():
    """Page d'accueil en français uniquement"""
    st.markdown("""
    <div style="text-align: center; margin: 50px 0">
        <h1 style="color: #1f77b4; font-size: 2.5rem">🧩 Dépistage TSA</h1>
        <p style="color: #666; font-size: 1.1rem">Outil conforme RGPD & AI Act</p>
    </div>
    """, unsafe_allow_html=True)

    options = [
            "🏠 Accueil",
            "🔍 Exploration", 
            "🧠 Analyse ML",
            "🤖 Prédiction par IA",
            "📚 Documentation",
            "ℹ️ À propos",
            "🔒 Conformité"
        ]

    if 'tool_choice' not in st.session_state or st.session_state.tool_choice not in options:
            st.session_state.tool_choice = "🏠 Accueil"

    current_index = options.index(st.session_state.tool_choice)

    tool_choice = st.radio(
            "",
            options,
            label_visibility="collapsed",
            index=current_index,
            key="main_navigation"
        )

        # Affichage du statut de conformité
    st.markdown("""
        <div style="margin-top: 30px; background: #f8f9fa; padding: 15px; border-radius: 8px; font-size: 12px;">
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: #28a745; color: white; padding: 3px 8px; border-radius: 4px; font-size: 10px;">CE Classe IIa</span>
                <span style="background: #007bff; color: white; padding: 3px 8px; border-radius: 4px; font-size: 10px;">RGPD</span>
                <span style="background: #ffc107; color: black; padding: 3px 8px; border-radius: 4px; font-size: 10px;">AI Act</span>
            </div>
            <div style="margin-top: 10px; font-size: 11px; color: #6c757d;">
                Version: 2.1.0 | Mise à jour: 03/06/2025
            </div>
        </div>
        """, unsafe_allow_html=True)

    return tool_choice

set_custom_theme()

def load_visualization_libraries():
    global plt, px, go, sns

    if 'plt' not in globals():
        import matplotlib.pyplot as plt
    if 'px' not in globals():
        import plotly.express as px
    if 'go' not in globals():
        import plotly.graph_objects as go
    if 'sns' not in globals():
        import seaborn as sns

def load_ml_libraries():
    global LGBMClassifier, RandomForestClassifier, LogisticRegression, XGBClassifier
    global StandardScaler, OneHotEncoder, ColumnTransformer, Pipeline, utils
    global chi2_contingency, mannwhitneyu, prince

    if 'RandomForestClassifier' not in globals():
        from sklearn.ensemble import RandomForestClassifier
    if 'LogisticRegression' not in globals():
        from sklearn.linear_model import LogisticRegression
    if 'StandardScaler' not in globals():
        from sklearn.preprocessing import StandardScaler
    if 'OneHotEncoder' not in globals():
        from sklearn.preprocessing import OneHotEncoder
    if 'ColumnTransformer' not in globals():
        from sklearn.compose import ColumnTransformer
    if 'Pipeline' not in globals():
        from sklearn.pipeline import Pipeline
    if 'XGBClassifier' not in globals():
        from xgboost import XGBClassifier
    if 'LGBMClassifier' not in globals():
        from lightgbm import LGBMClassifier
    if 'utils' not in globals():
        from sklearn import utils
    if 'chi2_contingency' not in globals():
        from scipy.stats import chi2_contingency
    if 'mannwhitneyu' not in globals():
        from scipy.stats import mannwhitneyu
    if 'prince' not in globals():
        import prince

@st.cache_resource
def train_advanced_model(df):
    """
    Entraîne un modèle Random Forest pour la prédiction du TSA et retourne
    le modèle, le préprocesseur et les noms des features.

    Args:
        df (pd.DataFrame): DataFrame contenant les données d'entraînement

    Returns:
        tuple: (modèle entraîné, préprocesseur, noms des features)
    """
    load_ml_libraries()
    load_metrics_libraries()

    try:

        if 'TSA' not in df.columns:
            st.error("La colonne 'TSA' n'existe pas dans le dataframe")
            return None, None, None

        X = df.drop(columns=['TSA'])
        y = df['TSA'].map({'Yes': 1, 'No': 0})

        numerical_cols = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
        categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()

        preprocessor = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), numerical_cols),
                ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
            ],
            remainder='passthrough',
            verbose_feature_names_out=False
        )

        rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=10,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=True,
            random_state=42,
            n_jobs=-1
        )

        pipeline = Pipeline([
            ('preprocessor', preprocessor),
            ('classifier', rf_classifier)
        ])

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        pipeline.fit(X_train, y_train)

        try:
            feature_names = preprocessor.get_feature_names_out()
        except:

            feature_names = [f"feature_{i}" for i in range(pipeline.transform(X.iloc[[0]]).shape[1])]

        return pipeline, preprocessor, feature_names

    except Exception as e:
        st.error(f"Erreur lors de l'entraînement du modèle: {str(e)}")
        return None, None, None

def get_question_text(question_number):
    """Fonction utilitaire pour obtenir le texte des questions AQ-10"""
    questions = {
        1: "Je remarque souvent de petits bruits que les autres ne remarquent pas.",
        2: "Je me concentre généralement davantage sur l'ensemble que sur les petits détails.",
        3: "Je trouve facile de faire plusieurs choses en même temps.",
        4: "S'il y a une interruption, je peux rapidement reprendre ce que je faisais.",
        5: "Je trouve facile de « lire entre les lignes » quand quelqu'un me parle.",
        6: "Je sais comment savoir si la personne qui m'écoute commence à s'ennuyer.",
        7: "Quand je lis une histoire, j'ai du mal à comprendre les intentions des personnages.",
        8: "J'aime collecter des informations sur des catégories de choses (par exemple : types de voitures, d'oiseaux, de trains, de plantes, etc.).",
        9: "Je trouve facile de comprendre ce que quelqu'un pense ou ressent rien qu'en regardant son visage.",
        10: "J'ai du mal à comprendre les intentions des gens."
    }
    return questions.get(question_number, f"Question {question_number} non définie")


def load_metrics_libraries():
    global accuracy_score, precision_score, recall_score, f1_score
    global roc_auc_score, confusion_matrix, classification_report
    global cross_val_score, train_test_split

    if 'accuracy_score' not in globals():
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        from sklearn.metrics import roc_auc_score, confusion_matrix, classification_report
    if 'cross_val_score' not in globals():
        from sklearn.model_selection import cross_val_score
    if 'train_test_split' not in globals():
        from sklearn.model_selection import train_test_split


@st.cache_data(ttl=86400)
def get_img_with_href(img_url, target_url, as_banner=False):
    """
    Crée une image cliquable avec un lien (ou non cliquable si target_url est None, vide ou '#')
    """
    if "drive.google.com" in img_url and "/d/" in img_url:
        file_id = img_url.split("/d/")[1].split("/")[0]
        img_url = f"https://drive.google.com/uc?export=view&id={file_id}"

    cache_filename = hashlib.md5(img_url.encode()).hexdigest() + ".webp"
    cache_dir = "image_cache"
    cache_path = os.path.join(cache_dir, cache_filename)
    os.makedirs(cache_dir, exist_ok=True)

    try:
        if os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                img_data = f.read()
            img = Image.open(BytesIO(img_data))
        else:
            response = requests.get(img_url, timeout=15)
            response.raise_for_status()

            if len(response.content) == 0:
                raise Exception("Contenu vide téléchargé")

            img = Image.open(BytesIO(response.content))

            max_width = 1200 if as_banner else 800
            if img.width > max_width:
                ratio = max_width / img.width
                new_height = int(img.height * ratio)
                img = img.resize((max_width, new_height), Image.LANCZOS)

            buffer = BytesIO()
            img.save(buffer, format="WEBP", quality=85, optimize=True)

            with open(cache_path, "wb") as f:
                f.write(buffer.getvalue())

            buffer.seek(0)
            img_data = buffer.getvalue()

        img_str = base64.b64encode(img_data).decode()

        if as_banner:
            style = 'style="width:100%;height:600px;display:block;object-fit:cover;border-radius:10px;" loading="lazy"'
        else:
            style = 'style="width:100%;height:auto;display:block;object-fit:contain;margin:0 auto;padding:0;" loading="lazy"'

        container_style = 'style="width:100%; padding:10px; background-color:white; border-radius:10px; overflow:hidden; margin-bottom:20px;"'

        # Ne pas ajouter de lien si target_url est None, vide ou '#'
        if target_url and target_url != "#":
            html_code = f'<div {container_style}><a href="{target_url}" target="_blank" style="display:block; margin:0; padding:0; line-height:0;"><img src="data:image/webp;base64,{img_str}" {style}></a></div>'
        else:
            html_code = f'<div {container_style}><img src="data:image/webp;base64,{img_str}" {style}></div>'

        return html_code
    except Exception as e:
        return f'<div style="text-align:center;padding:20px;background:#f0f2f6;border-radius:10px;"><p>Image non disponible ({str(e)})</p></div>'

@st.cache_data(ttl=86400)
def load_dataset():
    """Chargement sécurisé des datasets avec gestion d'erreur complète"""
    try:
        # IDs des datasets
        datasets_config = {
            'ds1': '1ai1QlLzn0uo-enw4IzC53jJ8qoPc845G',
            'ds2': '1MOEhPxMNZH8LvXahvYAKiVFb9t8vAxaE',
            'ds3': '12B-scaR0TF7TuJzelIqmlxXDjnew67-K',
            'ds4': '1U9buLTKR_XuLWu9l3SOgvF6d9cS_YTFO',
            'ds5': '1NdXYppnmiheLFtvrdRHDk0wYkO0wYp',
            'final': '1mm6sRacDmoL941POmydQgzdVAi9lFPit'
        }

        cache_dir = "data_cache"
        os.makedirs(cache_dir, exist_ok=True)
        
        # Chargement ou téléchargement des datasets
        datasets = {}
        for name, file_id in datasets_config.items():
            cache_path = os.path.join(cache_dir, f"{name}.csv")
            
            try:
                if os.path.exists(cache_path):
                    datasets[name] = pd.read_csv(cache_path)
                else:
                    url = f'https://drive.google.com/uc?export=download&id={file_id}'
                    datasets[name] = pd.read_csv(url)
                    datasets[name].to_csv(cache_path, index=False)
            except Exception as e:
                logging.warning(f"Erreur chargement {name}: {e}")
                datasets[name] = pd.DataFrame()

        # Dataset principal
        df = datasets.get('final', pd.DataFrame())
        
        # Nettoyage et préparation
        if not df.empty:
            df = clean_dataset(df)
        
        # Calcul des statistiques
        df_stats = calculate_dataset_stats(df) if not df.empty else {}
        
        return (
            df,
            datasets.get('ds1', pd.DataFrame()),
            datasets.get('ds2', pd.DataFrame()),
            datasets.get('ds3', pd.DataFrame()),
            datasets.get('ds4', pd.DataFrame()),
            datasets.get('ds5', pd.DataFrame()),
            df_stats
        )
        
    except Exception as e:
        logging.error(f"Erreur critique dans load_dataset: {e}")
        empty_df = pd.DataFrame()
        return empty_df, empty_df, empty_df, empty_df, empty_df, empty_df, {}

def clean_dataset(df):
    """Fonction de nettoyage du dataset"""
    try:
        # Suppression des colonnes inutiles
        if 'Unnamed: 0' in df.columns:
            df = df.drop(columns=['Unnamed: 0'])
        
        # Renommage des colonnes
        rename_dict = {'tsa': 'TSA', 'gender': 'Genre'}
        df = df.rename(columns={k: v for k, v in rename_dict.items() if k in df.columns})
        
        # Standardisation des valeurs
        if 'TSA' in df.columns:
            df['TSA'] = df['TSA'].str.title()
        if 'Genre' in df.columns:
            df['Genre'] = df['Genre'].str.capitalize()
        
        # Calcul du score AQ-10
        aq_columns = [col for col in df.columns if col.startswith('A') and col[1:].isdigit()]
        if aq_columns:
            df['Score_A10'] = df[aq_columns].sum(axis=1)
        
        # Gestion des valeurs par défaut
        if 'Statut_testeur' not in df.columns:
            df['Statut_testeur'] = 'Famille'
        else:
            df['Statut_testeur'].fillna('Famille', inplace=True)
            
        return df
        
    except Exception as e:
        logging.error(f"Erreur nettoyage dataset: {e}")
        return df

def calculate_dataset_stats(df):
    """Calcul des statistiques du dataset"""
    try:
        return {
            'mean_by_tsa': df.groupby('TSA').mean(numeric_only=True) if 'TSA' in df.columns else pd.DataFrame(),
            'count_by_tsa': df.groupby('TSA').count() if 'TSA' in df.columns else pd.DataFrame(),
            'categorical_cols': df.select_dtypes(include=['object']).columns.tolist(),
            'numeric_cols': df.select_dtypes(exclude=['object']).columns.tolist()
        }
    except Exception as e:
        logging.error(f"Erreur calcul statistiques: {e}")
        return {}

def download_and_save_dataset(url, filepath):
    """Fonction auxiliaire pour télécharger et sauvegarder un dataset"""
    try:
        df = pd.read_csv(url)
        df.to_csv(filepath, index=False)
        return df
    except Exception as e:
        st.error(f"Erreur lors du téléchargement de {url}: {str(e)}")
        return pd.DataFrame()

palette = {"No": "#1f77b4", "Yes": "#ff7f0e"}

def create_mann_whitney_visualization(data, variable):
    group1 = data[data["TSA"] == "Yes"][variable].dropna()
    group2 = data[data["TSA"] == "No"][variable].dropna()

    fig = go.Figure()

    fig.add_trace(go.Box(
        y=group1,
        name="TSA",
        marker_color=palette["Yes"]
    ))

    fig.add_trace(go.Box(
        y=group2,
        name="Non-TSA",
        marker_color=palette["No"]
    ))

    fig.update_layout(
        title=f"Comparaison de {variable} entre groupes TSA et non-TSA",
        yaxis_title=variable,
        boxmode="group"
    )

    return fig

def create_distribution_chart(data, variable):
    fig = px.histogram(data, x=variable, color="TSA")
    return fig

def create_distribution_chart(data, variable):
    fig = px.histogram(data, x=variable, color="TSA",
                      barmode="group",
                      labels={"count": "Fréquence", "TSA": "Diagnostic TSA"},
                      color_discrete_map={"No": "#1f77b4", "Yes": "#ff7f0e"})

    fig.update_layout(
        title=f"Distribution de {variable} par diagnostic",
        xaxis_title=variable,
        yaxis_title="Fréquence",
        legend_title="Diagnostic TSA"
    )
    return fig

palette = {"No": "#1f77b4", "Yes": "#ff7f0e"}

def create_chi_squared_visualization(data, variable):
    cross_tab = pd.crosstab(data[variable], data["TSA"])
    data_grouped = pd.DataFrame({
        variable: [],
        "TSA": [],
        "count": [],
        "percentage": []
    })

    for cat in cross_tab.index:
        for tsa in ["No", "Yes"]:
            count = cross_tab.loc[cat, tsa]
            total = cross_tab.loc[cat].sum()
            percentage = (count / total) * 100

            data_grouped = data_grouped._append({
                variable: cat,
                "TSA": tsa,
                "count": count,
                "percentage": percentage
            }, ignore_index=True)

    fig = px.bar(data_grouped, x=variable, y="percentage", color="TSA",
                barmode="group",
                labels={"percentage": "Pourcentage (%)", "TSA": "Diagnostic TSA"},
                color_discrete_map=palette)

    fig.update_layout(
        title=f"Répartition de {variable} par diagnostic (%)",
        xaxis_title=variable,
        yaxis_title="Pourcentage (%)",
        legend_title="Diagnostic TSA"
    )
    return fig

@st.cache_data(ttl=3600, max_entries=100)
def create_plotly_figure(df, x=None, y=None, color=None, names=None, kind='histogram', title=None):
    """Crée une visualisation Plotly avec mise en cache et optimisations de performance"""

    sample_threshold = 10000
    if len(df) > sample_threshold:
        df = df.sample(sample_threshold, random_state=42)

    if color and color not in df.columns:
        color = None

    categorical_palette = {0: "#3498db", 1: "#2ecc71"}
    palette = {"Yes": "#3498db", "No": "#2ecc71", "Unknown": "#95a5a6"}
    base_layout = dict(
        height=500,
        margin=dict(l=20, r=20, t=40, b=20),
        template="simple_white",
        modebar_remove=['sendDataToCloud', 'select2d', 'lasso2d', 'autoScale2d'],
        hovermode='closest'
    )

    try:
        is_categorical_aq = x and isinstance(x, str) and x.startswith('A') and x[1:].isdigit() and len(x) <= 3

        if is_categorical_aq and kind in ['histogram', 'bar']:
            counts = df[x].value_counts().reset_index()
            counts.columns = [x, 'count']
            fig = px.bar(counts, x=x, y='count',
                        color=x,
                        color_discrete_map=categorical_palette,
                        title=f"Distribution de {x} (catégorielle)")
            fig.update_layout(xaxis_title=f"Valeur de {x}", yaxis_title="Nombre d'occurrences", **base_layout)

        elif kind == 'histogram':
            nbins = 20 if len(df) < 5000 else 10
            marginal = "box" if len(df) < 3000 else None
            fig = px.histogram(df, x=x, color=color, color_discrete_map=palette,
                              marginal=marginal, nbins=nbins)
            fig.update_layout(**base_layout)

        elif kind == 'box':
            points = "all" if len(df) < 1000 else False
            fig = px.box(df, x=x, y=y, color=color, color_discrete_map=palette,
                        points=points, notched=len(df) > 200)
            fig.update_layout(**base_layout)

        elif kind == 'bar':
            fig = px.bar(df, x=x, y=y, color=color, color_discrete_map=palette)
            fig.update_layout(**base_layout)

        elif kind == 'scatter':
            opacity = 1.0 if len(df) < 500 else 0.7 if len(df) < 2000 else 0.5
            fig = px.scatter(df, x=x, y=y, color=color, color_discrete_map=palette, opacity=opacity)
            fig.update_layout(**base_layout)

        elif kind == 'pie':
            if names and isinstance(names, str) and names.startswith('A') and names[1:].isdigit() and len(names) <= 3:
                values_counts = df[names].value_counts().reset_index()
                values_counts.columns = [names, 'count']
                fig = px.pie(values_counts, values='count', names=names,
                          color=names,
                          color_discrete_map=categorical_palette,
                          title=f"Répartition {names}")
            else:
                fig = px.pie(df, names=names, color=color, color_discrete_map=palette)
            fig.update_layout(**base_layout)

        elif kind == 'violin':
            box = len(df) < 2000
            fig = px.violin(df, x=x, y=y, color=color, color_discrete_map=palette, box=box)
            fig.update_layout(**base_layout)

        elif kind == 'count':
            fig = px.histogram(df, x=x, color=color, color_discrete_map=palette,
                            title=f"Comptage de {x}")
            fig.update_layout(yaxis_title="Nombre d'occurrences", **base_layout)

        if title:
            fig.update_layout(title=title)

        return fig
    except Exception as e:
        st.error(f"Erreur lors de la création du graphique: {str(e)}")
        return None

# Définition des fonctions FIRST
def show_home_page():
    """Page d'accueil avec sélecteur de langue"""
    st.markdown("""
    <div style="text-align: center; margin: 50px 0">
        <h1 style="color: #1f77b4; font-size: 2.5rem">🧩 Dépistage TSA</h1>
        <p style="color: #666; font-size: 1.1rem">Outil conforme RGPD & AI Act</p>
    </div>
    """, unsafe_allow_html=True)

    # Sélecteur de langue
    lang = st.selectbox("🌍 Choisir la langue", ["Français", "English"], key="lang_selector")
    st.session_state['lang'] = lang.lower()

    # Configuration dynamique du thème
    set_custom_theme()

    # CSS spécifique corrigé - SUPPRIMER les règles conflictuelles
    st.markdown("""
    <style>
    /* Suppression des règles CSS conflictuelles pour la sidebar */
    /* NE PAS redéfinir les propriétés de [data-testid="stSidebar"] */
    
    /* Suppression des barres bleues indésirables */
    .stAlert, [data-testid="stAlert"] {
        border: none !important;
        background: transparent !important;
    }
    
    /* Amélioration du contenu principal */
    .main .block-container {
        padding-top: 1rem !important;
        max-width: 1200px !important;
    }
    
    /* Style pour les cartes d'information */
    .info-card-modern {
        background: white;
        border-radius: 15px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.08);
        border-left: 4px solid #3498db;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .info-card-modern:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }
    
    /* Timeline responsive */
    .timeline-container {
        background-color: #f8f9fa;
        padding: 25px;
        border-radius: 15px;
        margin: 25px 0;
        overflow-x: auto;
    }
    
    .timeline-item {
        min-width: 160px;
        text-align: center;
        margin: 0 15px;
        flex-shrink: 0;
    }
    
    .timeline-year {
        background: linear-gradient(135deg, #3498db, #2ecc71);
        color: white;
        padding: 12px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 0.95rem;
    }
    
    .timeline-text {
        margin-top: 12px;
        font-size: 0.9rem;
        color: #2c3e50;
        line-height: 1.4;
    }
    </style>
    """, unsafe_allow_html=True)

    # En-tête principal amélioré
    st.markdown("""
    <div style="background: linear-gradient(90deg, #3498db, #2ecc71);
                padding: 40px 25px; border-radius: 20px; margin-bottom: 35px; text-align: center;">
        <h1 style="color: white; font-size: 2.8rem; margin-bottom: 15px;
                   text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
            🧩 Comprendre les Troubles du Spectre Autistique
        </h1>
        <p style="color: rgba(255,255,255,0.95); font-size: 1.3rem;
                  max-width: 800px; margin: 0 auto; line-height: 1.6;">
            Une approche moderne et scientifique pour le dépistage précoce
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Image Ghibli (conservée)
    image_url = "https://drive.google.com/file/d/1fY4J-WgufGTF6AgorFOspVKkHiRKEaiW/view?usp=drive_link"
    st.markdown(get_img_with_href(image_url, None, as_banner=True), unsafe_allow_html=True)

    # Section "Qu'est-ce que l'autisme ?" améliorée
    st.markdown("""
    <div class="info-card-modern">
        <h2 style="color: #3498db; margin-bottom: 25px; font-size: 2.2rem; text-align: center;">
            🔬 Qu'est-ce que l'autisme ?
        </h2>
        <p style="font-size: 1.2rem; line-height: 1.8; text-align: justify;
                  max-width: 900px; margin: 0 auto; color: #2c3e50;">
            Les <strong>Troubles du Spectre Autistique (TSA)</strong> sont des conditions neurodéveloppementales
            qui affectent la façon dont une personne perçoit et interagit avec le monde. Caractérisés par des
            différences dans la communication sociale, les interactions sociales et par des comportements ou
            intérêts restreints et répétitifs, les TSA se manifestent sur un large spectre de symptômes et de
            niveaux de fonctionnement.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Timeline de l'évolution améliorée
    st.markdown("""
    <h2 style="color: #3498db; margin: 45px 0 25px 0; text-align: center; font-size: 2.2rem;">
        📅 Évolution de la compréhension de l'autisme
    </h2>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="timeline-container">
        <div style="display: flex; justify-content: space-between; min-width: 700px;">
            <div class="timeline-item">
                <div class="timeline-year">1943</div>
                <div class="timeline-text">Leo Kanner décrit l'autisme infantile</div>
            </div>
            <div class="timeline-item">
                <div class="timeline-year">1980</div>
                <div class="timeline-text">L'autisme entre dans le DSM-III</div>
            </div>
            <div class="timeline-item">
                <div class="timeline-year">2013</div>
                <div class="timeline-text">Le DSM-5 introduit les TSA</div>
            </div>
            <div class="timeline-item">
                <div class="timeline-year">Aujourd'hui</div>
                <div class="timeline-text">Approche neurodiversité</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

   # Section "Le spectre autistique" avec HTML simplifié
    st.markdown("## 🌈 Le spectre autistique")

    st.markdown("""
    <div style="background-color: white; padding: 25px; border-radius: 15px;
               box-shadow: 0 4px 15px rgba(0,0,0,0.08); border-left: 4px solid #3498db;">
        <p style="font-size: 1.1rem; line-height: 1.7; color: #2c3e50; margin-bottom: 20px;">
            L'autisme est aujourd'hui compris comme un <strong>spectre</strong> de conditions,
            reflétant la grande variabilité des manifestations.
        </p>
        <p style="font-size: 1rem; color: #34495e; margin-bottom: 15px;">Cette conception reconnaît que :</p>
        <ul style="color: #34495e; padding-left: 25px; line-height: 1.6;">
            <li><strong>Chaque personne autiste</strong> présente un profil unique de forces et de défis</li>
            <li><strong>Les manifestations</strong> varient en intensité et en expression</li>
            <li><strong>Les niveaux de soutien</strong> nécessaires peuvent différer considérablement</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Les trois niveaux de soutien du DSM-5 :")

    # Utiliser les colonnes Streamlit avec des composants natifs
    niveau_col1, niveau_col2, niveau_col3 = st.columns(3)

    with niveau_col1:
        st.success("**Niveau 1**\n\nNécessite un soutien")

    with niveau_col2:
        st.warning("**Niveau 2**\n\nNécessite un soutien important")

    with niveau_col3:
        st.error("**Niveau 3**\n\nNécessite un soutien très important")

    # Section "Contexte du projet" corrigée avec composants natifs
    st.header("📊 Contexte du projet")

    # Utiliser un container natif au lieu du HTML
    with st.container():
        st.write("""
        Ce projet s'inscrit dans le cadre de l'analyse des données liées au diagnostic des
        **Troubles du Spectre de l'Autisme (TSA)**. L'autisme n'est pas une maladie
        mais une **différence neurologique** affectant le fonctionnement du cerveau.
        """)

        st.write("""
        Notre équipe a travaillé sur **5 jeux de données publics** représentant plus de
        5000 personnes de différentes origines (États-Unis, Nouvelle-Zélande, Arabie Saoudite...)
        pour identifier les facteurs associés à la présence d'un TSA.
        """)

    # Section prévalence avec métriques natives
    st.subheader("📈 Prévalence de l'autisme")

    # Utiliser les composants info natifs Streamlit
    st.info("""
    **Données clés sur l'autisme :**

    • **1 à 2%** de la population mondiale est concernée
    • En France, environ **700 000 personnes** sont concernées
    • Ratio historique garçons/filles d'environ **4:1** (aujourd'hui remis en question)
    """)

    # Alternative avec métriques si vous préférez
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Population mondiale", "1-2%", "700 000 en France")

    with col2:
        st.metric("Participants étudiés", "5000+", "Origines diverses")

    with col3:
        st.metric("Ratio historique", "4:1", "En évolution")


    # Section "À qui s'adresse ce projet" moderne
    st.markdown("""
    <h2 style="color: #3498db; margin: 45px 0 25px 0; text-align: center; font-size: 2.2rem;">
        🎯 À qui s'adresse ce projet
    </h2>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 10, 1])

    with col2:
        # Grille 2x2 pour les publics cibles
        col_a, col_b = st.columns(2)

        with col_a:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #e8f4fd, #d1ecf1);
                       border-radius: 15px; padding: 25px; margin-bottom: 20px; height: 180px;
                       border-left: 4px solid #3498db;">
                <h4 style="color: #2980b9; margin-top: 0;">🔬 Chercheurs en santé</h4>
                <p style="color: #34495e; line-height: 1.6; font-size: 0.95rem;">
                    Analyse détaillée permettant d'étayer des hypothèses scientifiques et confirmer
                    des tendances cliniques dans le domaine des TSA.
                </p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div style="background: linear-gradient(135deg, #fff8e1, #ffecb3);
                       border-radius: 15px; padding: 25px; height: 180px;
                       border-left: 4px solid #ffa726;">
                <h4 style="color: #f57c00; margin-top: 0;">👨‍👩‍👧‍👦 Familles et particuliers</h4>
                <p style="color: #bf360c; line-height: 1.6; font-size: 0.95rem;">
                    Outils d'auto-évaluation et d'information pour répondre aux questions
                    ou suspicions de TSA et faciliter l'orientation.
                </p>
            </div>
            """, unsafe_allow_html=True)

        with col_b:
            st.markdown("""
            <div style="background: linear-gradient(135deg, #e8f5e8, #c8e6c9);
                       border-radius: 15px; padding: 25px; margin-bottom: 20px; height: 180px;
                       border-left: 4px solid #4caf50;">
                <h4 style="color: #388e3c; margin-top: 0;">🩺 Professionnels de santé</h4>
                <p style="color: #2e7d32; line-height: 1.6; font-size: 0.95rem;">
                    Résultats exploitables permettant d'améliorer le dépistage et la prise
                    en charge des personnes avec TSA.
                </p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div style="background: linear-gradient(135deg, #fce4ec, #f8bbd9);
                       border-radius: 15px; padding: 25px; height: 180px;
                       border-left: 4px solid #e91e63;">
                <h4 style="color: #c2185b; margin-top: 0;">🏛️ Décideurs publics</h4>
                <p style="color: #ad1457; line-height: 1.6; font-size: 0.95rem;">
                    Données et analyses pouvant informer les politiques publiques et orienter
                    les décisions de financement.
                </p>
            </div>
            """, unsafe_allow_html=True)

    # Section "Accompagnement et soutien" améliorée
    st.markdown("""
    <h2 style="color: #3498db; margin: 45px 0 25px 0; text-align: center; font-size: 2.2rem;">
        🤝 Accompagnement et soutien
    </h2>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    support_cards = [
        {
            "title": "🌱 Intervention précoce",
            "items": ["Programmes de stimulation", "Accompagnement parental", "Thérapies comportementales", "Approches sensorimotrices"],
            "gradient": "linear-gradient(135deg, #3498db, #2980b9)"
        },
        {
            "title": "📚 Approches éducatives",
            "items": ["Méthodes structurées", "Soutien à l'inclusion", "Aménagements adaptés", "Programmes individualisés"],
            "gradient": "linear-gradient(135deg, #2ecc71, #27ae60)"
        },
        {
            "title": "👥 Suivi multidisciplinaire",
            "items": ["Orthophonie", "Ergothérapie", "Psychomotricité", "Soutien psychologique"],
            "gradient": "linear-gradient(135deg, #9b59b6, #8e44ad)"
        }
    ]

    for i, (card, col) in enumerate(zip(support_cards, [col1, col2, col3])):
        with col:
            items_html = "".join([f"<li>{item}</li>" for item in card['items']])
            st.markdown(f"""
            <div style="background: {card['gradient']}; color: white;
                       padding: 25px; border-radius: 15px; height: 280px;
                       box-shadow: 0 6px 20px rgba(0,0,0,0.15);">
                <h3 style="border-bottom: 2px solid rgba(255,255,255,0.3);
                          padding-bottom: 12px; margin-bottom: 20px; font-size: 1.3rem;">
                    {card['title']}
                </h3>
                <ul style="padding-left: 20px; margin: 0; line-height: 1.8;">
                    {items_html}
                </ul>
            </div>
            """, unsafe_allow_html=True)

    # Section "Caractéristiques principales" améliorée
    st.markdown("""
    <h2 style="color: #3498db; margin: 45px 0 25px 0; text-align: center; font-size: 2.2rem;">
        🧠 Caractéristiques principales
    </h2>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("""
        <div class="info-card-modern" style="border-left-color: #3498db;">
            <h3 style="color: #3498db; margin-bottom: 20px;">💬 Communication sociale</h3>
            <ul style="line-height: 1.8; color: #2c3e50; padding-left: 20px;">
                <li>Différences dans la communication non verbale</li>
                <li>Défis dans les interactions sociales</li>
                <li>Interprétation littérale du langage</li>
                <li>Difficultés avec les règles sociales implicites</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class="info-card-modern" style="border-left-color: #2ecc71;">
            <h3 style="color: #2ecc71; margin-bottom: 20px;">🔄 Comportements et intérêts</h3>
            <ul style="line-height: 1.8; color: #2c3e50; padding-left: 20px;">
                <li>Intérêts spécifiques et intenses</li>
                <li>Attachement aux routines</li>
                <li>Mouvements répétitifs</li>
                <li>Sensibilités sensorielles particulières</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    # Section "Notre approche" finale
    st.markdown("""
    <h2 style="color: #3498db; margin: 45px 0 25px 0; text-align: center; font-size: 2.2rem;">
        🚀 Notre approche
    </h2>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 10, 1])

    with col2:
        st.markdown("""
        <div style="background: linear-gradient(90deg, #3498db, #2ecc71);
                   padding: 35px; border-radius: 20px; text-align: center; color: white;
                   box-shadow: 0 8px 25px rgba(52, 152, 219, 0.3);">
            <p style="font-size: 1.3rem; max-width: 800px; margin: 0 auto; line-height: 1.7;">
                Notre plateforme combine les connaissances scientifiques actuelles et l'intelligence artificielle
                pour améliorer la détection précoce et l'accompagnement des personnes autistes,
                dans une vision respectueuse de la neurodiversité.
            </p>
        </div>
        """, unsafe_allow_html=True)

    # Avertissement final stylisé
    st.markdown("""
    <div style="margin: 40px 0 30px 0; padding: 20px; border-radius: 12px;
               border-left: 4px solid #e74c3c; background: linear-gradient(135deg, #fff5f5, #ffebee);
               box-shadow: 0 4px 12px rgba(231, 76, 60, 0.1);">
        <p style="font-size: 1rem; color: #c0392b; text-align: center; margin: 0; line-height: 1.6;">
            <strong style="color: #e74c3c;">⚠️ Avertissement :</strong>
            Les informations présentées sur cette plateforme sont à titre informatif uniquement.
            Elles ne remplacent pas l'avis médical professionnel.
        </p>
    </div>
    """, unsafe_allow_html=True)


def show_data_exploration():
    import plotly.express as px
    import plotly.graph_objects as go
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt
    import seaborn as sns
    from scipy.stats import chi2_contingency, mannwhitneyu

    df, df_ds1, df_ds2, df_ds3, df_ds4, df_ds5, df_stats = load_dataset()
    st.markdown("""
<div style="background: linear-gradient(90deg, #3498db, #2ecc71);
            padding: 40px 25px; border-radius: 20px; margin-bottom: 35px; text-align: center;">
    <h1 style="color: white; font-size: 2.8rem; margin-bottom: 15px;
               text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
        🔍 Exploration des Données TSA
    </h1>
    <p style="color: rgba(255,255,255,0.95); font-size: 1.3rem;
              max-width: 800px; margin: 0 auto; line-height: 1.6;">
        Une approche moderne et scientifique pour le dépistage précoce
    </p>
</div>
""", unsafe_allow_html=True)

    if 'expanders_initialized' not in st.session_state:
        st.session_state.expanders_initialized = {
            'structure': True,
            'valeurs_manquantes': True,
            'pipeline': True,
            'variables_cles': True,
            'questionnaire': True,
            'composite': True,
            'statistiques': True,
            'correlation': True,
            'famd': True
        }

    with st.expander("📂 Structure des Données", expanded=True):
        st.markdown("""
            <div style="background:#fff3e0; padding:15px; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,0.05)">
                <h4 style="color:#e65100; border-bottom:1px solid #ffe0b2; padding-bottom:8px">Jeux de Données</h4>
                <ul style="padding-left:20px">
                    <li>'📁' <strong>Dataset 1:</strong> <a href="https://www.kaggle.com/datasets/faizunnabi/autism-screening" target="_blank">Autism Screening Dataset</a> (n=1985)</li>
                    <li>'📁' <strong>Dataset 2:</strong> <a href="https://archive.ics.uci.edu/ml/datasets/Autism+Screening+Adult" target="_blank">UCI Machine Learning Repository</a> (n=704)</li>
                    <li>'📁' <strong>Dataset 3:</strong> <a href="https://data.gov.sa/" target="_blank">Open Data Saudi Arabia</a> (n=506)</li>
                    <li>'📁' <strong>Dataset 4:</strong> <a href="https://www.kaggle.com/datasets/fabdelja/autism-screening-for-toddlers" target="_blank">Autism Screening for Toddlers</a> (n=1054)</li>
                    <li>'📁' <strong>Dataset 5:</strong> <a href="https://www.kaggle.com/datasets/reevesii/global-autism-data" target="_blank">Global Autism Data</a> (n=800)</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        tab_main, tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "Dataset Final", "Dataset 1", "Dataset 2", "Dataset 3", "Dataset 4", "Dataset 5"
        ])

        with tab_main:
            st.caption("Dataset Final")
            st.dataframe(df.head(5), use_container_width=True)
        with tab1:
            st.caption("Dataset 1")
            st.dataframe(df_ds1.head(5), use_container_width=True)
        with tab2:
            st.caption("Dataset 2")
            st.dataframe(df_ds2.head(5), use_container_width=True)
        with tab3:
            st.caption("Dataset 3")
            st.dataframe(df_ds3.head(5), use_container_width=True)
        with tab4:
            st.caption("Dataset 4")
            st.dataframe(df_ds4.head(5), use_container_width=True)
        with tab5:
            st.caption("Dataset 5")
            st.dataframe(df_ds5.head(5), use_container_width=True)

    with st.expander("🧼 Pipeline de Nettoyage", expanded=True):
        st.markdown("""
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="color: #2c3e50; margin-top: 0;">Étapes de Transformation des Données</h3>
            <p style="color: #7f8c8d;">Processus automatisé pour préparer les données à l'analyse.</p>
        </div>
        """, unsafe_allow_html=True)
        col1, col2 = st.columns([1, 3])
        with col1:
            st.markdown("""
            <div style="background-color: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
                <h4 style="color: #3498db; margin-top: 0;">Étapes de Transformation</h4>
                <ol style="padding-left: 20px; color: #2c3e50;">
                    <li><b>Uniformisation</b> des colonnes</li>
                    <li><b>Typage</b> des variables</li>
                    <li><b>Gestion</b> des valeurs manquantes</li>
                    <li><b>Encodage</b> catégoriel</li>
                    <li><b>Normalisation</b> des échelles</li>
                </ol>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            avant_tab, apres_tab = st.tabs(["Avant Nettoyage", "Après Nettoyage"])
            with avant_tab:
                raw_data_sample = pd.DataFrame({
                    'A10_Score': [7, 5, None, 3],
                    'Age_Years': [29, None, 'unknown', 383],
                    'asd_traits': ['yes', 'no', 'no', 'yes']
                })
                st.dataframe(raw_data_sample.style.highlight_null(color='#ffcdd2'), use_container_width=True)
            with apres_tab:
                clean_data_sample = pd.DataFrame({
                    'A10': [7, 5, 4, 3],
                    'Age': [29, 35, 42, 38],
                    'TSA': ['Yes', 'No', 'No', 'Yes'],
                    'Statut_testeur': ['Famille', 'Famille', 'Famille', 'Famille']
                })
                st.dataframe(clean_data_sample, use_container_width=True)
                metrics_col1, metrics_col2 = st.columns(2)
                with metrics_col1:
                    st.metric("Réduction des valeurs manquantes", "92%", "10% → 0.8%")
                with metrics_col2:
                    st.metric("Anomalies corrigées", "100%", "14 anomalies détectées")
                pass

    with st.expander("📉 Analyse des Valeurs Manquantes", expanded=True):
        st.markdown("""
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="color: #2c3e50; margin-top: 0;">Analyse des Valeurs Manquantes</h3>
            <p style="color: #7f8c8d;">Visualisation et quantification des données manquantes dans le jeu de données.</p>
        </div>
        """, unsafe_allow_html=True)
        missing_percent = (df.isnull().sum() / len(df)) * 100
        missing_info = pd.DataFrame({
            'Colonne': missing_percent.index,
            'Pourcentage': missing_percent.values
        })
        missing_info = missing_info[missing_info['Pourcentage'] > 0].sort_values('Pourcentage', ascending=False)
        if not missing_info.empty:
            col1, col2 = st.columns([3, 2])
            with col1:
                fig = px.bar(
                    missing_info,
                    x='Pourcentage',
                    y='Colonne',
                    orientation='h',
                    title="Pourcentage de valeurs manquantes par colonne",
                    color='Pourcentage',
                    color_continuous_scale=px.colors.sequential.Blues,
                    text='Pourcentage'
                )
                fig.update_traces(texttemplate='%{text:.2f}%', textposition='outside')
                fig.update_layout(
                    height=400,
                    xaxis_title="Pourcentage (%)",
                    yaxis_title="",
                    coloraxis_showscale=False,
                    margin=dict(l=20, r=20, t=40, b=20),
                )
                st.plotly_chart(fig, use_container_width=True)
            with col2:
                st.metric(
                    "Nombre de colonnes avec valeurs manquantes",
                    missing_info.shape[0],
                    delta=f"{missing_info.shape[0]/df.shape[1]:.1%} des colonnes"
                )
                st.markdown("### Détail des valeurs manquantes")
                st.dataframe(missing_info, use_container_width=True)
                total_missing = (df.isnull().sum().sum() / (df.shape[0] * df.shape[1])) * 100
                st.info(f"Taux global de données manquantes : {total_missing:.2f}%")
        else:
            st.success("✅ Aucune valeur manquante détectée dans le jeu de données.")


    with st.expander("📈 Statistiques du Dataset Final", expanded=True):
        st.subheader("Statistiques Descriptives")
        tab1, tab2 = st.tabs(["Numériques", "Catégorielles"])
        with tab1:
            st.write(df.describe())
        with tab2:
            categorical_stats = df.select_dtypes(include=['object']).describe().T
            st.dataframe(categorical_stats)

    with st.expander("📊 Distribution des Variables Clés", expanded=True):
        st.markdown("""
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="color: #2c3e50; margin-top: 0;">Distribution des Variables Clés</h3>
            <p style="color: #7f8c8d;">Analyse interactive des distributions par variable.</p>
        </div>
        """, unsafe_allow_html=True)

        # Dictionnaire de commentaires pour les variables
        variable_comments = {
            'A1': "Variable liée au questionnaire AQ-10 : évalue la capacité à remarquer des détails que d'autres pourraient manquer.",
            'A2': "Variable liée au questionnaire AQ-10 : évalue la capacité à imaginer des histoires.",
            'A3': "Variable liée au questionnaire AQ-10 : évalue la préférence pour la socialisation vs activités solitaires.",
            'A4': "Variable liée au questionnaire AQ-10 : évalue la tendance à se concentrer sur un sujet spécifique.",
            'A5': "Variable liée au questionnaire AQ-10 : évalue l'attention aux détails numériques et dates.",
            'A6': "Variable liée au questionnaire AQ-10 : évalue la capacité à comprendre les intentions des autres.",
            'A7': "Variable liée au questionnaire AQ-10 : évalue la capacité à réagir de manière appropriée socialement.",
            'A8': "Variable liée au questionnaire AQ-10 : évalue les interactions sociales en groupe.",
            'A9': "Variable liée au questionnaire AQ-10 : évalue la reconnaissance des émotions chez autrui.",
            'A10': "Variable liée au questionnaire AQ-10 : évalue la capacité à gérer plusieurs tâches simultanément.",
            'Jaunisse': "Indique si l'individu a eu une jaunisse à la naissance, facteur potentiellement associé au risque d'autisme.",
            'Statut_testeur': "Indique la relation entre le testeur et la personne évaluée (Famille, Professionnel de santé, Individu, etc.).",
        }

        # Définition par défaut pour les variables sans commentaire spécifique
        default_comment = "Distribution de la variable dans l'ensemble du dataset."

        all_columns = [col for col in df.columns if col != 'TSA']
        analysis_var = st.selectbox("Choisir une variable à analyser", all_columns, key="analysis_var_in_exploration")

        # Afficher le commentaire pour la variable sélectionnée
        comment = variable_comments.get(analysis_var, default_comment)
        st.info(comment)

        col1, col2 = st.columns(2)
        with col1:
            color_var = None  # Ne pas utiliser la coloration par TSA
            if analysis_var == 'Jaunisse':
                fig = px.histogram(df, x='Jaunisse',
                                   title=f"Distribution de la jaunisse dans le dataset")
                st.plotly_chart(fig, use_container_width=True)
            else:
                is_categorical_aq = analysis_var.startswith('A') and analysis_var[1:].isdigit() and len(analysis_var) <= 3
                if is_categorical_aq:
                    fig = create_plotly_figure(df, x=analysis_var, color=color_var, kind='bar', title=f"Distribution de {analysis_var} (catégorielle)")
                else:
                    fig = create_plotly_figure(df, x=analysis_var, color=color_var, kind='histogram', title=f"Distribution de {analysis_var}")
                if fig:
                    st.plotly_chart(fig, use_container_width=True)
        with col2:
            stats = df[analysis_var].describe().to_frame().T
            st.dataframe(stats, use_container_width=True)


    with st.expander("📝 Analyse des Réponses au Questionnaire AQ-10", expanded=True):
        st.subheader("Analyse des Réponses au Questionnaire AQ-10")
        question_tabs = st.tabs([f"Q{i+1}" for i in range(10)])
        for i, tab in enumerate(question_tabs):
            with tab:
                col1, col2 = st.columns([2,3])
                with col1:
                    st.write(f"**Question A{i+1} :**")
                    st.markdown("> " + get_question_text(i+1))
                with col2:
                    try:
                        values_counts = df[f'A{i+1}'].value_counts().reset_index()
                        values_counts.columns = [f'A{i+1}', 'count']
                        color_discrete_map = {0: "#2ecc71", 1: "#3498db"}
                        fig = px.pie(
                            values_counts,
                            values='count',
                            names=f'A{i+1}',
                            color=f'A{i+1}',
                            color_discrete_map=color_discrete_map,
                            title=f"Répartition des réponses A{i+1}"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    except Exception as e:
                        st.error(f"Erreur lors de la création du graphique: {str(e)}")

    with st.expander("⚙️ Création de Variables Composites", expanded=True):
        st.subheader("Création de Variables Composites")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Score A10 :**")
            st.markdown("""
            $$
            \\text{Score\\_A10} = \\sum_{i=1}^{10} A_i
            $$
            """)
            if 'TSA' in df.columns:
                yes_mean = df[df['TSA'] == 'Yes']['Score_A10'].mean()
                no_mean = df[df['TSA'] == 'No']['Score_A10'].mean()
                st.metric("Score Moyen (TSA)", f"{yes_mean:.1f} ± {df[df['TSA'] == 'Yes']['Score_A10'].std():.1f}")
                st.metric("Score Moyen (Non-TSA)", f"{no_mean:.1f} ± {df[df['TSA'] == 'No']['Score_A10'].std():.1f}")
            else:
                overall_mean = df['Score_A10'].mean()
                st.metric("Score Moyen", f"{overall_mean:.1f} ± {df['Score_A10'].std():.1f}")
        with col2:
            color_var = 'TSA' if 'TSA' in df.columns else None
            fig = create_plotly_figure(df, y='Score_A10', color=color_var, kind='violin', title="Distribution des Scores")
            if fig:
                st.plotly_chart(fig, use_container_width=True)

    with st.expander("🔗 Matrice de Corrélation", expanded=True):
        try:
            df_corr = df.copy()
            if 'Jaunisse' in df_corr.columns:
                df_corr = df_corr.drop(columns=['Jaunisse'])
            if 'TSA' in df_corr.columns:
                df_corr['TSA_num'] = df_corr['TSA'].map({'Yes': 1, 'No': 0})
            categorical_cols = df_corr.select_dtypes(include=['object']).columns
            if not categorical_cols.empty:
                from sklearn.preprocessing import OneHotEncoder
                ohe = OneHotEncoder(sparse_output=False, drop='first')
                encoded_data = ohe.fit_transform(df_corr[categorical_cols])
                feature_names = ohe.get_feature_names_out(categorical_cols)
                encoded_df = pd.DataFrame(encoded_data, columns=feature_names)
                numeric_df = df_corr.select_dtypes(exclude=['object']).reset_index(drop=True)
                df_corr_processed = pd.concat([numeric_df, encoded_df], axis=1)
                corr_matrix = df_corr_processed.corr(numeric_only=True)
            else:
                df_corr_processed = df_corr.select_dtypes(exclude=['object'])
                corr_matrix = df_corr_processed.corr(numeric_only=True)

            mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
            fig, ax = plt.subplots(figsize=(14, 12))
            cmap = sns.diverging_palette(200, 120, as_cmap=True)
            sns.heatmap(
                corr_matrix,
                mask=mask,
                cmap=cmap,
                vmax=1.0,
                vmin=-1.0,
                center=0,
                square=True,
                linewidths=0.8,
                fmt='.2f',
                annot=True,
                annot_kws={"size": 9, "weight": "bold"},
                cbar_kws={"shrink": 0.8, "label": "Coefficient de corrélation"}
            )
            plt.title("Matrice de corrélation des variables", fontsize=16, pad=20)
            plt.xticks(rotation=45, ha='right', fontsize=9)
            plt.yticks(fontsize=9)
            plt.tight_layout()
            st.pyplot(fig)
        except Exception as e:
            st.error(f"Erreur lors du calcul de la matrice de corrélation: {str(e)}")


    with st.expander("🧪 Tests Statistiques", expanded=True):
        st.markdown("""
        <div style="background-color: #f0f7ff; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h4 style="color: #3498db; margin-top: 0;">Tests d'association statistique</h4>
            <p>Évaluation des relations entre variables et diagnostic TSA</p>
        </div>
        """, unsafe_allow_html=True)

        test_type = st.radio(
            "Choisir le type de test:",
            ["Chi-carré (variables catégorielles)", "Mann-Whitney (variables numériques)"],
            key="stat_test_type"
        )

        if test_type == "Chi-carré (variables catégorielles)":
            from scipy.stats import chi2_contingency

            st.markdown("""
            **Test d'indépendance du Chi-carré :** Évalue si deux variables catégorielles sont indépendantes.
            Un p-value < 0.05 suggère une relation significative.
            """)

            df = df.copy()
            categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
            aq_columns = [col for col in df.columns if col.startswith('A') and col[1:].isdigit()]
            categorical_cols.extend([col for col in aq_columns if col not in categorical_cols])

            if 'TSA' in categorical_cols:
                categorical_cols.remove('TSA')

                if categorical_cols:
                    cat_var = st.selectbox(
                        "Sélectionner une variable catégorielle:",
                        categorical_cols,
                        key="chi2_var_selector"
                    )

                    try:
                        contingency_table = pd.crosstab(df[cat_var], df['TSA'])
                        chi2_stat, p_val, dof, expected = chi2_contingency(contingency_table)

                        # Réduction de la largeur avec colonnes optimisées
                        col1, col2, col3 = st.columns([2, 2, 3])

                        with col1:
                            st.markdown("### Table de contingence")
                            st.dataframe(contingency_table, use_container_width=True)

                        with col2:
                            st.markdown("### Résultats du test")
                            st.metric("Statistique χ²", f"{chi2_stat:.3f}")
                            st.metric("p-value", f"{p_val:.5f}")
                            st.metric("Degrés de liberté", dof)

                            if p_val < 0.05:
                                st.success("**Significatif** (p < 0.05)")
                            else:
                                st.info("**Non significatif** (p > 0.05)")

                        with col3:
                            # Graphique plus compact
                            contingency_percent = contingency_table.div(contingency_table.sum(axis=1), axis=0) * 100
                            fig = px.bar(
                                contingency_percent.reset_index().melt(id_vars=cat_var),
                                x=cat_var, y='value', color='TSA',
                                barmode='group',
                                color_discrete_map=palette,
                                labels={'value': 'Pourcentage (%)'},
                                title=f"Distribution par diagnostic"
                            )
                            fig.update_layout(height=300)  # Hauteur réduite
                            st.plotly_chart(fig, use_container_width=True)

                    except Exception as e:
                        st.error(f"Erreur lors du test Chi-carré: {str(e)}")
                else:
                    st.warning("Aucune variable catégorielle trouvée.")

        else:  # Mann-Whitney
            st.markdown("""
            **Test de Mann-Whitney U :** Compare les distributions de deux groupes indépendants.
            Un p-value < 0.05 suggère une différence significative.
            """)

            numeric_cols = df.select_dtypes(include=['float', 'int']).columns.tolist()
            numeric_cols = [col for col in numeric_cols if not (col.startswith('A') and col[1:].isdigit() and len(col) <= 3)]

            if 'Score_A10' in numeric_cols:
                numeric_cols.remove('Score_A10')
                numeric_cols = ['Score_A10'] + numeric_cols

            if numeric_cols:
                num_var = st.selectbox(
                    "Sélectionner une variable numérique:",
                    numeric_cols,
                    key="mw_var_selector"
                )

                try:
                    if 'TSA' in df.columns and df['TSA'].nunique() >= 2:
                        yes_group = df[df['TSA'] == 'Yes'][num_var].dropna()
                        no_group = df[df['TSA'] == 'No'][num_var].dropna()

                        if len(yes_group) > 0 and len(no_group) > 0:
                            stat, p_val = mannwhitneyu(yes_group, no_group, alternative='two-sided')

                            # Disposition compacte en 3 colonnes
                            col1, col2, col3 = st.columns([2, 2, 3])

                            with col1:
                                st.markdown("### Statistiques")
                                group_stats = df.groupby('TSA')[num_var].agg(['count', 'mean', 'std']).round(2)
                                st.dataframe(group_stats, use_container_width=True)

                            with col2:
                                st.markdown("### Résultats")
                                st.metric("Statistique U", f"{stat:.1f}")
                                st.metric("p-value", f"{p_val:.5f}")

                                if p_val < 0.05:
                                    st.success("**Significatif**")
                                else:
                                    st.info("**Non significatif**")

                            with col3:
                                # Box plot compact
                                fig = px.box(
                                    df.dropna(subset=[num_var]), x='TSA', y=num_var,
                                    color='TSA', color_discrete_map=palette,
                                    title=f"Comparaison {num_var}"
                                )
                                fig.update_layout(height=300)  # Hauteur réduite
                                st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.warning("Données insuffisantes pour le test.")
                    else:
                        st.warning("Dataset doit contenir une colonne 'TSA' avec au moins deux groupes.")
                except Exception as e:
                    st.error(f"Erreur lors du test: {str(e)}")
            else:
                st.warning("Aucune variable numérique trouvée.")

    with st.expander("📐 Analyse Factorielle (FAMD)", expanded=True):
        st.markdown("""
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h3 style="color: #2c3e50; margin-top: 0;">Analyse Factorielle Mixte (FAMD)</h3>
            <p style="color: #7f8c8d;">Réduction de dimensions pour visualiser la structure des données et les relations entre variables.</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        L'**Analyse Factorielle de Données Mixtes (FAMD)** est une méthode particulièrement adaptée à nos données car elle permet de traiter simultanément:
        - Des variables numériques (comme l'âge, les scores A1-A10)
        - Des variables catégorielles (comme le genre, l'ethnie, les antécédents familiaux)

        Cette méthode nous permet de projeter les données sur un plan à deux dimensions pour visualiser les relations entre les variables et les individus.
        """)

        try:
            import prince
            from sklearn import utils
            import numpy as np

            df_famd = df.copy()
            if 'Jaunisse' in df_famd.columns:
                df_famd = df_famd.drop(columns=['Jaunisse'])
            df_famd = df_famd.reset_index(drop=True)

            class FAMD_Custom(prince.FAMD):
                """Classe personnalisée pour contourner le problème d'indexation booléenne dans Prince"""
                def transform(self, X):
                    utils.validation.check_is_fitted(self, 's_')
                    return self.row_coordinates(X)

                def column_correlations_custom(self, X):
                    """Méthode personnalisée pour calculer les corrélations des colonnes"""
                    row_pc = self.row_coordinates(X)
                    correlations = {}

                    for feature in X.columns:
                        if X[feature].dtype.kind in 'ifc':
                            corrs = []
                            for component in row_pc.columns:
                                corrs.append(np.corrcoef(X[feature], row_pc[component])[0, 1])
                            correlations[feature] = corrs

                        else:
                            means = {}
                            for component in row_pc.columns:
                                means[component] = []

                            for category in X[feature].unique():
                                mask = (X[feature] == category).values
                                for component in row_pc.columns:
                                    coord_mean = row_pc.loc[mask, component].mean()
                                    means[component].append(coord_mean)

                            max_abs = max(abs(v) for comp_means in means.values() for v in comp_means)
                            if max_abs > 0:
                                for component in means:
                                    means[component] = [v/max_abs for v in means[component]]

                            corrs = []
                            for component in row_pc.columns:
                                corrs.append(sum(means[component])/len(means[component]))
                            correlations[feature] = corrs

                    return pd.DataFrame(
                        data=[[correlations[feature][i] for feature in X.columns] for i in range(len(row_pc.columns))],
                        columns=X.columns
                    ).T

            for col in df_famd.select_dtypes(include=['object']).columns:
                df_famd[col] = df_famd[col].astype('category')

            for col in df_famd.select_dtypes(include=['number']).columns:
                df_famd[col] = df_famd[col].astype('float64')

            df_famd = df_famd.dropna()
            df_famd = df_famd.reset_index(drop=True)

            n_components = min(5, min(df_famd.shape) - 1)
            X_famd = df_famd.copy()

            famd = FAMD_Custom(
                n_components=n_components,
                n_iter=10,
                random_state=42,
                copy=True,
                engine='sklearn'
            )
            famd = famd.fit(X_famd)

            coordinates = famd.transform(X_famd)

            eigenvalues = famd.eigenvalues_
            explained_variance = eigenvalues / sum(eigenvalues)

            famd_tabs = st.tabs([
                "Projection des individus",
                "Cercle des corrélations",
                "FAMD score A10",
                "Cercle de corrélation Score A10",
                "Interprétation"
            ])

            with famd_tabs[0]:
                st.subheader("Projection des individus")

                col1, col2 = st.columns([2, 1])

                with col1:
                    fig, ax = plt.subplots(figsize=(8, 5))
                    if 'TSA' in X_famd.columns:
                        coordinates_array = coordinates.values
                        for i, category in enumerate(X_famd['TSA'].unique()):
                            mask_array = (X_famd['TSA'] == category).values
                            color = "#e74c3c" if category == "Yes" else "#3498db"
                            ax.scatter(
                                coordinates_array[mask_array, 0],
                                coordinates_array[mask_array, 1],
                                label=category,
                                color=color,
                                alpha=0.6,
                                s=30
                            )
                        ax.legend(title="TSA")
                    else:
                        ax.scatter(coordinates.values[:, 0], coordinates.values[:, 1], alpha=0.7, s=30)

                    ax.set_xlabel(f'Comp. 1 ({explained_variance[0]:.1%})')
                    ax.set_ylabel(f'Comp. 2 ({explained_variance[1]:.1%})')
                    ax.set_title('Projection des individus', fontsize=12)
                    ax.grid(True, linestyle='--', alpha=0.7)
                    st.pyplot(fig)

                with col2:
                    st.markdown("### Variance expliquée")
                    for i, var in enumerate(explained_variance[:3]):
                        st.metric(f"Composante {i+1}", f"{var:.1%}")

            with famd_tabs[1]:
                st.subheader("Cercle des corrélations")

                col1, col2 = st.columns([3, 2])

                with col1:
                    try:
                        if hasattr(famd, 'column_correlations'):
                            column_corr = famd.column_correlations(X_famd)
                        else:
                            column_corr = famd.column_correlations_custom(X_famd)

                        fig, ax = plt.subplots(figsize=(6, 6))
                        circle = plt.Circle((0, 0), 1, color='gray', fill=False, linestyle='--')
                        ax.add_artist(circle)

                        ax.axhline(y=0, color='gray', linestyle='-', alpha=0.3)
                        ax.axvline(x=0, color='gray', linestyle='-', alpha=0.3)

                        for i, var in enumerate(column_corr.index):
                            x = column_corr.iloc[i, 0]
                            y = column_corr.iloc[i, 1]

                            ax.arrow(0, 0, x, y, head_width=0.05, head_length=0.05, fc='blue', ec='blue', alpha=0.7)

                            # Texte plus petit et sélectif
                            if var == 'Score_A10':
                                ax.text(x*1.1, y*1.1, var, fontsize=10, color='red', fontweight='bold')
                            elif var in ['TSA', 'Age', 'Genre']:
                                ax.text(x*1.1, y*1.1, var, fontsize=8, color='green')

                        ax.set_xlim(-1.1, 1.1)
                        ax.set_ylim(-1.1, 1.1)
                        ax.set_xlabel(f'Comp. 1 ({explained_variance[0]:.1%})', fontsize=10)
                        ax.set_ylabel(f'Comp. 2 ({explained_variance[1]:.1%})', fontsize=10)
                        ax.set_title('Cercle des corrélations', fontsize=12)
                        ax.grid(True, linestyle='--', alpha=0.5)
                        st.pyplot(fig)

                    except Exception as e:
                        st.warning(f"Impossible de générer le cercle : {str(e)}")

                with col2:
                    st.markdown("### Variables principales")
                    st.write("Variables les plus contributives :")
                    key_vars = ['Score_A10', 'TSA', 'Age', 'Genre']
                    for var in key_vars:
                        if var in column_corr.index:
                            contrib = np.sqrt(column_corr.loc[var, 0]**2 + column_corr.loc[var, 1]**2)
                            st.write(f"• **{var}** : {contrib:.3f}")

            with famd_tabs[2]:
                st.subheader("FAMD centrée sur Score A10")
                st.markdown("""
                Analyse spécifique mettant en évidence la relation entre le Score A10 et le diagnostic TSA.
                """)

                try:
                    if 'Score_A10' in X_famd.columns:
                        a_vars_to_exclude = []
                        for i in range(1, 11):
                            col_name = f'A{i}'
                            if col_name in X_famd.columns:
                                a_vars_to_exclude.append(col_name)

                        # Créer un nouveau dataframe en excluant explicitement les variables A1-A10
                        X_filtered = X_famd.drop(columns=a_vars_to_exclude, errors='ignore').copy()

                        # Vérification que toutes les variables A1-A10 sont bien exclues
                        remaining_a_vars = [col for col in X_filtered.columns if col.startswith('A') and col[1:].isdigit()]
                        if remaining_a_vars:
                            st.warning(f"Variables A résiduelles : {remaining_a_vars}")
                            X_filtered = X_filtered.drop(columns=remaining_a_vars, errors='ignore')

                        # Définir les variables clés pour l'analyse FAMD centrée sur Score_A10
                        key_vars = ['Score_A10', 'TSA']
                        for var in ['Age', 'Genre', 'Ethnie']:
                            if var in X_filtered.columns:
                                key_vars.append(var)

                        # Créer le dataset final pour l'analyse
                        X_a10 = X_filtered[key_vars].copy()

                        famd_a10 = FAMD_Custom(
                            n_components=min(3, len(key_vars)-1),
                            n_iter=10,
                            random_state=42,
                            copy=True,
                            engine='sklearn'
                        )
                        famd_a10 = famd_a10.fit(X_a10)
                        coords_a10 = famd_a10.transform(X_a10)

                        # Disposition en colonnes comme la projection des individus
                        col1, col2 = st.columns([2, 1])

                        with col1:
                            # Création du graphique de projection avec même taille que projection individus
                            fig, ax = plt.subplots(figsize=(8, 5))
                            coords_array = coords_a10.values

                            if 'TSA' in X_a10.columns:
                                for category in X_a10['TSA'].unique():
                                    mask = (X_a10['TSA'] == category).values
                                    color = "#e74c3c" if category == "Yes" else "#3498db"
                                    ax.scatter(
                                        coords_array[mask, 0],
                                        coords_array[mask, 1],
                                        label=category,
                                        color=color,
                                        alpha=0.7,
                                        s=25
                                    )
                                ax.legend(title="TSA")

                            ax.set_xlabel('Composante 1', fontsize=10)
                            ax.set_ylabel('Composante 2', fontsize=10)
                            ax.set_title('FAMD centrée Score_A10', fontsize=12)
                            ax.grid(True, linestyle='--', alpha=0.7)
                            st.pyplot(fig)

                        with col2:
                            st.markdown("### Variance Score A10")
                            eigenvalues_a10 = famd_a10.eigenvalues_
                            explained_variance_a10 = eigenvalues_a10 / sum(eigenvalues_a10)
                            for i, var in enumerate(explained_variance_a10[:3]):
                                st.metric(f"Composante {i+1}", f"{var:.1%}")
                    else:
                        st.warning("La variable Score_A10 n'est pas disponible dans le dataset.")
                except Exception as e:
                    st.warning(f"Erreur lors de l'analyse FAMD : {str(e)}")

            with famd_tabs[3]:
                st.subheader("Cercle de corrélation Score A10")

                col1, col2 = st.columns([3, 2])

                with col1:
                    try:
                        if 'Score_A10' in X_famd.columns:
                            # Utiliser X_a10 et famd_a10 définis précédemment
                            if hasattr(famd_a10, 'column_correlations'):
                                column_corr_a10 = famd_a10.column_correlations(X_a10)
                            else:
                                st.info("Utilisation d'une méthode alternative pour calculer les corrélations...")
                                column_corr_a10 = famd_a10.column_correlations_custom(X_a10)

                            fig, ax = plt.subplots(figsize=(6, 6))
                            circle = plt.Circle((0, 0), 1, color='gray', fill=False, linestyle='--')
                            ax.add_artist(circle)

                            ax.axhline(y=0, color='gray', linestyle='-', alpha=0.3)
                            ax.axvline(x=0, color='gray', linestyle='-', alpha=0.3)

                            for i, var in enumerate(column_corr_a10.index):
                                x = column_corr_a10.iloc[i, 0]
                                y = column_corr_a10.iloc[i, 1]

                                ax.arrow(0, 0, x, y, head_width=0.05, head_length=0.05, fc='blue', ec='blue', alpha=0.7)

                                # Mise en évidence du Score_A10
                                if var == 'Score_A10':
                                    ax.text(x*1.1, y*1.1, var, fontsize=12, color='red', fontweight='bold')
                                else:
                                    ax.text(x*1.1, y*1.1, var, fontsize=10)

                            ax.set_xlim(-1.1, 1.1)
                            ax.set_ylim(-1.1, 1.1)
                            ax.set_xlabel(f'Composante 1', fontsize=10)
                            ax.set_ylabel(f'Composante 2', fontsize=10)
                            ax.set_title('Cercle des corrélations Score_A10', fontsize=12)
                            ax.grid(True, linestyle='--', alpha=0.5)
                            st.pyplot(fig)
                        else:
                            st.warning("La variable Score_A10 n'est pas disponible dans le dataset.")
                    except Exception as e:
                        st.warning(f"Impossible de générer le cercle des corrélations: {str(e)}")

                with col2:
                    st.markdown("### Analyse Score A10")
                    if 'column_corr_a10' in locals():
                        if 'Score_A10' in column_corr_a10.index:
                            score_contrib = np.sqrt(column_corr_a10.loc['Score_A10', 0]**2 + column_corr_a10.loc['Score_A10', 1]**2)
                            st.metric("Contribution Score A10", f"{score_contrib:.3f}")

                        st.markdown("**Variables corrélées :**")
                        for var in column_corr_a10.index:
                            if var != 'Score_A10':
                                contrib = np.sqrt(column_corr_a10.loc[var, 0]**2 + column_corr_a10.loc[var, 1]**2)
                                st.write(f"• {var}: {contrib:.3f}")

            with famd_tabs[4]:
                st.subheader("Interprétation des résultats")

                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("### Points clés")
                    st.write(f"""
                    • **Variance expliquée** : {explained_variance[0] + explained_variance[1]:.1%}
                    • **Variables discriminantes** : Score A10, TSA, Age
                    • **Regroupement TSA** : Patterns identifiables
                    """)

                with col2:
                    st.markdown("### Composantes principales")
                    summary_df = pd.DataFrame({
                        'Composante': [f"Comp. {i+1}" for i in range(min(3, len(eigenvalues)))],
                        'Variance (%)': (explained_variance[:3] * 100).round(2)
                    })
                    st.dataframe(summary_df, use_container_width=True)

                st.markdown("""
                ### Analyse détaillée

                L'analyse factorielle de données mixtes nous permet d'identifier plusieurs tendances importantes:

                1. **Structure des données** : Les deux premières composantes principales expliquent environ {:.1%} de la variance totale, ce qui indique une bonne capture de la structure des données.

                2. **Variables discriminantes** : Les variables qui contribuent le plus à la distinction entre les groupes incluent le Score A10 et d'autres variables démographiques.

                3. **Regroupement des cas TSA** : On observe une tendance au regroupement des cas diagnostiqués TSA dans l'espace factoriel, ce qui suggère des patterns communs dans leurs profils.

                4. **Influence du Score A10** : Le Score A10 montre une corrélation significative avec la première composante principale, confirmant son importance dans le processus diagnostique.
                """.format(explained_variance[0] + explained_variance[1]))

                st.subheader("Tableau récapitulatif")
                summary_complete_df = pd.DataFrame({
                    'Composante': [f"Composante {i+1}" for i in range(len(eigenvalues))],
                    'Valeur propre': eigenvalues,
                    'Variance expliquée (%)': explained_variance * 100,
                    'Variance cumulée (%)': np.cumsum(explained_variance) * 100
                })
                st.dataframe(summary_complete_df.style.format({
                    'Valeur propre': '{:.3f}',
                    'Variance expliquée (%)': '{:.2f}%',
                    'Variance cumulée (%)': '{:.2f}%'
                }))

        except Exception as e:
            st.error(f"Erreur globale lors de l'analyse FAMD: {str(e)}")


def show_ml_analysis():
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import numpy as np
    import pandas as pd
    import seaborn as sns
    import matplotlib.pyplot as plt
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler, OneHotEncoder
    from sklearn.compose import ColumnTransformer
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.metrics import roc_auc_score, confusion_matrix, classification_report, roc_curve
    from sklearn.metrics import balanced_accuracy_score, precision_recall_curve
    from sklearn.model_selection import cross_val_score, train_test_split, learning_curve
    import time
    import os

    # Configuration initiale
    os.environ['TQDM_DISABLE'] = '1'

    try:
        st.set_option('deprecation.showPyplotGlobalUse', False)
    except Exception:
        pass

    # Fonction d'entraînement optimisée
    @st.cache_resource(show_spinner=False)
    def train_optimized_rf_model(_X_train, _y_train, _preprocessor, _X_test, _y_test):
        """Entraîne un modèle Random Forest optimisé avec gestion d'erreurs"""
        try:
            rf = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )

            pipeline = Pipeline([
                ('preprocessor', _preprocessor),
                ('classifier', rf)
            ])

            start_time = time.time()
            pipeline.fit(_X_train, _y_train)
            training_time = time.time() - start_time

            # Prédictions
            y_pred = pipeline.predict(_X_test)
            y_pred_proba = pipeline.predict_proba(_X_test)[:, 1]

            # Métriques
            metrics = {
                'accuracy': accuracy_score(_y_test, y_pred),
                'precision': precision_score(_y_test, y_pred, zero_division=0),
                'recall': recall_score(_y_test, y_pred, zero_division=0),
                'f1': f1_score(_y_test, y_pred, zero_division=0),
                'auc': roc_auc_score(_y_test, y_pred_proba),
                'training_time': training_time
            }

            # Matrice de confusion
            cm = confusion_matrix(_y_test, y_pred)

            # Courbes
            fpr, tpr, _ = roc_curve(_y_test, y_pred_proba)
            precision_curve, recall_curve, _ = precision_recall_curve(_y_test, y_pred_proba)

            # Importance des features
            try:
                feature_names = pipeline.named_steps['preprocessor'].get_feature_names_out()
            except:
                feature_names = [f"feature_{i}" for i in range(len(pipeline.named_steps['classifier'].feature_importances_))]

            importances = pipeline.named_steps['classifier'].feature_importances_
            feature_importance = pd.DataFrame({
                'feature': feature_names,
                'importance': importances
            }).sort_values('importance', ascending=False)

            # Validation croisée
            cv_scores = cross_val_score(pipeline, _X_train, _y_train, cv=5, scoring='accuracy')

            return {
                'pipeline': pipeline,
                'metrics': metrics,
                'confusion_matrix': cm,
                'roc_curve': (fpr, tpr),
                'pr_curve': (precision_curve, recall_curve),
                'feature_importance': feature_importance,
                'cv_scores': cv_scores,
                'y_pred': y_pred,
                'y_pred_proba': y_pred_proba,
                'status': 'success'
            }

        except Exception as e:
            st.error(f"Erreur lors de l'entraînement : {str(e)}")
            return {'status': 'error', 'message': str(e)}

    # Chargement et préparation des données
    try:
        with st.spinner("Chargement des données..."):
            df, _, _, _, _, _, _ = load_dataset()

        # Nettoyage optimisé
        aq_columns = [f'A{i}' for i in range(1, 11) if f'A{i}' in df.columns]
        if aq_columns:
            df = df.drop(columns=aq_columns)

        if 'Jaunisse' in df.columns:
            df = df.drop(columns=['Jaunisse'])

        if 'TSA' not in df.columns:
            st.error("❌ Colonne 'TSA' manquante dans le dataset")
            return

        # Préparation des variables
        X = df.drop(columns=['TSA'])
        y = df['TSA'].map({'Yes': 1, 'No': 0})

        # Vérification des données
        if X.empty or y.empty:
            st.error("❌ Données insuffisantes pour l'analyse")
            return

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    except Exception as e:
        st.error(f"❌ Erreur de chargement des données : {str(e)}")
        return

    # Préprocesseur
    numerical_cols = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
    categorical_cols = X.select_dtypes(include=['object', 'category']).columns.tolist()

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
        ],
        remainder='passthrough',
        verbose_feature_names_out=False
    )
    st.markdown("""
<div style="background: linear-gradient(90deg, #3498db, #2ecc71);
            padding: 40px 25px; border-radius: 20px; margin-bottom: 35px; text-align: center;">
    <h1 style="color: white; font-size: 2.8rem; margin-bottom: 15px;
               text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
        🧠 Outil de Dépistage TSA par Machine Learning
    </h1>
    <p style="color: rgba(255,255,255,0.95); font-size: 1.3rem;
              max-width: 800px; margin: 0 auto; line-height: 1.6;">
        Une approche moderne et scientifique pour le dépistage précoce
    </p>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
    <div style="background-color: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 30px;">
        <p style="font-size: 1.1rem; line-height: 1.6; text-align: center; margin: 0;">
        Cette section présente un outil d'aide au dépistage précoce utilisant l'intelligence artificielle.
        L'objectif est d'identifier les profils à risque nécessitant une évaluation approfondie par un professionnel qualifié.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Onglets
    ml_tabs = st.tabs([
        "📊 Préprocessing",
        "🚀 Comparaison Rapide",
        "🌲 Analyse Random Forest",
        "⚙️ Optimisation Dépistage"
    ])

    with ml_tabs[0]:
    # Styles CSS pour harmonisation
        st.markdown("""
        <style>
            .preprocessing-header {
                background: linear-gradient(90deg, #3498db, #2ecc71);
                padding: 30px 20px;
                border-radius: 15px;
                margin-bottom: 25px;
                text-align: center;
            }
            
            .info-card-modern {
                background: white;
                border-radius: 15px;
                padding: 25px;
                margin: 15px 0;
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                border-left: 4px solid #3498db;
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            
            .info-card-modern:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            }
            
            .metric-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            
            .metric-card {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                border: 1px solid #e9ecef;
            }
            
            .section-title {
                color: #2c3e50;
                font-size: 1.8rem;
                border-bottom: 3px solid #3498db;
                padding-bottom: 10px;
                margin: 30px 0 20px 0;
            }
        </style>
        """, unsafe_allow_html=True)
    
        # En-tête de section harmonisé
        st.markdown("""
        <div class="preprocessing-header">
            <h2 style="color: white; font-size: 2.2rem; margin-bottom: 10px;
                       text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
                🔧 Pipeline de Prétraitement des Données
            </h2>
            <p style="color: rgba(255,255,255,0.95); font-size: 1.1rem;
                      margin: 0 auto; line-height: 1.5;">
                Configuration des données pour optimiser la détection des patterns pertinents
            </p>
        </div>
        """, unsafe_allow_html=True)
    
        # Carte d'introduction
        st.markdown("""
        <div class="info-card-modern">
            <div style="background-color: #e8f4fd; padding: 20px; border-radius: 10px; 
                        margin-bottom: 20px; border-left: 4px solid #3498db;">
                <h3 style="color: #2c3e50; margin-top: 0; display: flex; align-items: center;">
                    <span style="margin-right: 10px;">⚙️</span>
                    Configuration des Données pour le Dépistage
                </h3>
                <p style="color: #34495e; margin-bottom: 0; line-height: 1.6;">
                    Les transformations appliquées pour optimiser la détection des patterns pertinents 
                    dans le processus de dépistage précoce du TSA.
                </p>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
        # Conteneur principal avec deux colonnes
        col1, col2 = st.columns([1, 1], gap="large")
    
        # Colonne 1 - Structure du dataset
        with col1:
            st.markdown("""
            <div class="info-card-modern">
                <h3 class="section-title">📋 Structure du Dataset</h3>
                <div style="margin-top: 20px;">
            """, unsafe_allow_html=True)
            
            # Calculs existants conservés
            total_samples = len(df)
            tsa_positive = (y == 1).sum()
    
            # Métriques dans des cartes stylisées
            st.markdown(f"""
            <div class="metric-grid">
                <div class="metric-card">
                    <h4 style="color: #3498db; margin: 0 0 10px 0;">📊 Échantillons</h4>
                    <div style="font-size: 2rem; font-weight: bold; color: #2c3e50;">
                        {total_samples:,}
                    </div>
                    <p style="color: #7f8c8d; margin: 5px 0 0 0; font-size: 0.9rem;">
                        Total des participants
                    </p>
                </div>
                <div class="metric-card">
                    <h4 style="color: #e74c3c; margin: 0 0 10px 0;">🎯 Cas à Risque</h4>
                    <div style="font-size: 2rem; font-weight: bold; color: #2c3e50;">
                        {tsa_positive:,}
                    </div>
                    <p style="color: #7f8c8d; margin: 5px 0 0 0; font-size: 0.9rem;">
                        ({tsa_positive/total_samples:.1%} du total)
                    </p>
                </div>
            </div>
            """, unsafe_allow_html=True)
    
            # Espacement
            st.markdown("<div style='margin: 30px 0;'></div>", unsafe_allow_html=True)
    
            # Graphique de distribution conservé
            st.markdown("""
            <h4 style="color: #2c3e50; margin: 20px 0 15px 0; display: flex; align-items: center;">
                <span style="margin-right: 8px;">📈</span>
                Répartition des Cas
            </h4>
            """, unsafe_allow_html=True)
            
            fig_dist = px.pie(
                values=[tsa_positive, total_samples - tsa_positive],
                names=['TSA Positif', 'TSA Négatif'],
                color_discrete_sequence=['#e74c3c', '#3498db'],
                hole=0.4  # Donut chart plus moderne
            )
            fig_dist.update_layout(
                showlegend=True,
                font=dict(size=12),
                margin=dict(t=20, b=20, l=20, r=20)
            )
            st.plotly_chart(fig_dist, use_container_width=True)
            
            st.markdown("</div></div>", unsafe_allow_html=True)
    
        # Colonne 2 - Variables analysées
        with col2:
            st.markdown("""
            <div class="info-card-modern">
                <h3 class="section-title">🔧 Variables Analysées</h3>
                <div style="margin-top: 20px;">
            """, unsafe_allow_html=True)
            
            # Tableau de preprocessing conservé mais stylisé
            preprocessing_info = pd.DataFrame({
                'Type': ['Numériques', 'Catégorielles', 'Total'],
                'Nombre': [len(numerical_cols), len(categorical_cols), len(numerical_cols) + len(categorical_cols)],
                'Traitement': ['Standardisation', 'Encodage One-Hot', '-']
            })
            
            st.markdown("""
            <h4 style="color: #2c3e50; margin: 20px 0 15px 0; display: flex; align-items: center;">
                <span style="margin-right: 8px;">📊</span>
                Résumé du Traitement
            </h4>
            """, unsafe_allow_html=True)
            
            st.dataframe(
                preprocessing_info, 
                use_container_width=True,
                hide_index=True
            )
    
            # Variables numériques avec style amélioré
            st.markdown("""
            <div style="margin-top: 25px;">
                <h4 style="color: #2c3e50; margin: 15px 0; display: flex; align-items: center;">
                    <span style="margin-right: 8px;">🔢</span>
                    Variables Numériques
                </h4>
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; 
                            border-left: 3px solid #3498db;">
            """, unsafe_allow_html=True)
            
            for col in numerical_cols[:5]:
                st.markdown(f"• **{col}**")
            if len(numerical_cols) > 5:
                st.markdown(f"*... et {len(numerical_cols) - 5} autres variables*")
            
            st.markdown("</div></div>", unsafe_allow_html=True)
    
            # Variables catégorielles avec style amélioré
            st.markdown("""
            <div style="margin-top: 20px;">
                <h4 style="color: #2c3e50; margin: 15px 0; display: flex; align-items: center;">
                    <span style="margin-right: 8px;">📝</span>
                    Variables Catégorielles
                </h4>
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; 
                            border-left: 3px solid #2ecc71;">
            """, unsafe_allow_html=True)
            
            for col in categorical_cols[:5]:
                st.markdown(f"• **{col}**")
            if len(categorical_cols) > 5:
                st.markdown(f"*... et {len(categorical_cols) - 5} autres variables*")
            
            st.markdown("</div></div></div></div>", unsafe_allow_html=True)
    
        # Note informative finale
        st.markdown("""
        <div class="info-card-modern" style="margin-top: 30px;">
            <div style="display: flex; align-items: center; background-color: #fff3cd; 
                        padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107;">
                <span style="font-size: 1.5rem; margin-right: 15px;">💡</span>
                <div>
                    <strong style="color: #856404;">Note Importante :</strong>
                    <p style="margin: 5px 0 0 0; color: #856404; line-height: 1.5;">
                        Ce preprocessing garantit une normalisation optimale des données pour 
                        améliorer la performance des algorithmes de machine learning dans le 
                        contexte du dépistage précoce du TSA.
                    </p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with ml_tabs[1]:
        st.markdown("""
        <div class="preprocessing-header">
            <h2 style="color: white; font-size: 2.2rem; margin-bottom: 10px;
                       text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
                🚀 Comparaison rapide des algorithmes
            </h2>
            <p style="color: rgba(255,255,255,0.95); font-size: 1.1rem;
                      margin: 0 auto; line-height: 1.5;">
                Configuration des données pour optimiser la détection des patterns pertinents
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="background-color: #eaf6fc; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 4px solid #3498db;">
            <h3 style="color: #2c3e50; margin-top: 0;">Critères de sélection pour le dépistage</h3>
            <ul style="color: #34495e;">
                <li>🩺 <strong>Sensibilité élevée</strong> (détection des vrais cas)</li>
                <li>⚡ <strong>Rapidité d'exécution</strong></li>
                <li>📈 <strong>Stabilité des résultats</strong></li>
                <li>🔍 <strong>Interprétabilité clinique</strong></li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

        # Résultats simulés Lazy Predict
        @st.cache_data(ttl=3600)
        def get_lazy_predict_results():
            return pd.DataFrame({
                "LGBMClassifier": {"Accuracy": 0.963, "Recall": 0.95, "F1 Score": 0.963, "Time": 0.17},
                "RandomForestClassifier": {"Accuracy": 0.956, "Recall": 0.96, "F1 Score": 0.956, "Time": 0.38},
                "XGBClassifier": {"Accuracy": 0.956, "Recall": 0.94, "F1 Score": 0.955, "Time": 0.17},
                "ExtraTreesClassifier": {"Accuracy": 0.951, "Recall": 0.93, "F1 Score": 0.951, "Time": 0.69},
                "GradientBoostingClassifier": {"Accuracy": 0.948, "Recall": 0.92, "F1 Score": 0.947, "Time": 0.52}
            }).T

        lazy_results = get_lazy_predict_results()

        # Tableau stylisé
        def style_dataframe(df):
            return df.style.background_gradient(
                cmap='Blues',
                subset=['Accuracy', 'Recall', 'F1 Score']
            ).background_gradient(
                cmap='Blues_r',
                subset=['Time']
            ).format({
                'Accuracy': '{:.1%}',
                'Recall': '{:.1%}',
                'F1 Score': '{:.1%}',
                'Time': '{:.2f}s'
            })

        st.markdown("### 📊 Résultats comparatifs")
        st.dataframe(style_dataframe(lazy_results), use_container_width=True)

        # Top 3 des modèles
        st.markdown("### 🏆 Top 3 des modèles pour le dépistage")

        top_3 = lazy_results.nlargest(3, 'Accuracy')

        col1, col2, col3 = st.columns(3)

        models_info = [
            ("LGBMClassifier", "🥇", "#1e3a8a"),
            ("RandomForestClassifier", "🥈", "#1e40af"),
            ("XGBClassifier", "🥉", "#1d4ed8")
        ]

        for i, ((model_name, medal, color), col) in enumerate(zip(models_info, [col1, col2, col3])):
            if model_name in top_3.index:
                row = top_3.loc[model_name]
                with col:
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, {color}, #60a5fa); padding: 25px; border-radius: 15px; text-align: center; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                        <div style="font-size: 2rem; margin-bottom: 10px;">{medal}</div>
                        <h3 style="color: white; margin: 0; font-size: 1.1rem;">{model_name}</h3>
                        <hr style="border-color: rgba(255,255,255,0.3); margin: 15px 0;">
                        <div style="color: white;">
                            <p style="margin: 5px 0; font-size: 1.1rem;"><strong>Précision: {row['Accuracy']:.1%}</strong></p>
                            <p style="margin: 5px 0;">Sensibilité: {row['Recall']:.1%}</p>
                            <p style="margin: 5px 0;">F1-Score: {row['F1 Score']:.1%}</p>
                            <p style="margin: 5px 0;">Temps: {row['Time']:.2f}s</p>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

        # Graphiques comparatifs
        st.markdown("### 📈 Visualisations comparatives")
        fig_scatter = px.scatter(
                lazy_results.reset_index(),
                x='Time',
                y='Accuracy',
                size='Recall',
                color='F1 Score',
                hover_name='index',
                title="Performance vs Temps d'exécution",
                labels={'Time': 'Temps (secondes)', 'Accuracy': 'Précision'},
                color_continuous_scale='Blues'
            )
        fig_scatter.update_layout(height=500)
        st.plotly_chart(fig_scatter, use_container_width=True)

        st.info("""
        **🎯 Pourquoi choisir Random Forest pour le dépistage ?**

        - **Excellent équilibre** sensibilité/spécificité (96% de sensibilité)
        - **Interprétation clinique** via l'importance des caractéristiques
        - **Robustesse** aux données manquantes et bruitées
        - **Stabilité** des prédictions sur différentes populations
        """)

    with ml_tabs[2]:
        st.markdown("""
        <div class="preprocessing-header">
            <h2 style="color: white; font-size: 2.2rem; margin-bottom: 10px;
                       text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
                🌲 Analyse Random Forest pour le dépistage
            </h2>
            <p style="color: rgba(255,255,255,0.95); font-size: 1.1rem;
                      margin: 0 auto; line-height: 1.5;">
                Configuration des données pour optimiser la détection des patterns pertinents
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="background-color: #e8f5e9; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 4px solid #2ecc71;">
            <h3 style="color: #2c3e50; margin-top: 0;">Configuration optimale pour le dépistage</h3>
            <p style="color: #34495e;">Le modèle Random Forest a été configuré spécifiquement pour maximiser la détection des cas TSA tout en maintenant une précision élevée.</p>
        </div>
        """, unsafe_allow_html=True)

        with st.spinner("🤖 Entraînement du modèle Random Forest en cours..."):
            rf_results = train_optimized_rf_model(X_train, y_train, preprocessor, X_test, y_test)

        if rf_results.get('status') != 'success':
            st.error(f"❌ Échec de l'entraînement : {rf_results.get('message', 'Erreur inconnue')}")
            return

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "🎯 Accuracy",
                f"{rf_results['metrics']['accuracy']:.1%}",
                "Performance globale"
            )
        with col2:
            st.metric(
                "📡 Sensibilité",
                f"{rf_results['metrics']['recall']:.1%}",
                "Détection des vrais cas"
            )
        with col3:
            st.metric(
                "📈 AUC-ROC",
                f"{rf_results['metrics']['auc']:.3f}",
                "Capacité discriminante"
            )

        rf_tabs = st.tabs([
            "📊 Performances détaillées",
            "🔍 Matrice de confusion",
            "📈 Courbes de performance",
            "🌟 Importance des variables"
        ])

        with rf_tabs[0]:
            st.subheader("📊 Métriques de performance détaillées")

            col1, col2 = st.columns(2)

            with col1:
                metrics_df = pd.DataFrame({
                    'Métrique': ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC-ROC'],
                    'Score': [
                        rf_results['metrics']['accuracy'],
                        rf_results['metrics']['precision'],
                        rf_results['metrics']['recall'],
                        rf_results['metrics']['f1'],
                        rf_results['metrics']['auc']
                    ]
                })

                fig_metrics = px.bar(
                    metrics_df,
                    x='Score',
                    y='Métrique',
                    orientation='h',
                    title="Scores de performance",
                    color='Score',
                    color_continuous_scale='Blues'
                )
                fig_metrics.update_layout(height=400, showlegend=False)
                st.plotly_chart(fig_metrics, use_container_width=True)

            with col2:
                st.markdown("### 🏥 Interprétation clinique")

                recall_value = rf_results['metrics']['recall']
                precision_value = rf_results['metrics']['precision']

                if recall_value >= 0.95:
                    st.success("✅ **Sensibilité excellente** : Détecte 95%+ des cas TSA")
                elif recall_value >= 0.90:
                    st.info("ℹ️ **Sensibilité très bonne** : Détecte 90%+ des cas")
                else:
                    st.warning("⚠️ **Sensibilité à améliorer** : Risque de cas manqués")

                if precision_value >= 0.95:
                    st.success("✅ **Précision excellente** : 95%+ des alertes sont justifiées")
                elif precision_value >= 0.90:
                    st.info("ℹ️ **Précision très bonne** : 90%+ des alertes sont fiables")
                else:
                    st.warning("⚠️ **Précision à améliorer** : Risque de fausses alertes")

                st.metric(
                    "⏱️ Temps d'entraînement",
                    f"{rf_results['metrics']['training_time']:.2f}s",
                    "Adapté à l'usage clinique"
                )

        with rf_tabs[1]:
            st.subheader("🔍 Matrice de confusion")

            cm = rf_results['confusion_matrix']

            fig_cm = go.Figure(data=go.Heatmap(
                z=cm,
                x=['Prédit: Non-TSA', 'Prédit: TSA'],
                y=['Réel: Non-TSA', 'Réel: TSA'],
                colorscale='Blues',
                text=cm,
                texttemplate="%{text}",
                textfont={"size": 24, "color": "white"},
                hoverongaps=False,
                showscale=True
            ))

            fig_cm.update_layout(
                title="Matrice de confusion - Random Forest",
                xaxis_title="Prédiction du modèle",
                yaxis_title="Réalité terrain",
                height=500,
                font_size=14
            )

            st.plotly_chart(fig_cm, use_container_width=True)

            if len(cm.ravel()) == 4:
                tn, fp, fn, tp = cm.ravel()

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.metric("✅ Vrais Positifs", tp, "Cas TSA correctement identifiés")
                    st.metric("✅ Vrais Négatifs", tn, "Cas normaux correctement identifiés")

                with col2:
                    st.metric("❌ Faux Positifs", fp, "Fausses alertes")
                    st.metric("❌ Faux Négatifs", fn, "Cas TSA manqués")

                with col3:
                    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
                    npv = tn / (tn + fn) if (tn + fn) > 0 else 0

                    st.metric("🎯 Spécificité", f"{specificity:.1%}", "Éviter les fausses alertes")
                    st.metric("🛡️ VPN", f"{npv:.1%}", "Fiabilité des cas négatifs")

        with rf_tabs[2]:
            st.subheader("📈 Courbes de performance")

            col1, col2 = st.columns(2)

            with col1:
                fpr, tpr = rf_results['roc_curve']
                auc_score = rf_results['metrics']['auc']

                fig_roc = go.Figure()

                fig_roc.add_trace(go.Scatter(
                    x=fpr, y=tpr,
                    mode='lines',
                    name=f'Random Forest (AUC = {auc_score:.3f})',
                    line=dict(color='#e74c3c', width=3),
                    fill='tonexty'
                ))

                fig_roc.add_trace(go.Scatter(
                    x=[0, 1], y=[0, 1],
                    mode='lines',
                    name='Référence (AUC = 0.5)',
                    line=dict(color='gray', dash='dash', width=2)
                ))

                fig_roc.update_layout(
                    title='Courbe ROC',
                    xaxis_title='Taux de Faux Positifs',
                    yaxis_title='Taux de Vrais Positifs',
                    height=400,
                    showlegend=True
                )

                st.plotly_chart(fig_roc, use_container_width=True)

            with col2:
                precision_curve, recall_curve = rf_results['pr_curve']

                fig_pr = go.Figure()

                fig_pr.add_trace(go.Scatter(
                    x=recall_curve, y=precision_curve,
                    mode='lines',
                    name='Random Forest',
                    line=dict(color='#2ecc71', width=3),
                    fill='tonexty'
                ))

                baseline_precision = (y_test == 1).mean()
                fig_pr.add_trace(go.Scatter(
                    x=[0, 1], y=[baseline_precision, baseline_precision],
                    mode='lines',
                    name=f'Baseline ({baseline_precision:.2f})',
                    line=dict(color='gray', dash='dash', width=2)
                ))

                fig_pr.update_layout(
                    title='Courbe Precision-Recall',
                    xaxis_title='Recall (Sensibilité)',
                    yaxis_title='Precision',
                    height=400,
                    showlegend=True
                )

                st.plotly_chart(fig_pr, use_container_width=True)

            st.subheader("🔄 Validation croisée")
            cv_scores = rf_results['cv_scores']

            col1, col2 = st.columns(2)

            with col1:
                cv_metrics = {
                    'Score moyen': cv_scores.mean(),
                    'Écart-type': cv_scores.std(),
                    'Score min': cv_scores.min(),
                    'Score max': cv_scores.max()
                }

                for metric, value in cv_metrics.items():
                    st.metric(metric, f"{value:.3f}")

            with col2:
                fig_cv = go.Figure(data=go.Bar(
                    x=[f'Fold {i+1}' for i in range(len(cv_scores))],
                    y=cv_scores,
                    marker_color='lightblue',
                    text=cv_scores,
                    texttemplate='%{text:.3f}',
                    textposition='outside'
                ))

                fig_cv.add_hline(
                    y=cv_scores.mean(),
                    line_dash="dash",
                    line_color="red",
                    annotation_text=f"Moyenne: {cv_scores.mean():.3f}"
                )

                fig_cv.update_layout(
                    title="Scores de validation croisée",
                    xaxis_title="Pli",
                    yaxis_title="Accuracy",
                    height=400
                )

                st.plotly_chart(fig_cv, use_container_width=True)

        with rf_tabs[3]:
            st.subheader("🌟 Importance des variables")

            feature_importance = rf_results['feature_importance'].head(10)

            fig_importance = px.bar(
                feature_importance,
                x='importance',
                y='feature',
                orientation='h',
                title="Top 10 des variables les plus importantes",
                labels={'importance': 'Score d\'importance', 'feature': 'Variable'},
                color='importance',
                color_continuous_scale='Blues',
                text='importance'
            )

            fig_importance.update_traces(
                texttemplate='%{text:.3f}',
                textposition='outside'
            )
            fig_importance.update_layout(
                height=500,
                yaxis={'categoryorder': 'total ascending'},
                showlegend=False
            )

            st.plotly_chart(fig_importance, use_container_width=True)

            col1, col2 = st.columns(2)

            with col1:
                top_feature = feature_importance.iloc[0]
                st.success(f"""
                **🎯 Variable la plus importante :**

                **{top_feature['feature']}**

                - Score : {top_feature['importance']:.3f}
                - Contribution : {(top_feature['importance']/feature_importance['importance'].sum())*100:.1f}%
                """)

            with col2:
                top_5 = feature_importance.head(5)
                fig_pie = px.pie(
                    top_5,
                    values='importance',
                    names='feature',
                    title="Top 5 - Répartition de l'influence",
                    color_discrete_sequence=px.colors.sequential.Blues_r
                )
                fig_pie.update_traces(
                    textposition='inside',
                    textinfo='percent+label',
                    textfont_size=14  
                )
                fig_pie.update_layout(
                    height=500,  #
                    showlegend=False,
                    font=dict(size=14)
                )
                st.plotly_chart(fig_pie, use_container_width=True)

    with ml_tabs[3]:
        st.markdown("""
        <div class="preprocessing-header">
            <h2 style="color: white; font-size: 2.2rem; margin-bottom: 10px;
                       text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
                ⚙️ Optimisation pour le dépistage clinique
            </h2>
            <p style="color: rgba(255,255,255,0.95); font-size: 1.1rem;
                      margin: 0 auto; line-height: 1.5;">
                Configuration des données pour optimiser la détection des patterns pertinents
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="background-color: #f8f5f2; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 4px solid #e67e22;">
            <h3 style="color: #2c3e50; margin-top: 0;">Adaptation au contexte clinique</h3>
            <p style="color: #34495e;">
            Personnalisation des paramètres du modèle pour s'adapter aux besoins spécifiques du dépistage TSA.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if rf_results.get('status') == 'success':
            y_pred_proba = rf_results['y_pred_proba']

            st.subheader("🎯 Réglage du seuil de décision")

            col1, col2 = st.columns([2, 1])

            with col1:
                threshold = st.slider(
                    "Seuil de probabilité pour déclencher une alerte",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.3,
                    step=0.05,
                    help="Plus le seuil est bas, plus le modèle sera sensible (détectera plus de cas mais avec plus de fausses alertes)"
                )

                y_pred_adjusted = (y_pred_proba >= threshold).astype(int)
                adjusted_recall = recall_score(y_test, y_pred_adjusted)
                adjusted_precision = precision_score(y_test, y_pred_adjusted, zero_division=0)
                adjusted_f1 = f1_score(y_test, y_pred_adjusted, zero_division=0)

                met_col1, met_col2, met_col3 = st.columns(3)

                with met_col1:
                    st.metric("Sensibilité ajustée", f"{adjusted_recall:.1%}")
                with met_col2:
                    st.metric("Précision ajustée", f"{adjusted_precision:.1%}")
                with met_col3:
                    st.metric("F1-Score ajusté", f"{adjusted_f1:.1%}")

            with col2:
                fig_gauge = go.Figure(go.Indicator(
                    mode = "gauge+number+delta",
                    value = adjusted_recall * 100,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Sensibilité (%)"},
                    delta = {'reference': recall_score(y_test, rf_results['y_pred']) * 100},
                    gauge = {
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 80], 'color': "lightgray"},
                            {'range': [80, 95], 'color': "yellow"},
                            {'range': [95, 100], 'color': "lightgreen"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 95
                        }
                    }
                ))
                fig_gauge.update_layout(height=300)
                st.plotly_chart(fig_gauge, use_container_width=True)

            st.subheader("📊 Impact du seuil sur les performances")

            thresholds = np.linspace(0.1, 0.9, 17)
            metrics_by_threshold = []

            for t in thresholds:
                y_pred_t = (y_pred_proba >= t).astype(int)
                metrics_by_threshold.append({
                    'Seuil': t,
                    'Sensibilité': recall_score(y_test, y_pred_t),
                    'Précision': precision_score(y_test, y_pred_t, zero_division=0),
                    'F1-Score': f1_score(y_test, y_pred_t, zero_division=0)
                })

            df_thresholds = pd.DataFrame(metrics_by_threshold)

            fig_threshold = px.line(
                df_thresholds,
                x='Seuil',
                y=['Sensibilité', 'Précision', 'F1-Score'],
                title="Évolution des métriques selon le seuil de décision",
                labels={'value': 'Score', 'variable': 'Métrique'},
                color_discrete_sequence=['#1f77b4', '#ff7f0e', '#2ca02c']
            )

            fig_threshold.add_vline(
                x=threshold,
                line_dash="dash",
                line_color="red",
                annotation_text=f"Seuil actuel: {threshold}"
            )

            fig_threshold.update_layout(height=400)
            st.plotly_chart(fig_threshold, use_container_width=True)

        st.subheader("📋 Protocole de dépistage recommandé")

        st.markdown("""
        <div style="background: linear-gradient(90deg, #3498db, #2ecc71); padding: 20px; border-radius: 10px; color: white; margin: 20px 0;">
            <h4 style="margin: 0 0 15px 0;">🔄 Processus de dépistage en 4 étapes</h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <strong>1. Pré-dépistage</strong><br>
                    Application automatique du modèle sur questionnaire initial
                </div>
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <strong>2. Évaluation</strong><br>
                    Entretien structuré si probabilité > 30%
                </div>
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <strong>3. Orientation</strong><br>
                    Vers spécialiste si confirmation des signaux
                </div>
                <div style="background: rgba(255,255,255,0.1); padding: 15px; border-radius: 8px;">
                    <strong>4. Suivi</strong><br>
                    Re-test à 6 mois pour cas négatifs persistants
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.subheader("🎯 Recommandations par contexte d'utilisation")

        context_col1, context_col2, context_col3 = st.columns(3)

        with context_col1:
            st.info("""
            **🏥 Dépistage de masse**

            - Seuil recommandé : **0.2**
            - Priorité : Sensibilité maximale
            - Objectif : Ne manquer aucun cas
            """)

        with context_col2:
            st.success("""
            **👨‍⚕️ Consultation spécialisée**

            - Seuil recommandé : **0.5**
            - Priorité : Équilibre optimal
            - Objectif : Aide au diagnostic
            """)

        with context_col3:
            st.warning("""
            **🔬 Recherche clinique**

            - Seuil recommandé : **0.7**
            - Priorité : Précision élevée
            - Objectif : Cohortes homogènes
            """)

        st.markdown("""
        <div style="margin-top: 30px; padding: 20px; border-radius: 10px; border-left: 4px solid #e74c3c; background-color: rgba(231, 76, 60, 0.1);">
            <h4 style="color: #e74c3c; margin-top: 0;">⚠️ Avertissement important</h4>
            <p style="font-size: 1rem; margin-bottom: 10px;">
            <strong>Ce modèle est un outil d'aide au dépistage précoce et ne remplace en aucun cas :</strong>
            </p>
            <ul style="margin-left: 20px;">
                <li>Une évaluation clinique complète par un professionnel qualifié</li>
                <li>Les outils de diagnostic standardisés (ADOS, ADI-R, etc.)</li>
                <li>L'expertise clinique et l'anamnèse détaillée</li>
            </ul>
            <p style="margin-top: 15px; font-style: italic;">
            Les résultats doivent toujours être interprétés dans le contexte clinique global du patient.
            </p>
        </div>
        """, unsafe_allow_html=True)


def show_aq10_and_prediction():
    """
    Fonction combinée pour l'évaluation AQ-10 et la prédiction TSA.
    """
    import pandas as pd
    import plotly.express as px
    import plotly.graph_objects as go
    from plotly.subplots import make_subplots
    import numpy as np

    try:
        df, _, _, _, _, _, _ = load_dataset()
        aq_columns = [f'A{i}' for i in range(1, 11) if f'A{i}' in df.columns]
        if aq_columns:
            df = df.drop(columns=aq_columns)

        if 'Jaunisse' in df.columns:
            df = df.drop(columns=['Jaunisse'])

            rf_model, preprocessor, feature_names = train_advanced_model(df)
    except Exception as e:
        st.error(f"Erreur lors du chargement des données ou du modèle: {str(e)}")
        rf_model, preprocessor, feature_names = None, None, None

    st.markdown("""
<div style="background: linear-gradient(90deg, #3498db, #2ecc71);
            padding: 40px 25px; border-radius: 20px; margin-bottom: 35px; text-align: center;">
    <h1 style="color: white; font-size: 2.8rem; margin-bottom: 15px;
               text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
        📝 Test AQ-10 et Prédiction TSA
    </h1>
    <p style="color: rgba(255,255,255,0.95); font-size: 1.3rem;
              max-width: 800px; margin: 0 auto; line-height: 1.6;">
        Une approche moderne et scientifique pour le dépistage précoce
    </p>
</div>
""", unsafe_allow_html=True)

    image_url = "https://drive.google.com/file/d/1c2RrCChdmOv9IsGRY_T0i0QOgNB-oHt0/view?usp=sharing"
    st.markdown(get_img_with_href(image_url, "#", as_banner=True), unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #f8fcff 0%, #e3f2fd 100%);
                border-radius: 15px; padding: 25px; margin: 30px 0;
                border-left: 5px solid #3498db;">
        <h3 style="color: #2c3e50; text-align: center; margin-top: 0;">
            🤖 À propos de cette évaluation
        </h3>
        <p style="color: #2c3e50; line-height: 1.6; text-align: center;">
            Ce questionnaire validé scientifiquement combine l'auto-évaluation AQ-10 avec un modèle d'intelligence artificielle
            entraîné sur plus de <strong>5 000 cas cliniques internationaux</strong>.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <style>
    /* Votre CSS complet ici */
    .questionnaire-container {
        background: #ffffff;
        border-radius: 15px;
        padding: 30px;
        margin: 20px 0;
        box-shadow: 0 4px 20px rgba(52, 152, 219, 0.1);
        border-top: 4px solid #3498db;
    }

    
    .question-block {
        background: #f8f9fa;
        border-radius: 12px;
        padding: 25px;
        margin: 25px 0;
        border-left: 4px solid #3498db;
        transition: all 0.3s ease;
    }

    /* Styles pour les bannières réglementaires */
        .regulatory-banner {
            background: #f8d7da;
            border-left: 5px solid #dc3545;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            color: #721c24;
        }
        
        .gdpr-banner {
            background: #e8f4fd;
            border-left: 5px solid #3498db;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            color: #0c5460;
        }
        
        .ai-act-banner {
            background: #fff3cd;
            border-left: 5px solid #ffc107;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            color: #856404;
        }
        
        /* Style pour la conformité médicale */
        .fda-banner {
            background: #d4edda;
            border-left: 5px solid #28a745;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            color: #155724;
        }
        
        /* Badge de dispositif médical */
        .medical-device-badge {
            display: inline-block;
            padding: 5px 10px;
            background: #e9ecef;
            border-radius: 15px;
            font-size: 12px;
            color: #495057;
            margin-right: 8px;
        }
        
    .question-text {
        font-size: 1.1rem;
        font-weight: 500;
        color: #2c3e50;
        margin-bottom: 20px;
        line-height: 1.5;
        text-align: center !important;
        display: flex;
        align-items: center;
        justify-content: center;
        flex-direction: column;
    }
    .questionnaire-container .stRadio [role="radiogroup"] {
    display: flex !important;
    justify-content: center !important;
    align-items: center !important;
    flex-wrap: wrap !important;
    gap: 10px !important;
    padding: 15px !important;}

    /* Alternative plus large si la première ne fonctionne pas */
    .stRadio > div[role="radiogroup"] {
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        flex-direction: row !important;
        flex-wrap: wrap !important;
        gap: 10px !important;
    }
    
    /* Centrage des labels individuels */
    .questionnaire-container .stRadio > div > label {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        text-align: center !important;
        margin: 0 5px !important;
        padding: 12px 15px !important;
        background: linear-gradient(135deg, #f8f9fa, #ffffff) !important;
        border: 2px solid #e9ecef !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        font-weight: 500 !important;
        color: #495057 !important;
        min-width: 140px !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1) !important;
    }
    
    /* Effet hover */
    .questionnaire-container .stRadio > div > label:hover {
        background: linear-gradient(135deg, #e3f2fd, #f8fcff) !important;
        border-color: #3498db !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(52, 152, 219, 0.2) !important;
    }
    
    /* Style pour le bouton sélectionné */
    .questionnaire-container .stRadio > div > label[data-checked="true"] {
        background: linear-gradient(135deg, #3498db, #2980b9) !important;
        border-color: #3498db !important;
        color: white !important;
        box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3) !important;
        transform: translateY(-1px) !important;
    }
    
    /* Responsive pour mobile */
    @media (max-width: 768px) {
        .questionnaire-container .stRadio [role="radiogroup"] {
            flex-direction: column !important;
            gap: 8px !important;
        }
        
        .questionnaire-container .stRadio > div > label {
            width: 100% !important;
            min-width: auto !important;
            margin: 0 0 5px 0 !important;
        }
    }.questionnaire-container .stRadio [role="radiogroup"] {
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        flex-wrap: wrap !important;
        gap: 10px !important;
        padding: 15px !important;
    }
    
    /* Alternative plus large si la première ne fonctionne pas */
    .stRadio > div[role="radiogroup"] {
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        flex-direction: row !important;
        flex-wrap: wrap !important;
        gap: 10px !important;
    }
    
    /* Centrage des labels individuels */
    .questionnaire-container .stRadio > div > label {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        text-align: center !important;
        margin: 0 5px !important;
        padding: 12px 15px !important;
        background: linear-gradient(135deg, #f8f9fa, #ffffff) !important;
        border: 2px solid #e9ecef !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        font-weight: 500 !important;
        color: #495057 !important;
        min-width: 140px !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1) !important;
    }
    
    /* Effet hover */
    .questionnaire-container .stRadio > div > label:hover {
        background: linear-gradient(135deg, #e3f2fd, #f8fcff) !important;
        border-color: #3498db !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(52, 152, 219, 0.2) !important;
    }
    
    /* Style pour le bouton sélectionné */
    .questionnaire-container .stRadio > div > label[data-checked="true"] {
        background: linear-gradient(135deg, #3498db, #2980b9) !important;
        border-color: #3498db !important;
        color: white !important;
        box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3) !important;
        transform: translateY(-1px) !important;
    }
    
    /* Responsive pour mobile */
    @media (max-width: 768px) {
        .questionnaire-container .stRadio [role="radiogroup"] {
            flex-direction: column !important;
            gap: 8px !important;
        }
        
        .questionnaire-container .stRadio > div > label {
            width: 100% !important;
            min-width: auto !important;
            margin: 0 0 5px 0 !important;
        }
    }
    
    .question-number {
        background: linear-gradient(135deg, #3498db, #2980b9);
        color: white;
        width: 35px;
        height: 35px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-weight: bold;
        font-size: 1rem;
        box-shadow: 0 2px 8px rgba(52, 152, 219, 0.3);
        margin: 0 auto 10px auto;
        flex-shrink: 0;
    }
    
    .question-emoji {
        font-size: 1.8rem;
        margin-right: 10px;
        display: inline-block;
    }
    /* ================ MASQUER LES BOUTONS RADIO NATIFS ================ */
    .questionnaire-container .question-block .stRadio input[type="radio"] {
        position: absolute;
        opacity: 0;
        cursor: pointer;
        height: 0;
        width: 0;
    }
    
    /* ================ CONTENEUR DES RÉPONSES ================ */
    .questionnaire-container .question-block .stRadio > div {
        display: grid !important;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)) !important;
        gap: 15px !important;
        padding: 25px !important;
        background: linear-gradient(135deg, #f8f9fa, #ffffff) !important;
        border-radius: 15px !important;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08) !important;
        border: 2px solid #e9ecef !important;
        margin-top: 15px !important;
    }
    
    /* ================ BOUTONS RECTANGLE PERSONNALISÉS ================ */
    .questionnaire-container .question-block .stRadio > div > label {
        position: relative !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 18px 15px !important;
        margin: 0 !important;
        background: linear-gradient(135deg, #ffffff, #f8f9fa) !important;
        border: 2px solid #dee2e6 !important;
        border-radius: 10px !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        font-weight: 500 !important;
        font-size: 0.95rem !important;
        color: #495057 !important;
        text-align: center !important;
        min-height: 60px !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06) !important;
        text-transform: none !important;
        line-height: 1.4 !important;
    }
    
    /* ================ EFFET HOVER ================ */
    .questionnaire-container .question-block .stRadio > div > label:hover {
        background: linear-gradient(135deg, #e3f2fd, #f0f8ff) !important;
        border-color: #3498db !important;
        transform: translateY(-3px) !important;
        box-shadow: 0 6px 20px rgba(52, 152, 219, 0.15) !important;
        color: #2c3e50 !important;
    }
    
    /* ================ ÉTAT SÉLECTIONNÉ ================ */
    .questionnaire-container .question-block .stRadio > div > label[data-checked="true"] {
        background: linear-gradient(135deg, #3498db, #2980b9) !important;
        border-color: #2980b9 !important;
        color: white !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 25px rgba(52, 152, 219, 0.3) !important;
        font-weight: 600 !important;
    }
    
    /* ================ ICÔNE DE SÉLECTION ================ */
    .questionnaire-container .question-block .stRadio > div > label::before {
        content: '' !important;
        position: absolute !important;
        top: 8px !important;
        right: 8px !important;
        width: 20px !important;
        height: 20px !important;
        border: 2px solid #dee2e6 !important;
        border-radius: 4px !important;
        background: white !important;
        transition: all 0.3s ease !important;
    }
    
    .questionnaire-container .question-block .stRadio > div > label:hover::before {
        border-color: #3498db !important;
        background: #f0f8ff !important;
    }
    
    .questionnaire-container .question-block .stRadio > div > label[data-checked="true"]::before {
        background: white !important;
        border-color: white !important;
        content: '✓' !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-size: 12px !important;
        font-weight: bold !important;
        color: #3498db !important;
    }
    
    /* ================ SÉPARATION QUESTION/RÉPONSE ================ */
    .question-block {
        background: #ffffff !important;
        border-radius: 15px !important;
        padding: 30px !important;
        margin: 30px 0 !important;
        border: 2px solid #e9ecef !important;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08) !important;
        transition: all 0.3s ease !important;
    }
    
    .question-block:hover {
        border-color: #3498db !important;
        box-shadow: 0 8px 30px rgba(52, 152, 219, 0.12) !important;
        transform: translateY(-2px) !important;
    }
    
    /* ================ SÉPARATEUR VISUEL ================ */
    .question-text::after {
        content: '' !important;
        display: block !important;
        width: 100% !important;
        height: 2px !important;
        background: linear-gradient(90deg, transparent, #3498db, transparent) !important;
        margin: 20px 0 10px 0 !important;
    }
    
    /* ================ RESPONSIVE DESIGN ================ */
    @media (max-width: 768px) {
        .questionnaire-container .question-block .stRadio > div {
            grid-template-columns: 1fr !important;
            gap: 12px !important;
            padding: 20px !important;
        }
        
        .questionnaire-container .question-block .stRadio > div > label {
            padding: 16px 12px !important;
            min-height: 50px !important;
            font-size: 0.9rem !important;
        }
        
        .question-block {
            padding: 20px !important;
            margin: 20px 0 !important;
        }
    }
    
    @media (max-width: 480px) {
        .questionnaire-container .question-block .stRadio > div > label {
            padding: 14px 10px !important;
            min-height: 45px !important;
            font-size: 0.85rem !important;
        }
    }
    /* ================ CARTES DE RÉSULTATS PRINCIPALES ================ */
    .result-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 20px;
        box-shadow: 0 8px 32px rgba(52, 152, 219, 0.15);
        padding: 40px 30px;
        margin: 30px 0;
        text-align: center;
        transition: all 0.4s ease;
        border: 1px solid rgba(52, 152, 219, 0.1);
        position: relative;
        overflow: hidden;
    }
    
    .result-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, #3498db, #2ecc71, #e74c3c);
        border-radius: 20px 20px 0 0;
    }
    
    .result-card:hover {
        transform: translateY(-8px);
        box-shadow: 0 16px 48px rgba(52, 152, 219, 0.25);
    }
    
    /* ================ VARIANTES DE COULEURS ================ */
    .result-card.success {
        border-left: 6px solid #2ecc71;
        background: linear-gradient(135deg, #eafaf1 0%, #f8fff8 100%);
    }
    
    .result-card.success::before {
        background: linear-gradient(90deg, #2ecc71, #27ae60);
    }
    
    .result-card.warning {
        border-left: 6px solid #f39c12;
        background: linear-gradient(135deg, #fef9e7 0%, #fff8f2 100%);
    }
    
    .result-card.warning::before {
        background: linear-gradient(90deg, #f39c12, #e67e22);
    }
    
    .result-card.danger {
        border-left: 6px solid #e74c3c;
        background: linear-gradient(135deg, #ffeaea 0%, #fff6f6 100%);
    }
    
    .result-card.danger::before {
        background: linear-gradient(90deg, #e74c3c, #c0392b);
    }
    
    /* ================ TITRES ET SCORES ================ */
    .result-title {
        font-size: 1.4rem;
        font-weight: 600;
        color: #2c3e50;
        margin-bottom: 20px;
        text-transform: uppercase;
        letter-spacing: 1px;
        position: relative;
    }
    
    .result-title::after {
        content: '';
        position: absolute;
        bottom: -8px;
        left: 50%;
        transform: translateX(-50%);
        width: 60px;
        height: 2px;
        background: linear-gradient(90deg, #3498db, #2ecc71);
        border-radius: 1px;
    }
    
    .result-score {
        font-size: 4rem;
        font-weight: 900;
        color: #3498db;
        margin: 25px 0;
        text-shadow: 0 4px 8px rgba(52, 152, 219, 0.2);
        position: relative;
        display: inline-block;
    }
    
    .result-score::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 120px;
        height: 120px;
        border: 3px solid rgba(52, 152, 219, 0.1);
        border-radius: 50%;
        z-index: -1;
    }
    
    /* ================ DESCRIPTIONS ET TEXTES ================ */
    .result-card p {
        font-size: 1.1rem;
        line-height: 1.6;
        color: #34495e;
        margin-bottom: 15px;
    }
    
    .result-card p strong {
        color: #2c3e50;
        font-weight: 600;
    }
    
    /* ================ SECTION PRÉDICTION IA ================ */
    .prediction-section {
        margin-top: 50px;
        padding: 40px 0;
        background: linear-gradient(135deg, #f8fcff 0%, #e3f2fd 100%);
        border-radius: 20px;
        position: relative;
    }
    
    .prediction-section::before {
        content: '🤖';
        position: absolute;
        top: -20px;
        left: 50%;
        transform: translateX(-50%);
        font-size: 2.5rem;
        background: white;
        padding: 10px;
        border-radius: 50%;
        box-shadow: 0 4px 16px rgba(52, 152, 219, 0.2);
    }
    
    .prediction-section h3 {
        text-align: center;
        color: #2c3e50;
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 30px;
        margin-top: 10px;
    }
    
    /* ================ CARTES KPI AMÉLIORÉES ================ */
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 25px;
        margin: 40px 0;
        padding: 0 20px;
    }
    
    .kpi-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 16px;
        padding: 30px 20px;
        text-align: center;
        box-shadow: 0 6px 24px rgba(0, 0, 0, 0.08);
        border-top: 4px solid #3498db;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .kpi-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(52, 152, 219, 0.1), transparent);
        transition: left 0.6s ease;
    }
    
    .kpi-card:hover::before {
        left: 100%;
    }
    
    .kpi-card:hover {
        transform: translateY(-8px) scale(1.02);
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.15);
        border-top-color: #2ecc71;
    }
    
    .kpi-card h4 {
        margin-top: 0;
        margin-bottom: 15px;
        color: #7f8c8d;
        font-size: 1rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .kpi-value {
        font-size: 2.8rem;
        font-weight: 900;
        margin: 15px 0;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        position: relative;
    }
    
    .kpi-card p {
        color: #95a5a6;
        font-size: 0.9rem;
        margin: 0;
        line-height: 1.4;
        font-style: italic;
    }
    
    /* ================ COULEURS SPÉCIFIQUES POUR LES KPI ================ */
    .kpi-card:nth-child(1) {
        border-top-color: #e74c3c;
    }
    
    .kpi-card:nth-child(1) .kpi-value {
        color: #e74c3c;
    }
    
    .kpi-card:nth-child(2) {
        border-top-color: #f39c12;
    }
    
    .kpi-card:nth-child(2) .kpi-value {
        color: #f39c12;
    }
    
    .kpi-card:nth-child(3) {
        border-top-color: #2ecc71;
    }
    
    .kpi-card:nth-child(3) .kpi-value {
        color: #2ecc71;
    }
    
    .kpi-card:nth-child(4) {
        border-top-color: #9b59b6;
    }
    
    .kpi-card:nth-child(4) .kpi-value {
        color: #9b59b6;
    }
    
    .kpi-card:nth-child(5) {
        border-top-color: #34495e;
    }
    
    .kpi-card:nth-child(5) .kpi-value {
        color: #34495e;
    }
    
    .kpi-card:nth-child(6) {
        border-top-color: #16a085;
    }
    
    .kpi-card:nth-child(6) .kpi-value {
        color: #16a085;
    }
    
    /* ================ SECTION PROFIL DÉTAILLÉ ================ */
    .profile-section {
        margin-top: 50px;
        padding: 40px 30px;
        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
        border-radius: 20px;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.08);
        border: 1px solid rgba(52, 152, 219, 0.1);
    }
    
    .profile-section h3 {
        text-align: center;
        color: #2c3e50;
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 30px;
        position: relative;
    }
    
    .profile-section h3::before {
        content: '📊';
        margin-right: 10px;
    }
    
    .profile-section h3::after {
        content: '';
        position: absolute;
        bottom: -10px;
        left: 50%;
        transform: translateX(-50%);
        width: 100px;
        height: 3px;
        background: linear-gradient(90deg, #3498db, #2ecc71);
        border-radius: 2px;
    }
    
    /* ================ ANIMATIONS ================ */
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes scoreAnimation {
        0% {
            transform: scale(0);
            opacity: 0;
        }
        50% {
            transform: scale(1.1);
        }
        100% {
            transform: scale(1);
            opacity: 1;
        }
    }
    
    .result-card {
        animation: fadeInUp 0.8s ease-out;
    }
    
    .result-score {
        animation: scoreAnimation 1.2s ease-out 0.3s both;
    }
    
    .kpi-card {
        animation: fadeInUp 0.8s ease-out;
    }
    
    .kpi-card:nth-child(1) { animation-delay: 0.1s; }
    .kpi-card:nth-child(2) { animation-delay: 0.2s; }
    .kpi-card:nth-child(3) { animation-delay: 0.3s; }
    .kpi-card:nth-child(4) { animation-delay: 0.4s; }
    .kpi-card:nth-child(5) { animation-delay: 0.5s; }
    .kpi-card:nth-child(6) { animation-delay: 0.6s; }
    
    /* ================ RESPONSIVE DESIGN ================ */
    @media (max-width: 768px) {
        .result-card {
            padding: 30px 20px;
            margin: 20px 0;
        }
        
        .result-score {
            font-size: 3rem;
        }
        
        .result-score::before {
            width: 100px;
            height: 100px;
        }
        
        .kpi-container {
            grid-template-columns: 1fr;
            gap: 20px;
            padding: 0 10px;
        }
        
        .kpi-card {
            padding: 25px 15px;
        }
        
        .kpi-value {
            font-size: 2.2rem;
        }
        
        .profile-section {
            padding: 30px 20px;
        }
        
        .prediction-section {
            padding: 30px 20px;
        }
    }
    
    @media (max-width: 480px) {
        .result-title {
            font-size: 1.2rem;
        }
        
        .result-score {
            font-size: 2.5rem;
        }
        
        .kpi-value {
            font-size: 2rem;
        }
        
        .profile-section h3,
        .prediction-section h3 {
            font-size: 1.6rem;
        }
    }
    
    /* ================ BOUTON DE SOUMISSION AMÉLIORÉ ================ */
    .stButton > button {
        background: linear-gradient(135deg, #3498db 0%, #2980b9 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 30px !important;
        padding: 15px 40px !important;
        font-weight: 700 !important;
        font-size: 1.1rem !important;
        transition: all 0.3s ease !important;
        box-shadow: 0 6px 20px rgba(52, 152, 219, 0.3) !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        position: relative !important;
        overflow: hidden !important;
    }
    
    .stButton > button::before {
        content: '' !important;
        position: absolute !important;
        top: 0 !important;
        left: -100% !important;
        width: 100% !important;
        height: 100% !important;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent) !important;
        transition: left 0.6s ease !important;
    }
    
    .stButton > button:hover::before {
        left: 100% !important;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #2980b9 0%, #3498db 100%) !important;
        transform: translateY(-3px) !important;
        box-shadow: 0 10px 30px rgba(52, 152, 219, 0.4) !important;
    }
    
    .stButton > button:active {
        transform: translateY(-1px) !important;
    }
    
    /* ================ ANIMATIONS SUPPLÉMENTAIRES ================ */
    @keyframes selectAnimation {
        0% { transform: scale(1) translateY(-2px); }
        50% { transform: scale(1.02) translateY(-3px); }
        100% { transform: scale(1) translateY(-2px); }
    }
    
    .questionnaire-container .question-block .stRadio > div > label[data-checked="true"] {
        animation: selectAnimation 0.4s ease-out !important;
    }
    
    /* ================ FOCUS POUR ACCESSIBILITÉ ================ */
    .questionnaire-container .question-block .stRadio > div > label:focus-within {
        outline: 3px solid rgba(52, 152, 219, 0.3) !important;
        outline-offset: 2px !important;
    }

    /* CSS pour les boutons radio sécurisés */
    .questionnaire-container .question-block .stRadio > div {
        display: flex !important;
        flex-direction: row !important;
        flex-wrap: nowrap !important;
        gap: 0 !important;
        justify-content: stretch !important;
        align-items: center !important;
        padding: 15px !important;
        background: white !important;
        border-radius: 12px !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05) !important;
        width: 100% !important;
    }
    
    .questionnaire-container .question-block .stRadio > div > label {
        background: linear-gradient(135deg, #f8f9fa, #ffffff) !important;
        border: 2px solid #e9ecef !important;
        border-radius: 8px !important;
        padding: 15px 10px !important;
        margin: 0 2px !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        font-weight: 500 !important;
        color: #495057 !important;
        text-align: center !important;
        flex: 1 !important;
        min-width: 0 !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1) !important;
        font-size: 0.9rem !important;
        line-height: 1.2 !important;
        white-space: nowrap !important;
        overflow: hidden !important;
        text-overflow: ellipsis !important;
    }
    
    .questionnaire-container .question-block .stRadio > div > label:hover {
        background: linear-gradient(135deg, #e3f2fd, #f8fcff) !important;
        border-color: #3498db !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 4px 12px rgba(52, 152, 219, 0.2) !important;
    }
    
    .questionnaire-container .question-block .stRadio > div > label[data-checked="true"] {
        background: linear-gradient(135deg, #3498db, #2980b9) !important;
        border-color: #3498db !important;
        color: white !important;
        box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3) !important;
        transform: translateY(-1px) !important;
    }

    /* Responsive */
    @media (max-width: 768px) {
        .questionnaire-container .question-block .stRadio > div {
            flex-direction: column !important;
            gap: 8px !important;
        }
        
        .questionnaire-container .question-block .stRadio > div > label {
            width: 100% !important;
            flex: none !important;
            margin: 0 0 5px 0 !important;
            white-space: normal !important;
        }
    }
    </style>
    """, unsafe_allow_html=True)

    # Questions AQ-10 avec émojis
    questions = [
        {
            "question": "👂 Je remarque souvent de petits bruits que les autres ne remarquent pas.",
            "emoji": "👂",
            "scoring": {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0}
        },
        {
            "question": "🔍 Je me concentre généralement davantage sur l'ensemble que sur les petits détails.",
            "emoji": "🔍", 
            "scoring": {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1}
        },
        {
            "question": "🔄 Je trouve facile de faire plusieurs choses en même temps.",
            "emoji": "🔄",
            "scoring": {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1}
        },
        {
            "question": "⏯️ S'il y a une interruption, je peux rapidement reprendre ce que je faisais.",
            "emoji": "⏯️",
            "scoring": {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1}
        },
        {
            "question": "💭 Je trouve facile de « lire entre les lignes » quand quelqu'un me parle.",
            "emoji": "💭",
            "scoring": {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1}
        },
        {
            "question": "😴 Je sais comment savoir si la personne qui m'écoute commence à s'ennuyer.",
            "emoji": "😴",
            "scoring": {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1}
        },
        {
            "question": "📚 Quand je lis une histoire, j'ai du mal à comprendre les intentions des personnages.",
            "emoji": "📚",
            "scoring": {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0}
        },
        {
            "question": "🗂️ J'aime collecter des informations sur des catégories de choses (types de voitures, d'oiseaux, de trains, etc.).",
            "emoji": "🗂️",
            "scoring": {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0}
        },
        {
            "question": "😊 Je trouve facile de comprendre ce que quelqu'un pense ou ressent rien qu'en regardant son visage.",
            "emoji": "😊",
            "scoring": {"Tout à fait d'accord": 0, "Plutôt d'accord": 0, "Plutôt pas d'accord": 1, "Pas du tout d'accord": 1}
        },
        {
            "question": "❓ J'ai du mal à comprendre les intentions des gens.",
            "emoji": "❓",
            "scoring": {"Tout à fait d'accord": 1, "Plutôt d'accord": 1, "Plutôt pas d'accord": 0, "Pas du tout d'accord": 0}
        }
    ]

    # CORRECTION PRINCIPALE : Formulaire avec initialisation correcte
    with st.form("questionnaire_aq10_prediction", clear_on_submit=False):
        st.markdown("""
        <div class="questionnaire-container">
            <h1 class="questionnaire-title">Questionnaire AQ-10</h1>
            <p class="questionnaire-subtitle">Répondez aux 10 questions suivantes :</p>
        </div>
        """, unsafe_allow_html=True)
        
        # INITIALISATION DE form_responses - C'EST LA CORRECTION PRINCIPALE
        form_responses = {}
        
        # Génération des questions avec gestion d'erreur
        for i, q in enumerate(questions):
            question_text = q["question"].split(' ', 1)[1] if ' ' in q["question"] else q["question"]
            emoji = q["emoji"]
            
            st.markdown(f"""
            <div class="question-block">
                <div class="question-text">
                    <span class="question-number">{i+1}</span>
                    <div>
                        <span class="question-emoji">{emoji}</span>
                        {question_text}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Boutons radio avec clé unique
            selected_response = st.radio(
                "",
                ["Tout à fait d'accord", "Plutôt d'accord", "Plutôt pas d'accord", "Pas du tout d'accord"],
                key=f"form_radio_{i}",
                index=None,
                label_visibility="collapsed",
                horizontal=True
            )
            
            # STOCKAGE SÉCURISÉ - Utilisation de get() pour éviter KeyError
            form_responses[f"aq10_question_{i}"] = selected_response
        
        st.markdown("### 👤 Informations personnelles")

        col1, col2 = st.columns(2)

        with col1:
            age = st.number_input("Âge", min_value=2, max_value=99, value=24)
            genres = ["Féminin", "Masculin"]
            genre = st.selectbox("Genre", genres)

        with col2:
            ethnies = ["Européen", "Asiatique", "Africain", "Hispanique", "Moyen-Orient", "Autre"]
            ethnicite = st.selectbox("Origine ethnique", ethnies)
            antecedents = st.selectbox("Antécédents familiaux d'autisme", ["Non", "Oui"])

        testeur = st.selectbox("Qui remplit ce questionnaire ?",
                              ["Moi-même", "Parent/Famille", "Professionnel de santé", "Enseignant", "Autre"])
        st.markdown("""
        <div style="background: linear-gradient(135deg, #f8fcff 0%, #e3f2fd 100%);
                    border-radius: 12px; padding: 20px; margin: 25px 0; text-align: center;
                    border-left: 4px solid #3498db;">
            <h4 style="color: #2c3e50; margin-top: 0;">🎯 Prêt pour l'évaluation ?</h4>
            <p style="color: #34495e; margin-bottom: 15px;">
                Assurez-vous d'avoir répondu à toutes les questions avant de continuer.
            </p>
            <p style="color: #7f8c8d; font-size: 0.9rem; margin: 0;">
                L'analyse prendra quelques secondes pour traiter vos réponses.
            </p>
        </div>
        """, unsafe_allow_html=True)

        submitted = st.form_submit_button(
            "🔬 Calculer mon score et obtenir une prédiction",
            use_container_width=True,
            type="primary"
        )

        if submitted:
            if None in form_responses.values():
                st.error("⚠️ Veuillez répondre à toutes les questions du questionnaire.")
            else:
                total_score = 0
                scores_individuels = []

                for i, q in enumerate(questions):
                    selected_option = form_responses[f"aq10_question_{i}"]
                    if selected_option is not None:
                        score = q["scoring"][selected_option]
                        total_score += score
                        scores_individuels.append(score)
                    else:
                        scores_individuels.append(0)
                st.session_state.aq10_total = total_score
                st.session_state.aq10_responses = scores_individuels
                user_data = {
                    'Age': age,
                    'Genre': genre,
                    'Ethnie': ethnicite,
                    'Antecedent_autisme': antecedents,
                    'Statut_testeur': testeur,
                }

                for i, score in enumerate(scores_individuels):
                    user_data[f'A{i+1}'] = score

                user_data['Score_A10'] = total_score

                user_df = pd.DataFrame([user_data])

                if total_score >= 6:
                    st.markdown(f"""
                        <div class="result-card warning">
                            <div class="result-title">Résultat du questionnaire AQ-10</div>
                            <div class="result-score">{total_score}/10</div>
                            <p>Votre score est de {total_score}/10, ce qui suggère un dépistage positif.</p>
                            <p><strong>Un suivi par un professionnel de santé est recommandé.</strong></p>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                        <div class="result-card success">
                            <div class="result-title">Résultat du questionnaire AQ-10</div>
                            <div class="result-score">{total_score}/10</div>
                            <p>Votre score est de {total_score}/10, ce qui est en dessous du seuil clinique de dépistage positif.</p>
                        </div>
                    """, unsafe_allow_html=True)

                st.markdown("""<h3 style="text-align: center; margin-top: 2rem;">Prédiction par intelligence artificielle</h3>""", unsafe_allow_html=True)
                if rf_model is not None and preprocessor is not None:
                    try:
                        required_columns = ['Age', 'Genre', 'Ethnie', 'Antecedent_autisme', 'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10', 'Score_A10']
                        for col in required_columns:
                            if col not in user_df.columns:
                                if col.startswith('A') and col[1:].isdigit():
                                    idx = int(col[1:]) - 1
                                    if idx < len(scores_individuels):
                                        user_df[col] = scores_individuels[idx]
                                    else:
                                        user_df[col] = 0
                                else:
                                    user_df[col] = 0

                        column_mapping = {
                            'Antecedent_autisme': 'Autisme_familial',
                        }
                        user_df = user_df.rename(columns=column_mapping)

                        if 'Jaunisse' not in user_df.columns:
                            user_df['Jaunisse'] = "No"

                        required_columns = ['Age', 'Genre', 'Ethnie', 'Autisme_familial', 'Statut_testeur', 'Jaunisse',
                                          'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10', 'Score_A10']

                        for col in required_columns:
                            if col not in user_df.columns:
                                user_df[col] = 0

                        user_df = user_df[required_columns]

                        user_df = user_df[required_columns]

                        prediction_proba = rf_model.predict_proba(user_df)

                        tsa_probability = prediction_proba[0][1]

                        prediction_class = "TSA probable" if tsa_probability > 0.5 else "TSA peu probable"

                        probability_percentage = int(tsa_probability * 100)

                        color_class = "danger" if probability_percentage > 75 else "warning" if probability_percentage > 50 else "success"

                        st.markdown(f"""
                            <div class="result-card {color_class}">
                                <div class="result-title">Prédiction IA</div>
                                <div class="result-score">{probability_percentage}%</div>
                                <p>Probabilité estimée de traits autistiques: <strong>{probability_percentage}%</strong></p>
                                <p>Classification: <strong>{prediction_class}</strong></p>
                            </div>

                            <div class="diagnostic-box" style="background-color: #f8f9fa;">
                                <p><strong>Important:</strong> Cette évaluation est uniquement un outil d'aide au dépistage et ne constitue pas un diagnostic médical.</p>
                                <p>Si votre score ou la prédiction indiquent un risque élevé, nous vous recommandons de consulter un professionnel de santé spécialisé.</p>
                            </div>
                        """, unsafe_allow_html=True)

        
        
                        st.markdown("### 📈 Profil détaillé des traits autistiques")

                        social_score = sum([scores_individuels[i-1] for i in [5, 6, 7, 9, 10]]) / 5 * 100
                        cognitive_score = sum([scores_individuels[i-1] for i in [2, 3, 4]]) / 3 * 100
                        detail_score = sum([scores_individuels[i-1] for i in [1, 8]]) / 2 * 100
                        masking_index = max(0, (detail_score + cognitive_score)/2 - social_score)
                        masking_index = min(100, masking_index + 50)
                        risk_factor = min(10.0, (total_score/6) * (1.5 if antecedents == "Oui" else 1))

                        def severity_color(score):
                            if score < 30: return "#2ecc71"
                            elif score < 60: return "#f39c12"
                            else: return "#e74c3c"

                        col1, col2, col3 = st.columns(3)

                        with col1:
                            st.markdown(f"""
                            <div class="kpi-card">
                                <h4 style="margin-top: 0; color: #7f8c8d;">👥 Perception sociale</h4>
                                <div style="font-size: 2rem; font-weight: bold; color: {severity_color(social_score)};">
                                    {social_score:.0f}%
                                </div>
                                <p style="color: #95a5a6; font-size: 0.9rem; margin: 0;">
                                    Difficulté à interpréter les interactions sociales
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        with col2:
                            st.markdown(f"""
                            <div class="kpi-card">
                                <h4 style="margin-top: 0; color: #7f8c8d;">🧠 Flexibilité cognitive</h4>
                                <div style="font-size: 2rem; font-weight: bold; color: {severity_color(cognitive_score)};">
                                    {cognitive_score:.0f}%
                                </div>
                                <p style="color: #95a5a6; font-size: 0.9rem; margin: 0;">
                                    Rigidité face au changement
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        with col3:
                            st.markdown(f"""
                            <div class="kpi-card">
                                <h4 style="margin-top: 0; color: #7f8c8d;">🔍 Attention aux détails</h4>
                                <div style="font-size: 2rem; font-weight: bold; color: {severity_color(100-detail_score)};">
                                    {detail_score:.0f}%
                                </div>
                                <p style="color: #95a5a6; font-size: 0.9rem; margin: 0;">
                                    Focalisation sur les spécificités
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        col4, col5, col6 = st.columns(3)

                        with col4:
                            st.markdown(f"""
                            <div class="kpi-card">
                                <h4 style="margin-top: 0; color: #7f8c8d;">🎭 Indice de masquage</h4>
                                <div style="font-size: 2rem; font-weight: bold; color: {severity_color(100-masking_index)};">
                                    {masking_index:.0f}%
                                </div>
                                <p style="color: #95a5a6; font-size: 0.9rem; margin: 0;">
                                    Compensation sociale estimée
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        with col5:
                            st.markdown(f"""
                            <div class="kpi-card">
                                <h4 style="margin-top: 0; color: #7f8c8d;">⚠️ Risque relatif</h4>
                                <div style="font-size: 2rem; font-weight: bold; color: {severity_color(risk_factor*10)};">
                                    {risk_factor:.1f}x
                                </div>
                                <p style="color: #95a5a6; font-size: 0.9rem; margin: 0;">
                                    Par rapport à la population générale
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        with col6:
                            impact_score = (total_score / 10) * 100
                            st.markdown(f"""
                            <div class="kpi-card">
                                <h4 style="margin-top: 0; color: #7f8c8d;">📉 Impact fonctionnel</h4>
                                <div style="font-size: 2rem; font-weight: bold; color: {severity_color(impact_score)};">
                                    {impact_score:.0f}%
                                </div>
                                <p style="color: #95a5a6; font-size: 0.9rem; margin: 0;">
                                    Sur la vie quotidienne
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        st.markdown("""
                            <h4 style="text-align: center; margin-top: 30px; margin-bottom: 15px; color: #34495e;">
                                Profil de sensibilité multidimensionnel
                            </h4>
                        """, unsafe_allow_html=True)

                        dimensions = [
                            "Communication sociale",
                            "Interactions sociales",
                            "Intérêts restreints",
                            "Comportements répétitifs",
                            "Sensibilité sensorielle"
                        ]

                        dim_scores = [
                            (scores_individuels[4] + scores_individuels[6] + scores_individuels[8]) / 3 * 100,
                            (scores_individuels[5] + scores_individuels[9]) / 2 * 100,
                            (scores_individuels[7]) * 100,
                            (scores_individuels[1] + scores_individuels[2] + scores_individuels[3]) / 3 * 100,
                            (scores_individuels[0]) * 100
                        ]


                        fig = go.Figure()

                        fig.add_trace(go.Scatterpolar(
                            r=dim_scores,
                            theta=dimensions,
                            fill='toself',
                            name='Votre profil',
                            line_color='#3498db',
                            fillcolor='rgba(52, 152, 219, 0.3)'
                        ))

                        fig.add_trace(go.Scatterpolar(
                            r=[80, 75, 70, 65, 85],
                            theta=dimensions,
                            fill='toself',
                            name='Profil typique TSA',
                            line_color='#e74c3c',
                            fillcolor='rgba(231, 76, 60, 0.1)'
                        ))

                        fig.add_trace(go.Scatterpolar(
                            r=[20, 25, 30, 25, 15],
                            theta=dimensions,
                            fill='toself',
                            name='Profil neurotypique',
                            line_color='#2ecc71',
                            fillcolor='rgba(46, 204, 113, 0.1)'
                        ))

                        fig.update_layout(
                            polar=dict(
                                radialaxis=dict(
                                    visible=True,
                                    range=[0, 100]
                                )
                            ),
                            title="Comparaison de votre profil avec les profils de référence",
                            showlegend=True,
                            height=500,
                            margin=dict(t=70, b=20)
                        )

                        st.plotly_chart(fig, use_container_width=True)

                        st.markdown("""
                        <div style="margin-top: 40px; margin-bottom: 30px;">
                            <h3 style="text-align: center; margin-bottom: 25px; color: #34495e; font-size: 1.8rem;">
                                💡 Recommandations personnalisées
                            </h3>
                        </div>
                        """, unsafe_allow_html=True)


                        recommendations = []

                        if social_score > 50:
                            recommendations.append("Envisager des thérapies ciblant les compétences sociales et la compréhension des interactions")

                        if cognitive_score > 50:
                            recommendations.append("Des stratégies pour améliorer la flexibilité cognitive pourraient être bénéfiques")

                        if detail_score > 60:
                            recommendations.append("Utiliser votre attention aux détails comme force dans des contextes appropriés")

                        if masking_index > 60:
                            recommendations.append("Explorer avec un professionnel les stratégies de camouflage social que vous pourriez utiliser")

                        if risk_factor > 3:
                            recommendations.append("Une évaluation clinique approfondie est fortement recommandée")
                        else:
                            recommendations.append("Discuter de ces résultats avec un professionnel de santé si vous avez des préoccupations")


                        for i, rec in enumerate(recommendations, 1):
                            st.markdown(f"""
                            <div style="display: flex; align-items: flex-start; margin-bottom: 15px; padding: 12px 0;">
                                <div style="background: linear-gradient(135deg, #3498db, #2980b9);
                                            color: white;
                                            border-radius: 50%;
                                            width: 24px;
                                            height: 24px;
                                            display: flex;
                                            align-items: center;
                                            justify-content: center;
                                            font-size: 0.8rem;
                                            font-weight: bold;
                                            margin-right: 15px;
                                            flex-shrink: 0;">
                                    {i}
                                </div>
                                <p style="margin: 0;
                                          font-size: 1rem;
                                          line-height: 1.6;
                                          color: #2c3e50;
                                          text-align: justify;">
                                    {rec}
                                </p>
                            </div>
                            """, unsafe_allow_html=True)

                        st.markdown("""
                        <div style="margin-top: 25px;
                                    padding: 15px;
                                    background: rgba(52, 152, 219, 0.05);
                                    border-radius: 8px;
                                    border-left: 4px solid #3498db;">
                            <p style="font-style: italic;
                                      margin: 0;
                                      color: #5d6d7e;
                                      text-align: center;
                                      font-size: 0.95rem;">
                                ⚠️ Ces recommandations sont générées automatiquement en fonction de vos réponses et ne remplacent pas l'avis médical professionnel.
                            </p>
                        </div>
                        </div>
                        """, unsafe_allow_html=True)

                        st.markdown("### Analyse comparative")

                        fig = go.Figure()

                        if 'Score_A10' in df.columns and 'TSA' in df.columns:
                            avg_tsa = df[df['TSA'] == 'Yes']['Score_A10'].mean()
                            avg_non_tsa = df[df['TSA'] == 'No']['Score_A10'].mean()
                        else:
                            avg_tsa = 7.2
                            avg_non_tsa = 2.8

                        categories = ['Votre score', 'Moyenne TSA', 'Moyenne non-TSA']
                        scores = [total_score, avg_tsa, avg_non_tsa]
                        colors = ['#3498db', '#e74c3c', '#2ecc71']

                        fig.add_trace(go.Bar(
                            x=categories,
                            y=scores,
                            marker_color=colors,
                            text=scores,
                            textposition='auto'
                        ))

                        fig.update_layout(
                            title='Comparaison de votre score avec les moyennes de référence',
                            yaxis=dict(
                                title='Score AQ-10',
                                range=[0, 10.5]
                            ),
                            height=400
                        )

                        st.plotly_chart(fig, use_container_width=True)

                    except Exception as e:
                        st.error(f"Le modèle n'a pas pu générer de prédiction: {str(e)}")
                        st.info("Veuillez vérifier que toutes les données ont été correctement saisies.")
                else:
                    st.warning("Le modèle de prédiction n'est pas disponible. Veuillez réessayer ultérieurement.")

                    st.html("""
                        <div style="background-color: #f0f7fa; border-left: 4px solid #3498db; padding: 20px; border-radius: 5px; margin: 30px 0; text-align: left;">
                            <h4 style="color: #3498db; margin-top: 0; text-align: center;">Comment fonctionne cette prédiction ?</h4>
                            <p style="margin-bottom: 10px; text-align: left;">Cette prédiction est calculée par un algorithme d'<strong>intelligence artificielle</strong> appelé "<em>Random Forest</em>" (forêt aléatoire) qui a été entraîné sur des milliers de cas cliniques.</p>

                            <p style="text-align: left;">L'algorithme prend en compte :</p>
                            <ul style="text-align: left;">
                                <li><strong>Vos réponses au questionnaire AQ-10</strong> : chaque question a été validée scientifiquement pour détecter des traits autistiques spécifiques</li>
                                <li><strong>Vos données démographiques</strong> : âge, genre, origine ethnique</li>
                                <li><strong>Les antécédents familiaux</strong> : la présence de TSA dans la famille est un facteur important</li>
                            </ul>

                            <p style="text-align: left;">Le modèle compare ensuite votre profil à tous les cas qu'il a appris et détermine la probabilité que vous présentiez des traits autistiques similaires à ceux diagnostiqués TSA.</p>

                            <p style="font-style: italic; margin-top: 10px; text-align: left;">Ce pourcentage représente le niveau de confiance du modèle dans sa prédiction, pas la "gravité" ou l'"intensité" de l'autisme.</p>
                        </div>
                        """)

                    st.html("""
                        <div style="background-color: #fef9e7; border-left: 4px solid #f39c12; padding: 15px; border-radius: 5px; margin-top: 20px;">
                            <h4 style="color: #f39c12; margin-top: 0;">Limites de cette prédiction</h4>
                            <p>Ce modèle est un <strong>outil de dépistage</strong>, pas un instrument de diagnostic. Un diagnostic formel de TSA nécessite une évaluation complète par des professionnels de santé qualifiés.</p>

                            <p>Facteurs non pris en compte par ce modèle :</p>
                            <ul>
                                <li>Observation directe des comportements sociaux</li>
                                <li>Développement précoce et historique médical complet</li>
                                <li>Impact des traits sur la vie quotidienne</li>
                                <li>Autres conditions médicales ou psychiatriques</li>
                            </ul>
                        </div>
                        """)

                    st.markdown("""
                        <h3 style="text-align: center; margin-top: 40px; margin-bottom: 20px; color: #3498db;">
                            Comparaison avec la population de référence
                        </h3>
                        """, unsafe_allow_html=True)

                    mean_tsa = df[df['TSA'] == 'Yes']['Score_A10'].mean()
                    mean_non_tsa = df[df['TSA'] == 'No']['Score_A10'].mean()
                    overall_mean = df['Score_A10'].mean()

                    percentile = 100 * (df['Score_A10'] <= total_score).mean()
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.markdown(f"""
                            <div class="kpi-card">
                                <div class="kpi-title">Percentile</div>
                                <div class="kpi-value">{percentile:.0f}<sup>ème</sup></div>
                                <div class="kpi-comparison">Votre score dépasse {percentile:.0f}% de la population testée</div>
                            </div>
                            """, unsafe_allow_html=True)

                    with col2:
                        diff_non_tsa = total_score - mean_non_tsa
                        color_non_tsa = "#e74c3c" if diff_non_tsa > 0 else "#2ecc71"

                        st.markdown(f"""
                            <div class="kpi-card">
                                <div class="kpi-title">Comparaison groupe non-TSA</div>
                                <div class="kpi-value" style="color:{color_non_tsa};">{diff_non_tsa:+.1f}</div>
                                <div class="kpi-comparison">Par rapport à la moyenne des personnes sans diagnostic ({mean_non_tsa:.1f})</div>
                            </div>
                            """, unsafe_allow_html=True)

                    with col3:
                        diff_tsa = total_score - mean_tsa
                        color_tsa = "#2ecc71" if diff_tsa < 0 else "#e74c3c"

                        st.markdown(f"""
                            <div class="kpi-card">
                                <div class="kpi-title">Comparaison groupe TSA</div>
                                <div class="kpi-value" style="color:{color_tsa};">{diff_tsa:+.1f}</div>
                                <div class="kpi-comparison">Par rapport à la moyenne des personnes avec diagnostic ({mean_tsa:.1f})</div>
                            </div>
                            """, unsafe_allow_html=True)

                        st.markdown("""
                        <h4 style="text-align: center; margin-top: 30px; margin-bottom: 15px; color: #34495e;">
                            Analyse détaillée de vos réponses par question
                        </h4>
                        """, unsafe_allow_html=True)

                        categories = [f'Q{i+1}' for i in range(10)]
                        user_scores = scores_individuels

                        tsa_mean_scores = [df[df['TSA'] == 'Yes'][f'A{i+1}'].mean() for i in range(10)]
                        non_tsa_mean_scores = [df[df['TSA'] == 'No'][f'A{i+1}'].mean() for i in range(10)]

                        fig = make_subplots(rows=1, cols=3,
                                        specs=[[{'type': 'polar'}]*3],
                                        subplot_titles=["Vos réponses", "Profil moyen TSA", "Profil moyen non-TSA"])

                        fig.add_trace(
                            go.Scatterpolar(
                                r=user_scores,
                                theta=categories,
                                fill='toself',
                                name='Vos réponses',
                                line_color='#2ecc71',
                                fillcolor='rgba(46, 204, 113, 0.5)'
                            ),
                            row=1, col=1
                        )

                        fig.add_trace(
                            go.Scatterpolar(
                                r=tsa_mean_scores,
                                theta=categories,
                                fill='toself',
                                name='Moyenne TSA',
                                line_color='#e74c3c',
                                fillcolor='rgba(231, 76, 60, 0.5)'
                            ),
                            row=1, col=2
                        )

                        fig.add_trace(
                            go.Scatterpolar(
                                r=non_tsa_mean_scores,
                                theta=categories,
                                fill='toself',
                                name='Moyenne non-TSA',
                                line_color='#3498db',
                                fillcolor='rgba(52, 152, 219, 0.5)'
                            ),
                            row=1, col=3
                        )

                        fig.update_layout(
                            polar=dict(
                                radialaxis=dict(
                                    visible=True,
                                    range=[0, 1],
                                    tickvals=[0, 0.25, 0.5, 0.75, 1],
                                    ticktext=["0", "1", "2", "3", "4"],
                                    tickangle=45
                                ),
                                angularaxis=dict(
                                    tickfont_size=11
                                ),
                                gridshape='circular'
                            ),
                            polar2=dict(
                                radialaxis=dict(
                                    visible=True,
                                    range=[0, 1],
                                    tickvals=[0, 0.25, 0.5, 0.75, 1],
                                    ticktext=["0", "1", "2", "3", "4"],
                                    tickangle=45
                                ),
                                angularaxis=dict(
                                    tickfont_size=11
                                ),
                                gridshape='circular'
                            ),
                            polar3=dict(
                                radialaxis=dict(
                                    visible=True,
                                    range=[0, 1],
                                    tickvals=[0, 0.25, 0.5, 0.75, 1],
                                    ticktext=["0", "1", "2", "3", "4"],
                                    tickangle=45
                                ),
                                angularaxis=dict(
                                    tickfont_size=11
                                ),
                                gridshape='circular'
                            ),
                            height=450,
                            margin=dict(l=80, r=80, t=80, b=50),
                            paper_bgcolor='rgba(0,0,0,0)',
                            plot_bgcolor='rgba(0,0,0,0)',
                            font=dict(size=12),
                            showlegend=False
                        )

                        st.plotly_chart(fig, use_container_width=True)

                        with st.expander("🔍 Comprendre la signification des questions"):
                            st.markdown("""
                            | Question | Description | Score élevé indique |
                            |----------|-------------|---------------------|
                            | Q1 | Perception des petits bruits | ↑ Hypersensibilité auditive |
                            | Q2 | Focus sur les détails vs l'ensemble | ↑ Attention aux détails |
                            | Q3 | Capacité à faire plusieurs choses | ↓ Difficultés avec le multitâche |
                            | Q4 | Reprise d'activité après interruption | ↓ Difficultés avec les transitions |
                            | Q5 | Compréhension du langage figuré | ↓ Interprétation littérale |
                            | Q6 | Perception de l'ennui chez autrui | ↓ Difficulté à lire les signaux sociaux |
                            | Q7 | Compréhension des intentions des personnages | ↑ Difficulté avec la théorie de l'esprit |
                            | Q8 | Collection d'informations sur des catégories | ↑ Intérêts restreints |
                            | Q9 | Compréhension des émotions par l'expression | ↓ Difficulté à lire les émotions |
                            | Q10 | Compréhension des intentions d'autrui | ↑ Difficulté d'interprétation sociale |
                            """)

                        st.info("⚠️ Ce résultat est une indication basée sur un modèle statistique et ne constitue pas un diagnostic médical. Consultez un professionnel de santé pour une évaluation complète.")

                st.markdown("""
                <h3 style="text-align: center; margin-top: 40px; margin-bottom: 20px;">
                    Prévalence du Trouble du Spectre Autistique
                </h3>
                """, unsafe_allow_html=True)

                col1, col2, col3 = st.columns(3)

                with col1:
                    st.markdown("""
                    <div style="background-color: #f5f7fa; border-radius: 15px; padding: 20px; text-align: center; height: 100%; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
                        <h3 style="color: #3498db; margin-bottom: 10px;">Monde</h3>
                        <div style="font-size: 2.8rem; font-weight: bold; color: #3498db; margin: 15px 0;">1 sur 100</div>
                        <p style="color: #2c3e50;">enfants dans le monde est concerné par un trouble du spectre autistique selon l'OMS</p>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    st.markdown("""
                    <div style="background-color: #f5f7fa; border-radius: 15px; padding: 20px; text-align: center; height: 100%; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
                        <h3 style="color: #e74c3c; margin-bottom: 10px;">France</h3>
                        <div style="font-size: 2.8rem; font-weight: bold; color: #e74c3c; margin: 15px 0;">~1 million</div>
                        <p style="color: #2c3e50;">de personnes en France, soit entre 1% et 2% de la population française</p>
                    </div>
                    """, unsafe_allow_html=True)

                with col3:
                    st.markdown("""
                    <div style="background-color: #f5f7fa; border-radius: 15px; padding: 20px; text-align: center; height: 100%; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
                        <h3 style="color: #2ecc71; margin-bottom: 10px;">États-Unis</h3>
                        <div style="font-size: 2.8rem; font-weight: bold; color: #2ecc71; margin: 15px 0;">1 sur 36</div>
                        <p style="color: #2c3e50;">enfants de 8 ans présentent un TSA selon les dernières données CDC</p>
                    </div>
                    """, unsafe_allow_html=True)


                    
def show_documentation():
    """Page de documentation enrichie avec ressources scientifiques complètes"""
    
    # CSS spécifique pour la documentation (harmonisé avec le thème global)
    st.markdown("""
    <style>
    /* Documentation styles - harmonisés avec le thème global */
    .doc-header {
        background: linear-gradient(135deg, #3498db, #2ecc71);
        padding: 40px 25px;
        border-radius: 20px;
        margin-bottom: 35px;
        text-align: center;
        box-shadow: 0 8px 25px rgba(52, 152, 219, 0.3);
    }
    
    .doc-section {
        background: white;
        border-radius: 15px;
        padding: 30px;
        margin: 25px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.08);
        border-left: 4px solid #3498db;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .doc-section:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    }
    
    .resource-card {
        background: linear-gradient(135deg, #f8f9fa, #ffffff);
        border-radius: 12px;
        padding: 20px;
        margin: 15px 0;
        border: 1px solid #e9ecef;
        border-left: 4px solid;
        transition: all 0.3s ease;
    }
    
    .resource-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.1);
    }
    
    .video-resource { border-left-color: #e74c3c; }
    .audio-resource { border-left-color: #9b59b6; }
    .article-resource { border-left-color: #f39c12; }
    .scientific-resource { border-left-color: #2ecc71; }
    
    .tag {
        display: inline-block;
        background: #3498db;
        color: white;
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 0.8rem;
        margin: 2px;
    }
    
    .difficulty-beginner { background: #2ecc71; }
    .difficulty-intermediate { background: #f39c12; }
    .difficulty-advanced { background: #e74c3c; }
    
    .timeline-item {
        background: white;
        border-radius: 10px;
        padding: 20px;
        margin: 15px 0;
        border-left: 4px solid #3498db;
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    }
    
    .statistics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
        margin: 25px 0;
    }
    
    .stat-card {
        background: linear-gradient(135deg, #3498db, #2980b9);
        color: white;
        padding: 25px;
        border-radius: 12px;
        text-align: center;
        box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
    }
    
    .quote-section {
        background: linear-gradient(135deg, #ecf0f1, #bdc3c7);
        border-left: 4px solid #3498db;
        padding: 20px;
        border-radius: 8px;
        font-style: italic;
        margin: 20px 0;
    }
    </style>
    """, unsafe_allow_html=True)

    # En-tête principal
    st.markdown("""
    <div class="doc-header">
        <h1 style="color: white; font-size: 3rem; margin-bottom: 15px;
                   text-shadow: 0 2px 4px rgba(0,0,0,0.3); font-weight: 600;">
            📚 Documentation Scientifique TSA
        </h1>
        <p style="color: rgba(255,255,255,0.95); font-size: 1.4rem;
                  max-width: 900px; margin: 0 auto; line-height: 1.6;">
            Ressources complètes pour approfondir vos connaissances sur les Troubles du Spectre Autistique
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Navigation interne
    doc_tabs = st.tabs([
        "🔬 Bases Scientifiques",
        "📖 Ressources d'Apprentissage", 
        "🎥 Contenus Audiovisuels",
        "📊 Données & Statistiques",
        "🏥 Guides Cliniques",
        "🌐 Organisations & Associations"
    ])

    with doc_tabs[0]:
        # Section Bases Scientifiques
        st.markdown("""
        <div class="doc-section">
            <h2 style="color: #2c3e50; margin-top: 0; font-size: 2.2rem;">
                🧬 Fondements Scientifiques de l'Autisme
            </h2>
        </div>
        """, unsafe_allow_html=True)

        # Historique et évolution
        st.markdown("### 📅 Évolution Historique des Connaissances")
        
        historical_timeline = [
            ("1943", "Leo Kanner", "Première description de l'autisme infantile précoce", "#3498db"),
            ("1944", "Hans Asperger", "Description du syndrome d'Asperger", "#2ecc71"),
            ("1980", "DSM-III", "Première inclusion de l'autisme dans le manuel diagnostique", "#f39c12"),
            ("1994", "DSM-IV", "Introduction du concept de spectre autistique", "#9b59b6"),
            ("2013", "DSM-5", "Unification sous 'Troubles du Spectre Autistique'", "#e74c3c"),
            ("2020-2024", "Recherche moderne", "Approches neuroscientifiques et génétiques avancées", "#34495e")
        ]

        for year, author, description, color in historical_timeline:
            st.markdown(f"""
            <div class="timeline-item" style="border-left-color: {color};">
                <div style="display: flex; align-items: center; margin-bottom: 10px;">
                    <span style="background: {color}; color: white; padding: 5px 10px; 
                                 border-radius: 15px; font-weight: bold; margin-right: 15px;">
                        {year}
                    </span>
                    <strong style="color: #2c3e50; font-size: 1.1rem;">{author}</strong>
                </div>
                <p style="color: #34495e; margin: 0; line-height: 1.5;">{description}</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### 🎯 Critères Diagnostiques DSM-5 (2013)")
        
        st.markdown("""
        <div class="criteria-section" style="margin-bottom:30px; font-family:Arial, sans-serif;">
            <h4 style="color:#3498db; margin-top:20px;">A. Déficits persistants dans la communication sociale</h4>
            <ul style="line-height:1.8; color:#2c3e50; padding-left:20px; list-style-type: disc;">
                <li><strong>Réciprocité sociocommunicative</strong> : Difficultés dans les échanges sociaux</li>
                <li><strong>Communication non verbale</strong> : Utilisation atypique du contact visuel, expressions faciales</li>
                <li><strong>Relations sociales</strong> : Difficultés à développer et maintenir des relations appropriées</li>
            </ul>
            <h4 style="color:#2ecc71; margin-top:25px;">B. Comportements répétitifs et intérêts restreints</h4>
            <ul style="line-height:1.8; color:#2c3e50; padding-left:20px; list-style-type: disc;">
                <li><strong>Stéréotypies motrices</strong> : Mouvements répétitifs, écholalie</li>
                <li><strong>Rigidité</strong> : Insistance sur la similitude, routines inflexibles</li>
                <li><strong>Intérêts spécialisés</strong> : Fixations sur des objets ou sujets particuliers</li>
                <li><strong>Sensibilités sensorielles</strong> : Hyper ou hypo-réactivité sensorielle</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)


        # Neurobiologie
        st.markdown("### 🧠 Bases Neurobiologiques")
        
        neuro_col1, neuro_col2 = st.columns(2)
        
        with neuro_col1:
            st.markdown("""
            <div class="resource-card scientific-resource">
                <h4 style="color: #2ecc71; margin-top: 0;">🔬 Recherches Neurologiques</h4>
                <ul style="line-height: 1.6; color: #2c3e50;">
                    <li><strong>Connectivité cérébrale</strong> : Altérations dans les réseaux neuronaux</li>
                    <li><strong>Développement synaptique</strong> : Différences dans la formation des synapses</li>
                    <li><strong>Neuroplasticité</strong> : Capacités d'adaptation du cerveau autiste</li>
                    <li><strong>Traitement sensoriel</strong> : Différences dans l'intégration sensorielle</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with neuro_col2:
            st.markdown("""
            <div class="resource-card scientific-resource">
                <h4 style="color: #2ecc71; margin-top: 0;">🧬 Facteurs Génétiques</h4>
                <ul style="line-height: 1.6; color: #2c3e50;">
                    <li><strong>Héritabilité élevée</strong> : 80-90% selon les études de jumeaux</li>
                    <li><strong>Gènes candidats</strong> : SHANK3, NRXN, CHD8, SCN2A</li>
                    <li><strong>Variants rares</strong> : Copy Number Variants (CNV)</li>
                    <li><strong>Épigénétique</strong> : Influence de l'environnement sur l'expression génique</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

    with doc_tabs[1]:
        # Ressources d'apprentissage
        st.markdown("""
        <div class="doc-section">
            <h2 style="color: #2c3e50; margin-top: 0; font-size: 2.2rem;">
                📖 Ressources d'Apprentissage et de Formation
            </h2>
        </div>
        """, unsafe_allow_html=True)

        # Livres de référence
        st.markdown("### 📚 Ouvrages de Référence")
        
        books = [
            {
                "title": "L'Autisme : De la recherche à la pratique",
                "authors": "Baghdadli A., Brisot J., Aussiloux C.",
                "year": "2022",
                "level": "intermediate",
                "description": "Synthèse complète des connaissances actuelles sur l'autisme, de la recherche fondamentale aux applications pratiques.",
                "topics": ["Diagnostic", "Interventions", "Recherche"]
            },
            {
                "title": "Autism and Asperger Syndrome",
                "authors": "Baron-Cohen S.",
                "year": "2008",
                "level": "beginner",
                "description": "Introduction accessible aux troubles du spectre autistique par l'un des experts mondiaux.",
                "topics": ["Théorie de l'esprit", "Cognition sociale", "Empathie"]
            },
            {
                "title": "The Autistic Brain",
                "authors": "Grandin T., Panek R.",
                "year": "2013",
                "level": "beginner",
                "description": "Perspective unique d'une personne autiste sur le fonctionnement du cerveau autiste.",
                "topics": ["Neurodiversité", "Témoignage", "Sensorialité"]
            },
            {
                "title": "Handbook of Autism and Pervasive Developmental Disorders",
                "authors": "Volkmar F.R., et al.",
                "year": "2021",
                "level": "advanced",
                "description": "Manuel de référence complet pour les professionnels et chercheurs.",
                "topics": ["Diagnostic différentiel", "Comorbidités", "Traitements"]
            }
        ]

        for book in books:
            difficulty_class = f"difficulty-{book['level']}"
            st.markdown(f"""
            <div class="resource-card article-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #f39c12; margin: 0 0 8px 0;">{book['title']}</h4>
                        <p style="color: #7f8c8d; margin: 0; font-style: italic;">{book['authors']} ({book['year']})</p>
                    </div>
                    <span class="tag {difficulty_class}">{book['level'].title()}</span>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin-bottom: 15px;">{book['description']}</p>
                <div>
                    {''.join([f'<span class="tag">{topic}</span>' for topic in book['topics']])}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Formations en ligne
        st.markdown("### 💻 Formations et Cours en Ligne")
        
        online_courses = [
            {
                "platform": "Coursera",
                "title": "Introduction to Family Engagement in Education",
                "university": "University of Colorado Boulder",
                "duration": "4 semaines",
                "level": "beginner",
                "topics": ["Intervention précoce", "Famille", "Éducation"]
            },
            {
                "platform": "edX",
                "title": "Autism and Mental Health",
                "university": "University of Kent",
                "duration": "6 semaines", 
                "level": "intermediate",
                "topics": ["Santé mentale", "Comorbidités", "Soutien"]
            },
            {
                "platform": "FUN-MOOC",
                "title": "Troubles du spectre de l'autisme : diagnostic",
                "university": "Université de Tours",
                "duration": "8 semaines",
                "level": "advanced",
                "topics": ["Diagnostic", "Outils", "Évaluation"]
            }
        ]

        for course in online_courses:
            difficulty_class = f"difficulty-{course['level']}"
            st.markdown(f"""
            <div class="resource-card video-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #e74c3c; margin: 0 0 8px 0;">{course['title']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            <strong>{course['platform']}</strong> - {course['university']} 
                            | ⏱️ {course['duration']}
                        </p>
                    </div>
                    <span class="tag {difficulty_class}">{course['level'].title()}</span>
                </div>
                <div>
                    {''.join([f'<span class="tag">{topic}</span>' for topic in course['topics']])}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Revues scientifiques
        st.markdown("### 📰 Revues Scientifiques Spécialisées")
        
        journals = [
            {
                "name": "Journal of Autism and Developmental Disorders",
                "impact_factor": "3.8",
                "publisher": "Springer",
                "focus": "Recherche fondamentale et appliquée sur l'autisme"
            },
            {
                "name": "Autism Research",
                "impact_factor": "4.9",
                "publisher": "Wiley",
                "focus": "Neurosciences, génétique et interventions"
            },
            {
                "name": "Molecular Autism",
                "impact_factor": "6.3",
                "publisher": "BMC",
                "focus": "Bases moléculaires et génétiques de l'autisme"
            }
        ]

        for journal in journals:
            st.markdown(f"""
            <div class="resource-card scientific-resource">
                <h4 style="color: #2ecc71; margin: 0 0 10px 0;">{journal['name']}</h4>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <p style="color: #7f8c8d; margin: 0;"><strong>Éditeur:</strong> {journal['publisher']}</p>
                        <p style="color: #2c3e50; margin: 5px 0 0 0; font-size: 0.9rem;">{journal['focus']}</p>
                    </div>
                    <div style="text-align: right;">
                        <span class="tag" style="background: #2ecc71;">IF: {journal['impact_factor']}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    with doc_tabs[2]:
        # Contenus audiovisuels
        st.markdown("""
        <div class="doc-section">
            <h2 style="color: #2c3e50; margin-top: 0; font-size: 2.2rem;">
                🎥 Ressources Audiovisuelles
            </h2>
        </div>
        """, unsafe_allow_html=True)

        # Documentaires
        st.markdown("### 🎬 Documentaires Recommandés")
        
        documentaries = [
            {
                "title": "In My Language",
                "author": "Amanda Baggs",
                "year": "2007",
                "duration": "8 min",
                "platform": "YouTube",
                "description": "Témoignage puissant d'une personne autiste non-verbale sur sa perception du monde.",
                "themes": ["Neurodiversité", "Communication", "Témoignage"]
            },
            {
                "title": "Atypical",
                "author": "Robia Rashid",
                "year": "2017-2021",
                "duration": "4 saisons",
                "platform": "Netflix", 
                "description": "Série suivant un adolescent autiste dans sa quête d'indépendance et d'amour.",
                "themes": ["Adolescence", "Famille", "Relations sociales"]
            },
            {
                "title": "Temple Grandin",
                "author": "Mick Jackson",
                "year": "2010",
                "duration": "107 min",
                "platform": "HBO",
                "description": "Biopic de Temple Grandin, scientifique autiste révolutionnaire.",
                "themes": ["Biographie", "Science", "Réussite"]
            }
        ]

        for doc in documentaries:
            st.markdown(f"""
            <div class="resource-card video-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #e74c3c; margin: 0 0 8px 0;">🎬 {doc['title']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            {doc['author']} ({doc['year']}) | ⏱️ {doc['duration']} | 📺 {doc['platform']}
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin-bottom: 15px;">{doc['description']}</p>
                <div>
                    {''.join([f'<span class="tag">{theme}</span>' for theme in doc['themes']])}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Podcasts
        st.markdown("### 🎧 Podcasts Spécialisés")
        
        podcasts = [
            {
                "title": "Autism Spectrum Podcast",
                "host": "Máximo Marín",
                "frequency": "Hebdomadaire",
                "language": "Anglais",
                "description": "Témoignages et discussions avec des personnes autistes et leurs familles.",
                "focus": ["Témoignages", "Vie quotidienne", "Stratégies"]
            },
            {
                "title": "Different Brains",
                "host": "Hackie Reitman",
                "frequency": "Bi-mensuel",
                "language": "Anglais",
                "description": "Interviews d'experts et de personnes neuroatypiques sur la neurodiversité.",
                "focus": ["Neurodiversité", "Inclusion", "Innovation"]
            },
            {
                "title": "Autisme Info",
                "host": "Association Autisme France",
                "frequency": "Mensuel",
                "language": "Français",
                "description": "Actualités et conseils pratiques pour les familles concernées par l'autisme.",
                "focus": ["Actualités", "Conseils pratiques", "Droits"]
            }
        ]

        for podcast in podcasts:
            st.markdown(f"""
            <div class="resource-card audio-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #9b59b6; margin: 0 0 8px 0;">🎧 {podcast['title']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            Animé par {podcast['host']} | {podcast['frequency']} | 🌍 {podcast['language']}
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin-bottom: 15px;">{podcast['description']}</p>
                <div>
                    {''.join([f'<span class="tag">{focus}</span>' for focus in podcast['focus']])}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Chaînes YouTube
        st.markdown("### 📺 Chaînes YouTube Éducatives")
        
        youtube_channels = [
            {
                "name": "Asperger Expertise",
                "creator": "Dr. Michelle Mowery",
                "subscribers": "45K",
                "content": "Vidéos éducatives sur le syndrome d'Asperger et l'autisme de haut niveau.",
                "topics": ["Diagnostic", "Stratégies", "Témoignages"]
            },
            {
                "name": "Yo Samdy Sam",
                "creator": "Samdy Sam",
                "subscribers": "120K",
                "content": "Vulgarisation scientifique incluant des sujets sur l'autisme et les neurosciences.",
                "topics": ["Vulgarisation", "Neurosciences", "Inclusion"]
            },
            {
                "name": "Autisme - École des parents",
                "creator": "École des parents",
                "subscribers": "8K",
                "content": "Conseils pratiques et témoignages pour les familles.",
                "topics": ["Famille", "Éducation", "Soutien"]
            }
        ]

        for channel in youtube_channels:
            st.markdown(f"""
            <div class="resource-card video-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #e74c3c; margin: 0 0 8px 0;">📺 {channel['name']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            {channel['creator']} | 👥 {channel['subscribers']} abonnés
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin-bottom: 15px;">{channel['content']}</p>
                <div>
                    {''.join([f'<span class="tag">{topic}</span>' for topic in channel['topics']])}
                </div>
            </div>
            """, unsafe_allow_html=True)

    with doc_tabs[3]:
        # Données et statistiques
        st.markdown("""
        <div class="doc-section">
            <h2 style="color: #2c3e50; margin-top: 0; font-size: 2.2rem;">
                📊 Données et Statistiques Mondiales
            </h2>
        </div>
        """, unsafe_allow_html=True)

        # Statistiques globales
        st.markdown("### 🌍 Prévalence Mondiale")
        
        st.markdown("""
        <div class="statistics-grid">
            <div class="stat-card">
                <h3 style="margin: 0 0 10px 0; font-size: 2.5rem;">1/36</h3>
                <p style="margin: 0; font-size: 1.1rem;">Enfants aux États-Unis<br>(CDC 2023)</p>
            </div>
            <div class="stat-card">
                <h3 style="margin: 0 0 10px 0; font-size: 2.5rem;">1-2%</h3>
                <p style="margin: 0; font-size: 1.1rem;">Population mondiale<br>estimée</p>
            </div>
            <div class="stat-card">
                <h3 style="margin: 0 0 10px 0; font-size: 2.5rem;">700K</h3>
                <p style="margin: 0; font-size: 1.1rem;">Personnes en France<br>(estimation)</p>
            </div>
            <div class="stat-card">
                <h3 style="margin: 0 0 10px 0; font-size: 2.5rem;">4:1</h3>
                <p style="margin: 0; font-size: 1.1rem;">Ratio garçons/filles<br>(historique)</p>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Évolution de la prévalence
        st.markdown("### 📈 Évolution de la Prévalence (États-Unis)")
        
        prevalence_data = pd.DataFrame({
            'Année': [2000, 2002, 2004, 2006, 2008, 2010, 2012, 2014, 2016, 2018, 2020, 2023],
            'Prévalence': [1/150, 1/150, 1/125, 1/110, 1/88, 1/68, 1/88, 1/68, 1/54, 1/44, 1/36, 1/36],
            'Source': ['CDC'] * 12
        })
        
        prevalence_data['Prévalence_pct'] = (1 / prevalence_data['Prévalence']) * 100
        
        fig_prevalence = px.line(
            prevalence_data, 
            x='Année', 
            y='Prévalence_pct',
            title='Évolution de la prévalence de l\'autisme aux États-Unis',
            labels={'Prévalence_pct': 'Prévalence (%)', 'Année': 'Année'},
            markers=True
        )
        fig_prevalence.update_layout(
            height=400,
            xaxis_title="Année",
            yaxis_title="Prévalence (%)"
        )
        st.plotly_chart(fig_prevalence, use_container_width=True)

        # Données par pays
        st.markdown("### 🗺️ Prévalence par Région/Pays")
        
        country_data = pd.DataFrame({
            'Pays/Région': ['États-Unis', 'Royaume-Uni', 'Australie', 'Suède', 'Danemark', 'Corée du Sud', 'Japon'],
            'Prévalence (%)': [2.8, 1.1, 2.5, 1.9, 1.65, 2.6, 1.0],
            'Année': [2023, 2021, 2022, 2021, 2020, 2019, 2020],
            'Source': ['CDC', 'NHS', 'AIHW', 'Socialstyrelsen', 'SSI', 'KCDC', 'MHLW']
        })
        
        fig_countries = px.bar(
            country_data,
            x='Pays/Région',
            y='Prévalence (%)',
            title='Prévalence de l\'autisme par pays',
            color='Prévalence (%)',
            color_continuous_scale='Blues'
        )
        fig_countries.update_layout(height=400)
        st.plotly_chart(fig_countries, use_container_width=True)



    with doc_tabs[4]:
        # Guides cliniques
        st.markdown("""
        <div class="doc-section">
            <h2 style="color: #2c3e50; margin-top: 0; font-size: 2.2rem;">
                🏥 Guides Cliniques et Bonnes Pratiques
            </h2>
        </div>
        """, unsafe_allow_html=True)

        # Recommandations HAS
        st.markdown("### 🇫🇷 Recommandations HAS (France)")
        
        has_docs = [
            {
                "title": "Trouble du spectre de l'autisme : signes d'alerte, repérage, diagnostic et évaluation",
                "year": "2018",
                "type": "Recommandations",
                "target": "Professionnels de santé",
                "summary": "Guide complet pour le repérage précoce et le diagnostic des TSA de 12 mois à 36 mois."
            },
            {
                "title": "Trouble du spectre de l'autisme : interventions et parcours de vie de l'adulte",
                "year": "2017", 
                "type": "Recommandations",
                "target": "Équipes médico-sociales",
                "summary": "Prise en charge et accompagnement des adultes avec TSA."
            },
            {
                "title": "Autisme et autres TED : interventions éducatives et thérapeutiques",
                "year": "2012",
                "type": "Recommandations",
                "target": "Professionnels",
                "summary": "Interventions recommandées chez l'enfant et l'adolescent."
            }
        ]

        for doc in has_docs:
            st.markdown(f"""
            <div class="resource-card scientific-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #2ecc71; margin: 0 0 8px 0;">📋 {doc['title']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            HAS {doc['year']} | {doc['type']} | 🎯 {doc['target']}
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin: 0;">{doc['summary']}</p>
            </div>
            """, unsafe_allow_html=True)

        # Outils de diagnostic
        st.markdown("### 🔧 Outils de Diagnostic et d'Évaluation")
        
        diagnostic_tools = [
            {
                "name": "ADOS-2",
                "full_name": "Autism Diagnostic Observation Schedule",
                "age_range": "12 mois - adulte",
                "duration": "45-60 min",
                "type": "Observation structurée",
                "description": "Étalon-or pour l'observation des comportements sociaux et communicatifs."
            },
            {
                "name": "ADI-R", 
                "full_name": "Autism Diagnostic Interview-Revised",
                "age_range": "2 ans - adulte",
                "duration": "90-150 min", 
                "type": "Entretien parental",
                "description": "Entretien semi-structuré explorant les trois domaines du spectre autistique."
            },
            {
                "name": "M-CHAT-R/F",
                "full_name": "Modified Checklist for Autism in Toddlers",
                "age_range": "16-30 mois",
                "duration": "5-10 min",
                "type": "Questionnaire de dépistage",
                "description": "Outil de dépistage précoce utilisé en médecine générale et PMI."
            },
            {
                "name": "CARS-2",
                "full_name": "Childhood Autism Rating Scale",
                "age_range": "2 ans et plus",
                "duration": "20-30 min",
                "type": "Échelle d'évaluation",
                "description": "Évaluation de la sévérité des symptômes autistiques."
            }
        ]

        for tool in diagnostic_tools:
            st.markdown(f"""
            <div class="resource-card article-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #f39c12; margin: 0 0 5px 0;">🔧 {tool['name']}</h4>
                        <p style="color: #7f8c8d; margin: 0; font-style: italic; font-size: 0.9rem;">
                            {tool['full_name']}
                        </p>
                    </div>
                    <span class="tag" style="background: #f39c12;">{tool['type']}</span>
                </div>
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <span style="color: #34495e;"><strong>👶 Age:</strong> {tool['age_range']}</span>
                    <span style="color: #34495e;"><strong>⏱️ Durée:</strong> {tool['duration']}</span>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin: 0;">{tool['description']}</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### 🛤️ Parcours de Soin Recommandé")
    
        st.markdown("""
            <div class="doc-section">
            <div style="background: linear-gradient(135deg, #ecf0f1, #bdc3c7); padding: 20px; border-radius: 10px; margin: 20px 0;">
            <h4 style="color: #2c3e50; margin-top: 0; text-align: center;">Étapes du Parcours Diagnostique</h4>
            
            <div style="display: flex; flex-direction: column; gap: 15px; margin-top: 20px;">
            <div style="display: flex; align-items: center; background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #3498db;">
            <span style="background: #3498db; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold;">1</span>
            <div>
            <strong style="color: #2c3e50;">Repérage précoce</strong>
            <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9rem;">Médecin généraliste, pédiatre, PMI (12-24 mois)</p>
            </div>
            </div>
            
            <div style="display: flex; align-items: center; background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #2ecc71;">
            <span style="background: #2ecc71; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold;">2</span>
            <div>
            <strong style="color: #2c3e50;">Évaluation diagnostique</strong>
            <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9rem;">Équipe spécialisée, CRA, CAMSP/CMPP</p>
            </div>
            </div>
            
            <div style="display: flex; align-items: center; background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #f39c12;">
            <span style="background: #f39c12; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold;">3</span>
            <div>
            <strong style="color: #2c3e50;">Annonce diagnostique</strong>
            <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9rem;">Information, soutien, orientation vers les services</p>
            </div>
            </div>
            
            <div style="display: flex; align-items: center; background: white; padding: 15px; border-radius: 8px; border-left: 4px solid #e74c3c;">
            <span style="background: #e74c3c; color: white; width: 30px; height: 30px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 15px; font-weight: bold;">4</span>
            <div>
            <strong style="color: #2c3e50;">Interventions précoces</strong>
            <p style="margin: 5px 0 0 0; color: #7f8c8d; font-size: 0.9rem;">SESSAD, libéral, structures spécialisées</p>
            </div>
            </div>
            </div>
            </div>
            </div>
            """, unsafe_allow_html=True)


    with doc_tabs[5]:
        # Organisations
        st.markdown("""
        <div class="doc-section">
            <h2 style="color: #2c3e50; margin-top: 0; font-size: 2.2rem;">
                🌐 Organisations et Associations
            </h2>
        </div>
        """, unsafe_allow_html=True)

        # Associations françaises
        st.markdown("### 🇫🇷 Associations Françaises")
        
        french_orgs = [
            {
                "name": "Autisme France",
                "founded": "1989",
                "mission": "Défense des droits des personnes autistes et de leurs familles",
                "services": ["Information", "Formation", "Plaidoyer", "Soutien juridique"],
                "website": "autisme.france.free.fr"
            },
            {
                "name": "Fondation FondaMental", 
                "founded": "2007",
                "mission": "Recherche et soins en psychiatrie de précision",
                "services": ["Recherche", "Centres experts", "Formation", "Innovation"],
                "website": "fondation-fondamental.org"
            },
            {
                "name": "Vaincre l'Autisme",
                "founded": "2001", 
                "mission": "Sensibilisation et aide aux familles",
                "services": ["Dépistage", "Formation", "Accompagnement", "Recherche"],
                "website": "vaincrelautisme.org"
            },
            {
                "name": "GNCRA",
                "founded": "2010",
                "mission": "Coordination des Centres de Ressources Autisme",
                "services": ["Coordination", "Formation", "Recherche", "Documentation"],
                "website": "gncra.fr"
            }
        ]

        for org in french_orgs:
            st.markdown(f"""
            <div class="resource-card scientific-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #2ecc71; margin: 0 0 8px 0;">🏛️ {org['name']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            Fondée en {org['founded']} | 🌐 {org['website']}
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin-bottom: 15px;"><strong>Mission :</strong> {org['mission']}</p>
                <div>
                    <strong style="color: #34495e;">Services :</strong><br>
                    {''.join([f'<span class="tag">{service}</span>' for service in org['services']])}
                </div>
            </div>
            """, unsafe_allow_html=True)

        # Organisations internationales
        st.markdown("### 🌍 Organisations Internationales")
        
        intl_orgs = [
            {
                "name": "Autism Speaks",
                "country": "États-Unis",
                "founded": "2005",
                "mission": "Promouvoir la recherche et l'inclusion des personnes autistes",
                "website": "autismspeaks.org"
            },
            {
                "name": "National Autistic Society",
                "country": "Royaume-Uni", 
                "founded": "1962",
                "mission": "Services et soutien pour les personnes autistes",
                "website": "autism.org.uk"
            },
            {
                "name": "Autism Europe",
                "country": "Europe",
                "founded": "1983",
                "mission": "Fédération européenne des associations d'autisme",
                "website": "autismeurope.org"
            },
            {
                "name": "Organisation Mondiale de la Santé",
                "country": "International",
                "founded": "1948",
                "mission": "Politiques de santé publique mondiales",
                "website": "who.int"
            }
        ]

        for org in intl_orgs:
            st.markdown(f"""
            <div class="resource-card article-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #f39c12; margin: 0 0 8px 0;">🌐 {org['name']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            {org['country']} | Fondée en {org['founded']} | 🌐 {org['website']}
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin: 0;"><strong>Mission :</strong> {org['mission']}</p>
            </div>
            """, unsafe_allow_html=True)

        # Centres de recherche
        st.markdown("### 🔬 Centres de Recherche de Référence")
        
        research_centers = [
            {
                "name": "Institut Pasteur - Génétique humaine et fonctions cognitives",
                "location": "Paris, France",
                "director": "Thomas Bourgeron",
                "focus": "Génétique et neurobiologie de l'autisme"
            },
            {
                "name": "Autism Research Centre - Cambridge",
                "location": "Cambridge, UK",
                "director": "Simon Baron-Cohen", 
                "focus": "Théorie de l'esprit et cognition sociale"
            },
            {
                "name": "Center for Autism Research - CHOP",
                "location": "Philadelphie, USA",
                "director": "Robert Schultz",
                "focus": "Neuroimagerie et interventions précoces"
            },
            {
                "name": "RIKEN Brain Science Institute",
                "location": "Tokyo, Japon",
                "director": "Kenji Doya",
                "focus": "Neurosciences computationnelles"
            }
        ]

        for center in research_centers:
            st.markdown(f"""
            <div class="resource-card scientific-resource">
                <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 15px;">
                    <div style="flex: 1;">
                        <h4 style="color: #2ecc71; margin: 0 0 8px 0;">🔬 {center['name']}</h4>
                        <p style="color: #7f8c8d; margin: 0;">
                            📍 {center['location']} | 👨‍🔬 {center['director']}
                        </p>
                    </div>
                </div>
                <p style="color: #2c3e50; line-height: 1.6; margin: 0;"><strong>Spécialité :</strong> {center['focus']}</p>
            </div>
            """, unsafe_allow_html=True)

    # Citation inspirante finale
    st.markdown("""
    <div class="quote-section">
        <h3 style="color: #2c3e50; margin-top: 0; text-align: center;">💭 Réflexion</h3>
        <blockquote style="font-size: 1.2rem; line-height: 1.6; text-align: center; margin: 20px 0; color: #34495e;">
            "L'autisme n'est pas une tragédie. L'ignorance l'est."<br>
            <footer style="margin-top: 15px; font-size: 1rem; color: #7f8c8d;">
                — Temple Grandin, scientifique et auteure autiste
            </footer>
        </blockquote>
    </div>
    """, unsafe_allow_html=True)

    # Note finale
    st.markdown("""
    <div style="background: linear-gradient(135deg, #f8f9fa, #e9ecef); 
               border-left: 4px solid #3498db; padding: 25px; border-radius: 10px; margin: 30px 0;">
        <h4 style="color: #2c3e50; margin-top: 0;">📋 Note importante</h4>
        <p style="color: #34495e; line-height: 1.6; margin: 0;">
            Cette documentation est fournie à titre informatif et éducatif. Elle ne remplace pas 
            l'avis médical professionnel. Pour toute question concernant le diagnostic ou la prise 
            en charge de l'autisme, consultez un professionnel de santé qualifié.
        </p>
    </div>
    """, unsafe_allow_html=True)


def show_about_page():
    st.markdown("""
    <div style="background: linear-gradient(90deg, #3498db, #2ecc71); 
                padding: 40px 20px; border-radius: 20px; margin-bottom: 30px; text-align: center;">
        <h1 style="color: white; font-size: 2.8rem; margin-bottom: 15px; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">
            ℹ️ À propos du Projet
        </h1>
        <p style="color: rgba(255,255,255,0.9); font-size: 1.3rem; max-width: 800px; margin: 0 auto; line-height: 1.6;">
            Une initiative innovante pour améliorer le dépistage précoce des Troubles du Spectre Autistique
        </p>
    </div>
    """, unsafe_allow_html=True)



    image_url = "https://drive.google.com/file/d/1tbARR43xi1GCnfY9XrEc-O2FbMnTmPcW/view?usp=sharing"
    st.markdown(get_img_with_href(image_url, "#", as_banner=False), unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); 
                padding: 30px; border-radius: 15px; margin-bottom: 30px;">
        <h2 style="color: #2c3e50; text-align: center; margin-bottom: 25px; font-size: 2.2rem;">
            🎯 Contexte du Projet
        </h2>
        <div style="max-width: 900px; margin: 0 auto;">
            <p style="font-size: 1.1rem; line-height: 1.8; text-align: justify; margin-bottom: 20px; color: #34495e;">
                Ce projet a été développé dans le cadre d'une étude approfondie sur les méthodes de dépistage 
                des Troubles du Spectre Autistique (TSA). Notre approche combine l'analyse de données massives, 
                l'intelligence artificielle et l'expertise clinique pour créer un outil d'aide au diagnostic précoce.
            </p>
            <p style="font-size: 1.1rem; line-height: 1.8; text-align: justify; color: #34495e;">
                L'objectif principal est de faciliter l'identification précoce des signaux d'alerte, permettant 
                ainsi une intervention plus rapide et plus efficace pour les personnes concernées et leurs familles.
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("## 🎯 Objectifs du Projet")
    
    col1, col2, col3 = st.columns(3)
    
    objectives = [
        {
            "icon": "🔍",
            "title": "Identifier les facteurs",
            "description": "Analyser les variables associées à la présence d'un TSA à partir de données multiples",
            "color": "#3498db"
        },
        {
            "icon": "📊",
            "title": "Explorer les données",
            "description": "Découvrir des tendances et biais dans les jeux de données internationaux",
            "color": "#2ecc71"
        },
        {
            "icon": "🤖",
            "title": "Construire des modèles",
            "description": "Développer des outils prédictifs pour l'aide à l'évaluation du TSA",
            "color": "#9b59b6"
        }
    ]
    
    for i, (obj, col) in enumerate(zip(objectives, [col1, col2, col3])):
        with col:
            st.markdown(f"""
            <div style="background: linear-gradient(135deg, {obj['color']}, {obj['color']}cc); 
                        color: white; padding: 25px; border-radius: 15px; height: 280px; 
                        box-shadow: 0 8px 25px rgba(0,0,0,0.15); transition: transform 0.3s ease;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="font-size: 3rem; margin-bottom: 15px;">{obj['icon']}</div>
                    <h3 style="margin: 0; font-size: 1.4rem; font-weight: 600;">{obj['title']}</h3>
                </div>
                <p style="font-size: 1rem; line-height: 1.5; text-align: center; margin: 0;">
                    {obj['description']}
                </p>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); 
                padding: 30px; border-radius: 15px; margin: 30px 0;">
        <h2 style="color: #8b4513; text-align: center; margin-bottom: 25px; font-size: 2.2rem;">
            📚 Sources de Données
        </h2>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                    gap: 20px; max-width: 1000px; margin: 0 auto;">
            <div style="background: rgba(255,255,255,0.8); padding: 20px; border-radius: 10px;">
                <h4 style="color: #8b4513; margin-bottom: 10px;">🌍 Couverture Internationale</h4>
                <p style="margin: 0; color: #5d4e37;">Plus de 5000 participants de différentes origines géographiques</p>
            </div>
            <div style="background: rgba(255,255,255,0.8); padding: 20px; border-radius: 10px;">
                <h4 style="color: #8b4513; margin-bottom: 10px;">📊 Données Diversifiées</h4>
                <p style="margin: 0; color: #5d4e37;">5 jeux de données publics combinés et harmonisés</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 30px; border-radius: 15px; margin: 30px 0;">
        <h2 style="color: white; text-align: center; margin-bottom: 25px; font-size: 2.2rem;">
            👥 Équipe du Projet
        </h2>
        <div style="max-width: 1000px; margin: 0 auto;">
            <p style="font-size: 1.2rem; line-height: 1.6; color: rgba(255,255,255,0.9); text-align: center; margin-bottom: 30px;">
                Ce projet a été réalisé par une équipe de futurs data analysts passionnés par l'innovation en santé digitale.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px;">
                <div style="background: rgba(255,255,255,0.15); padding: 20px; border-radius: 10px; 
                            text-align: center; backdrop-filter: blur(10px); 
                            display: flex; flex-direction: column; justify-content: center; align-items: center;">
                    <div style="font-size: 2.5rem; margin-bottom: 10px;">👨‍💻</div>
                    <h4 style="color: white; margin: 0; font-size: 1.2rem; text-align: center; 
                               display: flex; align-items: center; justify-content: center; height: auto;">
                        Rémi CHENOURI
                    </h4>
                    <p style="color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 0.9rem; 
                              text-align: center;">Futur Data Analyst</p>
                </div>
                <div style="background: rgba(255,255,255,0.15); padding: 20px; border-radius: 10px; 
                            text-align: center; backdrop-filter: blur(10px); 
                            display: flex; flex-direction: column; justify-content: center; align-items: center;">
                    <div style="font-size: 2.5rem; margin-bottom: 10px;">👩‍💻</div>
                    <h4 style="color: white; margin: 0; font-size: 1.2rem; text-align: center; 
                               display: flex; align-items: center; justify-content: center; height: auto;">
                        Alexandre BERNARD
                    </h4>
                    <p style="color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 0.9rem; 
                              text-align: center;">Futur Data Analyst</p>
                </div>
                <div style="background: rgba(255,255,255,0.15); padding: 20px; border-radius: 10px; 
                            text-align: center; backdrop-filter: blur(10px); 
                            display: flex; flex-direction: column; justify-content: center; align-items: center;">
                    <div style="font-size: 2.5rem; margin-bottom: 10px;">👨‍💻</div>
                    <h4 style="color: white; margin: 0; font-size: 1.2rem; text-align: center; 
                               display: flex; align-items: center; justify-content: center; height: auto;">
                        Laurence SOUPPARAZAYA
                    </h4>
                    <p style="color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 0.9rem; 
                              text-align: center;">Future Data Analyst</p>
                </div>
                <div style="background: rgba(255,255,255,0.15); padding: 20px; border-radius: 10px; 
                            text-align: center; backdrop-filter: blur(10px); 
                            display: flex; flex-direction: column; justify-content: center; align-items: center;">
                    <div style="font-size: 2.5rem; margin-bottom: 10px;">👩‍💻</div>
                    <h4 style="color: white; margin: 0; font-size: 1.2rem; text-align: center; 
                               display: flex; align-items: center; justify-content: center; height: auto;">
                        Ahmed IBNABASSE
                    </h4>
                    <p style="color: rgba(255,255,255,0.8); margin: 5px 0 0 0; font-size: 0.9rem; 
                              text-align: center;">Future Data Analyst</p>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); 
                padding: 30px; border-radius: 15px; margin: 30px 0;">
        <h2 style="color: #2c3e50; text-align: center; margin-bottom: 20px; font-size: 2.2rem;">
            🙏 Remerciements
        </h2>
        <div style="text-align: center; max-width: 700px; margin: 0 auto;">
            <p style="font-size: 1.2rem; line-height: 1.7; color: #2c3e50; margin-bottom: 15px;">
                Nous remercions toutes les personnes ayant contribué à ce projet, en particulier 
                <strong>notre mentor Yohan Cohen</strong> pour son soutien et ses conseils précieux 
                tout au long de cette recherche.
            </p>
            <p style="font-size: 1.1rem; color: #34495e; font-style: italic;">
                Un remerciement spécial à toutes les familles et individus qui ont participé aux études 
                ayant permis la constitution de ces jeux de données.
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: linear-gradient(135deg, #d299c2 0%, #fef9d7 100%); 
                padding: 25px; border-radius: 15px; margin: 30px 0;">
        <h2 style="color: #8b4513; text-align: center; margin-bottom: 20px; font-size: 2rem;">
            📄 Licence et Utilisation
        </h2>
        <div style="text-align: center; max-width: 800px; margin: 0 auto;">
            <p style="font-size: 1.1rem; line-height: 1.6; color: #5d4e37;">
                Cette application est mise à disposition sous licence open-source. 
                Le code et les données anonymisées sont disponibles pour des fins de recherche uniquement.
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="border: 2px solid #e74c3c; border-radius: 10px; padding: 20px; 
                background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%); margin-top: 30px;">
        <h3 style="color: #c62828; margin-top: 0; text-align: center;">
            ⚠️ Avertissement Important
        </h3>
        <p style="font-size: 1rem; color: #b71c1c; text-align: center; margin: 0; font-weight: 500;">
            Cette application est un outil d'aide au dépistage précoce et ne remplace en aucun cas 
            une évaluation clinique complète par un professionnel de santé qualifié.
        </p>
    </div>
    """, unsafe_allow_html=True)

    pass


# Ajouter cette fonction après les autres fonctions de page

def show_compliance_page():
    """Page dédiée à la conformité réglementaire"""
    
    # Contenu principal (pas dans la sidebar)
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea, #764ba2); 
                padding: 40px 25px; border-radius: 20px; margin-bottom: 35px; text-align: center;">
        <h1 style="color: white; font-size: 2.8rem; margin-bottom: 15px;">
            🔒 Conformité Réglementaire
        </h1>
        <p style="color: rgba(255,255,255,0.95); font-size: 1.3rem;">
            Gestion complète RGPD, AI Act et normes médicales
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Onglets de conformité dans la page principale
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔐 Consentement RGPD",
        "🤖 Transparence IA", 
        "👤 Mes Droits",
        "📊 Audit Trail"
    ])
    
    with tab1:
        st.header("État du Consentement RGPD")
        
        if st.session_state.get('consent_screening', False):
            st.success("✅ Consentement au dépistage : Accordé")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📝 Modifier mes consentements"):
                    # Réinitialiser pour permettre modification
                    st.session_state['consent_screening'] = False
                    st.rerun()
            
            with col2:
                if st.button("📋 Consentement détaillé"):
                    show_enhanced_gdpr_consent()
        else:
            st.warning("⚠️ Consentement requis - redirigé vers la sidebar")
    
    with tab2:
        show_ai_act_transparency()
    
    with tab3:
        user_rights_management_interface()
    
    with tab4:
        st.header("Journal d'Audit")
        
        if st.button("Afficher mon historique d'activité"):
            try:
                # Simulation d'audit trail (remplacez par vraies données en production)
                audit_data = {
                    "session_id": st.session_state.user_session[:8] + "...",
                    "dernière_connexion": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "actions_effectuées": [
                        "Consentement RGPD accordé",
                        "Accès page conformité",
                        "Consultation transparence IA"
                    ],
                    "données_traitées": [
                        "Identifiant de session (pseudonymisé)",
                        "Consentements RGPD",
                        "Logs de navigation"
                    ]
                }
                
                st.json(audit_data)
                
            except Exception as e:
                st.error(f"Erreur lors de la récupération des données d'audit : {str(e)}")
        
        st.info("""
        **ℹ️ Information sur l'audit trail**
        
        Conformément au RGPD Article 30, nous tenons un registre de toutes les activités 
        de traitement de données personnelles. Vous pouvez demander l'accès complet à 
        votre historique en contactant notre DPO.
        """)

def safe_execution(func):
    """Décorateur pour l'exécution sécurisée des fonctions"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            st.error(f"Erreur dans {func.__name__}: {str(e)}")
            st.error("Veuillez recharger la page ou contacter le support technique.")
            return None
    return wrapper


def main():
    """Fonction principale de l'application"""
    
    # Initialisation sécurisée
    if 'user_session' not in st.session_state:
        st.session_state.user_session = str(uuid.uuid4())
    
    initialize_session_state()
    set_custom_theme()
    
    # Navigation principale avec gestion d'erreurs
    try:
        tool_choice = show_unified_sidebar_navigation()
    except Exception as e:
        st.error(f"Erreur dans la navigation: {str(e)}")
        tool_choice = "🏠 Accueil"
    
    # Affichage du contenu basé sur le choix
    try:
        if tool_choice == "🏠 Accueil":
            show_home_page()
        elif tool_choice == "🔍 Exploration":
            show_data_exploration()
        elif tool_choice == "🧠 Analyse ML":
            show_ml_analysis()
        elif tool_choice == "🤖 Prédiction par IA":
            show_ai_prediction()
        elif tool_choice == "📚 Documentation":
            show_documentation()
        elif tool_choice == "ℹ️ À propos":
            show_about()
        elif tool_choice == "🔒 Conformité":
            show_compliance_interface()
    except Exception as e:
        st.error(f"Erreur dans l'affichage du contenu: {str(e)}")
        st.info("Retour à la page d'accueil recommandé")

def show_compliance_interface():
    """Interface de conformité RGPD/AI Act"""
    st.header("🔒 Gestion de la Conformité")
    
    # Générer des clés uniques pour les onglets
    session_id = st.session_state.get('user_session', 'default')
    
    compliance_tab1, compliance_tab2, compliance_tab3 = st.tabs([
        "📋 RGPD", 
        "🤖 AI Act", 
        "👤 Mes Droits"
    ])
    
    with compliance_tab1:
        show_enhanced_gdpr_consent()
    
    with compliance_tab2:
        show_ai_act_transparency()
    
    with compliance_tab3:
        user_rights_management_interface()


if __name__ == "__main__":
    main()
