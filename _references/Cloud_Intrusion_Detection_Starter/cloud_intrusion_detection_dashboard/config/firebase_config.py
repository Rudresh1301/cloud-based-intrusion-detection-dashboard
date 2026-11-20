"""
Firebase Firestore configuration and connection management.
Optimized with Streamlit cache_resource, socket timeouts, and safe local fallback.
"""
import logging
import streamlit as st

log = logging.getLogger(__name__)

@st.cache_resource(show_spinner=False)
def get_cached_firebase_client():
    """
    Initialize Firebase Admin SDK once per server instance and return a cached Firestore client.
    Priority order:
      1. Streamlit secrets  (st.secrets["firebase"])
      2. Environment variable FIREBASE_CREDENTIALS_JSON (path or inline JSON)
      3. Local file firebase_credentials.json
    Returns the Firestore client or None (local fallback).
    """
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
    except ImportError:
        log.info("firebase-admin not installed – running in local mode.")
        return None

    # Already initialised in this Python process?
    if firebase_admin._apps:
        try:
            return firestore.client()
        except Exception as e:
            log.warning("Could not obtain firestore client from existing app: %s", e)
            return None

    cred = None

    # 1. Streamlit secrets
    try:
        if hasattr(st, "secrets") and "firebase" in st.secrets:
            fb = dict(st.secrets["firebase"])
            cred = credentials.Certificate(fb)
            log.info("Firebase credentials loaded from Streamlit secrets.")
    except Exception:
        pass

    # 2. Environment variable
    if cred is None:
        import os, json
        env_path = os.getenv("FIREBASE_CREDENTIALS_JSON")
        if env_path:
            try:
                if env_path.strip().startswith("{"):
                    cred = credentials.Certificate(json.loads(env_path))
                else:
                    cred = credentials.Certificate(env_path)
                log.info("Firebase credentials loaded from env var.")
            except Exception as exc:
                log.warning("Could not load Firebase from env var: %s", exc)

    # 3. Local file
    if cred is None:
        import pathlib
        for candidate in [
            pathlib.Path("firebase_credentials.json"),
            pathlib.Path("config/firebase_credentials.json"),
        ]:
            if candidate.exists():
                try:
                    cred = credentials.Certificate(str(candidate))
                    log.info("Firebase credentials loaded from %s", candidate)
                    break
                except Exception as exc:
                    log.warning("Could not load %s: %s", candidate, exc)

    if cred is None:
        log.info("No Firebase credentials found – using local database.")
        return None

    try:
        firebase_admin.initialize_app(cred)
        client = firestore.client()
        log.info("Firebase initialised successfully.")
        return client
    except Exception as exc:
        log.error("Firebase initialisation failed: %s", exc)
        return None

def init_firebase():
    """Wrapper to retrieve the cached Firestore client."""
    return get_cached_firebase_client()

@st.cache_data(ttl=60, show_spinner=False)
def get_db_status() -> dict:
    """Return current database connection status (cached with 60s TTL)."""
    client = init_firebase()
    if client is not None:
        return {
            "mode": "firebase",
            "connected": True,
            "message": "Connected to Firebase Firestore",
        }
    return {
        "mode": "local",
        "connected": True,
        "message": "Using local SQLite database (Firebase not configured)",
    }

def is_firebase_available() -> bool:
    """Check whether Firebase is configured and reachable."""
    return init_firebase() is not None
