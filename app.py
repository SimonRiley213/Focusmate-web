# app.py
import streamlit as st
from datetime import datetime, timedelta
import time
import json
import os
import secrets

# ---------- Config ----------
DEFAULT_WORK_MIN = 25
DEFAULT_BREAK_MIN = 5
WARNING_BEFORE_LOCK_SEC = 8  # seconds before break after work finishes
SESSIONS_FILE = "sessions.json"
PASSWORD_FILE = "password_store.json"  # store PBKDF2-like salt/hash (simple secure-storage simulation)

# ---------- Content ----------
EXERCISES = [
    "Blink your eyes slowly 10 times.",
    "Rub your palms together and place them over your eyes.",
    "Rotate your shoulders forward and backward 10 times.",
    "Roll your wrists slowly.",
    "Take 5 deep breaths — in through the nose, out through the mouth.",
    "Look up, down, left, and right — stretch your eyes.",
    "Massage your forehead gently.",
    "Sit straight — align your back and relax your shoulders."
]

QUOTES = [
    "Your health is more important than the screen.",
    "Take care of your eyes — they serve you for life.",
    "A short break improves long-term focus.",
    "Relax now, focus better later.",
    "Good posture, good productivity."
]

# ---------- Utilities ----------
def load_sessions():
    if not os.path.exists(SESSIONS_FILE):
        return []
    try:
        with open(SESSIONS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_session(record):
    s = load_sessions()
    s.append(record)
    try:
        with open(SESSIONS_FILE, "w") as f:
            json.dump(s, f, indent=2, default=str)
    except Exception as e:
        st.error(f"Failed to write session file: {e}")

def create_password_store_if_missing():
    """Initialize a password store if it doesn't exist (very basic)."""
    if not os.path.exists(PASSWORD_FILE):
        # create with empty value
        with open(PASSWORD_FILE, "w") as f:
            json.dump({"password_hash": None, "salt": None}, f)

def set_password(password: str):
    # We will store a simple salted hash using secrets.token_hex + builtin hashing (sha256).
    import hashlib
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    with open(PASSWORD_FILE, "w") as f:
        json.dump({"password_hash": h, "salt": salt}, f)

def verify_password(password: str):
    import hashlib
    if not os.path.exists(PASSWORD_FILE):
        return False
    try:
        with open(PASSWORD_FILE, "r") as f:
            stored = json.load(f)
        if not stored.get("password_hash") or not stored.get("salt"):
            return False
        calc = hashlib.sha256((stored["salt"] + password).encode()).hexdigest()
        return secrets.compare_digest(calc, stored["password_hash"])
    except Exception:
        return False

# ---------- Streamlit UI ----------
st.set_page_config(page_title="FocusMate Web", layout="centered")

create_password_store_if_missing()

st.title("🎯 FocusMate — Web Version")

# Sidebar settings & session controls
with st.sidebar:
    st.header("Settings")
    work_min = st.number_input("Work duration (minutes)", min_value=1, max_value=240, value=DEFAULT_WORK_MIN)
    break_min = st.number_input("Break duration (minutes)", min_value=1, max_value=240, value=DEFAULT_BREAK_MIN)
    warning_sec = st.number_input("Warning seconds before break", min_value=1, max_value=60, value=WARNING_BEFORE_LOCK_SEC)
    st.markdown("---")
    st.write("Password for aborting breaks:")
    pw_action = st.radio("Password action", options=["Check / Change", "Set (if none)"], index=0)
    if pw_action == "Set (if none)":
        p1 = st.text_input("New Password", type="password")
        p2 = st.text_input("Confirm Password", type="password")
        if st.button("Save password"):
            if not p1 or len(p1) < 4:
                st.warning("Choose a stronger password (min 4 chars for demo).")
            elif p1 != p2:
                st.error("Passwords do not match.")
            else:
                set_password(p1)
                st.success("Password saved.")
    else:
        # Check / Change
        check_pw = st.text_input("Enter current password to verify", type="password")
        if st.button("Verify"):
            if verify_password(check_pw):
                st.success("Password is correct.")
            else:
                st.error("Incorrect password or none set.")
        st.markdown("To change the password, clear and set a new one in 'Set (if none)'.")

st.markdown("---")

# App main area
col1, col2 = st.columns([2,1])

with col1:
    st.subheader("Start a focus session")
    start = st.button("🚀 Start Focus Session")
    stop = st.button("⏹️ Stop/Abort Session (safe abort)")

    # Display current status saved in session_state
    if "status" not in st.session_state:
        st.session_state.status = "idle"  # idle, working, warning, break
        st.session_state.work_ends_at = None
        st.session_state.break_ends_at = None
        st.session_state.session_start = None
        st.session_state.warning_ends_at = None
        st.session_state.abort_requested = False
        st.session_state.break_locked = False  # whether break overlay is mandatory

    # Start flow
    if start and st.session_state.status in ("idle", "completed", "aborted"):
        st.session_state.session_start = datetime.now().isoformat()
        st.session_state.status = "working"
        st.session_state.work_ends_at = (datetime.now() + timedelta(minutes=int(work_min))).isoformat()
        st.session_state.warning_ends_at = None
        st.session_state.break_ends_at = None
        st.session_state.abort_requested = False
        st.session_state.break_locked = False
        st.rerun()

    if stop:
        # Safe abort from user (not password-protected)
        if st.session_state.status in ("working", "warning", "break"):
            now = datetime.now()
            save_session({
                "type": "aborted",
                "start_time": st.session_state.session_start,
                "end_time": now.isoformat(),
                "duration": (now - datetime.fromisoformat(st.session_state.session_start)).total_seconds()
            })
            st.session_state.status = "aborted"
            st.success("Session aborted and logged.")
            st.rerun()

    # Main status display logic
    def seconds_left(target_iso):
        return max(0, int((datetime.fromisoformat(target_iso) - datetime.now()).total_seconds()))

    if st.session_state.status == "idle":
        st.info("Ready. Set durations in the sidebar and press Start.")

    elif st.session_state.status == "working":
        # Calculate remaining
        left = seconds_left(st.session_state.work_ends_at)
        mins = left // 60
        secs = left % 60
        st.markdown(f"### Work time remaining: **{mins:02d}:{secs:02d}**")
        # Provide progress
        started = datetime.fromisoformat(st.session_state.session_start)
        total = int(work_min)*60
        elapsed = total - left
        st.progress(min(1.0, elapsed/total))
        # Check for end -> transition to warning
        if left <= int(warning_sec):
            # begin warning, show countdown
            st.session_state.status = "warning"
            st.session_state.warning_ends_at = (datetime.now() + timedelta(seconds=int(warning_sec))).isoformat()
            st.rerun()

        # lightweight tick
        st.rerun()

    elif st.session_state.status == "warning":
        left = seconds_left(st.session_state.warning_ends_at)
        st.warning(f"⚠️ Break incoming in: **{left:02d}s** — save your work.")
        if left <= 0:
            # transition to break
            st.session_state.status = "break"
            st.session_state.break_ends_at = (datetime.now() + timedelta(minutes=int(break_min))).isoformat()
            st.session_state.break_locked = True
            st.rerun()
        st.rerun()

    elif st.session_state.status == "break":
        left = seconds_left(st.session_state.break_ends_at)
        mins = left // 60
        secs = left % 60
        st.markdown(f"## 🛑 Mandatory Break — time remaining: **{mins:02d}:{secs:02d}**")
        # Exercise & quote rotation
        # rotate index by seconds elapsed
        total_break_seconds = int(break_min) * 60
        elapsed = total_break_seconds - left
        exercise_index = (elapsed // max(1, total_break_seconds//len(EXERCISES)+1)) % len(EXERCISES)
        quote_index = (elapsed // 5) % len(QUOTES)
        st.write("**Exercise:**", EXERCISES[int(exercise_index)])
        st.write("**Note:**", QUOTES[int(quote_index)])

        # Show abort option but require password
        st.markdown("---")
        st.write("To abort the break early, enter the password and press 'Abort Break (verify)'.")
        pw_attempt = st.text_input("Password to abort (keeps break mandatory otherwise)", type="password", key="pw_abort")
        if st.button("Abort Break (verify)"):
            if verify_password(pw_attempt):
                # abort break
                now = datetime.now()
                save_session({
                    "type": "aborted",
                    "start_time": st.session_state.session_start,
                    "end_time": now.isoformat(),
                    "duration": (now - datetime.fromisoformat(st.session_state.session_start)).total_seconds()
                })
                st.session_state.status = "aborted"
                st.session_state.break_locked = False
                st.success("Break aborted and session logged.")
                st.rerun()
            else:
                st.error("Incorrect password. Break continues.")
        # When break ends normally:
        if left <= 0:
            now = datetime.now()
            save_session({
                "type": "completed",
                "start_time": st.session_state.session_start,
                "end_time": now.isoformat(),
                "work_duration_min": int(work_min),
                "break_duration_min": int(break_min),
                "duration": (now - datetime.fromisoformat(st.session_state.session_start)).total_seconds()
            })
            st.session_state.status = "completed"
            st.session_state.break_locked = False
            st.success("Break finished. Logged completed session.")
            st.rerun()

        # Use JS to speak the current exercise/quote (small TTS)
        if "tts_toggle" not in st.session_state:
            st.session_state.tts_toggle = False
        if st.button("🔊 Speak current exercise/quote"):
            # Inject JS TTS using st.components.v1
            text_to_speak = f"{EXERCISES[int(exercise_index)]}. {QUOTES[int(quote_index)]}"
            js = f"""
            var u = new SpeechSynthesisUtterance({json.dumps(text_to_speak)});
            window.speechSynthesis.cancel();
            window.speechSynthesis.speak(u);
            """
            st.components.v1.html(f"<script>{js}</script>", height=0)

        # Prevent user navigation away - not strictly enforceable in browser (we can warn)
        st.info("This break is intended to be enforced. To stop break early, use the Abort Break (verify) button with correct password.")

# Right column: summary / admin view
with col2:
    st.subheader("Session Summary")
    sessions = load_sessions()
    st.write(f"Total sessions logged: {len(sessions)}")
    if sessions:
        last = sessions[-10:][::-1]  # show last 10
        for s in last:
            st.write(s)
    if st.button("Clear sessions (danger)"):
        try:
            with open(SESSIONS_FILE, "w") as f:
                json.dump([], f)
            st.success("Sessions cleared.")
        except Exception as e:
            st.error(f"Failed to clear: {e}")

st.markdown("---")
st.caption("Note: This web demo keeps session logs in a local JSON file. Deploying publicly will store sessions on the server filesystem of the host — consider a DB for multi-user public deployments.")

# Keep minimal heartbeat to update UI automatically when running locally
# Streamlit automatically reruns when widgets change; we trigger small sleep to avoid CPU spin.
time.sleep(0.1)
