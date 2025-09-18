# import streamlit as st

# def rerun():
#     """Safe rerun wrapper (handles Streamlit API changes)."""
#     if hasattr(st, "rerun"):
#         st.rerun()
#     elif hasattr(st, "experimental_rerun"):
#         st.experimental_rerun()
#     else:
#         raise RuntimeError("rerun not supported in this Streamlit version")
import streamlit as st
import logging

logger = logging.getLogger("compat")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)

def rerun():
    """Safe rerun wrapper (handles Streamlit API changes and failures)."""
    version = st.__version__
    major = int(version.split(".")[0])
    minor = int(version.split(".")[1]) if "." in version else 0
    if major < 1:
        st.warning("Upgrade Streamlit to 1.0 or higher for rerun support")
        return  # Don't raise, just skip rerun

    if minor >= 27:
        try:
            st.rerun()
            return
        except Exception as e:
            logger.error(f"st.rerun failed: {e}")
    if hasattr(st, "experimental_rerun"):
        try:
            st.experimental_rerun()
            return
        except Exception as e:
            logger.error(f"experimental_rerun failed: {e}")
    logger.warning("No rerun method available; refresh manually")
    st.info("Manual refresh needed - rerun not supported.")