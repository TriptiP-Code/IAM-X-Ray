import streamlit as st

def rerun():
    """Safe rerun wrapper (handles Streamlit API changes)."""
    if hasattr(st, "rerun"):
        st.rerun()
    elif hasattr(st, "experimental_rerun"):
        st.experimental_rerun()
    else:
        raise RuntimeError("rerun not supported in this Streamlit version")
