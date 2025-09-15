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

def rerun():
    """Safe rerun wrapper (handles Streamlit API changes)."""
    # Check Streamlit version and enforce >= 1.27
    version = float(st.__version__.split(".")[0])
    if version < 1.27:
        raise RuntimeError("Upgrade Streamlit to version 1.27 or higher")
    
    # Use latest st.rerun() for Streamlit >= 1.27
    st.rerun()