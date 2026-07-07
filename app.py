import streamlit as st
from checker import check_url_safety

st.set_page_config(page_title="URL Safety Checker", page_icon="🔗")

st.title("🔗 URL/Link Safety Checker")
st.write("Paste any link to check if it looks suspicious or safe.")

url = st.text_input("Enter a URL")

if url:
    rating, score, warnings = check_url_safety(url)

    if rating == "Safe":
        st.success(f"Rating: {rating} (Risk Score: {score})")
    elif rating == "Low Risk":
        st.info(f"Rating: {rating} (Risk Score: {score})")
    elif rating == "Suspicious":
        st.warning(f"Rating: {rating} (Risk Score: {score})")
    else:
        st.error(f"Rating: {rating} (Risk Score: {score})")

    if warnings:
        st.subheader("Details:")
        for w in warnings:
            st.write(f"- {w}")