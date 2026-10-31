# ExposureLens

Passive external exposure checker (domains + subdomains, A-F grade, bulk, Ask AI). App #5 of the suite.

## Run in VS Code
1. Copy your `bg.jpeg` into this folder (same one as the other apps).
2. Terminal: `python -m venv .venv` then `.venv\Scripts\activate` (Windows) or `source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. `streamlit run app.py`

## Optional AI keys
Create `.streamlit/secrets.toml` (already git-ignored):
```
GEMINI_API_KEY = "your-key"
GROQ_API_KEY = "your-key"
```
Or paste your own key in the sidebar. ChatGPT and Claude are own-key only.

## Deploy (Streamlit Cloud)
Push the folder to GitHub (include bg.jpeg), deploy app.py, add secrets under Settings > Secrets.

## Notes
- Passive only: public DNS, crt.sh, one TLS handshake and one HTTPS request per host. No port scanning.
- Limits: `DOMAINS_MAX` and `SUBS_MAX` at the top of app.py.
- Only assess domains you own or are authorised to assess.
