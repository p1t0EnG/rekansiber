# rasecurity
This project helping my team for creating security dashboard that easy to use

# RA Security - Modular App

Structure:
- app/ (FastAPI app)
  - ioc_service (IoC aggregator)
  - ransom_info (Ransom info placeholders)

## Run locally
1. Create virtualenv
   python -m venv .venv
   source .venv/bin/activate

2. Install
   pip install -r requirements.txt

3. Provide env vars (copy .env)
   ABUSEIPDB_KEY=...
   VT_KEY=...
   OTX_KEY=...
   MXTOOLBOX_KEY=...

4. Run
   uvicorn app.main:app --reload

Open http://localhost:8000/docs for Swagger UI.

