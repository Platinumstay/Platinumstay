Full Rental Tracker with tenant complaints & tenant payment editing.

Run locally:
1. python -m venv .venv
2. Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
3. pip install -r requirements.txt
4. python app.py
5. Open http://127.0.0.1:5000

Seeded accounts:
- landlord@example.com / password123
- tenant1@example.com / tenant123

Notes:
- Landlord can add/edit/delete tenants, add/edit/delete payments, and manage complaints.
- Tenants can log complaints and add/edit their own payments.
