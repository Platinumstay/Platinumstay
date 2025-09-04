
# PlatinumStay (PWA-enabled)

- Super admin (seeded): **petsbuzz@gmail.com / admin123**
- Mobile-ready + installable (PWA).

## Run locally
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000/login

### Install as an app (local)
- Chrome (desktop): Address bar → Install icon (or Menu → Install).
- Android: Chrome → Menu → **Install app**.
- iPhone: Safari → **Share** → **Add to Home Screen**.

## Deploy (Git)
Laptop:
```bash
git add -A
git commit -m "PWA + icons + admin/tenant fixes"
git push origin main
```
VPS:
```bash
ssh root@<YOUR_VPS_IP>
cd /var/www/platinumstay
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
systemctl restart gunicorn
nginx -t && systemctl reload nginx
```

## Nginx snippets (ensure correct paths)
```
location /static/ {
    alias /var/www/platinumstay/static/;
    add_header Cache-Control "public, max-age=31536000, immutable";
}
location = /static/sw.js {
    alias /var/www/platinumstay/static/sw.js;
    add_header Cache-Control "no-cache";
    default_type application/javascript;
}
location = /static/manifest.json {
    alias /var/www/platinumstay/static/manifest.json;
    add_header Cache-Control "no-cache";
    default_type application/manifest+json;
}
```

## Updating PWA
- When you change `sw.js`, bump `CACHE` version (e.g., `platinumstay-v2`) so clients get fresh assets.
