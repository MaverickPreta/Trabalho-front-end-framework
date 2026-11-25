# Scanner VirusTotal (Flutter web + Flask)

## 1. Backend
```bash
cd backend
python -m venv venv
# Windows: venv\Scripts\activate   |   Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # edite e coloque sua VT_API_KEY
python app.py            # sobe em http://127.0.0.1:5000
```
Teste: http://127.0.0.1:5000/api/health

## 2. Frontend
```bash
flutter create --platforms=web frontend_app
cd frontend_app
flutter pub add http file_picker
# substitua lib/main.dart pelo arquivo frontend/lib/main.dart
flutter run -d chrome
```

## Como funciona
- `/api/downloads`: lista arquivos recentes da pasta Downloads (do PC onde o Flask roda).
- `/api/scan/download`: calcula o SHA-256 e consulta o VirusTotal; se ele não conhece o arquivo, faz upload.
- `/api/scan/upload`: o mesmo, para arquivo escolhido no navegador.
- `/api/analysis/<id>`: o Flutter consulta de 6 em 6 s até a análise terminar.

Obs.: a chave gratuita do VT permite ~4 consultas/min e 500/dia.
