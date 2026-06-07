#!/bin/bash
# Instala dependências e sobe o servidor
pip install -r requirements.txt --break-system-packages -q
echo ""
echo "======================================"
echo "  RTSP Expose — Demo IFAC"
echo "  Acesse: http://localhost:8000"
echo "======================================"
echo ""
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
