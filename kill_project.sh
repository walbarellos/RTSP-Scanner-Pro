#!/bin/bash
# Script para finalizar apenas os processos relacionados a este projeto RTSP Audit

echo "[*] Iniciando extermínio de processos do projeto..."

# 1. Finaliza uvicorn rodando server:app
pkill -9 -f "uvicorn server:app"

# 2. Finaliza qualquer python rodando dentro do venv deste projeto
pkill -9 -f "/home/walbarellos/rtsp_audit/.venv/bin/python"

# 3. Finaliza nmap e ffprobe que podem ter ficado órfãos
pkill -9 -f "ffprobe.*rtsp"
pkill -9 -f "nmap.*554"

# 4. Finaliza o script de inicialização
pkill -9 -f "run.sh"

echo "[+] Todos os processos relacionados foram finalizados."
