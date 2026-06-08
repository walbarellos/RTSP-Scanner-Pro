# RTSP-Scanner-Pro 🛡️ v8.8 (Modular)

**A high-performance, modular RTSP audit engine with GPU acceleration and global target interleaving.**

---

## 🛑 ADVERTÊNCIA BRUTAL: LEIA OU ASSUMA AS CONSEQUÊNCIAS

**ESTE SOFTWARE É PARA FINS EXCLUSIVAMENTE EDUCACIONAIS E DE AUDITORIA DE SEGURANÇA AUTORIZADA.**

O acesso não autorizado a sistemas de vigilância, câmeras privadas ou redes de terceiros **É UM CRIME GRAVE**. O desenvolvedor não se responsabiliza por suas ações.

---

## 🚀 Novidades da Versão 8.8 (Quantum-Jump Modular)

O sistema foi totalmente refatorado para uma arquitetura de micro-módulos, garantindo estabilidade e performance extrema em hardwares modestos (i3/i5).

### 🏗️ Arquitetura Modular (`engine/`)
- **`harvester.py`**: Coletor inteligente de redes. Agora com **Global Interleave**, misturando alvos de todos os continentes (Europa, Ásia, Américas) desde o primeiro segundo.
- **`orchestrator.py`**: O cérebro do sistema. Gerencia o fluxo de varredura com **Eco-Mode** (limite de 10-30 workers) e prioridade absoluta para comandos **JUMP**.
- **`probe.py`**: Especialista em protocolos. Realiza handshakes RTSP, descoberta SDP e brute-force de credenciais padrão.
- **`archiver.py`**: Central de inteligência. Gerencia o banco de dados SQLite, eventos SSE e sincronização automática de favoritos.

## 🚀 Funcionalidades de Elite

- **Eco-Mode & Homeostase:** Proteção contra travamentos do PC. Configurado para baixo consumo de CPU e memória.
- **True Global Shuffle:** Fim do monopólio regional. Varre o mundo inteiro de forma intercalada (França, Japão, Brasil, etc. aparecem misturados).
- **Expansion Mode (WebRTC):** Integração com `go2rtc` para visualização de ultra-baixa latência usando a **GPU (CUDA/NVDEC)** para decodificação.
- **Mission Wall:** Um dashboard focado apenas nos seus favoritos (★), otimizado para monitoramento de alvos confirmados.
- **Favorites Sync:** Todos os favoritos são salvos automaticamente em `favorites.txt` na raiz para fácil acesso.

## 🛠️ Instalação e Setup

### Pré-requisitos
- Python 3.9+
- FFmpeg
- GPU NVIDIA (Opcional, para aceleração CUDA no Expansion Mode)

### Passo a Passo

1.  **Prepare o Ambiente:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Aumente os Limites do Sistema (Linux):**
    O script `run.sh` já aplica `ulimit -n 65536` para evitar erros de "Too many open files".

3.  **Inicie o Sistema:**
    ```bash
    ./run.sh
    ```
    Acesse: `http://localhost:8000`

### ⚡ Ativando o Modo Expansão (WebRTC)

Para visualizar seus favoritos com aceleração de GPU e sem os limites do navegador:

1.  **Gere a configuração:**
    ```bash
    python3 generate_rtc_config.py
    ```
2.  **Inicie o Proxy go2rtc:**
    Baixe o binário do [go2rtc](https://github.com/AlexxIT/go2rtc) e execute-o na pasta raiz:
    ```bash
    ./go2rtc
    ```
3.  No dashboard, clique em **🚀 WEBRTC EXPANSION MODE**.

## 👨‍💻 Créditos

Desenvolvido e mantido por: **Willian Albarello**

---

## ⚖️ Licença
Distribuído apenas para fins de pesquisa.
