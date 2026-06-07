# RTSP-Scanner-Pro 🛡️

**A high-performance RTSP audit engine and interactive visualization dashboard.**

---

## 🛑 ADVERTÊNCIA BRUTAL: LEIA OU ASSUMA AS CONSEQUÊNCIAS

**ESTE SOFTWARE É PARA FINS EXCLUSIVAMENTE EDUCACIONAIS E DE AUDITORIA DE SEGURANÇA AUTORIZADA.**

O acesso não autorizado a sistemas de vigilância, câmeras privadas ou redes de terceiros **É UM CRIME GRAVE** em quase todas as jurisdições do planeta. 

1. **INVASÃO DE DISPOSITIVO INFORMÁTICO:** Você pode ser processado criminalmente por acessar dispositivos sem autorização expressa.
2. **VIOLAÇÃO DE PRIVACIDADE:** Capturar imagens de áreas privadas sem consentimento pode resultar em penas de prisão e multas astronômicas.
3. **MONITORAMENTO PELAS AUTORIDADES:** Lembre-se, suas atividades deixam rastros. O uso deste software para atividades ilícitas colocará você diretamente no radar de unidades de crimes cibernéticos.

**VOCÊ É O ÚNICO RESPONSÁVEL POR SUAS AÇÕES.** Se você usar esta ferramenta para fins maliciosos, não espere piedade da justiça. O desenvolvedor não se responsabiliza por danos, processos ou prisões decorrentes do uso indevido deste código.

---

## 🚀 Visão Geral

O **RTSP-Scanner-Pro** é uma ferramenta avançada projetada para identificar e visualizar vulnerabilidades em feeds RTSP. Ele utiliza um motor de alta performance (Quantum-Jump) para escanear grandes faixas de IPs, identificar credenciais fracas e gerar um dashboard em tempo real com capturas de tela e geolocalização.

### Funcionalidades Principais
- **Motor Quantum-Jump:** Escaneamento paralelo massivo com baixo consumo de recursos.
- **Dicionário de Credenciais:** Teste automatizado de usuários e senhas padrões de diversos fabricantes.
- **Dashboard Interativo:** Interface moderna baseada em FastAPI para visualização de resultados.
- **Captura Inteligente:** Extração automática de frames de streams ativos.
- **Geolocalização:** Mapeamento de IPs para identificar a origem física dos dispositivos.

## 🛠️ Instalação

### Pré-requisitos
- Python 3.9+
- FFmpeg (necessário para captura de frames)

### Passo a Passo

1.  **Clone o repositório:**
    ```bash
    git clone https://github.com/seu-usuario/RTSP-Scanner-Pro.git
    cd RTSP-Scanner-Pro
    ```

2.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```

## ⚡ Como Usar

### Iniciando o Dashboard e o Scanner
Para iniciar a interface web e o motor de auditoria, utilize o script de execução:

```bash
chmod +x run.sh
./run.sh
```

Acesse o dashboard em: `http://localhost:8000`

### Configuração de Alvos
Os alvos de scan podem ser configurados no arquivo `targets.txt` (conforme definido no `scanner_engine.py`).

## 👨‍💻 Créditos

Desenvolvido e mantido por: **Willian Albarello**

---

## ⚖️ Licença

Este projeto é distribuído apenas para fins de pesquisa. Consulte as leis locais antes de qualquer execução.
