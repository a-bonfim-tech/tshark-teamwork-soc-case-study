# 🦈 TShark Challenge I: Teamwork — SOC Case Study

Languages: **[EN] [PT] [DE]**

This repository documents a SOC-style network forensics investigation using **TShark (CLI)**, focusing on phishing detection, IOC extraction, and threat intelligence correlation.

---

## Proof of Completion

![TShark Challenge I: Teamwork — Completed](img/tshark-challenge-I-teamwork-completed.png)

Official TryHackMe room link:  
https://tryhackme.com/room/tsharkchallengesone

---

## [EN] Case Study — Phishing Detection via Network Traffic Analysis

**Platform:** TryHackMe  
**Room:** TShark Challenge I – Teamwork  
**Difficulty:** Easy  
**Tools:** TShark, VirusTotal  

### Objective
Analyze a provided PCAP file (`teamwork.pcap`) to identify malicious activity and extract actionable indicators for detection tooling.

### Methodology
- Establish traffic baseline using TCP conversation statistics
- Inspect HTTP traffic for suspicious domains
- Identify look-alike phishing domain impersonating PayPal
- Decode HTTP POST payloads to confirm credential submission
- Correlate findings with VirusTotal
- Normalize and defang IOCs

### Key Findings
- Look-alike phishing domain impersonating **PayPal**
- Credentials submitted via HTTP POST
- Domain confirmed as malicious via threat intelligence

### Indicators of Compromise (IOCs)

| Type | Value (Defanged) |
|----|----|
| URL | hxxp://www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/ |
| IP | 184[.]154[.]127[.]226 |
| Impersonated Service | PayPal |
| Email | johnny5alive[at]gmail[.]com |

### Conclusion
The investigation confirms a phishing incident with likely credential compromise, following a realistic Tier 1 / Tier 2 SOC workflow using command-line network analysis.

---

## [PT] Estudo de Caso — Detecção de Phishing via Análise de Tráfego

**Plataforma:** TryHackMe  
**Sala:** TShark Challenge I – Teamwork  
**Ferramentas:** TShark, VirusTotal  

### Objetivo
Analisar um arquivo PCAP (`teamwork.pcap`) para identificar atividade maliciosa e extrair IOCs utilizáveis.

### Metodologia
- Criação de baseline das conversas TCP
- Inspeção de tráfego HTTP
- Identificação de domínio look-alike se passando pelo PayPal
- Decodificação de payloads HTTP POST
- Correlação com VirusTotal
- Normalização e defang de IOCs

### Conclusão
O caso confirma um ataque de phishing com provável comprometimento de credenciais, documentado em um fluxo SOC realista.

---

## [DE] Fallstudie — Phishing-Erkennung durch Netzwerkverkehrsanalyse

**Plattform:** TryHackMe  
**Raum:** TShark Challenge I – Teamwork  
**Werkzeuge:** TShark, VirusTotal  

### Ziel
Analyse einer PCAP-Datei (`teamwork.pcap`) zur Identifikation bösartiger Aktivitäten und Extraktion verwertbarer IOCs.

### Vorgehen
- Baseline-Analyse der TCP-Konversationen
- Untersuchung des HTTP-Verkehrs
- Identifikation einer PayPal-imitierenden Phishing-Domain
- Dekodierung von HTTP-POST-Payloads
- Abgleich mit VirusTotal
- Normalisierung und Defanging der IOCs

### Fazit
Die Analyse bestätigt einen Phishing-Vorfall mit wahrscheinlichem Credential Compromise, durchgeführt nach einem realistischen SOC-Workflow.

---

**Author:** André  
**Status:** ✅ Completed (100%)
