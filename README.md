# 🦈 TShark Challenge I: Teamwork — SOC Case Study

Languages: **[EN] [PT] [DE]**

This repository documents a **TryHackMe-derived guided training case study** using **TShark (CLI)**, focused on phishing-related network analysis, IOC handling, and threat-intelligence correlation.

The repository does not retain the supplied PCAP, TShark command output, raw packet excerpts, or dated threat-intelligence lookup required to independently verify the reported training findings.

Executive summary: [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md)

---

## Training Completion Record

Training completion was reported in the earlier repository narrative, but the referenced completion screenshot is not retained in this repository.

Official TryHackMe room link:  
https://tryhackme.com/room/tsharkchallengesone

---

## [EN] Case Study — Phishing Detection via Network Traffic Analysis

**Platform:** TryHackMe  
**Room:** TShark Challenge I – Teamwork  
**Difficulty:** Easy  
**Tools:** TShark, VirusTotal  

### Objective
The guided TryHackMe exercise involved analysis of a supplied PCAP file (`teamwork.pcap`) to investigate phishing-related network traffic and extract indicators for defensive analysis.

### Methodology
- Establish traffic baseline using TCP conversation statistics
- Inspect HTTP traffic for suspicious domains
- Review look-alike-domain indicators within the supplied training scenario
- Review HTTP POST payloads for credential-submission indicators
- Correlate reported indicators with VirusTotal within the training exercise
- Normalize and defang IOCs

### Reported Training Findings
- The exercise narrative reported a look-alike domain impersonating **PayPal**.
- It reported HTTP POST activity interpreted as credential submission.
- It reported the domain as malicious based on threat-intelligence correlation.

These are **training-derived reported findings**. This repository does not retain the PCAP, command transcript, raw output, or dated threat-intelligence lookup required to verify them independently.

### Reported Training IOCs
The earlier README listed defanged indicators from the exercise. Because their packet/output provenance is not retained here—and challenge answers should not be republished—those values are not presented as independently verified IOCs in this repository.

### Conclusion
The guided TryHackMe exercise documented a phishing-related scenario and credential-submission analysis. This repository supports the training narrative and methodology only; it does not independently confirm a phishing incident or credential compromise.

Security scope and safe reporting expectations are documented in
[SECURITY.md](SECURITY.md).

---

## [PT] Estudo de Caso — Detecção de Phishing via Análise de Tráfego

**Plataforma:** TryHackMe  
**Sala:** TShark Challenge I – Teamwork  
**Ferramentas:** TShark, VirusTotal  

### Objetivo
O exercício guiado do TryHackMe envolveu a análise de um arquivo PCAP fornecido (`teamwork.pcap`) para investigar tráfego relacionado a phishing e extrair indicadores para análise defensiva.

### Metodologia
- Criação de baseline das conversas TCP
- Inspeção de tráfego HTTP
- Revisão de indicadores de domínio look-alike no cenário de treinamento fornecido
- Revisão de payloads HTTP POST em busca de indicadores de envio de credenciais
- Correlação dos indicadores relatados com VirusTotal no contexto do exercício
- Normalização e defang de IOCs

### Conclusão
O exercício guiado do TryHackMe descreveu um cenário relacionado a phishing e análise de possível envio de credenciais. Este repositório sustenta apenas a narrativa de treinamento e a metodologia; não confirma de forma independente um incidente de phishing nem comprometimento de credenciais.

---

## [DE] Fallstudie — Phishing-Erkennung durch Netzwerkverkehrsanalyse

**Plattform:** TryHackMe  
**Raum:** TShark Challenge I – Teamwork  
**Werkzeuge:** TShark, VirusTotal  

### Ziel
Die geführte TryHackMe-Übung umfasste die Analyse einer bereitgestellten PCAP-Datei (`teamwork.pcap`), um phishingbezogenen Netzwerkverkehr zu untersuchen und Indikatoren für defensive Analysen zu erfassen.

### Vorgehen
- Baseline-Analyse der TCP-Konversationen
- Untersuchung des HTTP-Verkehrs
- Prüfung von Look-alike-Domain-Indikatoren im bereitgestellten Trainingsszenario
- Prüfung von HTTP-POST-Payloads auf Hinweise auf eine Übermittlung von Zugangsdaten
- Abgleich der im Training berichteten Indikatoren mit VirusTotal
- Normalisierung und Defanging der IOCs

### Fazit
Die geführte TryHackMe-Übung behandelte ein phishingbezogenes Szenario und die Analyse einer möglichen Übermittlung von Zugangsdaten. Dieses Repository dokumentiert nur die Trainingsnarrative und Methodik; es bestätigt weder einen Phishing-Vorfall noch einen Credential Compromise unabhängig.

---

**Author:** André  
**Status:** Guided training case study; completion previously reported, retained completion proof not present
