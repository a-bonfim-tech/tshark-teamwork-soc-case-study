# 🦈 TShark Challenge I: Teamwork — SOC Case Study

[EN] | [PT] | [DE

https://tryhackme.com/room/tsharkchallengesone?utm_campaign=social_share&utm_medium=social&utm_content=room&utm_source=copy&sharerId=684227f46df691972a111bb0

---

## [EN] Case Study — Phishing Detection via Network Traffic Analysis

**Platform:** TryHackMe
**Room:** TShark Challenge I – Teamwork
**Difficulty:** Easy
**Time:** ~60 minutes
**Tools:** TShark, VirusTotal
**Skills:** Network Analysis, Phishing Detection, IOC Extraction, Threat Intelligence

### Context

A threat research alert identified a suspicious domain potentially targeting the organization.
The task was to analyze a provided PCAP file and extract actionable artefacts for detection tooling.

### Methodology

* File system enumeration to locate the capture file
* Baseline analysis of TCP conversations
* HTTP traffic inspection
* Identification of a look-alike phishing domain impersonating PayPal
* Payload decoding of HTTP POST data
* Correlation with VirusTotal threat intelligence

### Findings

* Malicious look-alike domain using keyword stuffing
* User credentials submitted via HTTP POST
* Domain confirmed as malicious on VirusTotal

### Indicators of Compromise (IOCs)

| Type                 | Value (Defanged)                                                             |
| -------------------- | ---------------------------------------------------------------------------- |
| URL                  | hxxp://www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/ |
| IP                   | 184[.]154[.]127[.]226                                                        |
| Impersonated Service | PayPal                                                                       |
| Email                | johnny5alive[at]gmail[.]com                                                  |

### Conclusion

The analysis confirms a phishing attack resulting in credential compromise.
This case demonstrates a realistic Tier 1 / Tier 2 SOC workflow using command-line tooling and evidence-driven conclusions.

---

## [PT] Estudo de Caso — Detecção de Phishing via Análise de Tráfego

**Plataforma:** TryHackMe
**Sala:** TShark Challenge I – Teamwork
**Ferramentas:** TShark, VirusTotal

### Contexto

Um alerta do time de threat research indicou um domínio suspeito que poderia representar risco à organização.
O objetivo foi analisar um arquivo PCAP e extrair artefatos utilizáveis em ferramentas de detecção.

### Metodologia

* Enumeração inicial do sistema de arquivos
* Análise de baseline das conversas TCP
* Inspeção de tráfego HTTP
* Identificação de domínio look-alike se passando pelo PayPal
* Decodificação de dados enviados via HTTP POST
* Correlação com inteligência de ameaças (VirusTotal)

### Resultados

* Domínio malicioso com técnica de phishing
* Envio de credenciais em texto claro
* Confirmação do domínio como malicioso

### Indicadores de Comprometimento (IOCs)

| Tipo            | Valor (Defanged)                                                             |
| --------------- | ---------------------------------------------------------------------------- |
| URL             | hxxp://www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/ |
| IP              | 184[.]154[.]127[.]226                                                        |
| Serviço Imitado | PayPal                                                                       |
| Email           | johnny5alive[at]gmail[.]com                                                  |

### Conclusão

O caso confirma um ataque de phishing com possível comprometimento de credenciais, seguindo um fluxo típico de análise SOC real.

---

## [DE] Fallstudie — Phishing-Erkennung durch Netzwerkverkehrsanalyse

**Plattform:** TryHackMe
**Raum:** TShark Challenge I – Teamwork
**Werkzeuge:** TShark, VirusTotal

### Kontext

Ein Alarm des Threat-Research-Teams identifizierte eine verdächtige Domain mit potenziellem Risiko für die Organisation.
Ziel war die Analyse einer PCAP-Datei und die Extraktion verwertbarer Artefakte.

### Vorgehensweise

* Initiale Dateisystem-Enumeration
* Baseline-Analyse von TCP-Konversationen
* Untersuchung des HTTP-Verkehrs
* Identifikation einer PayPal-imitierenden Phishing-Domain
* Dekodierung von HTTP-POST-Nutzdaten
* Abgleich mit Threat-Intelligence (VirusTotal)

### Ergebnisse

* Look-alike-Phishing-Domain
* Übertragung von Zugangsdaten
* Bestätigung als bösartige Domain

### Indicators of Compromise (IOCs)

| Typ               | Wert (Defanged)                                                              |
| ----------------- | ---------------------------------------------------------------------------- |
| URL               | hxxp://www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/ |
| IP                | 184[.]154[.]127[.]226                                                        |
| Imitierter Dienst | PayPal                                                                       |
| E-Mail            | johnny5alive[at]gmail[.]com                                                  |

### Fazit

Diese Analyse zeigt einen realistischen SOC-Workflow zur Erkennung und Dokumentation eines Phishing-Angriffs mittels Netzwerkforensik.

---

**Author:** André
**Track:** Cybersecurity / SOC / Cloud Security
**Status:** Completed (100%)
