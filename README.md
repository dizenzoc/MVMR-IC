# MVMR-IC

MVMR-IC è un'applicazione mobile avanzata sviluppata per dispositivi iOS, progettata per semplificare il lavoro dei penetration tester. L'app si integra con il server MVMR per l'aggregazione e l'analisi automatica dei report di vulnerabilità informatica. MVMR-IC utilizza strumenti di sicurezza come NMAP, OWASP ZAP, Nessus e OpenVAS e si avvale di tecnologie moderne per offrire un'interfaccia intuitiva e una gestione efficiente dei dati.

## Funzionalità principali
- Integrazione con il server MVMR per l'analisi dei report di vulnerabilità.
- Aggregazione dei dati da strumenti di sicurezza come NMAP, OWASP ZAP, Nessus e OpenVAS.
- Arricchimento dei dati con informazioni supplementari attraverso il Web Scraping.
- Classificazione automatica delle vulnerabilità tramite un algoritmo Naive Bayes.

## Tecnologie utilizzate
- **Ionic Framework** per lo sviluppo dell'interfaccia utente multipiattaforma.
- **Capacitor** per l'integrazione delle funzionalità native e l'esportazione in formato iOS.
- **Angular** per la gestione dinamica dei dati e la struttura dell'applicazione.
- **TypeScript** come linguaggio principale per migliorare la qualità e manutenibilità del codice.
- **HTML5/CSS3** per la progettazione dell'interfaccia utente.
- **REST API** per la comunicazione con il server.
- **JSON** per lo scambio dati tra il client e il server.

## Requisiti
- Node.js >= 14.x
- Ionic CLI >= 6.x
- Capacitor >= 3.x
- Xcode (per lo sviluppo iOS)
- Git

***********************************
## INSTALLAZIONE
***********************************

1. **Clona il repository**:
   ```bash
   git clone https://github.com/username/mvmr-ic.git
   cd mvmr-ic

2. Installa le dipendenze:
    npm install

3. Configura Capacitor per iOS (facoltativo, per sviluppo iOS):
    npx cap add ios

***********************************
## COMANDI PER AVVIARE IL PROGETTO
***********************************

--------------------------
Avviare il server MVMR
--------------------------

1. Accedi alla cartella del server:
    cd MVMR_server

2. Avvia il server:
    node index.js

--------------------------
Avviare il client iOS
--------------------------

1. Accedi alla cartella del client:
    cd MVMR_ionic_client

2. Esegui build per iOS:
    npx cap sync

3. Apri il progetto in Xcode:
    cd ios/App
    open App.xcworkspace

--------------------------
Avviare il client browser
--------------------------

1. Accedi alla cartella del client:
    cd MVMR_ionic_client

2. Aprire l'app nel browser predefinito:
    ionic serve

***********************************
## AGGIORNAMENTO DEL PROGETTO
***********************************

1. Aggiorna le dipendenze:
    npm install

2. Sincronizzare le modifiche con iOS (se sviluppi per iOS):
    npx cap sync ios


