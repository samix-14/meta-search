# Meta Search

Analizzatore locale di metadati per Windows. Versione corrente: **0.2**.

## Funzioni incluse
- Rilevamento euristico di firme binarie, MIME, estensione e dimensione.
- Hash SHA-256, SHA-1 e MD5.
- Entropia, byte nulli e valori di byte distinti.
- Estrazione di stringhe ASCII e anteprima HEX.
- Dimensioni e metadati EXIF delle immagini supportate, con riepilogo leggibile.
- Estrazione delle coordinate GPS EXIF e collegamento a Google Maps, quando la foto le contiene.
- Riepilogo rapido di posizione, data dello scatto e fotocamera, quando disponibili.
- Numero pagine, cifratura e metadati standard PDF.
- Ricerca nei metadati ed esportazione JSON.

## Requisiti
Python 3.10 o successivo.

## Avvio su Windows
Apri PowerShell nella cartella del progetto:

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python app.py

Apri poi http://127.0.0.1:5000. Per chiudere il server, premi Ctrl+C nel terminale.

Se PowerShell blocca l'attivazione, puoi eseguire direttamente:

    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
    .\.venv\Scripts\python.exe app.py

## Privacy e limiti
Il server ascolta solo su 127.0.0.1. Il file viene scritto temporaneamente durante l'analisi e poi eliminato; il rapporto resta nel browser finché la pagina è aperta, salvo esportazione. Nessun file viene inviato a servizi esterni. Limite per file: 100 MB.

Le firme sono euristiche e i metadati possono essere falsificati o incompleti. SHA-1 e MD5 sono inclusi per confronto, non come garanzia crittografica moderna. I font dell'interfaccia possono essere richiesti a Google Fonts quando Internet è disponibile; l'analisi resta locale. Per uso completamente offline, rimuovi la riga @import da style.css.

## Struttura
- app.py — server locale e motore di analisi.
- index.html — struttura dell'interfaccia.
- style.css — tema e layout.
- script.js — interazioni, ricerca, laboratorio ed esportazione.
- requirements.txt — dipendenze Python.

## Roadmap
La 0.2 analizza singoli file e rende più leggibili i dati principali. Versioni future potranno aggiungere analisi più profonde per formati specifici, esportazione CSV/HTML, confronto file e scansione cartelle.
