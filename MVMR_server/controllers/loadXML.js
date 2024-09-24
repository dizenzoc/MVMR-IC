/**
 * 
 * loadXML (o Multer): modulo principale per la fase 1/3
 * 
 * Fusione dei reports (NMAP, OWASP ZAP, Nessus e OpenVAS): durante questa prima fase, come suggerito in \figurename~\ref{fig:interaction-module-1}, dopo che l'utente ha completato l'attività di Vulnerability Mapping nel normale processo di penetration testing, si suppone che abbia a sua disposizione una serie di reports in XML che, a seconda degli strumenti utilizzati, potrebbero restituire più o meno informazioni circa il livello di sicurezza dell'asset sotto esame. A questo punto, l'utente sfrutta il modulo "USER INTERFACE" per caricare i vari reports XML e inviarli al server MVMR che si occuperà della loro analisi. Il server innanzitutto andrà a memorizzare i diversi file XML in maniera persistente sfruttando il modulo "MULTER". Purtroppo, data l'eterogeneità dei file XML è necessario un successivo step di normalizzazione dei dati poiché di base in ogni file XML ci sono una serie di keywords univoche che ci consentono di recuperare informazioni quali host, servizio, porta, exploit, severity, mitigazioni, ecc... 
 * A tal proposito, il modulo "NORMALIZER" ci consente di costruire, a partire dai file XML eterogenei, dei file JSON standardizzati in modo da ottenere per ogni tools degli oggetti aventi una stessa struttura. In questo modo, indipendentemente dal tool utilizzato per estrarre le informazioni, possiamo accedere ad un particolare dato tramite una keyword che rappresenta una proprietà standard.
 * Una volta che sono stati ottenuti i reports JSON normalizzati, vengono utilizzate delle strutture dati come le mappe (o Map) per innestare gli oggetti in modo da raggruppare le diverse vulnerabilità sulla base degli host (es: 192.168.81.131) e, per ogni host, le diverse vulnerabilità vengono raggruppate in base alle porte/servizi (es: 21/ftp, 22/ssh, 80/http, ecc...). Quest'attività viene portata a termine dal modulo di "REFACTORING".
 * Ottenuti questi nuovi tipi di oggetti, utilizziamo il "MERGER" per effettuare un join delle vulnerabilità contenute in ciascun report, proprio sulla base dell'host e del servizio/porta utilizzato. Al termine del processo di fusione, otterremo un singolo report contenente le informazioni estrapolate dai diversi tool (NMAP, OWASP ZAP, Nessus e/o OpenVAS).
 * A questo punto, tramite il modulo "DICT" viene costruito un dizionario contenente tutte le descrizioni di tutte le vulnerabilità presenti nel report ottenuto dall'operazione di fusione e tramite l'"OPTIMIZER" vengono rimossi i duplicati che su ogni coppia (host + porta/servizio) godono della stessa descrizione. Il risultato così ottenuto sarà l'output di questa prima fase e verrà inviato al client con il nome di "x\_summary".
 * 
 */


const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const refactoring = require('./refactoring')
const dict = require('./dict')
const normalizer = require('./normalizer')
const optimizer = require('./optimizer')
const merger = require('./merger')
const global = require('../utils/global');


var hosts = []

var flag_nmap = false;
var flag_nessus = false;
var flag_openvas = false;
var flag_owaspzap = false;

/**
 * Riceve i file XMLs caricati dall'utente per iniziare la loro elaborazione
 * @param {*} req xmls
 * @param {*} res 
 * @param {*} next 
 */
 exports.loadXMLFiles = async (req, res, next) => {

    //Fa tutto il middleware (/middleware/uploadXML.js)

    nmap_summary = {}
    nessus_summary = {}
    openvas_summary = {}
    owaspzap_summary = {}

    merged_summary = {}  //FILE RISULTANTE DAL MERGE DELLE VULNERABILITA' CATTURATE DAI VARI TOOL
    short_summary = {}

    refer_retrieval = {} //webscraping result


    //console.log('loadXMLFiles - req.body', req.body)

    flag_nmap = req.body.flag_nmap == 'true' ? true : false
    flag_nessus = req.body.flag_nessus == 'true' ? true : false
    flag_openvas = req.body.flag_openvas == 'true' ? true : false
    flag_owaspzap = req.body.flag_owaspzap == 'true' ? true : false

    console.log('flag_nmap', flag_nmap)
    console.log('flag_nessus', flag_nessus)
    console.log('flag_openvas', flag_openvas)
    console.log('flag_owaspzap', flag_owaspzap)

    var xmls = [] //array che contiene la lista dei files da caricare

    if(flag_nmap){  //se è stato caricato un XML relativo ad nmap
        //console.log('req.files.nmap.filename', req.files.nmap[0].filename)
        let obj = {
            tool : 'nmap',
            name : req.files.nmap[0].filename
        }
        xmls.push(obj)
    }
    if(flag_nessus){  //se è stato caricato un XML relativo ad nessus
        //console.log('req.files.nessus.filename', req.files.nessus[0].filename)
        let obj = {
            tool : 'nessus',
            name : req.files.nessus[0].filename
        }
        xmls.push(obj)
    }
    if(flag_openvas){  //se è stato caricato un XML relativo ad openvas
        //console.log('req.files.openvas.filename', req.files.openvas[0].filename)
        let obj = {
            tool : 'openvas',
            name : req.files.openvas[0].filename
        }
        xmls.push(obj)
    }
    if(flag_owaspzap){  //se è stato caricato un XML relativo ad owaspzap
        //console.log('req.files.owaspzap.filename', req.files.owaspzap[0].filename)
        let obj = {
            tool : 'owaspzap',
            name : req.files.owaspzap[0].filename
        }
        xmls.push(obj)
    }

    normalizer.XML2JSON(xmls);  //converte i file XML in JSON

    //let summaries_for_dict = [] //inserisce nell'array i documenti caricati dall'utente (è il parametro che sarà poi passato alla funzione buildDescDictionary)

    if(flag_nmap){  //se è stato caricato un XML relativo a nmap
        //console.log('req.files.nmap.filename', req.files.nmap[0].filename)
        nmap_summary = normalizer.getNmapSummary(req.files.nmap[0].filename.replace(".xml",".json"))
        //console.log('NMAP_SUMMARY', nmap_summary)
    }
    if(flag_nessus){  //se è stato caricato un XML relativo a nessus
        //console.log('req.files.nmap.filename', req.files.nmap[0].filename)
        nessus_summary = normalizer.getNessusSummary(req.files.nessus[0].filename.replace(".xml",".json"))
        //console.log('NESSUS_SUMMARY', nessus_summary)
    }
    if(flag_openvas){  //se è stato caricato un XML relativo a openvas
        //console.log('req.files.nmap.filename', req.files.nmap[0].filename)
        openvas_summary = normalizer.getOpenVasSummary(req.files.openvas[0].filename.replace(".xml",".json"))
        //console.log('OPENVAS_SUMMARY', openvas_summary)
    }
    if(flag_owaspzap){  //se è stato caricato un XML relativo a owaspzap
        //console.log('req.files.nmap.filename', req.files.nmap[0].filename)
        owaspzap_summary = normalizer.getOwaspZapSummary(req.files.owaspzap[0].filename.replace(".xml",".json"))
        //console.log('OWASPZAP_SUMMARY', owaspzap_summary)
    }

    /*Ordine preferenza per il merge:
    * NMAP > OTHER TOOLS
    * se non c'è NMAP...
    * OWASPZAP > OTHER TOOLS (NESSUS + OPENVAS)
    * se non ci sono nè NMAP nè OWASPZAP...
    * OPENVAS > NESSUS
    * se non ci sono nè NMAP nè OWASPZAP né OPENVAS
    * NESSUS
    * */

    let other_summary = []

    if(flag_nmap){ //Se è stato caricato un XML di Nmap (main file) sul quale costruire il merge
        if(flag_owaspzap)
            other_summary.push(owaspzap_summary)
        if(flag_openvas)
            other_summary.push(openvas_summary)
        if(flag_nessus)
            other_summary.push(nessus_summary)
            merged_summary = merger.getMergedSummary(nmap_summary, other_summary)
    }else{ //se non c'è il file XML di NMAP..
        if(flag_owaspzap){ //ed è stato caricato un file XML di OwaspZAP
            if(flag_openvas)
                other_summary.push(openvas_summary)
            if(flag_nessus)
                other_summary.push(nessus_summary)
            merged_summary = merger.getMergedSummary(owaspzap_summary, other_summary)
        }else{  //se non c'è il file XML di OWASPZAP (e di conseguenza quello di NMAP)...
            if(flag_openvas){  //ed è stato caricato un file XML di OpenVas
                if(flag_nessus){
                    other_summary.push(nessus_summary)
                    merged_summary = merger.getMergedSummary(openvas_summary, other_summary)
                }else{  //se openvas è l'unico file caricato..restituisce quello come merged summary
                    openvas_summary.summary.vulnerabilities = refactoring.getMapAddress_Service(openvas_summary) //refactoring dell'array vulnerabilities: viene trasformato in un Map in cui per ogni key address ha un map (port/service -> vulnerabilities)
                    openvas_summary.summary.vulnerabilities = refactoring.Map2JSON(openvas_summary) //conversione dei MAP in JSON
                    merged_summary = openvas_summary
                    merged_summary = normalizer.setVulnID(merged_summary)
                    //console.log('merged only openvas', merged_summary)
                }
            }else{ //se c'è solo il file di Nessus...restituisce quello come merged_summary
                nessus_summary.summary.vulnerabilities = refactoring.getMapAddress_Service(nessus_summary) //refactoring dell'array vulnerabilities: viene trasformato in un Map in cui per ogni key address ha un map (port/service -> vulnerabilities)
                nessus_summary.summary.vulnerabilities = refactoring.Map2JSON(nessus_summary) //conversione dei MAP in JSON
                merged_summary = nessus_summary
                merged_summary = normalizer.setVulnID(merged_summary)
                //console.log('merged only nessus', merged_summary)
            }
        }
    }

    //console.log('merged_summary', merged_summary)

    fs.writeFileSync('./public/merged_summary/merged-scan-'+global.id_scan, JSON.stringify(merged_summary.summary), { flag: "w" }) 

    /*Itera finché il file MERGED non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto"
    while(!fs.existsSync('./public/merged_summary/merged-scan-'+global.id_scan)){
        console.log('il file di merge non esiste', './public/merged_summary/merged-scan-'+global.id_scan)
    }*/

    var description_dict = new Set(dict.buildDescDictionary(merged_summary.summary)) //costruisce un dizionario con le descrizioni relative alle diverse vulnerabilità

    //short_summary = merged_summary in cui vengono complementati i risultati delle vulnerabilità individuate dai vari strumenti sulla base di HOST + SERVICE + DESCRIPTION
    var short_summary = optimizer.removeDuplicatesByDescriptions(description_dict, merged_summary.summary)

    //summary contenente tre strati di nidificazione: HOST -> PORT -> TYPE -> vulnerabilità
    var x_summary = refactoring.groupsByType(short_summary)    

    //var ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192';

    

    res.status(201).json({
        'name' : 'Merged Summary',
        'merged_summary' : merged_summary,
        'short_summary' : short_summary,
        'x_summary' : x_summary,
        'x_summary_filename' : 'x_summary_'+global.id_scan+'.json' //utile nella chiamata per il webScraping per recuperare il file dato che è troppo grande e non può essere passato tramite request
    })
 }


/*
 * Riceve i file XMLs caricati dall'utente per iniziare la loro elaborazione
 * @param {*} req xmls
 * @param {*} res 
 * @param {*} next 
 *
 exports.testScraping = async (req, res, next) => {

    console.log('method() => testScraping')

    webScraping(req, res, next)

 }*/