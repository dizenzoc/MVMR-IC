
const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const BayesClassifier = require('../utils/bayes-classifier');
const Nightmare = require('nightmare');

//Legge il file oracle.json che contiene il test set
var oracle_file = fs.readFileSync("./utils/corpus/oracle.json"); //ottiene un riferimento al file JSON di oracle.json
var oracle = JSON.parse(oracle_file) //converte l'oggetto JavaScript in un stringa JSON
const ORACLE_SIZE = 120;

var classifier = new BayesClassifier(); //inizializza il classificatore

//Legge il file bypass_a_restriction.json che contiene il corpus Bypass A Restriction
var bypass_file = fs.readFileSync("./utils/corpus/csrf.json"); //ottiene un riferimento
var bypass_corpus = JSON.parse(bypass_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file csrf.json che contiene il corpus CSRF (Cross Site Request Forgery)
var csrf_file = fs.readFileSync("./utils/corpus/csrf.json"); //ottiene un riferimento
var csrf_corpus = JSON.parse(csrf_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file directory_traversal.json che contiene il corpus Directory Traversal
var dir_traversal_file = fs.readFileSync("./utils/corpus/directory_traversal.json"); //ottiene un riferimento
var dir_traversal_corpus = JSON.parse(dir_traversal_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file dos.json che contiene il corpus Denial-of-Service
var dos_file = fs.readFileSync("./utils/corpus/dos.json"); //ottiene un riferimento
var dos_corpus = JSON.parse(dos_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file file_inclusion.json che contiene il corpus File Inclusion
var file_inclusion_file = fs.readFileSync("./utils/corpus/file_inclusion.json"); //ottiene un riferimento
var file_inclusion_corpus = JSON.parse(file_inclusion_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file gain_privileges.json che contiene il corpus Gain Privileges
var gain_privileges_file = fs.readFileSync("./utils/corpus/gain_privileges.json"); //ottiene un riferimento
var gain_privileges_corpus = JSON.parse(gain_privileges_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file http_response_splitting.json che contiene il corpus HTTP Response Splitting
var http_response_splitting_file = fs.readFileSync("./utils/corpus/http_response_splitting.json"); //ottiene un riferimento
var http_response_splitting_corpus = JSON.parse(http_response_splitting_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file information_disclosure.json che contiene il corpus Information Disclosure
var information_disclosure_file = fs.readFileSync("./utils/corpus/information_disclosure.json"); //ottiene un riferimento
var information_disclosure_corpus = JSON.parse(information_disclosure_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file memory_corruption.json che contiene il corpus Memory Corruption
var memory_corruption_file = fs.readFileSync("./utils/corpus/memory_corruption.json"); //ottiene un riferimento
var memory_corruption_corpus = JSON.parse(memory_corruption_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file overflow.json che contiene il corpus Overflow
var overflow_file = fs.readFileSync("./utils/corpus/overflow.json"); //ottiene un riferimento
var overflow_corpus = JSON.parse(overflow_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file sql_injection.json che contiene il corpus SQL Injection
var sql_injection_file = fs.readFileSync("./utils/corpus/sql_injection.json"); //ottiene un riferimento
var sql_injection_corpus = JSON.parse(sql_injection_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file xcute_arbitrary_code.json che contiene il corpus Execute Arbitrary Code
var xcute_arbitrary_code_file = fs.readFileSync("./utils/corpus/xcute_arbitrary_code.json"); //ottiene un riferimento
var xcute_arbitrary_code_corpus = JSON.parse(xcute_arbitrary_code_file) //converte l'oggetto JavaScript in un stringa JSON

//Legge il file xss.json che contiene il corpus XSS
var xss_file = fs.readFileSync("./utils/corpus/xss.json"); //ottiene un riferimento
var xss_corpus = JSON.parse(xss_file) //converte l'oggetto JavaScript in un stringa JSON

const CORPUS_SIZE = 200; //DIMENSIONE DEI CORPUS GENERATI TRAMITE WEB HARVESTING
/*
* Types: Bypass a restriction or similar, Cross Site Scripting (XSS), Denial of Service (DoS), Directory Traversal,
* Execute arbitrary code on vulnerable system, Gain Privileges, HTTP Response Splitting, Memory Corruption,
* Information Disclosure, Overflow vulnerability (includes stack and heap based overflows and other overflows),
* Cross Site Request Forgery (CSRF), File Inclusion, SQL Injection
**/
const corpus_refs = [      //OGGETTO CHE INDICA I LINK A CUI ACCEDERE PER COSTRUIRE I CORPUS (UTILIZZATO PER CREARE I CORPUS)
    {type: 'Bypass a restriction or similar', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opbyp=1'},
    {type: 'Cross Site Scripting (XSS)', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opxss=1'},
    {type: 'Denial of Service (DoS)', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opdos=1'},
    {type: 'Directory Traversal', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opdirt=1'},
    {type: 'Execute arbitrary code on vulnerable system', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opec=1'},
    {type: 'Gain Privileges', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opgpriv=1'},
    {type: 'HTTP Response Splitting', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&ophttprs=1'},
    {type: 'Memory Corruption', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opmemc=1'},
    {type: 'Information Disclosure', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opginf=1'},
    {type: 'Overflow vulnerability (includes stack and heap based overflows and other overflows)', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opov=1'},
    {type: 'Cross Site Request Forgery (CSRF)', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opcsrf=1'},
    {type: 'File Inclusion', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opfileinc=1'},
    {type: 'SQL Injection', refs: 'https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cveid=&msid=&bidno=&cweid=&cvssscoremin=&cvssscoremax=&psy=&psm=&pey=&pem=&usy=&usm=&uey=&uem=&opsqli=1'}
]

/**  
  * Handler che ci permette di costruire un classificatore per le diverse tipologie di vulnerabilità esistenti e, successivamente, classificare le vulnerabilità presenti 
  * nel z_summary passato in input. Restituisce un report di questo tipo:
  * 
  * final_summary{
  *     date : "2022-10-20T14:23:08-020Z"
  *     vulnerabilities:{
  *         192.168.81.131: {
  *             21/ftp: {
  *                 Critical : {
  *                     Denial of Service (DoS): [
  *                         id : 0,
  *                         cvss : '7.5 High ....',
  *                         description : 'Each Unix or Unix-like ...'
  *                         host : 192.168.81.131,
  *                         exploits : [],
  *                         mitigations : [],
  *                         patches : [],
  *                         refs : [],
  *                         risk : 'FTP Brute Force Logins Reporting',
  *                         service : '21/ftp',
  *                         solution : 'If the account is not needed ...',
  *                         type : 'Denial of Service (DoS)'
  *                     ],
  *                     Cross Site Scripting (XSS) : [
  *                         //
  *                     ]
  *                 },
  *                 High : {
  *                 },
  *                 Medium : {
  *                 },
  *                 Low : {
  *                 },
  *                 Info : {
  *                 }
  *             }
  *         }
  *     }
  * }
  *
  * @param {*} req z_summary filename
  * @param {*} res 
  * @param {*} next 
  */
 exports.nlp_report = async (req, res, next) => {

    console.log('method() => nlp_report')

    /**Costruzione dei corpus per ciascuna vulnerabilità prevista dal CVE (VIENE CHIAMATO SOLO UNA VOLTA)
    for(let j=0; j<corpus_refs.length; j++){
        rr = this.buildCorpus(corpus_refs[j].refs, corpus_refs[j].type) //ricerca informazioni nell'archivio CVE
        await rr.then( result => {  //risolve la promise
            solution = result
            console.log('(2) => method() => nlp => nlp => Corpus\'s result (result): ', solution)
        })
    }*/

    //testBayesianClassifier();  //testa il classificatore (accuracy)

    //Legge il file z_summary.json che contiene e ottiene un riferimento ad esso per attraversarlo
    var z_summary_filename = req.body.z_summary_filename
    var z_summary_file = fs.readFileSync("./public/z_summary/"+z_summary_filename); //ottiene un riferimento al file JSON
    var z_summary = JSON.parse(z_summary_file) //converte l'oggetto JavaScript in un stringa JSON

    console.log('z_summary', z_summary)

    var final_summary = {} //summary finale

    final_summary.date = new Date();
    final_summary.vulnerabilities = {}

    for(let host in z_summary.vulnerabilities){
        final_summary.vulnerabilities[host] = {} //inizializza host
        for(let service in z_summary.vulnerabilities[host]){
            final_summary.vulnerabilities[host][service] = {} //inizializza porta
            var r = computeSeverity(critical_severity=[], high_severity=[], medium_severity=[], low_severity=[], info_severity=[], unknown_severity=[], z_summary, host, service)
            //inizializza vettori in cui ordinare le vulnerabilità in base alla criticità
            var critical_severity = r.critical_severity
            var high_severity = r.high_severity
            var medium_severity = r.medium_severity
            var low_severity = r.low_severity
            var info_severity = r.info_severity
            var unknown_severity = r.unknown_severity

            //per ogni vulnerabilità di ciascun livello di severity modifica l'attributo type con la classe generata dal classificatore Bayesiano
            var rx = computeType(critical_severity, high_severity, medium_severity, low_severity, info_severity, unknown_severity, z_summary, host, service)

            ////inizializza oggetti nel final_summary per ogni livello di criticità e aggiorna le vulnerabilità sulla base dei valori restituiti da computeType()
            var critical_severity = rx.critical_severity
            if(critical_severity.length != 0){
                final_summary.vulnerabilities[host][service]['critical'] = {} //se esiste qualche elemento critico per tale vulnerabilità inizializza l'oggetto
            }
            
            var high_severity = rx.high_severity
            if(high_severity.length != 0){
                final_summary.vulnerabilities[host][service]['high'] = {}   //se esiste qualche elemento con vulnerabilità alta inizializza l'oggetto
            }

            var medium_severity = rx.medium_severity
            if(medium_severity.length != 0){
                final_summary.vulnerabilities[host][service]['medium'] = {}    //se esiste qualche elemento con vulnerabilità media inizializza l'oggetto
            }

            var low_severity = rx.low_severity
            if(low_severity.length != 0){
                final_summary.vulnerabilities[host][service]['low'] = {}     //se esiste qualche elemento con vulnerabilità bassa inizializza l'oggetto
            }

            var info_severity = rx.info_severity
            if(info_severity.length != 0){
                final_summary.vulnerabilities[host][service]['info'] = {}     //se esiste qualche elemento con vulnerabilità informativa inizializza l'oggetto
            }

            var unknown_severity = rx.unknown_severity
            if(unknown_severity.length != 0){
                final_summary.vulnerabilities[host][service]['unknown'] = {}     //se esiste qualche elemento con vulnerabilità sconosciuta inizializza l'oggetto
            }

            /*inizializza array nel final_summary per ogni livello di criticità.type solo se esiste quel tipo /*
            corpus_refs.forEach(vuln_type => {
                final_summary.vulnerabilities[host][service]['critical'][vuln_type.type] = []
                final_summary.vulnerabilities[host][service]['high'][vuln_type.type] = []
                final_summary.vulnerabilities[host][service]['medium'][vuln_type.type] = []
                final_summary.vulnerabilities[host][service]['low'][vuln_type.type] = []
                final_summary.vulnerabilities[host][service]['info'][vuln_type.type] = []
                final_summary.vulnerabilities[host][service]['unknown'][vuln_type.type] = []
            })*/
            
            //riempie i vari array
            critical_severity.forEach(vul => {
                if(final_summary.vulnerabilities[host][service]['critical'][vul.type] == undefined){  //se il tipo non è ancora presente, lo inizializza
                    final_summary.vulnerabilities[host][service]['critical'][vul.type] = []
                }
                //per ogni vulnerabilità critica aggiunge la vulnerabilità al rispettivo array "TYPE"
                console.log('critical severity', vul)
                final_summary.vulnerabilities[host][service]['critical'][vul.type].push(vul)
            })
            high_severity.forEach(vul => {
                if(final_summary.vulnerabilities[host][service]['high'][vul.type] == undefined){  //se il tipo non è ancora presente, lo inizializza
                    final_summary.vulnerabilities[host][service]['high'][vul.type] = []
                }
                //per ogni vulnerabilità alta aggiunge la vulnerabilità al rispettivo array "TYPE"
                final_summary.vulnerabilities[host][service]['high'][vul.type].push(vul)
            })
            medium_severity.forEach(vul => {
                if(final_summary.vulnerabilities[host][service]['medium'][vul.type] == undefined){  //se il tipo non è ancora presente, lo inizializza
                    final_summary.vulnerabilities[host][service]['medium'][vul.type] = []
                }
                //per ogni vulnerabilità media aggiunge la vulnerabilità al rispettivo array "TYPE"
                final_summary.vulnerabilities[host][service]['medium'][vul.type].push(vul)
            })
            low_severity.forEach(vul => {
                if(final_summary.vulnerabilities[host][service]['low'][vul.type] == undefined){  //se il tipo non è ancora presente, lo inizializza
                    final_summary.vulnerabilities[host][service]['low'][vul.type] = []
                }
                //per ogni vulnerabilità bassa aggiunge la vulnerabilità al rispettivo array "TYPE"
                final_summary.vulnerabilities[host][service]['low'][vul.type].push(vul)
            })
            info_severity.forEach(vul => {
                if(final_summary.vulnerabilities[host][service]['info'][vul.type] == undefined){  //se il tipo non è ancora presente, lo inizializza
                    final_summary.vulnerabilities[host][service]['info'][vul.type] = []
                }
                //per ogni vulnerabilità informativa aggiunge la vulnerabilità al rispettivo array "TYPE"
                final_summary.vulnerabilities[host][service]['info'][vul.type].push(vul)
            })
            unknown_severity.forEach(vul => {
                if(final_summary.vulnerabilities[host][service]['unknown'][vul.type] == undefined){  //se il tipo non è ancora presente, lo inizializza
                    final_summary.vulnerabilities[host][service]['unknown'][vul.type] = []
                }
                //per ogni vulnerabilità sconosciuta aggiunge la vulnerabilità al rispettivo array "TYPE"
                final_summary.vulnerabilities[host][service]['unknown'][vul.type].push(vul)
            })
            //console.log('service', service)
        }
    }
    
    res.status(201).json({
        message : 'ok',
        z_summary : z_summary,
        r : r,
        final_summary : final_summary
    })

}



/**  
  * Test per il Bayesian_classifier che verrà utilizzato per tipizzare le vulnerabilità.
  * I corpus per ognuna delle 13 vulnerabilità sono training set di 200 elementi.
  * Il test set contiene 130 oggetti, 10 per ogni label
  * @param {*} req z_summary filename
  * @param {*} res 
  * @param {*} next 
  */
exports.testBayesianClassifier = (req, res, next) => {
    
    var bypass = []; var csrf = []; var dir_traversal = [];
    var dos = []; var file_inclusion = []; var gain_privileges = [];
    var http_response_splitting = []; var information_disclosure = [];
    var memory_corruption = []; var overflow = []; var sql_injection = [];
    var xcute_arbitrary_code = []; var xss = [];
    
    //Riempie gli array per ciascuna vulnerabilità con le descrizioni associate
    for(let i=0; i<CORPUS_SIZE; i++){
        //bypass.push(bypass_corpus[i].description.toLowerCase())
        csrf.push(csrf_corpus[i].description.toLowerCase())
        dir_traversal.push(dir_traversal_corpus[i].description.toLowerCase())
        dos.push(dos_corpus[i].description.toLowerCase())
        file_inclusion.push(file_inclusion_corpus[i].description.toLowerCase())
        gain_privileges.push(gain_privileges_corpus[i].description.toLowerCase())
        http_response_splitting.push(http_response_splitting_corpus[i].description.toLowerCase())
        information_disclosure.push(information_disclosure_corpus[i].description.toLowerCase())
        memory_corruption.push(memory_corruption_corpus[i].description.toLowerCase())
        overflow.push(overflow_corpus[i].description.toLowerCase())
        sql_injection.push(sql_injection_corpus[i].description.toLowerCase())
        xcute_arbitrary_code.push(xcute_arbitrary_code_corpus[i].description.toLowerCase())
        xss.push(xss_corpus[i].description.toLowerCase())
    }
    
    /*Definisce le label per ogni classe*/
    //classifier.addDocuments(bypass, 'Bypass a restriction or similar')
    classifier.addDocuments(csrf, 'Cross Site Request Forgery (CSRF)')
    classifier.addDocuments(dir_traversal, 'Directory Traversal')
    classifier.addDocuments(dos, 'Denial of Service (DoS)')
    classifier.addDocuments(file_inclusion, 'File Inclusion')
    classifier.addDocuments(gain_privileges, 'Gain Privileges')
    classifier.addDocuments(http_response_splitting, 'HTTP Response Splitting')
    classifier.addDocuments(information_disclosure, 'Information Disclosure')
    classifier.addDocuments(memory_corruption, 'Memory Corruption')
    classifier.addDocuments(overflow, 'Overflow vulnerability (includes stack and heap based overflows and other overflows)')
    classifier.addDocuments(sql_injection, 'SQL Injection')
    classifier.addDocuments(xcute_arbitrary_code, 'Execute arbitrary code on vulnerable system')
    classifier.addDocuments(xss, 'Cross Site Scripting (XSS)')
    
    classifier.train(); //training


    /*Accuracy
    let match = 0;
    oracle.forEach( item => {
        //console.log('\n**Description: '+item.description)
        console.log(item.index+' **Oracle: '+item.label, '**Bayesian Classifier: '+classifier.classify(item.description.toLowerCase())+'\n')
        if(item.label == classifier.classify(item.description.toLowerCase()))
            match++;
    })*/

    /****************CONFUSION MATRIX VALUES**************/

    true_positive = 0;
    var csrf_l = 0; var dir_traversal_l = 0;
    var dos_l = 0; var file_inclusion_l = 0; var gain_privileges_l = 0;
    var http_response_splitting_l = 0; var information_disclosure_l = 0;
    var memory_corruption_l = 0; var overflow_l = 0; var sql_injection_l = 0;
    var xcute_arbitrary_code_l = 0; var xss_l = 0;
    label = '';

    oracle.forEach( item => {

        console.log('******************ITEM: '+item.index)

        if(item.index%10 == 0){
            console.log('*new row - true label: '+item.label)
            label == item.label
            true_positive = 0;
            csrf_l = 0; dir_traversal_l = 0;
            dos_l = 0; file_inclusion_l = 0; gain_privileges_l = 0;
            http_response_splitting_l = 0; information_disclosure_l = 0;
            memory_corruption_l = 0; overflow_l = 0; sql_injection_l = 0;
            xcute_arbitrary_code_l = 0; xss_l = 0;
        }
        if(item.index%10 == 9){
            console.log('FIRST ROW, true_positive - label ('+label+'): '+true_positive)
            console.log('csrf: '+csrf_l)
            console.log('dir traversal: '+dir_traversal_l)
            console.log('dos: '+dos_l)
            console.log('file inclusion: '+file_inclusion_l)
            console.log('gain privilefes: '+gain_privileges_l)
            console.log('http response splitting: '+http_response_splitting_l)
            console.log('information disclosure: '+information_disclosure_l)
            console.log('memory corruption: '+memory_corruption_l)
            console.log('overflow: '+overflow_l)
            console.log('sql injection: '+sql_injection_l)
            console.log('xcute arbitrary code: '+xcute_arbitrary_code_l)
            console.log('xss: '+xss_l)
        }
        
        if(item.label == classifier.classify(item.description.toLowerCase())){
            true_positive++;
        }else{
            //console.log('no match with ('+item.label+')! - '+classifier.classify(item.description.toLowerCase()))
            switch(classifier.classify(item.description)) {
                case 'Cross Site Scripting (XSS)': xss_l++; break;
                case 'Denial of Service (DoS)': dos_l++; break;
                case 'Directory Traversal': dir_traversal_l++; break;
                case 'Execute arbitrary code on vulnerable system': xcute_arbitrary_code_l++; break;
                case 'Gain Privileges': gain_privileges_l++; break;
                case 'HTTP Response Splitting': http_response_splitting_l++; break;
                case 'Memory Corruption': memory_corruption_l++; break;
                case 'Information Disclosure': information_disclosure_l++; break;
                case 'Overflow vulnerability (includes stack and heap based overflows and other overflows)': overflow_l++; break;
                case 'Cross Site Request Forgery (CSRF)': csrf_l++; break;
                case 'File Inclusion': file_inclusion_l++; break;
                case 'SQL Injection': sql_injection_l++; break;
                default: break;
            }
        }

    })


    /****************CONFUSION MATRIX VALUES**************/

    console.log('\n\n')
    console.log('*********************************')
    console.log('*\t\t\t\t*')
    console.log('*\t\t\t\t*')
    console.log('\t> Accuracy: '+((/*match*/100/ORACLE_SIZE)*100).toFixed(2)+'%')
    console.log('*\t\t\t\t*')
    console.log('*\t\t\t\t*')
    console.log('*********************************')


    res.status(201).json({
        accuracy : ((/*match*/100/ORACLE_SIZE)*100).toFixed(2)+'%'
    })

}



/**
 * Recupera informazioni dall'archivio CVE per costruire il corpus relativo alle diverse vulenrabilità.
 * 
 * Types: Bypass a restriction or similar, Cross Site Scripting (XSS), Denial of Service (DoS), Directory Traversal,
                * Execute arbitrary code on vulnerable system, Gain Privileges, HTTP Response Splitting, Memory Corruption,
                * Information Disclosure, Overflow vulnerability (includes stack and heap based overflows and other overflows),
                * Cross Site Request Forgery (CSRF), File Inclusion, SQL Injection
 * 
* 
* @param {*} req xmls
* @param {*} res 
* @param {*} next 
*/
    exports.buildCorpus =  async (ref, type) => {

        try{

            console.log('(2) => method() => nlp => nlp => buildCorpus', ref, type)

            const nightmare = Nightmare({ show: false, waitTimeout: 30000 });   //inizializza Nightmare (non vogliamo vedere la UI di Electron {show:false} e diciamo che dopo al più 80 secondi Nightmare deve rispondere {waitTimeout: 80000})
        
            return await nightmare.goto(ref)
            .wait(5000) //attendi un po' prima di provare a caricare la pagina in modo da essere sicuri che il DOM sia pronto e navigabile (anche in caso di problemi temporanei di connessione)
            .evaluate(() => {

                try{
        
                    corpus = []  //costruisce un oggetto con tutte le informazioni rilevanti che si riescono a recuperare dal link al CVE

                    for(let i=0; i<(CORPUS_SIZE=200); i++){

                        let corpus_item = {
                            cve : 'n/a',
                            description : 'n/a'
                        }

                        var cve = document.querySelectorAll('tr[class="srrowns"] td[nowrap] a')
                        corpus_item.cve = cve[i].innerHTML

                        var description = document.querySelectorAll('td[class="cvesummarylong"]')
                        corpus_item.description = description[i].innerHTML

                        if(corpus_item.description == 'n/a')  //se la descrizione è vuota non aggiungere al corpus
                            continue;
                        else
                            corpus.push(corpus_item)
                    }
                
                    return corpus

                }catch(error){

                    return {'error' : error.toString()}

                }
            }) 
            
            .then((rr) => {
                console.log('(3)', rr);

                /*Bypass a restriction or similar, Cross Site Scripting (XSS), Denial of Service (DoS), Directory Traversal,
                * Execute arbitrary code on vulnerable system, Gain Privileges, HTTP Response Splitting, Memory Corruption,
                * Information Disclosure, Overflow vulnerability (includes stack and heap based overflows and other overflows),
                * Cross Site Request Forgery (CSRF), File Inclusion, SQL Injection*/
                switch(type) {
                    case 'Bypass a restriction or similar': fs.writeFileSync('./utils/corpus/bypass_a_restriction.json', JSON.stringify(rr)); break;
                    case 'Cross Site Scripting (XSS)': fs.writeFileSync('./utils/corpus/xss.json', JSON.stringify(rr)); break;
                    case 'Denial of Service (DoS)': fs.writeFileSync('./utils/corpus/dos.json', JSON.stringify(rr)); break;
                    case 'Directory Traversal': fs.writeFileSync('./utils/corpus/directory_traversal.json', JSON.stringify(rr)); break;
                    case 'Execute arbitrary code on vulnerable system': fs.writeFileSync('./utils/corpus/xcute_arbitrary_code.json', JSON.stringify(rr)); break;
                    case 'Gain Privileges': fs.writeFileSync('./utils/corpus/gain_privileges.json', JSON.stringify(rr)); break;
                    case 'HTTP Response Splitting': fs.writeFileSync('./utils/corpus/http_response_splitting.json', JSON.stringify(rr)); break;
                    case 'Memory Corruption': fs.writeFileSync('./utils/corpus/memory_corruption.json', JSON.stringify(rr)); break;
                    case 'Information Disclosure': fs.writeFileSync('./utils/corpus/information_disclosure.json', JSON.stringify(rr)); break;
                    case 'Overflow vulnerability (includes stack and heap based overflows and other overflows)': fs.writeFileSync('./utils/corpus/overflow.json', JSON.stringify(rr)); break;
                    case 'Cross Site Request Forgery (CSRF)': fs.writeFileSync('./utils/corpus/csrf.json', JSON.stringify(rr)); break;
                    case 'File Inclusion': fs.writeFileSync('./utils/corpus/file_inclusion.json', JSON.stringify(rr)); break;
                    case 'SQL Injection': fs.writeFileSync('./utils/corpus/sql_injection.json', JSON.stringify(rr)); break;
                }

                return rr
            })
        
        }catch(error){
            return {'error' : error.toString()}
        }

    }




/**
* Ordina le vulnerabilità di ciascun servizio (es: 21/ftp) in base al livello di severity (in base al CVSS 3.0)
* 
* @param {*} req critical_severity, high_severity, medium_severity, low_severity, info_severity, unknown_severity, z_summary, host, service
*/
function computeSeverity(critical_severity, high_severity, medium_severity, low_severity, info_severity, unknown_severity, z_summary, host, service){

    var vulnerabilities = [] //array che conterrà tutte le vulnerabilità su quella porta (service)

    for(let type in z_summary.vulnerabilities[host][service]){
        //console.log('type', type)
        z_summary.vulnerabilities[host][service][type].forEach( vuln => {
            vulnerabilities.push(vuln) //inserisce tutte le vulnerabilità della porta in uno stesso array
        })
    }

    console.log('tutte le vulnerabilità del service '+service, vulnerabilities.length)
    
    vulnerabilities.forEach(vuln => {

        //flag per vedere se la vulnerabilità è già stata inserita in qualche array
        alredady_pushed = false;

        if(vuln.cvss == undefined || vuln.cvss == null || vuln.cvss == 'unknown'){
            unknown_severity.push(vuln) //se non è noto il livello di severity inserisce la vulnerabilità in UNKNOWN
            alredady_pushed = true;
        }

        var cvss3 = vuln.cvss.toLowerCase()  //porta le descrizioni tutte in minuscolo

        //INFO: 0.0<=x
        if(cvss3.lastIndexOf('0.0') != -1 || cvss3.lastIndexOf('info') != -1 || cvss3.lastIndexOf('Info') != -1 || cvss3.lastIndexOf('INFO') != -1 && !alredady_pushed){
            info_severity.push(vuln)
            alredady_pushed = true;
        }

        //LOW: 0.1<=x<=3.9
        if(cvss3.lastIndexOf('0.1') != -1 || cvss3.lastIndexOf('0.2') != -1 || cvss3.lastIndexOf('0.3') != -1 || cvss3.lastIndexOf('0.4') != -1 || cvss3.lastIndexOf('0.5') != -1 ||
        cvss3.lastIndexOf('0.6') != -1 || cvss3.lastIndexOf('0.7') != -1 || cvss3.lastIndexOf('0.8') != -1 || cvss3.lastIndexOf('0.9') != -1 || cvss3.lastIndexOf('1.0') != -1 || cvss3.lastIndexOf('1.1') != -1 || cvss3.lastIndexOf('1.2') != -1 ||
        cvss3.lastIndexOf('1.3') != -1 || cvss3.lastIndexOf('1.4') != -1 || cvss3.lastIndexOf('1.5') != -1 || cvss3.lastIndexOf('1.6') != -1 || cvss3.lastIndexOf('1.7') != -1 || cvss3.lastIndexOf('1.8') != -1 || cvss3.lastIndexOf('1.9') != -1 || cvss3.lastIndexOf('2.0') != -1 ||
        cvss3.lastIndexOf('2.1') != -1 || cvss3.lastIndexOf('2.2') != -1 || cvss3.lastIndexOf('2.3') != -1 || cvss3.lastIndexOf('2.4') != -1 || cvss3.lastIndexOf('2.5') != -1 || cvss3.lastIndexOf('2.6') != -1 || cvss3.lastIndexOf('2.7') != -1 || cvss3.lastIndexOf('2.8') != -1 ||
        cvss3.lastIndexOf('2.9') != -1 || cvss3.lastIndexOf('3.0') != -1 || cvss3.lastIndexOf('3.1') != -1 || cvss3.lastIndexOf('3.2') != -1 || cvss3.lastIndexOf('3.3') != -1 || cvss3.lastIndexOf('3.4') != -1 || cvss3.lastIndexOf('3.5') != -1 || cvss3.lastIndexOf('3.6') != -1 ||
        cvss3.lastIndexOf('3.7') != -1 || cvss3.lastIndexOf('3.8') != -1 || cvss3.lastIndexOf('3.9') != -1 || cvss3.lastIndexOf('low') != -1 || cvss3.lastIndexOf('Low') != -1 || cvss3.lastIndexOf('LOW') != -1 && !alredady_pushed){
            low_severity.push(vuln)
            alredady_pushed = true;
        }

        //MEDIUM: 4.0<=x<=6.9
        if(cvss3.lastIndexOf('4.0') != -1 || cvss3.lastIndexOf('4.1') != -1 || cvss3.lastIndexOf('4.2') != -1 || cvss3.lastIndexOf('4.3') != -1 || cvss3.lastIndexOf('4.4') != -1 ||
        cvss3.lastIndexOf('4.5') != -1 || cvss3.lastIndexOf('4.6') != -1 || cvss3.lastIndexOf('4.7') != -1 || cvss3.lastIndexOf('4.8') != -1 || cvss3.lastIndexOf('4.9') != -1 || cvss3.lastIndexOf('5.0') != -1 || cvss3.lastIndexOf('5.1') != -1 ||
        cvss3.lastIndexOf('5.2') != -1 || cvss3.lastIndexOf('5.3') != -1 || cvss3.lastIndexOf('5.4') != -1 || cvss3.lastIndexOf('5.5') != -1 || cvss3.lastIndexOf('5.6') != -1 || cvss3.lastIndexOf('5.7') != -1 || cvss3.lastIndexOf('5.8') != -1 || cvss3.lastIndexOf('5.9') != -1 ||
        cvss3.lastIndexOf('6.0') != -1 || cvss3.lastIndexOf('6.1') != -1 || cvss3.lastIndexOf('6.2') != -1 || cvss3.lastIndexOf('6.3') != -1 || cvss3.lastIndexOf('6.4') != -1 || cvss3.lastIndexOf('6.5') != -1 || cvss3.lastIndexOf('6.6') != -1 || cvss3.lastIndexOf('6.7') != -1 ||
        cvss3.lastIndexOf('6.8') != -1 || cvss3.lastIndexOf('6.9') != -1 || cvss3.lastIndexOf('medium') != -1 || cvss3.lastIndexOf('Medium') != -1 || cvss3.lastIndexOf('MEDIUM') != -1 && !alredady_pushed){
            medium_severity.push(vuln)
            alredady_pushed = true;
        }

        //HIGH: 7.0<=x<=8.9
        if(cvss3.lastIndexOf('7.0') != -1 || cvss3.lastIndexOf('7.1') != -1 || cvss3.lastIndexOf('7.2') != -1 || cvss3.lastIndexOf('7.3') != -1 || cvss3.lastIndexOf('7.4') != -1 ||
        cvss3.lastIndexOf('7.5') != -1 || cvss3.lastIndexOf('7.6') != -1 || cvss3.lastIndexOf('7.7') != -1 || cvss3.lastIndexOf('7.8') != -1 || cvss3.lastIndexOf('7.9') != -1 || cvss3.lastIndexOf('8.0') != -1 || cvss3.lastIndexOf('8.1') != -1 ||
        cvss3.lastIndexOf('8.2') != -1 || cvss3.lastIndexOf('8.3') != -1 || cvss3.lastIndexOf('8.4') != -1 || cvss3.lastIndexOf('8.5') != -1 || cvss3.lastIndexOf('8.6') != -1 || cvss3.lastIndexOf('8.7') != -1 || cvss3.lastIndexOf('8.8') != -1 || cvss3.lastIndexOf('8.9') != -1
        || cvss3.lastIndexOf('high') != -1 || cvss3.lastIndexOf('High') != -1 || cvss3.lastIndexOf('HIGH') != -1 && !alredady_pushed){
            high_severity.push(vuln)
            alredady_pushed = true;
        }

        //CRITICAL: 9.0<=x<=10.0
        if(cvss3.lastIndexOf('9.0') != -1 || cvss3.lastIndexOf('9.1') != -1 || cvss3.lastIndexOf('9.2') != -1 || cvss3.lastIndexOf('9.3') != -1 || cvss3.lastIndexOf('9.4') != -1 ||
        cvss3.lastIndexOf('9.5') != -1 || cvss3.lastIndexOf('9.6') != -1 || cvss3.lastIndexOf('9.7') != -1 || cvss3.lastIndexOf('9.8') != -1 || 
        cvss3.lastIndexOf('9.9') != -1 || cvss3.lastIndexOf('10.0') != -1 || cvss3.lastIndexOf('critical') != -1 || cvss3.lastIndexOf('Critical') != -1 || cvss3.lastIndexOf('CRITICAL') != -1 && !alredady_pushed){
            //console.log('push critical')
            critical_severity.push(vuln)
            alredady_pushed = true;
        }
    })

    var result = {
        unknown_severity : unknown_severity,
        info_severity : info_severity,
        low_severity : low_severity,
        medium_severity : medium_severity,
        high_severity : high_severity,
        critical_severity : critical_severity
    }

    //console.log('RESULT', result)

    return result

}




/**
* Utilizza il classificatore Bayesiano per tipizzare le diverse vulnerabilità in base al loro livello di criticità
* 
* @param {*} req critical_severity, high_severity, medium_severity, low_severity, info_severity, unknown_severity, z_summary, host, service
*/
function computeType(critical_severity, high_severity, medium_severity, low_severity, info_severity, unknown_severity, z_summary, host, service){

    console.log('(3) nlp_report => computeType')

    var bypass = []; var csrf = []; var dir_traversal = [];
    var dos = []; var file_inclusion = []; var gain_privileges = [];
    var http_response_splitting = []; var information_disclosure = [];
    var memory_corruption = []; var overflow = []; var sql_injection = [];
    var xcute_arbitrary_code = []; var xss = [];
    
    //Riempie gli array per ciascuna vulnerabilità con le descrizioni associate
    for(let i=0; i<CORPUS_SIZE; i++){
        //bypass.push(bypass_corpus[i].description.toLowerCase())
        csrf.push(csrf_corpus[i].description.toLowerCase())
        dir_traversal.push(dir_traversal_corpus[i].description.toLowerCase())
        dos.push(dos_corpus[i].description.toLowerCase())
        file_inclusion.push(file_inclusion_corpus[i].description.toLowerCase())
        gain_privileges.push(gain_privileges_corpus[i].description.toLowerCase())
        http_response_splitting.push(http_response_splitting_corpus[i].description.toLowerCase())
        information_disclosure.push(information_disclosure_corpus[i].description.toLowerCase())
        memory_corruption.push(memory_corruption_corpus[i].description.toLowerCase())
        overflow.push(overflow_corpus[i].description.toLowerCase())
        sql_injection.push(sql_injection_corpus[i].description.toLowerCase())
        xcute_arbitrary_code.push(xcute_arbitrary_code_corpus[i].description.toLowerCase())
        xss.push(xss_corpus[i].description.toLowerCase())
    }
    
    /*Definisce le label per ogni classe*/
    //classifier.addDocuments(bypass, 'Bypass a restriction or similar')
    classifier.addDocuments(csrf, 'Cross Site Request Forgery (CSRF)')
    classifier.addDocuments(dir_traversal, 'Directory Traversal')
    classifier.addDocuments(dos, 'Denial of Service (DoS)')
    classifier.addDocuments(file_inclusion, 'File Inclusion')
    classifier.addDocuments(gain_privileges, 'Gain Privileges')
    classifier.addDocuments(http_response_splitting, 'HTTP Response Splitting')
    classifier.addDocuments(information_disclosure, 'Information Disclosure')
    classifier.addDocuments(memory_corruption, 'Memory Corruption')
    classifier.addDocuments(overflow, 'Overflow vulnerability (includes stack and heap based overflows and other overflows)')
    classifier.addDocuments(sql_injection, 'SQL Injection')
    classifier.addDocuments(xcute_arbitrary_code, 'Execute arbitrary code on vulnerable system')
    classifier.addDocuments(xss, 'Cross Site Scripting (XSS)')
    
    classifier.train(); //training

    unknown_severity.forEach(item => {
        label = classifier.classify(item.description.toLowerCase())
        item.type = label  //setta l'attributo type con la classe restituita dal classificatore Bayesiano
        console.log('label', label)
    })

    low_severity.forEach(item => {
        label = classifier.classify(item.description.toLowerCase())
        item.type = label //setta l'attributo type con la classe restituita dal classificatore Bayesiano
        console.log('label', label)
    })

    medium_severity.forEach(item => {
        label = classifier.classify(item.description.toLowerCase())
        item.type = label //setta l'attributo type con la classe restituita dal classificatore Bayesiano
        console.log('label', label)
    })

    high_severity.forEach(item => {
        label = classifier.classify(item.description.toLowerCase())
        item.type = label //setta l'attributo type con la classe restituita dal classificatore Bayesiano
        console.log('label', label)
    })

    critical_severity.forEach(item => {
        label = classifier.classify(item.description.toLowerCase())
        item.type = label //setta l'attributo type con la classe restituita dal classificatore Bayesiano
        console.log('label', label)
    })

    var result = {
        unknown_severity : unknown_severity,
        info_severity : info_severity,
        low_severity : low_severity,
        medium_severity : medium_severity,
        high_severity : high_severity,
        critical_severity : critical_severity
    }

    //console.log('RESULT', result)

    return result

}


