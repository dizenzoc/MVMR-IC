/**
 * 
 *  webScraping: modulo principale per la fase 2/3
 * 
 *  L'obiettivo di questa seconda fase è quello di esaminare i riferimenti "consigliati" presenti nel report "x\_summary" restituito dalla fase 1 (Fusione dei reports)
 *  al fine di approfondire la conoscenza circa le diverse vulnerabilità e costruire un report che riesca ad essere il quanto più esaustivo possibile, non limitandosi ad un 
 *  banale merge delle informazioni ricavate da tool come NMAP, Nessus, OpenVAS e OWASP ZAP. Come suggerito in \figurename~\ref{fig:interaction-module-2}, in questa seconda fase il modulo "USER INTERFACE" invia al server MVMR il filename dell'"x\_summary" 
 *  che deve essere utilizzato per l'attività di Web Harvesting. A questo punto, recuperato lato server il file sulla base del nome dalla directory in cui vengono memorizzati i file in maniera persistente, per ciascuna vulnerabilità presente nel report si esaminano i 
 *  diversi riferimenti "suggeriti". Se durante la scansione ci si accorge che il riferimento fa parte del dominio relativo ai CVE, IBM Cloud, RedHat oppure Apache Tomcat, viene chiamato per ciascun caso un metodo ad-hoc che andrà a recuperare informazioni scandendo il DOM tree. 
 *  Una volta che per ciascuna vulnerabilità sono stati generati i diversi reports, ancora una volta utilizziamo il modulo "OPTIMIZER" per rimuovere eventuali duplicati o log di errori per poi passare ad un modulo finale "MERGER" il quale andrà a unificare tutte le informazioni ottenute, generando un report 
 *  finale dal nome "z\_summary" che verrà poi restituito al client.
 * 
 */

const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const nightmare = require('nightmare'); /** L'obiettivo è esporre alcuni semplici metodi che imitano le azioni dell'utente (come goto, typee click), con un'API che si sente sincrona per ogni blocco di script, piuttosto che callback profondamente nidificati. È stato originariamente progettato per automatizzare le attività su siti che non dispongono di API, ma viene spesso utilizzato per il test e la scansione dell'interfaccia utente.*/
const Nightmare = require('nightmare');
const optimizer = require('./optimizer');
const merger = require('./merger')

const NIST_DETAIL_CVE = 'https://nvd.nist.gov/vuln/detail/'
/*Stringhe per effettuare il controllo riguardo al dominio da cui si recuperano le informazioni*/
const CVE = 'CVE'
const REDHAT = 'RedHat'
const APACHE = 'Apache Tomcat'
const CVE_IBM = 'CVE IBM Cloud'

const MAX_ITERATION_CVE_HARVESTING = 10   //rappresenta il numero massimo di tentativi di chiamate ricorsive per ogni link - metodo CVE_harvesting


/**
 * Riceve il report x_summary e per ognuno dei riferimenti contenuti al suo interno (campi: id_cve, refs) costruisce un report tramite attività di web scraping
 * @param {*} req x_summary_filename
 * @param {*} res 
 * @param {*} next 
 */
 exports.webScraping = async (req, res, next) => {

    console.log('(2) => method() => webScraping')

    var reference_reports = []   //array che conterrà tutti i report che andremo a costruire nella fase di web harvesting a partire dai riferimenti

    var rx = [] //DEMO con tutte le references di tutti gli host e di tutte le vulnerabilità (utilizzato in fase di test, irrilevante per il corretto funzionamento della web app)

    var x_summary_filename = req.body.x_summary_filename //recupera il nome del x_summary (ultimo summary della fase 1)

    var z_summary = {} //summary finale contenente i dati del report iniziale integrato con i risultati dell'attività di web harvesting


    //Legge il file x_summary.json che contiene e ottiene un riferimento ad esso per attraversarlo
    var x_summary_file = fs.readFileSync("./public/x_summary/"+x_summary_filename); //ottiene un riferimento al file JSON delle porte
    var x_summary = JSON.parse(x_summary_file) //converte l'oggetto JavaScript in un stringa JSON

    //console.log('(2) => method() => webScraping => x_summary', x_summary)

    var promises = []    //array di promise necessario per attendere i risultati di nightmare prima di restituire la risposta al client (risoluzione tramite Promise.all())

    //Itera per ogni host, su ogni porta/servizio, su ogni tipo di vulnerabilità..
    for(var host in x_summary.vulnerabilities){
        //console.log('(2) => method() => webScraping => host', host)
        for(var service in x_summary.vulnerabilities[host]){
            //console.log('(2) => method() => webScraping => service', service)
            for(var type in x_summary.vulnerabilities[host][service]){
                //console.log('(2) => method() => webScraping => type', type)
                x_summary.vulnerabilities[host][service][type].forEach( vuln => {
                    //console.log('(2) => method() => webScraping => vuln', vuln)

                    var refs = new Set() //costruisce l'array di riferimenti da esaminare per costruire i diversi report (li estrae dalle proprietà refs e id_cve)
                    vuln.refs.forEach( reference => {
                        if(reference.indexOf('https://cve.mitre.org') != -1){ //se è un riferimento al cve modifica il link con quello del NIST che contiene informazioni aggiuntive
                            /**CASO CVE **
                             * 
                             * Si effettua un recupero della stringa 'CVE-****-****' contenente il riferimento al documento e si effettua una ricerca approfondita sul sito del NIST per ottenere informazioni aggiuntive (https://nvd.nist.gov/vuln/detail/CVE-****-****).
                             * https://exchange.xforce.ibmcloud.com/vulnerabilities/69396
                            */

                            console.log('**********CVE********', reference)

                            index_CVE = reference.lastIndexOf('CVE-')   //recupera nell'URL il richiamo al CVE-
                            //console.log('Index occorrenza CVE-', index_CVE)
                            subs = reference.substring(index_CVE,index_CVE+13) //sono 13 i caratteri dell'ID del CVE
                            
                            //console.log('(2) => method() => webScraping => CVE full name:', subs)
                            refs.add(NIST_DETAIL_CVE.concat(subs))
                        }else{
                            refs.add(reference)     //se non è un archivio CVE inserisce il link cosi com'è
                        }
                    })
                    vuln.id_cve.forEach( cve => {
                        console.log('**********ID CVE********', cve, NIST_DETAIL_CVE.concat(cve))
                        if(cve.indexOf('CVE') != -1){  //se si tratta di un ID di un CVE allora costruisce il link da visitare
                            refs.add(NIST_DETAIL_CVE.concat(cve))//link al sito del NIST contenente tale vulnerabilità
                        }
                    })

                    //console.log('all references for each vulnerability', refs)

                    /*****PER OGNI RIFERIMENTO BISOGNA INVOCARE scraping_handler che alla fine restituirà un array di reports (da unire) */
                    reference_reports = new Set()
                    refs.forEach( async link => {
                        rx.push(link)     //utilizzato per i test (irrilevante per il corretto funzionamento della web app)
                        global_ref = link
                        //reference_reports.add(this.scraping_handler(link))
                        let promise = this.scraping_handler(link, host, service, type, vuln.id)
                        promises.push(promise)
                        //console.log('promises', promises)
                    })
                    //console.log('(2) => method() => webScraping => array of report for each vulnerability', reference_reports)

                })
            }
        }
    }

    //Risoluzione delle chiamate al metodo scraping_handler per ogni riferimento..
    await Promise.all(promises).then(res => {
        //console.log('Risolutore promises di this.scraping_handler(link, host, service, type, vuln.id)', res)

        const results = res.filter(element => {    //rimuove gli array vuoti dal risultato
            if (Object.keys(element).length !== 0) {
              return true;
            }
          
            return false;
          });

        reference_reports = results
    })

    //simulazione contenuto reference_report
    /*Legge il file ports.json che contiene le coppie port/service (21/ftp)
    reference_reports = fs.readFileSync('./public/ref_reports/'+x_summary_filename); //ottiene un riferimento al file reference_reports
    reference_reports = JSON.parse(reference_reports) //converte l'oggetto JavaScript in un stringa JSON
    x_summary = fs.readFileSync('./public/demo/'+x_summary_filename); //ottiene un riferimento al file reference_reports
    x_summary = JSON.parse(x_summary) //converte l'oggetto JavaScript in un stringa JSON
    /*********** */ 

    reference_reports = optimizer.removeIncompleteReports(reference_reports)   //rimuove tutti i reports che restituiscono oggetti di errore (non utili ai fini del data integration)

    z_summary = merger.dataIntegration(x_summary, reference_reports)   //DATA INTEGRATION: aggiunge per ogni vulnerabilità dell'x_summary i dati ricavati dall'attività di web harvesting
    
    //salva il file JSON relativo alla lista dei reports frutto dell'attività di harvesting in '/public/ref_reports/filename.json'
    fs.writeFileSync('./public/z_summary/'+x_summary_filename.replace('x_','z_'), JSON.stringify(z_summary));

    console.log('finished') 

    /*****PER OGNI RIFERIMENTO BISOGNA INVOCARE scraping_handler che allla fine restituirà un array di reports (da unire) *//*
    var promises = []
    var refs = []
    var id_not_found = 'https://nvd.nist.gov/vuln/detail/CVE-1999-0553'
    //refs.push('https://nvd.nist.gov/vuln/detail/CVE-2016-0800')
    refs.push('https://nvd.nist.gov/vuln/detail/CVE-2011-0411','https://nvd.nist.gov/vuln/detail/CVE-1999-0501','https://nvd.nist.gov/vuln/detail/CVE-2007-2447','https://nvd.nist.gov/vuln/detail/CVE-2021-34697','https://nvd.nist.gov/vuln/detail/CVE-2021-3909','https://nvd.nist.gov/vuln/detail/CVE-2022-28871','https://nvd.nist.gov/vuln/detail/CVE-2022-22970','https://nvd.nist.gov/vuln/detail/CVE-2021-22401','https://nvd.nist.gov/vuln/detail/CVE-2022-26143','https://nvd.nist.gov/vuln/detail/CVE-2021-33598',
    'https://nvd.nist.gov/vuln/detail/CVE-2012-0053','https://nvd.nist.gov/vuln/detail/CVE-2003-1567','https://nvd.nist.gov/vuln/detail/CVE-2003-1418','https://nvd.nist.gov/vuln/detail/CVE-2008-5304','https://nvd.nist.gov/vuln/detail/CVE-2018-20719','https://nvd.nist.gov/vuln/detail/CVE-2020-29254','https://nvd.nist.gov/vuln/detail/CVE-2010-1135','https://nvd.nist.gov/vuln/detail/CVE-2016-10143','https://nvd.nist.gov/vuln/detail/CVE-2009-4898',
    'https://nvd.nist.gov/vuln/detail/CVE-2020-16131','https://nvd.nist.gov/vuln/detail/CVE-2018-20212','https://nvd.nist.gov/vuln/detail/CVE-2020-8966','https://nvd.nist.gov/vuln/detail/CVE-2009-1339','https://nvd.nist.gov/vuln/detail/CVE-2019-15314','https://nvd.nist.gov/vuln/detail/CVE-2018-7188','https://nvd.nist.gov/vuln/detail/CVE-2008-5318', 'https://nvd.nist.gov/vuln/detail/CVE-2009-1204', 'https://nvd.nist.gov/vuln/detail/CVE-2020-1938',
    'https://nvd.nist.gov/vuln/detail/CVE-2004-2687','https://nvd.nist.gov/vuln/detail/CVE-2014-0224','https://nvd.nist.gov/vuln/detail/CVE-2014-3566','https://nvd.nist.gov/vuln/detail/CVE-2011-3389','https://nvd.nist.gov/vuln/detail/CVE-2016-0800','https://nvd.nist.gov/vuln/detail/CVE-2013-2566','https://nvd.nist.gov/vuln/detail/CVE-1999-0501','https://nvd.nist.gov/vuln/detail/CVE-2011-0411','https://nvd.nist.gov/vuln/detail/CVE-2014-3566','https://nvd.nist.gov/vuln/detail/CVE-2016-0800','https://nvd.nist.gov/vuln/detail/CVE-2011-3389','https://nvd.nist.gov/vuln/detail/CVE-2015-0204','https://nvd.nist.gov/vuln/detail/CVE-2015-4000','https://nvd.nist.gov/vuln/detail/CVE-2007-2447')
    reference_reports = new Set()

    refs.forEach( async link => {
        global_ref = link
        //reference_reports.add(this.scraping_handler(link))
        let promise = this.scraping_handler(link, '192.168.81.131', '21/ftp', 'demo', 0123)
        promises.push(promise)
        //console.log('promises', promises)
    })

    await Promise.all(promises).then(res => {
        //console.log('Risolutore promises di this.scraping_handler(link, host, service, type, vuln.id)', res)

        const results = res.filter(element => {    //rimuove gli array vuoti
            if (Object.keys(element).length !== 0) {
              return true;
            }
          
            return false;
          });

        reference_reports = results
    })
    
    /*************+ */
   
    res.status(201).json({
        'refer_retrieval' : reference_reports,
        'z_summary' : z_summary,
        'z_summary_filename' : x_summary_filename.replace('x_','z_'),
        'references' : rx
    })

 }



 /* 
 * Riceve in input un riferimento (link) e in base a quest'ultimo genera il report in base all'attività di web harvesting
 * 
 * @param {*} req ref
 * @param {*} res 
 * @param {*} next 
 */
 exports.scraping_handler =  async (ref, host, service, type, id) => {

    var refer_retrieval = {}     //inizializza un oggetto che conterrà i dati del report ricavabile dall'attività di web harvesting su ref

    //console.log('**(2) => method() => webScraping => scraping_handler => ref:', ref)

    //CVE-REFERENCE
    if(ref.indexOf('https://cve.mitre.org') != -1 || ref.indexOf(NIST_DETAIL_CVE) != -1){    //se il riferimento è relativo ad un archivio CVE..
        console.log('(2) => method() => webScraping => CVE archive : '+ref)
        var cve_report = {}

        rr = this.CVE_harvesting(ref, MAX_ITERATION_CVE_HARVESTING) //ricerca informazioni nell'archivio CVE (passa anche una costante che rappresenta il numero massimo di tentativi di chiamate ricorsive per ogni link - metodo CVE_harvesting)
        await rr.then( result => {  //risolve la promise
           //if(result.x_electron != undefined){   //vuol dire che la chiamata precedente non è andata a buon fine
          //  console.log("Il link non è più attivo. Il riferimento verrà ignorato.")
          // }else{
           cve_report = result
           //console.log('(2) => method() => webScraping => CVE Nightmare\'s result (result): ', cve_report)
           refer_retrieval = cve_report //lo aggiunge ai report da restituire
           refer_retrieval.id = id  //copia nell'oggetto l'id della vulnerabilità a cui fa riferimento
           refer_retrieval.host = host  //copia nell'oggetto l'indirizzo dell'host a cui la vulnerabilità fa riferimento
           refer_retrieval.service = service //copia nell'oggetto il servizio a cui la vulnerabilità fa riferimento
           refer_retrieval.type = type   //copia nell'oggetto l'indirizzo di vulnerabilità interessata
           refer_retrieval.link = ref   //copia nell'oggetto l'indirizzo originale del riferimento da cui sono state estratte le varie informazioni
           refer_retrieval.harvesting = CVE   //copia nell'oggetto la stringa che indica da quale dominio sono state recuperate tutte queste informazioni
          // }
        })

        //console.log('after CVE_Harvesting ::::::::::>>>>>', refer_retrieval)
        //console.log('refer-retrieva-lpot solutlion', refer_retrieval.pot_solution_ref)
        
        if(refer_retrieval.pot_solution_ref != undefined){   //se nel report CVE ottenuto fino a questo momento è presente un link che fa riferimento ad una potenziale soluzione (un collegamento al dominio https://exchange.xforce.ibmcloud.com/vulnerabilities/..)
            rr = this.CVE_nested_harvesting_IBMCloud(refer_retrieval.pot_solution_ref) //ricerca informazioni nell'archivio CVE
            await rr.then( result => {  //risolve la promise
                solution = result
                //console.log('(2) => method() => webScraping => CVE Nested IBM Nightmare\'s result (result): ', solution)
                cve_report.description_x = solution?.description_x //copia nell'oggetto la descrizione della vulnerabilità a cui fa riferimento
                cve_report.type_x = solution?.type_x   //copia nell'oggetto il tipo della vulnerabilità a cui fa riferimento
                cve_report.solution_x = solution?.solution_x+'. Maggiori info ('+refer_retrieval.pot_solution_ref+')'  //copia nell'oggetto la possibile mitigazione della vulnerabilità a cui fa riferimento
                refer_retrieval = cve_report   //copia il tutto nel report da restituire
                refer_retrieval.id = id  //copia nell'oggetto l'id della vulnerabilità a cui fa riferimento
                refer_retrieval.host = host  //copia nell'oggetto l'indirizzo dell'host a cui la vulnerabilità fa riferimento
                refer_retrieval.service = service //copia nell'oggetto il servizio a cui la vulnerabilità fa riferimento
                refer_retrieval.type = type   //copia nell'oggetto l'indirizzo di vulnerabilità interessata
                refer_retrieval.link = ref   //copia nell'oggetto l'indirizzo originale del riferimento da cui sono state estratte le varie informazioni
                refer_retrieval.harvesting = CVE_IBM  //copia nell'oggetto la stringa che indica da quale dominio sono state recuperate tutte queste informazioni
                //console.log('***REFER_RETRIEVAL', refer_retrieval)
            })
        }

        //console.log('refer CVE', refer_retrieval)

    }

    //REDHAT
    if(ref.indexOf('https://access.redhat.com') != -1){
        //console.log('(2) => method() => webScraping => scraping_handler => REDHAT archive : '+ref)
        rr = this.REDHAT_harvesting(ref) //ricerca informazioni nell'archivio REDHAT
        await rr.then( result => {  //risolve la promise
            var reportREDHAT = result
            //console.log('(2) => method() => webScraping => REDHAT Nightmare\'s result (result): ', reportREDHAT)
            refer_retrieval = reportREDHAT //lo aggiunge ai report da restituire
            refer_retrieval.id = id  //copia nell'oggetto l'id della vulnerabilità a cui fa riferimento
            refer_retrieval.host = host  //copia nell'oggetto l'indirizzo dell'host a cui la vulnerabilità fa riferimento
            refer_retrieval.service = service //copia nell'oggetto il servizio a cui la vulnerabilità fa riferimento
            refer_retrieval.type = type   //copia nell'oggetto l'indirizzo di vulnerabilità interessata
            refer_retrieval.link = ref   //copia nell'oggetto l'indirizzo originale del riferimento da cui sono state estratte le varie informazioni
            refer_retrieval.harvesting = REDHAT   //copia nell'oggetto la stringa che indica da quale dominio sono state recuperate tutte queste informazioni
        })
    }

    //TOMCAT-APACHE
    if(ref.indexOf('https://tomcat.apache.org') != -1){
        //console.log('(2) => method() => webScraping => scraping_handler => TOMCAT APACHE archive : '+ref)
        rr = this.TomcatApache_harvesting(ref) //ricerca informazioni nell'archivio REDHAT
        await rr.then( result => {  //risolve la promise
            var reportTomcatApache = result
            //console.log('(2) => method() => webScraping => TOMCAT APACHE Nightmare\'s result (result): ', reportTomcatApache)
            refer_retrieval = reportTomcatApache //lo aggiunge ai report da restituire
            refer_retrieval.id = id  //copia nell'oggetto l'id della vulnerabilità a cui fa riferimento
            refer_retrieval.host = host  //copia nell'oggetto l'indirizzo dell'host a cui la vulnerabilità fa riferimento
            refer_retrieval.service = service //copia nell'oggetto il servizio a cui la vulnerabilità fa riferimento
            refer_retrieval.type = type   //copia nell'oggetto l'indirizzo di vulnerabilità interessata
            refer_retrieval.link = ref   //copia nell'oggetto l'indirizzo originale del riferimento da cui sono state estratte le varie informazioni
            refer_retrieval.harvesting = APACHE    //copia nell'oggetto la stringa che indica da quale dominio sono state recuperate tutte queste informazioni
        })
    }

    return new Promise((resolve, reject) => { resolve(refer_retrieval) })
  
}
 







 
 /**
 * Recupera informazioni dal CVE in input e restituisce un oggetto di questo tipo:
 * 
 * refer_retrieval {
    cvss: '7.8 HIGH',
    description: 'The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through 2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a denial of service (memory and CPU consumption) via a Range header that expresses multiple overlapping ranges, as exploited in the wild in August 2011, a different vulnerability than CVE-2007-0086.',
    exploits: [
        'http://seclists.org/fulldisclosure/2011/Aug/175',
        'http://www.exploit-db.com/exploits/17696',
        'https://bugzilla.redhat.com/show_bug.cgi?id=732928',
        'https://issues.apache.org/bugzilla/show_bug.cgi?id=51714'
    ],
    mitigations: [
        'http://mail-archives.apache.org/mod_mbox/httpd-announce/201108.mbox/%3c20110824161640.122D387DD@minotaur.apache.org%3e',
        'https://lists.apache.org/thread.html/rb9c9f42dafa25d2f669dac2a536a03f2575bc5ec1be6f480618aee10@%3Ccvs.httpd.apache.org%3E'
    ],
    patches: [
        'http://mail-archives.apache.org/mod_mbox/httpd-dev/201108.mbox/%3cCAAPSnn2PO-d-C4nQt_TES2RRWiZr7urefhTKPWBC1b+K1Dqc7g@mail.gmail.com%3e'
    ]
    }
 * 
 * @param {*} req ref = link, max_iteration = numero massimo di chiamate ricorsive per tentare di recuperare informazioni dal link in questione
 * @param {*} res 
 * @param {*} next 
 */
  exports.CVE_harvesting =  async (ref, max_iteration) => {

    //ref = 'https://nvd.nist.gov/vuln/detail/CVE-1999-0501' //SIMULAZIONE
    //CASO BASE
    if(max_iteration == 0)
        return { 'error' : 'maximum number of iterations attempted'}
    else
        console.log('(2) => method() => webScraping => scraping_handler => CVE_harvesting', ref)
        //console.log('method() => webScraping => ref : '+ref)

        const nightmare = Nightmare({ show: false, waitTimeout: 10000 });    //inizializza Nightmare (non vogliamo vedere la UI di Electron {show:false} e diciamo che dopo al più 80 secondi Nightmare deve rispondere {waitTimeout: 80000})

        return await nightmare.goto(ref)
        .wait(5000)    //attendi un po' prima di provare a caricare la pagina in modo da essere sicuri che il DOM sia pronto e navigabile (anche in caso di problemi temporanei di connessione)
        .evaluate(async () => {

            try{

                var refer_retrieval = {}  //costruisce un oggetto con tutte le informazioni rilevanti che si riescono a recuperare dal link al CVE

                exploits = [] //informations
                mitigations = [] //mitigations
                patches = [] //patches
                pot_solution_refs = [] //potenziali soluzioni

                var desc = document.querySelector('p[data-testid="vuln-description"]');  //DESCRIZIONE VULNERABILITA'
                var title = document.title
                var cvss = document.querySelector('a[id="Cvss2CalculatorAnchor"]');  //CVSS2.0 VULNERABILITA'

                if(desc != null){
                    refer_retrieval.description = (desc.innerHTML)  //Descrizione
                }
                else{
                    desc = ''
                    refer_retrieval.description = desc
                }
                    
                
                if(cvss != null)
                    refer_retrieval.cvss = (cvss.innerHTML)  //CVSS score
                else 
                    refer_retrieval.cvss = cvss

                refer_retrieval.title = title
                refer_retrieval.tags = []
                

                /*bisogna scorrere la lista di riferimenti per la vulnerabilità nella pagina del NIST*/
                let i=0;
                while(1){ //itera scandendo gli indici dei link (solitamente sono compresi tra 75-130, quindi si è scelto 150 come soglia MAX
                
                        var link = document.querySelector(`td[data-testid="vuln-hyperlinks-link-${i}"] a`);  //RIFERIMENTI EXPLOIT, MITIGAZIONI, ECC...
                        var tags = document.querySelectorAll(`td[data-testid="vuln-hyperlinks-resType-${i}"] span span`);  //TIPO DI LINK
                        refer_retrieval.tags.push('iterazione iniziata')
                        refer_retrieval.tags.push(link.getAttribute('href'))
                        refer_retrieval.tags.push(tags)
                        refer_retrieval.tags.push('iterazione finita')
                        
                        //console.log('++++++++++tags', tags)
                        for(let j=0; j<link.length; j++){  //itera i tag associati a ciascun riferimento

                            if(tags[j].innerHTML == 'Exploit'){
                                //array.push(tags[j].innerHTML)    //push dei link relativi agli exploits
                                exploits.push(link.getAttribute('href'))
                            }

                            if(tags[j].innerHTML == 'Mitigation'){
                                //array.push(tags[j].innerHTML)    //push dei link relativi alle mitigazioni
                                mitigations.push(link.getAttribute('href'))
                            }

                            if(tags[j].innerHTML == 'Patch'){
                                //array.push(tags[j].innerHTML)    //push dei link relativi alle patches
                                patches.push(link.getAttribute('href'))
                            }

                        }   

                        if(document.querySelector(`td[data-testid="vuln-hyperlinks-link-${i}"] a`) && link.getAttribute('href').indexOf('exchange.xforce.ibmcloud.com') != -1){
                            //refer_retrieval.ciao = 'ao'
                            refer_retrieval.pot_solution_ref = link.getAttribute('href')
                        }

                        i++;

                        if(!document.querySelector(`td[data-testid="vuln-hyperlinks-link-${i}"] a`))  //se non esiste un successivo elemento allora esci
                            break;

                }

                refer_retrieval.exploits = exploits; //setta l'array di exploits
                refer_retrieval.mitigations = mitigations; //setta l'array di mitigations
                refer_retrieval.patches = patches; //setta l'array di patch
                        
                return refer_retrieval
            
            }catch(error){
                let ref = document.location //ottiene il link della web page poiché nello scope di Electron la variabile 'ref' esterna non è accessibile..
                //return this.CVE_harvesting(document.location)
                return { 'x_electron' : document.location }  //dato che nemmeno CVE_harvesting è raggiungibile nel contesto Electron, restituisce un oggetto x_electron con il path da reinvocare dall'esterno (in scarping_handler()). UPDATE: non fa nulla all'esterno oltre a mostrare una console.log() perché spesso sono link non più attivi
            }
        }) 
        .end()
        .then((rr) => {

            if(rr.x_electron != undefined){   //se la chiamata non è andata a buon fine per qualche motivo
                console.log(":::::A problem has occurred: ", rr.x_electron.href)
                return this.CVE_harvesting(rr.x_electron.href, max_iteration-1)
            }

            if(rr.description == ''){
                //console.log('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ rr.description = ""')
                return this.CVE_harvesting(ref, max_iteration-1) //se non trova la descrizione (che hanno tutti i CVE), richiamalo ricorsivamente perché alcune volte alla prima chiamata le informazioni del DOM non vengono estratte correttamente
            }
            //console.log('(2) => method() => CVE_harvesting => refer_retrieval => BUILDING OBJECT', rr);
            return rr
        })
        .catch(error => {
            if(error.toString().indexOf('is not defined') != -1)
                return { 'error' : error.toString() }
            if(error.toString().indexOf('navigation error') != -1)
                return this.CVE_harvesting(ref, max_iteration-1)
            else
                return { 'error' : error.toString() }
                //return this.CVE_harvesting('$'+ref) //se c'è un errore allora richiama ricorsivamente nightmare.js perché alcune volte alla prima chiamata le informazioni del DOM non vengono estratte correttamente
        })
  }


   /**
     * Recupera informazioni dal WEAKDH in input e restituisce un oggetto di questo tipo:
     * 
     * refer_retrieval {
     
        }
    * 
    * @param {*} req xmls
    * @param {*} res 
    * @param {*} next 
    */
    exports.CVE_nested_harvesting_IBMCloud =  async (ref) => {

        try{

            console.log('(2) => method() => webScraping => scraping_handler => CVE_nested_harvesting_IBMCloud', ref)

            const nightmare = Nightmare({ show: false, waitTimeout: 10000 });   //inizializza Nightmare (non vogliamo vedere la UI di Electron {show:false} e diciamo che dopo al più 80 secondi Nightmare deve rispondere {waitTimeout: 80000})
        
            return await nightmare.goto(ref)
            .wait(5000) //attendi un po' prima di provare a caricare la pagina in modo da essere sicuri che il DOM sia pronto e navigabile (anche in caso di problemi temporanei di connessione)
            .evaluate(() => {

                try{
        
                    refer_retrieval = {}  //costruisce un oggetto con tutte le informazioni rilevanti che si riescono a recuperare dal link al CVE

                    var description = document.querySelector('p[ng-bind-html="report.data.vulnerability.description"]')
                    var type = document.querySelector('div[class="consequences detailsline"]')
                    var solutions = document.querySelector('div[class="detailssubsection"] > p')
                    

                    refer_retrieval.description_x = (description.innerHTML)  //Description
                    refer_retrieval.type_x = (type.innerHTML)  //Type
                    refer_retrieval.solution_x = (solutions.innerHTML).replace(/(<p[^>]+?>|<p>|<\/p>)/img, "").replace(/(<br[^>]+?>|<br>|<\/br>)/img, ""); //Type
                            
                    return refer_retrieval

                }catch(error){

                    return {'error' : error.toString()}

                }
            }) 
            //.end()
            .then((rr) => {
                //console.log('(2) => method() => CVE_harvesting => refer_retrieval => BUILDING OBJECT', rr);
                return rr
            })
        
        }catch(error){
            return {'error' : error.toString()}
        }

    }

  



   /**
 * Recupera informazioni dal WEAKDH in input e restituisce un oggetto di questo tipo:
 * 
 * refer_retrieval {
   
    }
 * 
 * @param {*} req xmls
 * @param {*} res 
 * @param {*} next 
 */
    exports.REDHAT_harvesting =  async (ref) => {

        try{

            console.log('(2) => method() => webScraping => scraping_handler => CVE_harvesting')
            //console.log('method() => webScraping => ref : '+ref)
        
            const nightmare = Nightmare({ show: false, waitTimeout: 10000 });     //inizializza Nightmare (non vogliamo vedere la UI di Electron {show:false} e diciamo che dopo al più 80 secondi Nightmare deve rispondere {waitTimeout: 80000})
        
            return await nightmare.goto(ref)
            .wait(5000)  //attendi un po' prima di provare a caricare la pagina in modo da essere sicuri che il DOM sia pronto e navigabile (anche in caso di problemi temporanei di connessione)
            .evaluate(() => {

                try{
        
                    refer_retrieval = {}  //costruisce un oggetto con tutte le informazioni rilevanti che si riescono a recuperare dal link al CVE
                    
                    var textDiv = document.querySelectorAll('#main-content > div > div > div > div > p')
                    //var cvss = document.querySelector('a[id="Cvss2CalculatorAnchor"]');  //CVSS2.0 VULNERABILITA'
                    
                    refer_retrieval.description = (textDiv[0].innerHTML)  //Descrizione
                    refer_retrieval.description = refer_retrieval.description+' '+(textDiv[1].innerHTML)  //Descrizione
                    refer_retrieval.description = refer_retrieval.description+' '+(textDiv[2].innerHTML)  //Descrizione
                    refer_retrieval.description = refer_retrieval.description+' '+(textDiv[3].innerHTML)  //Descrizione

                    refer_retrieval.solution = (textDiv[4].innerHTML)  //Descrizione
                    refer_retrieval.solution = refer_retrieval.solution+' '+(textDiv[5].innerHTML)  //Descrizione
                    refer_retrieval.solution = refer_retrieval.solution+' '+(textDiv[6].innerHTML)  //Descrizione

                    //refer_retrieval.cvss = (cvss.innerHTML)  //CVSS score
            
                            
                    return refer_retrieval

                }catch(error){

                    return {'error' : error.toString()}

                }
            }) 
            //.end()
            .then((rr) => {
                //console.log('(2) => method() => CVE_harvesting => refer_retrieval => BUILDING OBJECT', rr);
                return rr
            })

        }catch(error){
            return {'error' : error.toString()}
        }
        
    
    }
    




   /**
     * Recupera informazioni dal WEAKDH in input e restituisce un oggetto di questo tipo:
     * 
     * refer_retrieval {
     
        }
    * 
    * @param {*} req xmls
    * @param {*} res 
    * @param {*} next 
 */
    exports.TomcatApache_harvesting =  async (ref) => {

        try{
     
            console.log('(2) => method() => webScraping => scraping_handler => TomcatApache_harvesting')
            //console.log('method() => webScraping => ref : '+ref)
        
            const nightmare = Nightmare({ show: false, waitTimeout: 10000 });    //inizializza Nightmare (non vogliamo vedere la UI di Electron {show:false} e diciamo che dopo al più 80 secondi Nightmare deve rispondere {waitTimeout: 80000})
        
            return await nightmare.goto(ref)
            .wait(5000)   //attendi un po' prima di provare a caricare la pagina in modo da essere sicuri che il DOM sia pronto e navigabile (anche in caso di problemi temporanei di connessione)
            .evaluate(() => {

                try{
        
                    refer_retrieval = {}  //costruisce un oggetto con tutte le informazioni rilevanti che si riescono a recuperare dal link al CVE
                    
                    var textDiv = document.querySelectorAll('div[class="text"]')
                    var solution = textDiv[1].innerHTML.replace(/(<p[^>]+?>|<p>|<\/p>)/img, "").replace(/(<ul[^>]+?>|<ul>|<\/ul>)/img, "").replace(/(<li[^>]+?>|<li>|<\/li>)/img, "").replace('style="text-align: center;"', "")

                    refer_retrieval.solution = solution
                        
                    return refer_retrieval

                }catch(error){

                    return {'error' : error.toString()}

                }
            }) 
            //.end()
            .then((rr) => {
                //console.log('(2) => method() => CVE_harvesting => refer_retrieval => BUILDING OBJECT', rr);
                return rr
            })

        }catch(error){
            return {'error' : error.toString()}
        }
    
    }
      


 
    