/**
 * 
 * normalizer: modulo in cui per ogni tool vengono estratte le informazioni rilevanti dall'XML al fine di costruire un file JSON con le stesse proprietà per ciascuno strumento in esame (NMAP, Nessus, OpenVAS, OWASP ZAP);
 * 
 */

const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const xml2js = require('xml2js'); //permette di convertire file XML in JSON
const global = require('../utils/global')

/**
 * Effettua un'analisi del file json del tool NMAP e restituisce un JSON contenente le informazioni chiave
 * (Salva in /public/normalized_json/nmap/ il file normalizzato contenente solo le informazioni di nostro interesse)
 * @param {*} req nmap_file
 * @param {*} res 
 * @param {*} next 
 */
 exports.getNmapSummary = (filename) => {

    /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto"
    while(!fs.existsSync('./public/json/'+filename)){
        //console.log('il file nmap non esiste', './public/json/'+filename)
    }
    if(fs.existsSync('./public/json/'+filename)){
        //console.log('il file nmap esiste')
    }*/

    console.log('method() => getNmapSummary')

    let nmap_summary = {} //inizializza l'oggetto da restituire

    var nmap_refs = fs.readFileSync("./public/json/"+filename); //ottiene un riferimento al file JSON di NMAP

    nmap_file_json = JSON.parse(nmap_refs) //converte l'oggetto JavaScript in un stringa JSON
    
    //TOOL + VERSIONE
    nmap_summary.tool = nmap_file_json.nmaprun.$.scanner+" v."+nmap_file_json.nmaprun.$.version; //inserisce nel summary il nome del tool utilizzato e la versione
    
    //COMANDO NMAP
    nmap_summary.param = nmap_file_json.nmaprun.$.args; //inserisce nel summary il comando lanciato

    //DATA E ORA DELLA SCANSIONE
    nmap_summary.date = nmap_file_json.nmaprun.$.startstr; //inserisce nel summary la data della scansione
   
    //INDIRIZZI IP DELLE MACCHINE ANALIZZATE
    nmap_summary.addresses = [];
    nmap_file_json.nmaprun.hosthint.forEach(host => {
        let i = 0; //ad ogni iterazione in address si trova nell'oggetto IP > MAC Address > IP > MAC Address alternati. Prendiamo solo gli IP pushando nell'array solo gli index pari
        host.address.forEach( address => {
            if(i%2==0){
                nmap_summary.addresses.push(address.$.addr)
            }
            i++;
        })
    })

    let host_index = 0; //l'array di vulnerabilità è legato ad ogni address, pertanto leghiamo le vulnerabilità ad ogni host incrementando 
                        //l'indice dell'host ad ogni iterazione dell'oggetto host (oggetto che contiene le vulnerabilità)
                        /*address[0]==>host[0] -- address[1]==>host[1] -- address[2]==>host[2] -- ecc...*/

    //VULNERABILITA'
    nmap_summary.vulnerabilities = [];
    //console.log("nmaprun.host", nmap_file_json.nmaprun.host)
    
    nmap_file_json.nmaprun.host.forEach( host => {
        //console.log("nmaprun.host[0]", host)
        host.ports.forEach( ports => {
            //console.log("nmaprun.host[0].ports", ports)
            ports.port.forEach( port => {

                let vuln = {}  //costruisce un oggetto per ogni vulnerabilità
                vuln.host = host.address[host_index].$.addr //indirizzo dell'host associato alle vulnerabilità
                let os = '';

                port.service.forEach( service => {
                    //console.log("****SERVICE***", service)
                    if(service.$.ostype != undefined){
                        os = service.$.ostype;
                        nmap_summary.os_type = os; //Se è stato rilevato, aggiunge il sistema operativo
                    }
                    
                    vuln.service = port.$.portid+'/'+service.$.name  //porta+nome_servizio
                    if(service.$.version != undefined)
                        vuln.version = service.$.product+" "+service.$.version //versione del servizio
                    else
                        vuln.version = service.$.product
                })

                if(port.script != undefined){ //Check perché lo script non è presente per ogni vulnerabilità riscontrata
                    port.script.forEach( script => {
                        vuln.risk = script.$.id
                        //vuln.description = script.$.output
                        //console.log("SCRIPT.TABLE", script.table)

                        if(script.table != undefined){  //Se esiste la table informativa della vulnerabilità
                            script.table.forEach( table => {
                                if(table.elem != undefined){
                                   //console.log("SCHROPPEETE.table.elem",table.elem);
                                    vuln.type = table.elem[0]._
                                }
                                if(table.table != undefined){
                                    table.table.forEach( tab => {
                                        console.log("SCHROPPEETE.table.table",tab);
                                       /* if(tab.$.key == "description"){
                                            //console.log("SCHROPPEETE.table.table.$",tab.elem);
                                            vuln.description = tab.elem[0]
                                        }
                                        if(tab.$.key == "refs"){
                                            vuln.refs = tab.elem
                                        }
                                        if(tab.$.key == "scores"){
                                            //console.log("SEVERITY",tab.elem[0]._)
                                            vuln.cvss = tab.elem[0]._
                                        }*/
                                    })
                                    
                                }
                            })
                            
                        }
                        
                    })
                }
                
                nmap_summary.vulnerabilities.push(vuln)
            })
            host_index++;
        })
    }) 

    //console.log('***NMAP_SUMMARY***', nmap_summary)

    //salva il file JSON di nmap con il nome "normalized-"+nome in /public/normalized_json/nmap
    fs.writeFileSync('./public/normalized_json/nmap/normalized-'+filename, JSON.stringify(nmap_summary));

    //Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto" in futuro
    while(!fs.existsSync('./public/normalized_json/nmap/normalized-'+filename)){
        //console.log('il file nmap non esiste', './public/json/'+filename)
    }
    
    return {
        message : "NMAP Summary!",
        summary : nmap_summary
    }

}








/**
 * Effettua un'analisi del file JSON del tool NESSUS e restituisce un JSON contenente le informazioni chiave
 * (Salva in /public/normalized_json/nessus/ il file normalizzato contenente solo le informazioni di nostro interesse)
 * @param {*} req nessus_file
 * @param {*} res 
 * @param {*} next 
 */
 exports.getNessusSummary = (filename) => {

    try{

        /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto"
        while(!fs.existsSync('./public/json/'+filename)){
            //console.log('il file nessus non esiste', './public/json/'+filename)
        }
        if(fs.existsSync('./public/json/'+filename)){
            //console.log('il file nessus esiste')
        }*/

        console.log('method() => getNessusSummary')

        let nessus_summary = {} //inizializza l'oggetto da restituire

        //Legge il file ports.json che contiene le coppie port/service (21/ftp)
        var ports_file = fs.readFileSync("./ports.json"); //ottiene un riferimento al file JSON delle porte
        ports_file_json = JSON.parse(ports_file) //converte l'oggetto JavaScript in un stringa JSON

        console.log('method() => ports.json')

        var nessus_refs = fs.readFileSync("./public/json/"+filename); //ottiene un riferimento al file JSON di NESSUS

        console.log('method() => filename.json', filename)


        nessus_file_json = JSON.parse(nessus_refs) //converte l'oggetto JavaScript in un stringa JSON

        console.log('method() => filename.json')

        //console.log('TOOL + VERSIONE', "nessus \""+nessus_file_json.NessusClientData_v2.Policy[0].policyName+"\"")

        nessus_summary.tool = "nessus" //TOOL
        nessus_summary.param = nessus_file_json.NessusClientData_v2.Policy[0].policyName[0]  //PARAMETRI SCANSIONE

        //Accede agli attributi di data e ora
        nessus_file_json.NessusClientData_v2.Report.forEach( report => {
            report.ReportHost.forEach( reportHost => {
                nessus_summary.date = reportHost.HostProperties[0].tag[1]._  //DATA E ORA
            })
        })

        //COSTRUISCE UN OGGETTO PER OGNI VULNERABILITA' E LO SALVA NELL'ARRAY VULNERABILITIES
        let vulnerabilities = [];

        nessus_file_json.NessusClientData_v2.Report.forEach( report => {
            report.ReportHost.forEach( reportHost => {
                reportHost.ReportItem.forEach( reportItem => {

                    let vuln = {}
                    vuln.host = reportHost.$.name //HOST

                    //console.log("****reportITEM")
                    port = reportItem.$.port  //OTTIENE IL NUMERO DI PORTA DEL SERVIZIO VULNERABILE
                    let service = "";
                    if(port != "general"){
                        if(ports_file_json[port.toString()+"/tcp"] != undefined)
                            service = ports_file_json[port.toString()+"/tcp"].name;
                        else
                            service = "tcp"
                    }else{
                        service = "tcp"
                    }
                    if(service == "")
                        service = "tcp"

                    let port_service = port+"/"+service  //PORTA + SERVIZIO
                    vuln.service = port_service; //AGGIUNGE PORTA/SERVIZIO (es: 21/ftp) ALL'OGGETTO VULN
                    vuln.risk = reportItem.$.pluginName  //RISCHI ASSOCIATO ALLA VULNERABILITA'
                    vuln.type = reportItem.$.pluginName  //TIPO DI VULNERABILITA'
                    if(reportItem.description[0] != undefined){
                        vuln.description = reportItem.description[0]
                    }
                    if(reportItem.synopsis[0] != undefined){    //DESCRIZIONE VULNERABILITA'
                        if(vuln.description == undefined){
                            vuln.description = reportItem.synopsis[0]
                        }else{
                            vuln.description = vuln.description+" "+reportItem.synopsis[0]
                        }
                    }

                    //CVSS
                    if(reportItem.cvss_base_score !== undefined){
                        
                        //console.log("CVSS BAASE SCORE", reportItem.cvss_base_score)
                        
                        if(reportItem.cvss_base_score[0] != undefined){  //SCORE

                            let severity = ""
                            if(reportItem.cvss_base_score[0] <= 3.9)
                                severity = "Low";
                            if(reportItem.cvss_base_score[0] >= 4.0 && reportItem.cvss_base_score[0] <=6.9)
                                severity = "Medium";
                            if(reportItem.cvss_base_score[0] >= 7.0)
                                severity = "High";

                            vuln.cvss = reportItem.cvss_base_score[0]+" "+severity
                            
                        }
                        if(reportItem.cvss_vector[0] != undefined){  //VECTOR STRING
                            if(vuln.cvss == undefined){
                                vuln.cvss = reportItem.cvss_vector[0]
                            }else{
                                vuln.cvss = vuln.cvss+" "+reportItem.cvss_vector[0]
                            }
                        }

                    }

                    //RIFERIMENTI
                    let refs = []
                    let id_cve = []
                    if(reportItem.xref != undefined){
                        id_cve.push(reportItem.xref[0])
                    }
                    if(reportItem.cve != undefined){
                        //refs = reportItem.cve.forEach( cve =>{
                        id_cve.push(...reportItem.cve)
                        //})
                    }

                    //RIFERIMENTI
                    if(reportItem.see_also != undefined){
                        refs.push(...reportItem.see_also)    //OTHER LINKS
                    }
                    //console.log('REFS', refs)
                    vuln.id_cve = id_cve
                    vuln.refs = refs
                    vulnerabilities.push(vuln)


                    //EXPLOIT INFO
                    if(reportItem.exploit_available != undefined){
                        vuln.exploit_flag = reportItem.exploit_available[0] //TRUE|FALSE
                    }
                    
                    //SOLUTION
                    if(reportItem.solution != undefined){
                        //console.log('solution', reportItem.solution[0])
                        vuln.solution = reportItem.solution[0] //SOLUTION
                    }
                    
                })

                
            })
        })

        nessus_summary.vulnerabilities = vulnerabilities; //INSERISCE LE VULNERABILITIES NEL SUMMARY JSON

        //console.log('Nessus Summary', nessus_summary)

        //salva il file JSON di openvas con il nome "normalized-"+nome in /public/normalized_json/nessus
        fs.writeFileSync('./public/normalized_json/nessus/normalized-'+filename, JSON.stringify(nessus_summary));

        /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto" in futuro
        while(!fs.existsSync('./public/normalized_json/nessus/normalized-'+filename)){
            //console.log('il file nmap non esiste', './public/json/'+filename)
        }*/

        return {
            message : "Nessus Summary!",
            summary : nessus_summary
        }
    }catch(error){
        console.log('error',error)
    }
 }






 /**
 * Effettua un'analisi del file JSON del tool OPENVAS e restituisce un JSON contenente le informazioni chiave
 * (Salva in /public/normalized_json/openvas/ il file normalizzato contenente solo le informazioni di nostro interesse)
 * @param {*} req openvas_file
 * @param {*} res 
 * @param {*} next 
 */
  exports.getOpenVasSummary = (filename) => {

    /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto"
    while(!fs.existsSync('./public/json/'+filename)){
        //console.log('il file openvas non esiste', './public/json/'+filename)
    }
    if(fs.existsSync('./public/json/'+filename)){
        //console.log('il file openvas esiste')
    }*/

    console.log('method() => getOpenVasSummary')

    let openvas_summary = {} //inizializza l'oggetto da restituire

    //Legge il file ports.json che contiene le coppie port/service (21/ftp)
    var ports_file = fs.readFileSync("./ports.json"); //ottiene un riferimento al file JSON delle porte
    ports_file_json = JSON.parse(ports_file) //converte l'oggetto JavaScript in un stringa JSON

    console.log('method() => ports.json')

    var openvas_refs =  fs.readFileSync("./public/json/"+filename); //ottiene un riferimento al file JSON di OPENVAS

    openvas_file_json = JSON.parse(openvas_refs) //converte l'oggetto JavaScript in un stringa JSON

    //TOOL UTILIZZATO
    openvas_summary.tool = "openvas"

    //COME E' STATO PARAMETRIZZATO OPENVAS
    openvas_summary.param = 'openvas '+openvas_file_json.report.report[0].filters[0].term[0]

    //DATA E ORA DELLA SCANSIONE
    openvas_summary.date = openvas_file_json.report.creation_time[0]

    //VULNERABILITA' E MITIGAZIONI
    openvas_file_json.report.report.forEach( report => {
        report.results.forEach( results => {
            let vulnerabilities = [] //costruisce un oggetto per ogni vulnerabilità
            results.result.forEach( async result => {

                let vuln = {} //costruisce un oggetto per ogni vulnerabilità
                vuln.host = result.host[0]._ //HOST A CUI FA RIFERIMENTO LA VULNERABILITA'

                //RECUPERA PORTA/SERVIZIO
                let index_of = result.port[0].indexOf("/") //recupera l'indice dello / in (es: 21/tcp)
                let port_number = result.port[0].slice(0,index_of)
                //console.log("*********INDEX_OF**********",port_number)
                let service = "";
                if(port_number != "general"){
                    //console.log('ports_file_json[port_number].name',ports_file_json[result.port[0].toString()].name)
                    service = ports_file_json[result.port[0].toString()].name;
                }else{
                    service = "tcp"
                }

                //console.log('port/service',port_number+"/"+service)

                vuln.service = port_number+"/"+service
                vuln.risk = result.name[0] //NOME DELLA VULNERABILITA'
                vuln.type = result.nvt[0].family[0] //CATEGORIA (TIPO) DI APPARTENENZA
                vuln.description = result.description[0]  //DESCRIZIONE DELLA VULNERABILITA' 
                let severity = ""
                if(result.nvt[0].severities[0].severity[0].score[0] <= 3.9)
                    severity = "Low";
                if(result.nvt[0].severities[0].severity[0].score[0] >= 4.0 && result.nvt[0].severities[0].severity[0].score[0] <=6.9)
                    severity = "Medium";
                if(result.nvt[0].severities[0].severity[0].score[0] >= 7.0)
                    severity = "High";
                vuln.cvss = result.nvt[0].severities[0].severity[0].score[0]+" "+severity+" "+result.nvt[0].severities[0].severity[0].value[0]  //VALORE CVSS_2.0 + VECTOR STRING

                if(result.nvt[0].refs != undefined){
                    let refs = [] //riferimenti agli archi CVE, RAPID7, EXPLOIT-DB, ecc...
                    if(result.nvt[0].refs[0].ref != undefined){
                        //console.log('REFS.REF',result.nvt[0].refs[0].ref[0].$.id)
                        refs.push(result.nvt[0].refs[0].ref[0].$.id)  //riferimenti agli archi CVE, RAPID7, EXPLOIT-DB, ecc...
                        vuln.refs = refs;  //riferimenti agli archi CVE, RAPID7, EXPLOIT-DB, ecc...
                    }   
                }

                vuln.solution = result.nvt[0].solution[0]._ //MITIGAZIONE PER LA VULNERABILITA' RISCONTRATA

                vulnerabilities.push(vuln);
                
            })
            openvas_summary.vulnerabilities = vulnerabilities
        })
    })

    //console.log('OpenVAS Summary', openvas_summary)

    //salva il file JSON di openvas con il nome "normalized-"+nome in /public/normalized_json/openvas
    fs.writeFileSync('./public/normalized_json/openvas/normalized-'+filename, JSON.stringify(openvas_summary));

    /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto" in futuro
    while(!fs.existsSync('./public/normalized_json/openvas/normalized-'+filename)){
        //console.log('il file nmap non esiste', './public/json/'+filename)
    }*/

    return {
        message : "OpenVAS Summary!",
        summary : openvas_summary
    }
 }











 /**
 * Effettua un'analisi del file JSON del tool OWASPZAP e restituisce un JSON contenente le informazioni chiave
 * (Salva in /public/normalized_json/owaspzap/ il file normalizzato contenente solo le informazioni di nostro interesse)
 * @param {*} req owaspzap_file
 * @param {*} res 
 * @param {*} next 
 */
  exports.getOwaspZapSummary = (filename) => {

    /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto"
    while(!fs.existsSync('./public/json/'+filename)){
        //console.log('il file owaspzap non esiste', './public/json/'+filename)
    }
    if(fs.existsSync('./public/json/'+filename)){
        //console.log('il file owaspzap esiste')
    }*/

    console.log('method() => getOwaspZapSummary')

    let owaspzap_summary = {} //inizializza l'oggetto da restituire

    //Legge il file ports.json che contiene le coppie port/service (21/ftp)
    var ports_file = fs.readFileSync("./ports.json"); //ottiene un riferimento al file JSON delle porte
    ports_file_json = JSON.parse(ports_file) //converte l'oggetto JavaScript in un stringa JSON

    console.log('method() => ports.json')

    var owaspzap_refs = fs.readFileSync("./public/json/"+filename); //ottiene un riferimento al file JSON di OWASPZAP

    owaspzap_file_json = JSON.parse(owaspzap_refs) //converte l'oggetto JavaScript in un stringa JSON

    owaspzap_summary.tool = "owaspzap v."+owaspzap_file_json.OWASPZAPReport.$.version  //TOOL + VERSIONE
    owaspzap_summary.date = owaspzap_file_json.OWASPZAPReport.$.generated  //DATA E ORA
    owaspzap_summary.param = "scanning via standard plugins" //PARAMETRI SCANSIONE (SCANSIONE TRAMITE WEB APP)

    //VULNERABILITA' RISCONTRATE
    let vulnerabilities = []; //array di vulnerabilità

    owaspzap_file_json.OWASPZAPReport.site.forEach( site => {

        let vuln = {}  //costruisce l'oggetto per ciascuna vulnerabilità

        let host = site.$.host  //HOST

        //RECUPERA PORTA/SERVIZIO
        console.log('port', site.$.port)
        let port = site.$.port        
        let service = "";
        if(port != "general"){
            if(ports_file_json[port.toString()+"/tcp"] != undefined)
                service = ports_file_json[port.toString()+"/tcp"].name;
            else
                service = "tcp"
        }else{
            service = "tcp"
        }

        let port_service = site.$.port+"/"+service  //PORTA + SERVIZIO

        site.alerts.forEach( alerts => {
            alerts.alertitem.forEach( alertitem => {

                let vuln = {}  //costruisce l'oggetto per ciascuna vulnerabilità

                vuln.host = host;
                vuln.service = port_service;
                
                vuln.risk = alertitem.name[0]
                //console.log("******vuln risk", alertitem.name[0])
                vuln.type = alertitem.alert[0]
                vuln.description = alertitem.desc[0].replace( /(<([^>]+)>)/ig, '') //replace rimuove i tag HTML
                vuln.cvss = alertitem.riskdesc[0]
                vuln.solution = alertitem.solution[0].replace( /(<([^>]+)>)/ig, '') //replace rimuove i tag HTML

                vuln.refs = []

                //refs = [] //riferimenti

                //RIFERIMENTI
                alertitem.reference.forEach(reference => {

                    //console.log('reference before', reference)
                    reference = reference.replace( /(<([^>]+)>)/ig, '') //replace rimuove i tag HTML
                    refs = reference.split("http") //SEPARA I VARI PARAGRAFI HTML CONTENENTI I DIVERSI LINK
                    refs.shift()  //RIMUOVE IL PRIMO ELEMENTO CHE E' VUOTO
                    refs.forEach( r => {
                        r = "http"+r     //AGGIUNGE L'INTESTAZIONE HTTP AD OGNI LINK (CANCELLATA IN PRECEDENZA DAL METODO SPLIT)
                        vuln.refs.push(r)
                    })
                    
                })                

                //EXPLOIT e INFO AGGIUNTIVE
                alertitem.instances.forEach( instances => {
                    instances.instance.forEach( instance => {
                        vuln.exploit = instance.attack[0]
                        vuln.evidence = instance.evidence[0]
                    })
                })

                vulnerabilities.push(vuln)
                                
            })
        })
    })

    owaspzap_summary.vulnerabilities = vulnerabilities  //Inserisce l'array di vulnerabilità nell'oggetto json

    //console.log('OwaspZAP Summary', owaspzap_summary)

    //salva il file JSON di openvas con il nome "normalized-"+nome in /public/normalized_json/owaspzap
    fs.writeFileSync('./public/normalized_json/owaspzap/normalized-'+filename, JSON.stringify(owaspzap_summary));

    /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere un file "non pronto" in futuro
    while(!fs.existsSync('./public/normalized_json/owaspzap/normalized-'+filename)){
        //console.log('il file nmap non esiste', './public/json/'+filename)
    }*/

    return{
        message : "OwaspZAP Summary!",
        summary : owaspzap_summary
    }
}





/**
 * Riceve in input un array di oggetti del tipo [{ tool: 'nmap', name : 'nmap-file.xml' }] e per ciascuno degli oggetti
 * converte il file XML in JSON per poi salvarli nella directory public/json
 * @param {*} req xmls
 * @param {*} res 
 * @param {*} next 
 */
 exports.XML2JSON = (xmls) => {

    console.log('method() => XML2JSON')

    //xmls contiene le caratteristiche dei documenti XML caricati dal client tramite il form
    //console.log("XMLS documents", xmls)

    var parse = new Map()

    //Per ogni file che è stato caricato dall'utente tramite il form
    xmls.forEach( async function(file) {

        //console.log('xmls file in forEach: ', file.name)

        var filename = file.name; //ricostruisce il nome del file
        
        var xml_file = fs.readFileSync("./public/xmls/" + filename); //ottiene un riferimento al file

        // convert XML to JSON
        xml2js.parseString(xml_file, (err, result) => {
            // `result` is a JavaScript object
            // convert it to a JSON string
            const json = JSON.stringify(result, null, 4);
            parse.set(file.tool, {
                xml2json : json,
                filename : file.name,
                tool : file.tool
            })
        });

    })

    //console.log('parse', parse)

    /**Scrittura dei vari files in public/json */
    if(parse.has('nmap')){
        //console.log('key nmap')
        fs.writeFileSync('./public/json/'+parse.get('nmap').filename.replace('.xml','.json'), parse.get('nmap').xml2json);  //salva il file con l'estensione.json in public/json
    }
    if(parse.has('openvas')){
        //console.log('key openvas')
        fs.writeFileSync('./public/json/'+parse.get('openvas').filename.replace('.xml','.json'), parse.get('openvas').xml2json);  //salva il file con l'estensione.json in public/json
    }
    if(parse.has('owaspzap')){
        //console.log('key owaspzap')
        fs.writeFileSync('./public/json/'+parse.get('owaspzap').filename.replace('.xml','.json'), parse.get('owaspzap').xml2json);  //salva il file con l'estensione.json in public/json

    }
    if(parse.has('nessus')){
        //console.log('key nessus')
        fs.writeFileSync('./public/json/'+parse.get('nessus').filename.replace('.xml','.json'), parse.get('nessus').xml2json);  //salva il file con l'estensione.json in public/json
    }
    
    return;

}







/**  
  * Aggiunge un ID per ciascuna vulnerabilità presente nel merged_summary (utile per la UI di DevGrid lato client)
  *
  * @param {*} req merged_summary
  * @param {*} res 
  * @param {*} next 
  */
 exports.setVulnID = (merged_summary) => {

    console.log('method() => setVulnID')

    //scandisce tutte le proprietà in vulnerabilities (equivale a ciascun host) e aggiunge un ID per ciascuna vulnerabilità
    for (var host in merged_summary.summary.vulnerabilities) {
        //console.log(' name=' + host + ' value=' + merged_summary.summary.vulnerabilities[host]);
        //scandisce tutte le proprietà dell'oggetto host (equivale ad ogni servizio di quell'host)
        for (var service in merged_summary.summary.vulnerabilities[host]) {

            console.log('DIOOOOOOOOOOOO vulnerabilities 1', global.id_vuln)
            merged_summary.summary.vulnerabilities[host][service].forEach( vuln => {
            vuln.id = global.id_vuln; //aggiunge l'ID a ciascuna vulnerabilità (richiesta da DevGridExtreme lato client per la gestione dei dati)
            global.id_vuln++;
            })
        }
    }

    return merged_summary
}
