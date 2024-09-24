/**
 * 
 * optimizer: modulo che si occupa di rimuovere campi vuoti o oggetti relativi a possibili errori dalla lista dei risultati che il report poi andrà a fornire al penetration tester tramite UI;
 * 
 */

const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const global = require('../utils/global')

/**
 * Il metodo in questione si occupa di analizzare il file “merged” costruito nel punto (8. getMergedSummary = (main_summary, other_summaries)).
 * Costruisco uno short_summary dove per ciascuna descrizione nel dizionario ricerco tutte le vulnerabilità che hanno la stessa proprietà “description”, unisco le informazioni e aggiungo la vulnerabilità nel nuovo summary.
 * @param {*} req (set) description_dict, merged_summary
 * @param {*} res 
 * @param {*} next 
 */
 exports.removeDuplicatesByDescriptions = (description_dict, merged_summary) => {

    console.log('method() => removeDuplicatesByDescriptions')

    //Per ogni descrizione presente nel dizionario..
    let dict = [...description_dict]

    let short_summary = {} //inizializza uno short_summary
    short_summary.date = new Date(); //aggiunge la proprietà relativa alla data di scansione
    short_summary.vulnerabilities = {}
    for(var host in merged_summary.vulnerabilities){
        short_summary.vulnerabilities[host] = {} //inizializza host
        for(var service in merged_summary.vulnerabilities[host]){
            short_summary.vulnerabilities[host][service] = [] //inizializza servizio/porta
        }
    }

    //console.log('method() => removeDuplicatesByDescriptions => short_summary => before', short_summary)

    dict.forEach( description => {
        for(var host in merged_summary.vulnerabilities){
            for(var service in merged_summary.vulnerabilities[host]){
                x = [] //array contenente tutte le vulnerabilità da unire
                merged_summary.vulnerabilities[host][service].forEach( vuln => {
                //for(var vuln in merged_summary.vulnerabilities[host][service]){
                if(description == vuln.description){
                    //console.log('description match 104', vuln)
                    x.push(vuln)
                }
                })
                //}
                if(x.length >= 1){  //se ci sono dei duplicati, bisogna scriverne solo uno
                    //console.log('x > 1, vuln da unire (e capit eh)', x)

                    /*CAMPI SU CUI POTER FARE IL JOIN
                        id : 0,
                        host : "192.168.81.131",
                        service : "80/http",
                        version (?),
                        cvss : "6.0 Medium AV:N/AC:M/Au:S/C:P/I:P/A:P",
                        description : "The following input fields where identified (URL:input name):http://192.168.81.131/twiki/bin/view/TWiki/TWikiUserAuthentication:oldpassword",
                        solution : "Enforce the transmission of sensitive data via an encrypted SSL/TLS connection. Additionally make sure the host / application is redirecting all users to the secured SSL/TLS connection…",
                        risk : "Cleartext Transmission of Sensitive Information via HTTP",
                        type : "Web application abuses",
                        refs : ["https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_Management"],
                        id_cve (?),
                        exploit_flag (?)*/
                        /**
                         * costruzione della short vulnerability prendiamo in esame tutti i campi della vulnerabilità e per ognuna vediamo se "la prima replica" contiene tale informazione:
                         * --> se la contiene allora si passa al successivo attributo
                         * --> se non la contiene si vede se l'informazione è presente nella "seconda replica", "terza replica", e così via..
                         * field: id, host, service, version, cvss, description, solution, risk, type, refs, id_cve, exploit_flag.
                         * Nota: per il campo refs[] contenente i riferimenti agli archivi dai quali viene fuori la vulnerabilità, non si procede per "integrazione" bensì costruiamo un nuovo array refs = [cve1, cve2, ...] contenente tutte i riferimenti a tutti i cve suggeriti da ogni replica. Inoltre, tutti i riferimenti ad archivi come ad esempio "CVE-2007-6750" che non sono link, vengono inseriti in id_cve.
                         * */

                        j_vuln = {}  //temp vulnerability
                        j_vuln.id = x[0].id  //ID: va bene anche l'ID del primo elemento che matcha (irrilevante)
                        j_vuln.host = x[0].host //HOST: l'host coincide per tutte le ridondanze
                        j_vuln.service = x[0].service //SERVICE: il servizio/porta coincide per tutte le ridondanze
                        j_vuln.description = x[0].description //DESCRIPTION: la descrizione è il criterio del match ed è uguale per tutti

                        //CVSS: se il primo elemento dell'array non contiene tale proprietà, verifica nel secondo, poi il terzo, e così via...se nessuno contiene tale informazione, inserisce unknown
                        for(let i=0; i<x.length; i++){
                            if(x[i].cvss != undefined){
                                //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].cvss)
                                j_vuln.cvss = x[i].cvss
                                break;
                            }
                        }
                        if(j_vuln.cvss == undefined){
                            j_vuln.cvss = 'unknown'
                        }

                        //SOLUTION: se il primo elemento dell'array non contiene tale proprietà, verifica nel secondo, poi il terzo, e così via...se nessuno contiene tale informazione, inserisce n/a (alcuni già ce l'hanno)
                        for(let i=0; i<x.length; i++){
                            if(x[i].solution != undefined && x[i].solution != 'n/a'){
                                //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].solution)
                                j_vuln.solution = x[i].solution
                                break;
                            }
                        }
                        if(j_vuln.solution == undefined){
                            j_vuln.solution = 'n/a'
                        }

                        //RISK: se il primo elemento dell'array non contiene tale proprietà, verifica nel secondo, poi il terzo, e così via...se nessuno contiene tale informazione, inserisce unknown
                        for(let i=0; i<x.length; i++){
                            if(x[i].risk != undefined){
                                //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].risk)
                                j_vuln.risk = x[i].risk
                                break;
                            }
                        }
                        if(j_vuln.risk == undefined){
                            j_vuln.risk = 'unknown'
                        }

                        //TYPE: se il primo elemento dell'array non contiene tale proprietà, verifica nel secondo, poi il terzo, e così via...se nessuno contiene tale informazione, inserisce unknown
                        for(let i=0; i<x.length; i++){
                            if(x[i].type != undefined){
                                //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].risk)
                                j_vuln.type = x[i].type
                                break;
                            }
                        }
                        if(j_vuln.type == undefined){
                            j_vuln.type = 'unknown'
                        }

                        //REFS + ID_CVE: mette in append i link di tutti gli elementi in comune per creare un refs più esaustivo (con duplicati rimossi).
                        //Se tra i refs ci sono dei CVE oppure dei IAVA, li inseriamo nell'attributo id_cve
                        //In alcuni casi diversi CVE sono divisi dal simbolo \n ma fanno parte di una singola stringa "http://vuln1\nhttp://vuln2" => andiamo a separarli
                        let refs = new Set() //set => se inserisco più volte lo stesso elemento (stesso riferimento) mantiene una sola istanza
                        j_vuln.id_cve = new Set()
                        j_vuln.refs = new Set()

                        for(let i=0; i<x.length; i++){
                            //console.log('x[i]_xX',x[i].refs)
                            if(x[i].refs != undefined){
                                x[i].refs.forEach(r => {
                                    split_refs = [] = r.split('\n') //separa le vulnerabilità rappresentate su una singola stringa e separate da \n

                                    split_refs.forEach(refer => {
                                        //console.log('refer', refer)
                                        if(refer.includes('http')){
                                            j_vuln.refs.add(refer)  //se è un link va nei riferimenti
                                        }else{
                                            j_vuln.id_cve.add(refer)  //altrimenti se è l'id di un archivio va in id_cve
                                        }
                                    })
                                    //refs.add(...split_refs)  //splitta l'array e inserisce le varie istanze in refs
                                })
                            }
                            /*x[i].refs.forEach(r => {
                                refs.add(r)
                            })*/
                        }
                        j_vuln.refs = [...j_vuln.refs]
                        j_vuln.id_cve = [...j_vuln.id_cve]
                        //j_vuln.refs = [...refs]
                        //console.log('x[i]_o=',j_vuln.refs)

                    short_summary.vulnerabilities[host][service].push(j_vuln)
                }
            }
        }
    })

    //aggiungere tutte le vulnerabilità che hanno descrizione undefined, settando tutti i campi required come nel caso != undefined
    for(var host in merged_summary.vulnerabilities){
        for(var service in merged_summary.vulnerabilities[host]){
            merged_summary.vulnerabilities[host][service].forEach( vuln => {
                //for(var vuln in merged_summary.vulnerabilities[host][service]){
                if(vuln.description == undefined){
                    //console.log('description is undefined in ['+host+']['+service+']['+vuln.id+']', vuln)
                    
                    j_vuln = {}  //temp vulnerability
                    j_vuln.id = parseInt(vuln.id) //ID
                    j_vuln.host = vuln.host //HOST
                    j_vuln.service = vuln.service //SERVICE
                    j_vuln.description = 'unknown' //DESCRIPTION (dato che è undefined inseriamo unknown)

                    //CVSS: se la vulnerabilità non contiene tale proprietà inserisce unknown
                    if(vuln.cvss != undefined){
                        j_vuln.cvss = vuln.cvss
                    }else{
                        j_vuln.cvss = 'unknown'
                    }

                    //SOLUTION: se la vulnerabilità non contiene tale informazione inserisce n/a (alcuni già ce l'hanno)
                    if(vuln.solution != undefined && vuln.solution != 'n/a'){
                        //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].solution)
                        j_vuln.solution = vuln.solution
                        
                    }else{
                        j_vuln.solution = 'n/a'
                    }

                    //RISK: se la vulnerabilità non contiene tale proprietà inserisce unknown
                    if(vuln.risk != undefined){
                        //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].risk)
                        j_vuln.risk = vuln.risk
                    }else{
                        j_vuln.risk = 'unknown'
                    }

                    //TYPE: se la vulnerabilità non contiene tale proprietà inserisce unknown (se si tratta di informazioni estratte da nmap inserisce la versione che presenta la vulnerabilità)
                    if(vuln.type != undefined){
                        //console.log('entrato ['+x[i].host+'] ['+x[i].service+'] ['+x[i].id+']', x[i].type)
                        j_vuln.type = vuln.type
                    }else{
                        j_vuln.type = vuln.version != undefined ? vuln.version : 'unknown'
                    }

                    //REFS + ID_CVE: mette in append i link di tutti gli elementi in comune per creare un refs più esaustivo (con duplicati rimossi).
                    //Se tra i refs ci sono dei CVE oppure dei IAVA, li inseriamo nell'attributo id_cve
                    //In alcuni casi diversi CVE sono divisi dal simbolo \n ma fanno parte di una singola stringa "http://vuln1\nhttp://vuln2" => andiamo a separarli
                    let refs = new Set() //set => se inserisco più volte lo stesso elemento (stesso riferimento) mantiene una sola istanza
                    j_vuln.id_cve = new Set()
                    j_vuln.refs = new Set()

                    //console.log('x[i]_xX',x[i].refs)
                    if(vuln.refs != undefined){
                        vuln.refs.forEach(r => {
                            split_refs = [] = r.split('\n') //separa le vulnerabilità rappresentate su una singola stringa e separate da \n

                            split_refs.forEach(refer => {
                                //console.log('refer', refer)
                                if(refer.includes('http')){
                                    j_vuln.refs.add(refer)  //se è un link va nei riferimenti
                                }else{
                                    j_vuln.id_cve.add(refer)  //altrimenti se è l'id di un archivio va in id_cve
                                }
                            })
                        })
                    }

                    j_vuln.refs = [...j_vuln.refs]
                    j_vuln.id_cve = [...j_vuln.id_cve]
                    //j_vuln.refs = [...refs]
                    //console.log('x[i]_o=',j_vuln.refs)

                    short_summary.vulnerabilities[host][service].push(j_vuln)
                }
            })
        }
    }

    return short_summary

  }











/**
     *  Rimuove tutti i reports che restituiscono oggetti di errore (
     * 
    * 
    * @param {*} req reference_reports
    * @param {*} res 
    * @param {*} next 
 */
 exports.removeIncompleteReports = (reference_reports) => {

    console.log('(2) => method() => webScraping => removeIncompleteReports')

    var temp = [] //risultato contenente solo i report senza errori

    for(let i=0; i<reference_reports.length; i++){
        var item = reference_reports[i]
        if(item.error == undefined){  //se il report non presenta degli errori allora lo inserisce in temp 
            temp.push(item)
        }
    }

    return temp

}