/**
 * 
 * refactoring: modulo che per ogni file normalizzato utilizza una particolare tecnica di mappatura. Il modulo in questione è in grado di raggruppare le vulnerbilità in termini di host - service - type;
 * 
 */


const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const xml2js = require('xml2js'); //permette di convertire file XML in JSON
const global = require('../utils/global')

/* Costruisce una coppia di MAP: il primo ha come chiave l’ HOST e come valore un nuovo Map contenente una coppia chiave-valore composto da (key : port/servizio, value: vulnerabilità relativa a quell’host+porta). 
 * Esempio: vulnerabilities: Map( key : 192.168.81.131, value : Map( key: 21/tcp, value : [host: 192.168.81.131, service: 80/http, version: ‘Apache http 2.2.8’, risk: ‘http-server-header’, . . .]))
 * @param {*} req { flag_nmap, flag_nessus, flag_openvas, flag_owaspzap }
 * @param {*} res 
 * @param {*} next 
 */
 /* ottiene un main_summary del genere (un MAP per ogni IP e per ognuno di essi un MAP per ogni servizio)
    *
    * {
    *    tool: 'nmap v.7.92',
    *    param: 'nmap -Pn -p- -A --script=vuln -oX NMAP-MS1-192.168.81.131.xml 192.168.81.131',
    *    date: 'Tue Sep 13 06:47:57 2022',
    *    addresses: [ '192.168.81.131' ],
    *    vulnerabilities: Map(1) {
    *        '192.168.81.131' => Map(13) {
    *            '21/ftp' => [Array],
    *            '22/ssh' => [Array],
    *            '23/telnet' => [Array],
    *            '25/smtp' => [Array],
    *            '53/domain' => [Array],
    *            '80/http' => [Array],
    *            '139/netbios-ssn' => [Array],
    *            '445/netbios-ssn' => [Array],
    *            '3306/mysql' => [Array],
    *            '3632/distccd' => [Array],
    *            '5432/postgresql' => [Array],
    *            '8009/ajp13' => [Array],
    *            '8180/http' => [Array]
    *        }
    *    },
    *    os_type: 'Linux'
    * }
    *
    * */
 exports.getMapAddress_Service = (summary) => {

    console.log('method() => getMapAddress_Service')

    let main_map = new Map()  //costruisce un MAP per ogni host
    let second_map = new Map()  //a cui collega un MAP per ogni servizio relativo a quell'host

    //console.log('mappe', summary.summary)

    summary.summary.vulnerabilities.forEach( vuln => {

        //console.log('vuln', vuln)

        let address = vuln.host  //recupera IP 
        let service = vuln.service  //recupera port+service

        //console.log('vuln address and vul service', address, service)

        if(!main_map.has((address))){ //se l'indirizzo non è presente nel main_map

            //console.log('main_map have not '+address+' address')

            second_map = new Map() //per ogni indirizzo nuovo va costruito un second_map 

            //dobbiamo creare una nuova entry con tutte le vulnerabilità associate a tale indirizzo
            summary.summary.vulnerabilities.forEach( vulnerability => {

                //console.log('analyzing all vulnerabilities')
               
                if(vulnerability.host == address){   //DATO CHE STIAMO COSTRUENDO IL MAP DI ADDRESS, CI INTERESSANO SOLO LE VULNERABILITA' ASSOCIATE A TALE INDIRIZZO IP

                    //console.log('this vulnerability has the address target like host', vulnerability.host)

                    if(!second_map.has(vulnerability.service)){  //se nel map relativo ai servizi tale combo port+service ancora non è presente allora aggiungilo con un push
                        //console.log('summary have no data for service', vulnerability.service)
                        second_map.set(vulnerability.service,[vulnerability])
                        //console.log('setting a second_map for the first time', second_map)
                    }else{ //se la combo port+service è già presente, allora aggiungiamo l'elemento all'array associato a quella chiave
                        //console.log('setting a second_map for the second time, i go into the else brackets', second_map.get(service))
                        second_map.set(vulnerability.service, [...second_map.get(vulnerability.service), vulnerability])
                        //console.log('operation in the else brackets completed')
                    }
                }

            })

            //console.log('main_map.set', second_map)
            
            main_map.set(address, second_map) //se l'indirizzo non è presente allora lo aggiungiamo con tutti i suoi services
            //console.log('MAPPAZZONE', JSON.stringify(main_map))

        }
    })

    //console.log('MAPPAZZONE', JSON.stringify(main_map))

    return main_map;

}








/**
 * Riceve in input il summary contenente le coppie key:value tra address => (service => vulnerability) e li trasforma
 * in array di oggetti in modo che poi il JSON possa essere scritto nel file nel modo corretto
 * @param {*} req nessus_file
 * @param {*} res 
 * @param {*} next 
 */
/* ottiene un main_summary del genere
    *
     *  * {
        tool: 'nmap v.7.92',
        param: 'nmap -Pn -p- -A --script=vuln -oX NMAP-MS1-192.168.81.131.xml 192.168.81.131',
        date: 'Tue Sep 13 06:47:57 2022',
        addresses: [ '192.168.81.131' ],
        vulnerabilities: {
            '192.168.81.131': {
            '21/ftp': [Array],
            '22/ssh': [Array],
             ...
            }
        },
        os_type: 'Linux'
        }
    * */
    exports.Map2JSON = (summary) => {

        console.log('method() => Map2JSON')
    
        let s = {}  //sarà un oggetto contenente una serie di proprietà host, per ognuno dei quali ci sarà una proprietà "port/service" alla quale corrisponderà un array di vulnerabilità
    
        let addresses = [] //array di address
    
        iterator = summary.summary.vulnerabilities
    
        iterator.forEach((services_map, address_key) => {
    
            s[address_key] = {} //inizializza una proprietà per ogni host
    
            global.hosts.push(address_key) //salva in un array globale la lista degli host della scansione
    
            services_map.forEach((service,service_key) => {
                //console.log('summary.vulnerabilities', summary.vulnerabilities.address_key[service_key])
                //console.log('service', service)
                
                let vulnerabilities = services_map.get(service_key) //array di vulnerabilità per ogni servizio
                s[address_key][service_key] = {}  //inizializza una proprietà per ogni servizio
                s[address_key][service_key] = vulnerabilities  //e gli assegna l'array di vulnerabilità associato
    
                //console.log('vulnerabilities summary', s)
            })
            
        })
    
        return s
    
            /* 
        *  {
        *    vulnerabilities: {
        *           192.168.81.131 : {
        * 
        *               21/ftp : [
        * 
        *                       {vuln1}, {vuln2}, ....
        * 
        *                  ]
        * 
        *            }
        *       }  
        *    }
        *
        * 
        * 
        * */
    
    }








/**
 * Prende in input lo short_summary del punto (10. removeDuplicatesByDescriptions(merged_summary) - return short_summary) e raggruppa le vulnerabilità relative ad ogni HOST/SERVICE in base al tipo, aggiungendo un ulteriore livello di profondità al file JSON risultante e salva il report in //salva il report risultante nella directory public/x_summary/.
 * Costruisce un oggetto di questo tipo:
 * 
 {
  short_summary: {
    date: ”Tue, 20 Sep 2022 13:52:59”,
    vulnerabilities: {
        "192.168.81.131": {
          	    "80/http" : {
                    “Web application abuses”: [ 
                                    {
                                    id : 120,
                                    host : "192.168.81.131",
                                    service : "80/http",
                                    cvss : "6.0 Medium AV:N/AC:M/Au:S/C:P/I:P/A:P || unknown“,
                                    description : "The following input fields where identified (URL:input name):http://192.168.81.131/twiki/bin/view/TWiki/TWikiUserAuthentication:oldpassword",
                                    solution : "Enforce the transmission of sensitive data via an encrypted SSL/TLS connection. Additionally make sure the host / application is redirecting all users to the secured SSL/TLS connection… || “n/a,
                                    risk : "Cleartext Transmission of Sensitive Information via HTTP || “unknown,
                                    type : "Web application abuses || “unknown,
                                    refs : ["https://www.owasp.org/index.php/Top_10_2013-A2-Broken_Authentication_and_Session_Management"],
                                    id_cve : [“CVE-2018-20212”, “CVE-2020-16131”]
                                    }
                    ]
                } 
        }
    }
  }
}
 * 
 * @param {*} req short_summary
 * @param {*} res 
 * @param {*} next 
 */
exports.groupsByType = (short_summary) => {

    console.log('method() => groupsByType');

    x_summary = {} //inizializza quello che dovrebbe essere il summary finale
    x_summary.date = new Date(); //data e ora della scansione
    x_summary.vulnerabilities = {} //inizializza l'oggetto relativo alle vulnerabilità

    //inizializza per vulnerabilities l'HOST, il SERVICE e i diversi TYPE per ogni HOST+SERVICE
    for(var host in short_summary.vulnerabilities){
        x_summary.vulnerabilities[host] = {} //inizializza ogni host
        for(var service in short_summary.vulnerabilities[host]){
            x_summary.vulnerabilities[host][service] = {}  //inizializza ogni host+service
            vuln_types = [];
            vuln_types = this.getVulnTypesByHostAndService(short_summary, host, service) //restituisce la lista dei valori della proprietà "type" delle diverse vulnerabilità di uno specifico host su uno specifico servizio (porta)
            //console.log('xcss_vulnerabilities type', vuln_types)
            for(let i=0; i < vuln_types.length; i++){
                //console.log('vulnerabilities type', host, service, vuln_types[i])
                x_summary.vulnerabilities[host][service][vuln_types[i]] = []  //inizializza ogni host+service+type

                //PER OGNI TIPO, ITERA TUTTE LE VULNERABILITA' SU QUELL HOST E SU QUELLA PORTA: SE LA VULNERABILITA' COINCIDE CON IL TIPO IN ESAME, ALLORA INSERISCE LA VULNERABILITA' NELL'ARRAY
                short_summary.vulnerabilities[host][service].forEach( bug => {
                    if(bug.type == vuln_types[i]){
                        x_summary.vulnerabilities[host][service][vuln_types[i]].push(bug)
                    }
                })
            }
            
        }
    }

    //salva il report risultante nella directory public/x_summary/
    fs.writeFileSync('./public/x_summary/x_summary_'+global.id_scan+'.json', JSON.stringify(x_summary))

    return x_summary

  }






/**  
  * Restituisce un'array di stringhe che riguardano il contenuto della proprietà type relativa alle diverse vulnerabilità in esame di uno specifico host su uno specifico servizio (porta)
  *
  * @param {*} req short_summary
  * @param {*} res 
  * @param {*} next 
  */
 exports.getVulnTypesByHostAndService = (short_summary, host, service) => {

    //console.log('method() => getVulnTypes', vuln_types, host, service)
 
    vuln_types = new Set() //inizializza quello che dovrebbe essere il set di vulnerabilità

    //console.log('method() => builDescDictionary => else{service}', merged_file_json.vulnerabilities[host][service])
    short_summary.vulnerabilities[host][service].forEach( vuln => {
        //if(!vuln_types.has(vuln.type))  //se la vulnerabilità non è presente nel set allora l'aggiunge altrimenti non fa niente
        vuln_types.add(vuln.type)
    })

    //rimuove eventuali elementi NULL dall'array
    vuln_types = [...vuln_types]
    vuln_types = vuln_types.filter( function (el) {
        return el != null;
    })

    return vuln_types;
 
   }




/*A partire dal file ports.json genera il file porteJS.json con le coppie porta/servizio*/
function generatePortServiceJSON(){

    //Legge il file ports.json che contiene le coppie port/service (21/ftp)
    var ports_file = fs.readFileSync("./ports.json"); //ottiene un riferimento al file JSON delle porte
    var ports_file_json = JSON.parse(ports_file) //converte l'oggetto JavaScript in un stringa JSON

    //console.log('ports_file_json',ports_file_json)

    array = new Set()

    for(port in ports_file_json){
        //console.log('port',ports_file_json[port])
        p = port.split('/')
        //console.log('p',p[0])
        service = ports_file_json[port].name
        //console.log('service',service)
        if(service=='')
            service = 'tcp'
        array.add(p[0]+'/'+service)
    }

    array.add('general/tcp')

    console.log('set', array)

    fs.writeFileSync('../porteJS.json', JSON.stringify([...array]))

}


