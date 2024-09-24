/**
 * 
 * dict: modulo relativo alla costruzione dei dizionari, utili per la rimozione dei duplicati e per la classificazione dei tipi di vulnerabilità;
 * 
 */

const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)

/**
 * Riceve in input i summaries relativi a NMAP, Nessus, OpenVAS e OWASP ZAP. Sulla base delle descrizioni costruisce un dizionario 
 * contenente tutte le descrizioni, in modo da poterlo utilizzare di seguito per il join delle vulnerabilità
 * @param {*} req all_summaries
 * @param {*} res 
 * @param {*} next 
 */
/**/ 
exports.buildDescDictionary = (merged_summary) => {

    console.log('method() => builDescDictionary')

    //Se il file relativo al dizionario (/public/dictionary/description.json) è già presente allora viene letto, il suo contenuto convertito in JSON e poi in set(), vengono aggiunte le nuove descrizioni alla struttura dati e sovrascritto il file originale aggiungendo alle descrizioni precedenti tutte quelle nuove relative all’ultima richiesta da parte del client.
    if(fs.existsSync('./public/dictionary/description.json')){

        //Legge il file description.json che contiene un'array di descrizioni recuperate dalle vulnerabilità che sono state esaminate in passato
        var dictionary_file = fs.readFileSync("./public/dictionary/description.json"); //ottiene un riferimento al file JSON del dizionario delle descrizioni
        dict = JSON.parse(dictionary_file) //converte l'oggetto JavaScript in un stringa JSON

        //console.log('method() => builDescDictionary => dict', dict)
        var set = new Set(dict) //inizializza un insieme che dovrà contenere tutte le descrizioni univoche

        //console.log('method() => builDescDictionary => set', set)

        for(var host in merged_summary.vulnerabilities){
            //console.log('method() => builDescDictionary => else{host}', host)
            for(var service in merged_summary.vulnerabilities[host]){
                //console.log('method() => builDescDictionary => else{service}', merged_file_json.vulnerabilities[host][service])
                merged_summary.vulnerabilities[host][service].forEach( vuln => {
                    if(!set.has(vuln.description))  //se la vulnerabilità non è presente nel set allora l'aggiunge altrimenti non fa niente
                        set.add(vuln.description)
                })
            }
        }

        //rimuove eventuali elementi NULL dall'array
        set = [...set]
        set = set.filter( function (el) {
            return el != null;
        })

        //salva il dizionario relativo alle descrizioni dopo averlo convertito in JSON
        fs.writeFileSync('./public/dictionary/description.json', JSON.stringify(Array.from(set)))

        /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere il dizionario quando ancora non è pronto
        while(!fs.existsSync('./public/dictionary/description.json')){
            //console.log('il file description.js non è stato ancora caricato', './public/json/'+filename)
        }*/

        //console.log('il file owaspzap esiste')
    }else{  //se il file relativo al dizionario (/public/dictionary/description.json) non esiste ancora allora procede nella scrittura del set() con le descrizioni dei documenti caricati durante tale sessione client-server.
        console.log('method() => builDescDictionary => file /public/dictionary/description.json non trovato!')

        set = new Set()  //inizializza un insieme che dovrà contenere tutte le descrizioni univoche

        //Se è stato costruito il dizionario solo su un host (potrebbe essere MS1 o MS2) allora bisogna mettere in append le description dell'altro host 
        //nel caso in cui dovesse essere caricato
        console.log('method() => builDescDictionary => else{}', merged_summary)

        for(var host in merged_summary.vulnerabilities){
            //console.log('method() => builDescDictionary => else{host}', host)
            for(var service in merged_summary.vulnerabilities[host]){
                //console.log('method() => builDescDictionary => else{service}', merged_file_json.vulnerabilities[host][service])
                merged_summary.vulnerabilities[host][service].forEach( vuln => {
                    set.add(vuln.description)
                })
            }
        }

        //rimuove eventuali elementi NULL dall'array
        set = [...set]
        set = set.filter( function (el) {
            return el != null;
        })

        //salva il dizionario relativo alle descrizioni dopo averlo convertito in JSON
        fs.writeFileSync('./public/dictionary/description.json', JSON.stringify(Array.from(set)))

        /*Itera finché il file non è stato scritto per evitare di avere errori nel tentativo di leggere il dizionario quando ancora non è pronto
        while(!fs.existsSync('./public/dictionary/description.json')){
            //console.log('il file description.js non è stato ancora caricato', './public/json/'+filename)
        }*/

    }

    return set
}
               