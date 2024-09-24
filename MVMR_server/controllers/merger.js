/**
 * 
 * merger: modulo che si occupa delle operazioni di fusione a partire dai diversi report;
 * 
 */

const fs = require('fs');  //permette di accedere al filesystem (lettura, scrittura)
const global = require('../utils/global')
const refactoring = require('./refactoring')

/*Stringhe per effettuare il controllo riguardo al dominio da cui si recuperano le informazioni*/
const CVE = 'CVE'
const REDHAT = 'RedHat'
const APACHE = 'Apache Tomcat'
const CVE_IBM = 'CVE IBM Cloud'



/* Costruisce un summary complessivo risultante dalla fusione dei vari summary NMAP, OPENVAS, OWASPZAP E NESSUS
 * e salva il risultato nella directory public/merged_summary/
 * @param {*} req { flag_nmap, flag_nessus, flag_openvas, flag_owaspzap }
 * @param {*} res 
 * @param {*} next 
 * 
 * NMAP > OWASPZAP > OPENVAS > NESSUS
 * 
 * Ordine preferenza per il merge:
 * NMAP > OTHER TOOLS
 * se non c'è NMAP...
 * OWASPZAP > OTHER TOOLS (NESSUS + OPENVAS)
 * se non ci sono nè NMAP nè OWASPZAP...
 * OPENVAS > NESSUS
 * se non ci sono nè NMAP nè OWASPZAP né OPENVAS
 * NESSUS
 * 
 */
exports.getMergedSummary = (main_summary, other_summaries) => {

    let merged_summary = {}


    main_summary.summary.vulnerabilities = refactoring.getMapAddress_Service(main_summary) //refactoring dell'array vulnerabilities: viene trasformato in un Map in cui per ogni key address ha un map (port/service -> vulnerabilities)
    //console.log('main_summary after getMapAddress_Service', main_summary)
    other_summaries.forEach( summary => {
        summary.summary.vulnerabilities = refactoring.getMapAddress_Service(summary)  //refactoring dell'array vulnerabilities: viene trasformato in un Map in cui per ogni key address ha un map (port/service -> vulnerabilities)
        //console.log('other_summary after getMapAddress_Service',summary)
    })

    main_summary.summary.vulnerabilities.forEach( (host, host_key) => {  //scandisce tutti gli host relativi al summary principale
        //console.log('hosts', host, host_key)
        host.forEach( (main_service, main_service_key) => { //scandisce tutti i servizi del report principale
            //console.log('main_services', main_service, main_service_key)
                
            other_summaries.forEach( summary => {
                console.log('key', host_key)
                console.log('secondary_report', summary.summary.vulnerabilities.get(host_key))
                if(summary.summary.vulnerabilities.get(host_key)!=null && summary.summary.vulnerabilities.get(host_key)!=undefined){
                summary.summary.vulnerabilities.get(host_key).forEach( (secondary_service, secondary_service_key) => {  //ottiene il riferimento all'host esaminato nel main report e restituisce tutti i servizi ad esso associato
                    //console.log('secondary_service_key', secondary_service, secondary_service_key)
                    if(secondary_service_key == main_service_key){   //se la chiave nel report secondario è presente nel MAP del report principale...
                        //fonde le vulnerabilità presenti nei due report
                       // console.log('unisco le vulnerabilità')
                        main_service = [...main_service, ...secondary_service] 
                        main_summary.summary.vulnerabilities.get(host_key).set(main_service_key, main_service)
                        //console.log('main_summary.summary.vulnerabilities.get(host_key)', main_summary.summary.vulnerabilities.get(host_key).get(main_service_key))
                        //console.log('main_service', main_service)
                    }
                    //console.log('host.get(secondary_service_key', host.get(secondary_service_key))
                    if(host.get(secondary_service_key) == undefined){  //se il servizio vulnerabile presente nel report secondario non è presente nel report principale..
                        //console.log('aggiungo la vulnerabilità perché non è presente nel main report')
                        main_summary.summary.vulnerabilities.get(host_key).set(secondary_service_key, secondary_service) //lo aggiunge
                    }
                })}
            })

        })

        //console.log('main_service after join', main_summary.summary)
        main_summary.summary.vulnerabilities.forEach( (host, host_key) => {
            //console.log('hostsTHjoin', host)
        })
        /*other_summaries.forEach(summary => {     //scandisce tutti i summary secondari
            console.log('other_summary', summary.summary.vulnerabilities.get(key))
        })*/
    })

   //merged_summary = main_summary //merged viene fatto puntare a main_summary che in precedenza ha inglobato i dati dei report secondari

    /******CONVERSIONE DEI MAP IN JSON********/
    merged_summary.message = 'Merged Summary!'
    merged_summary.summary = {} //inizializza il summary
    merged_summary.summary.date = new Date() //aggiorna il campo date con la data e l'ora di creazione del file merged
    merged_summary.summary.vulnerabilities = refactoring.Map2JSON(main_summary)

    //console.log('ora continuo', merged_summary)

    /**
     * 
     *  OGGETTO DOPO AVER CHIAMATO Map2JSON
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
    * 
    */

    //scandisce tutte le proprietà in vulnerabilities (equivale a ciascun host) e aggiunge un ID per ciascuna vulnerabilità
    for (var host in merged_summary.summary.vulnerabilities) {
        //console.log(' name=' + host + ' value=' + merged_summary.summary.vulnerabilities[host]);
        //scandisce tutte le proprietà dell'oggetto host (equivale ad ogni servizio di quell'host)
        for (var service in merged_summary.summary.vulnerabilities[host]) {

            //console.log('vulnerabilities 1', merged_summary.summary.vulnerabilities[host][service])
            merged_summary.summary.vulnerabilities[host][service].forEach( vuln => {
            vuln.id = global.id_vuln; //aggiunge l'ID a ciascuna vulnerabilità (richiesta da DevGridExtreme lato client per la gestione dei dati)
            global.id_vuln++;
            })
        }
    }

    return merged_summary
    
}






/**
     *  DATA INTEGRATION: aggiunge per ogni vulnerabilità dell'x_summary i dati ricavati dall'attività di web harvesting
     * 
    * 
    * @param {*} req reference_reports
    * @param {*} res 
    * @param {*} next 
 */
 exports.dataIntegration = (x_summary, reference_reports) => {

    console.log('(2) => method() => webScraping => dataIntegration')

    for(var i=0; i<reference_reports.length; i++){
        var item = reference_reports[i]

        //console.log('item', item)
        
        switch (item.harvesting) {   //switch perché per ogni tool Nightmare.js è riuscito a recuperare informazioni diverse

            case CVE:
                    //console.log('CVE')
                    for(var j=0; j<x_summary.vulnerabilities[item.host][item.service][item.type].length; j++){
                        //console.log('AOO', x_summary.vulnerabilities[item.host][item.service][item.type][j])
                        var vuln = x_summary.vulnerabilities[item.host][item.service][item.type][j]
                        //console.log('ID', vuln.id, item.id)
                        if(vuln.id == item.id){  //se la vulnerabilità matcha (bisogna integrare i dati ottenuti dal web harvesting sui suoi riferimenti)
                            //console.log('match!', vuln.id, vuln.service, vuln.type, item.exploits, item.mitigations, item.patches)

                            //Description
                            vuln.description = item.description+"\n\n"+vuln.description;

                            //CVSS
                            if(!vuln.cvss)
                                vuln.cvss = item.cvss

                            //EXPLOITS
                            if(vuln.exploits == undefined || vuln.exploits == null){
                                vuln.exploits = [];
                                vuln.exploits = item.exploits;
                            }else{  //se già ci sono degli exploits
                                let set_exploits = new Set(vuln.exploits)
                                set_exploits.add(...item.exploits)
                                vuln.exploits = Array.from(set_exploits)
                            }

                            //PATCHES
                            vuln.patches = [];
                            vuln.patches = item.patches;

                            //MITIGATIONS
                            vuln.mitigations = [];
                            vuln.mitigations = item.mitigations;
                            
                        }
                    }
                    break;
            case CVE_IBM:
                    //console.log('CVE IBM CLOUD')
                    for(var j=0; j<x_summary.vulnerabilities[item.host][item.service][item.type].length; j++){
                        //console.log('AOO', x_summary.vulnerabilities[item.host][item.service][item.type][j])
                        var vuln = x_summary.vulnerabilities[item.host][item.service][item.type][j]
                        //console.log('ID', vuln.id, item.id)
                        if(vuln.id == item.id){  //se la vulnerabilità matcha (bisogna integrare i dati ottenuti dal web harvesting sui suoi riferimenti)
                            //console.log('match!', vuln.id, vuln.service, vuln.type, item.exploits, item.mitigations, item.patches)

                            //Description
                            vuln.description = item.description+"\n\n"+vuln.description;
                            if(item.description_x)
                                vuln.description = item.description_x+"\n\n"+vuln.description   //se riesce a ricavare un approfondimento della descrizione, allora la inserisce come descrizione della vulnerabilità

                            //CVSS
                            if(!vuln.cvss)
                                vuln.cvss = item.cvss

                            //SOLUTION
                            if(item.solution_x)
                                vuln.solution = item.solution_x+"\n\n"+vuln.solution   //se riesce a ricavare un approfondimento sulla mitigazione, allora la inserisce come solution della vulnerabilità

                            //EXPLOITS
                            if(vuln.exploits == undefined || vuln.exploits == null){
                                vuln.exploits = [];
                                vuln.exploits = item.exploits;
                            }else{  //se già ci sono degli exploits
                                let set_exploits = new Set(vuln.exploits)
                                set_exploits.add(...item.exploits)
                                vuln.exploits = Array.from(set_exploits)
                            }

                            //PATCHES
                            vuln.patches = [];
                            vuln.patches = item.patches;

                            //MITIGATIONS
                            vuln.mitigations = [];
                            vuln.mitigations = item.mitigations;
                            
                        }
                    }
                    break;
            case REDHAT:
                    //console.log('RedHat')
                    for(var j=0; j<x_summary.vulnerabilities[item.host][item.service][item.type].length; j++){
                        //console.log('AOO', x_summary.vulnerabilities[item.host][item.service][item.type][j])
                        var vuln = x_summary.vulnerabilities[item.host][item.service][item.type][j]
                        //console.log('ID', vuln.id, item.id)
                        if(vuln.id == item.id){  //se la vulnerabilità matcha (bisogna integrare i dati ottenuti dal web harvesting sui suoi riferimenti)
                            
                            console.log('match!', vuln.id, vuln.service, vuln.type, item.exploits, item.mitigations, item.patches)

                            //DESCRIPTION
                            if(item.description)
                                if(vuln.description != 'n/a')
                                    vuln.description = item.description+"\n\n"+vuln.description   //se riesce a ricavare un approfondimento sulla descrizione, allora la inserisce come description della vulnerabilità
                            else
                                vuln.description = item.description

                            //SOLUTION
                            if(item.solution)
                                if(vuln.solution != 'n/a')
                                    vuln.solution = item.solution+"\n\n"+vuln.solution   //se riesce a ricavare un approfondimento sulla mitigazione, allora la inserisce come solution della vulnerabilità
                            else
                                vuln.solution = item.solution
                        }
                    }
                    break;
            case APACHE:
                    //console.log('Apache Tomcat')
                    for(var j=0; j<x_summary.vulnerabilities[item.host][item.service][item.type].length; j++){
                        //console.log('AOO', x_summary.vulnerabilities[item.host][item.service][item.type][j])
                        var vuln = x_summary.vulnerabilities[item.host][item.service][item.type][j]
                        //console.log('ID', vuln.id, item.id)
                        if(vuln.id == item.id){  //se la vulnerabilità matcha (bisogna integrare i dati ottenuti dal web harvesting sui suoi riferimenti)
                            
                            //console.log('match!', vuln.id, vuln.service, vuln.type, item.exploits, item.mitigations, item.patches)

                            //SOLUTION
                            if(item.solution)
                                if(vuln.solution != 'n/a')
                                    vuln.solution = item.solution+"\n\n"+vuln.solution   //se riesce a ricavare un approfondimento sulla mitigazione, allora la inserisce come solution della vulnerabilità
                            else
                                vuln.solution = item.solution
                        }
                    }
                    break;
            default:
                    break;

        }

        /**
         * {
            "cvss": "6.8 MEDIUM",
            "description": "The STARTTLS implementation in Postfix 2.4.x before 2.4.16, 2.5.x before 2.5.12, 2.6.x before 2.6.9, and 2.7.x before 2.7.3 does not properly restrict I/O buffering, which allows man-in-the-middle attackers to insert commands into encrypted SMTP sessions by sending a cleartext command that is processed after TLS is in place, related to a \"plaintext command injection\" attack.",
            "exploits": [],
            "mitigations": [],
            "patches": [],
            "tags": [
                "iterazione iniziata",
                "http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10705",
                {}
            ],
            "title": "NVD - CVE-2011-0411",
            "id": 438,
            "host": "192.168.81.131",
            "service": "25/smtp",
            "type": "SMTP problems",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2011-0411",
            "harvesting": "CVE"
            }
         * 
         */

        /**
         * CVE IBM CLOUD
         * {
            "cvss": "4.6 MEDIUM",
            "description": "A Unix account has a guessable password.",
            "exploits": [],
            "mitigations": [],
            "patches": [],
            "pot_solution_ref": "https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0501",
            "tags": [
                "iterazione iniziata",
                "https://exchange.xforce.ibmcloud.com/vulnerabilities/CVE-1999-0501",
                {},
                "iterazione finita"
            ],
            "title": "NVD - CVE-1999-0501",
            "id": 406,
            "host": "192.168.81.131",
            "service": "21/ftp",
            "type": "Brute force attacks",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-1999-0501",
            "harvesting": "CVE IBM Cloud"
        }
         */

        /**
         * APACHE
         * 
         * {
            "solution": "\n\nThe Apache Tomcat Project is proud to announce the release of version 10.1.1\nof Apache Tomcat. This release implements specifications that are part of the\nJakarta EE 10 platform.\nApplications that run on Tomcat 9 and earlier will not run on Tomcat 10\nwithout changes. Java EE based applications designed for Tomcat 9 and earlier\nmay be placed in the <code>$CATALINA_BASE/webapps-javaee</code> directory and\nTomcat will automatically convert them to Jakarta EE and copy them to the\nwebapps directory. This conversion is performed using the\n<a href=\"https://github.com/apache/tomcat-jakartaee-migration\">Apache Tomcat\nmigration tool for Jakarta EE tool</a> which is also available as a separate\n<a href=\"https://tomcat.apache.org/download-migration.cgi\">download</a> for off-line use.\nThe notable changes in this release are:\n\nFix bug <a href=\"https://bz.apache.org/bugzilla/show_bug.cgi?id=66277\">66277</a>, a refactoring regression that broke JSP includes\n    amongst other functionality\nFix unexpected timeouts that may appear as client disconnections when using\n    HTTP/2 and NIO2\nEnforce the requirement of RFC 7230 onwards that a request with a malformed\n    content-length header should always be rejected with a 400 response. \n\n\nFull details of these changes, and all the other changes, are available in the\n<a href=\"tomcat-10.1-doc/changelog.html#Tomcat_10.1.1_(markt)\">Tomcat 10.1\nchangelog</a>.\n\n\n\n<a href=\"https://tomcat.apache.org/download-10.cgi\">Download</a>\n\n",
            "id": 638,
            "host": "192.168.81.131",
            "service": "8180/tcp",
            "type": "Apache Tomcat Detection",
            "link": "https://tomcat.apache.org/",
            "harvesting": "Apache Tomcat"
            }
         */
        /**
         * 
         * {
            "description": "We use the term backporting to describe the action of taking a fix for a security flaw out of the most recent version of an upstream software package and applying that fix to an older version of the package we distribute. Backporting is common among vendors like Red Hat and is essential to ensuring we can deploy automated updates to customers with minimal risk. Backporting might be a new concept for those more familiar with proprietary software updates. Here is an example of why we backport security fixes: Red Hat provides version 5.3 of PHP in Red Hat Enterprise Linux 6. The upstream version of PHP 5.3 has reached the end of life on August 14, 2014, meaning that no additional fixes or enhancements are provided for this version by upstream. However, on October 14, 2014, a buffer overflow flaw <a href=\"https://access.redhat.com/security/cve/CVE-2014-3670\">CVE-2014-3670</a>, rated as <a href=\"https://access.redhat.com/security/updates/classification/#important\">Important</a>, has been discovered in all versions of PHP that could allow a remote attacker to crash a PHP application or, possibly, execute arbitrary code with the privileges of the user running that PHP application.",
            "solution": "Because version 5.3 of PHP has been retired upstream, the fix for this issue was not provided in an upstream release of PHP 5.3. The only way to mitigate the issue would be to upgrade to PHP 5.4, which did provide a fix for CVE-2014-3670. However, Red Hat customers using PHP 5.3 may not be able to migrate to PHP 5.4 due to possible backward compatibility problems between versions 5.3 and 5.4. The migration process would require manual effort by system administrators or developers. For this reason, Red Hat provided (backported) the fix for this issue to the PHP 5.3 packages shipped with Red Hat Enterprise Linux 6 so that customers could keep using PHP 5.3 and would mitigate CVE-2014-3670 at the same time. When we backport security fixes, we: For most products, our default practice is to backport security fixes, but we do sometimes provide version updates for some packages after careful testing and analysis. These are likely to be packages that have no interaction with others, or those used by an end-user, such as web browsers and instant messaging clients.",
            "id": 945,
            "host": "192.168.81.131",
            "service": "80/http",
            "type": "Backported Security Patch Detection (WWW)",
            "link": "https://access.redhat.com/security/updates/backporting/?sc_cid=3093",
            "harvesting": "RedHat"
        }
         */

    }

    return x_summary
    
}
