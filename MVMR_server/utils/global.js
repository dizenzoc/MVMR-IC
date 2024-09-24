exports.hosts = [] //lista degli hosts relativi ad una scansione, inizialmente vuoto
exports.id_scan = 0; //id per salvare il file merged (viene incrementato in getMergedSummary)
exports.id_vuln = (Math.random()*1000).toFixed(0); //associa ad ogni vulnerabilità un id univoco (viene richiesto da DevGridExtreme per visualizzare correttamente la griglia lato client)

