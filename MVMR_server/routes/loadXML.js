const express = require('express');
const router = express.Router();
const loadXMLController = require("../controllers/loadXML");
const upload = require('../middleware/multer'); //uploadXML middleware per l'upload dei file XML
const global = require('../utils/global')
/*const { body } = require('express-validator');
const upload = require('../middleware/uploadImg'); //uploadImg middleware per l'upload delle immagini
const isAuth = require('../middleware/is-auth');
const isAuthAdmin = require('../middleware/is-auth-admin');*/


//Carica sul server i file XML inviati dal client (richiama il middleware multer per lo storage dei file XML sul server, vedi middleware/uploadXML.js) 
router.post('/getXMLFiles', upload.fields([{name : 'nmap'},{name : 'openvas'},{name : 'nessus'},{name : 'owaspzap'}]), loadXMLController.loadXMLFiles); 

//Riceve in input i file XML caricati dall'utente, li converte in JSON e li salva nella directory public/json
//router.post('/XML2JSON', loadXMLController.XML2JSON); 

//Effettua un'analisi del file JSON del tool NMAP e restituisce un JSON contenente le informazioni chiave
//(Salva in /public/normalized_json/nmap/ il file normalizzato contenente solo le informazioni di nostro interesse)
//router.post('/getNmapSummary', loadXMLController.getNmapSummary); 

//Effettua un'analisi del file JSON del tool OPENVAS e restituisce un JSON contenente le informazioni chiave
//(Salva in /public/normalized_json/openvas/ il file normalizzato contenente solo le informazioni di nostro interesse)
//router.post('/getOpenVasSummary', loadXMLController.getOpenVasSummary); 

//Effettua un'analisi del file JSON del tool OWASPZAP e restituisce un JSON contenente le informazioni chiave
//(Salva in /public/normalized_json/owaspzap/ il file normalizzato contenente solo le informazioni di nostro interesse)
//router.post('/getOwaspZapSummary', loadXMLController.getOwaspZapSummary); 

//Effettua un'analisi del file JSON del tool NESSUS e restituisce un JSON contenente le informazioni chiave
//(Salva in /public/normalized_json/nessus/ il file normalizzato contenente solo le informazioni di nostro interesse)
//router.post('/getNessusSummary', loadXMLController.getNessusSummary); 

/*Effettua una chiamata al server al fine di ottenere un summary complessivo, risultante dalla fusione dei vari summary NMAP, OPENVAS, OWASPZAP E NESSUS*/
//router.post('/getMergedSummary', loadXMLController.getMergedSummary); 


module.exports = router;