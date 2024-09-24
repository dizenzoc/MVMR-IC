const express = require('express');  //importa il package
const app = express();  //app usufruisce dei servizi del package 'express'

//const bodyParser = require('body-parser');
//app.use(bodyParser.json()); //application/json ??(is depecrated)
//bodyParser deprecato, nella nuova versione si estende l'encoded di express richiamando poi express.json()
app.use(express.urlencoded({extended: true})); 
app.use(express.json());  

const cors = require('cors'); //importa il package 'cors'
app.use(cors()); //risolve il problema del CORS


//const authRoutes = require ('./routes/auth');


//app.use('/auth', authRoutes);
 

//const db = require('./utils/connection'); /*DATABASE*/

 
// *** Routes
const loadXML = require('./routes/loadXML');
app.use('/loadXML', loadXML);

const webScraping = require('./routes/webScraping');
app.use('/webScraping', webScraping);

const ai = require('./routes/ai');
app.use('/ai', ai);

app.use(express.static('public'))




app.listen(8080, () => {
    console.log("Il server è in ascolto sulla porta 8080.") //localhost porta 8080
}) 