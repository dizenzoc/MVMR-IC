const express = require('express');
const router = express.Router();
const loadWebScrapingController = require("../controllers/webScraping");

//DEMO: proviamo ad attraversare il DOM di una pagina HTML
router.post('/', loadWebScrapingController.webScraping);

module.exports = router;