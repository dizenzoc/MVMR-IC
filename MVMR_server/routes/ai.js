const express = require('express');
const router = express.Router();
const aiController = require("../controllers/ai");

router.post('/', aiController.nlp_report);
router.post('/bayesianClassifierTest', aiController.testBayesianClassifier)

module.exports = router;
