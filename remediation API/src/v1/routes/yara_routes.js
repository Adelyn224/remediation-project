/**
 * defines the routes for YARA rule-related HTTP operations.
 * it maps HTTP requests to the appropriate YARA controller functions.
 */
const express = require('express');
const router = express.Router();
const yara_controller = require('../../controllers/yara_controllers');


router.post('/yara-rules', yara_controller.createYaraRule); // route to store a triggered YARA rule entry
router.get('/yara-rules/malware/:malware_id', yara_controller.getRulesByMalware); // route to list all YARA rules associated with a specific malware ID


module.exports = router;