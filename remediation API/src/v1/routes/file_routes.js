/**
 * defines the routes for file-related HTTP operations.
 * it maps HTTP requests to the appropriate file controller functions.
 */
const express = require('express');
const router = express.Router();
const file_controller = require('../../controllers/file_controllers');


// route to add a new file path to the database if it doesn't exist before scanning
router.post('/files', file_controller.addFilePath); 


module.exports = router;