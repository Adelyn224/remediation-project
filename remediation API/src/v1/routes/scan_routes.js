/**
 * it defines the routes for scan-related HTTP operations in the application.
 * it maps HTTP requests to the appropriate scan controller functions.
 */

const express = require('express');
const router = express.Router();
const scan_controller = require('../../controllers/scan_controllers');

// route to start a new scan
router.post('/scans', scan_controller.startNewScan);

// route to list all scans
router.get('/scans', scan_controller.listAllScans);

// route to get a specific scan by ID
router.get('/scans/:id', scan_controller.getScan);

// route to get detections for a specific scan ID
router.get('/scans/:id/detections', scan_controller.getDetections);

module.exports = router;