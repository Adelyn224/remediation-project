/**
 * it defines the routes for scan-related HTTP operations in the application.
 * it maps HTTP requests to the appropriate scan controller functions.
 */
const express = require('express');
const router = express.Router();
const scan_controller = require('../../controllers/scan_controllers');


router.post('/scans', scan_controller.startNewScan); // route to start a new scan
router.get('/scans', scan_controller.listAllScans); // route to list all scans
router.get('/scans/:id', scan_controller.getScan); // route to get a specific scan by ID
router.get('/scans/:id/detections', scan_controller.getDetections); // route to get detections for a specific scan ID
router.post('/scans/:id/detections', scan_controller.submitDetections); // route to submit a new detection for a specific scan ID


module.exports = router; //this makes the router available to the main app, i.e. app.js