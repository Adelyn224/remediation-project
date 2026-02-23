/**
 * it handles the incoming requests related to scans
 * and based on the type of request, delegates the business logic to 
 * the scan service by calling the appropriate functions.
 */

const scanService = require('../services/scan_service');

module.exports = {

    // handles the request to starts a new scan
    startNewScan: async (req, res, next) => {
        //it reads the target_path and analysis_type from the request body,
        //then tries to initiate a new scan using the scan service
        //and sends back the result as a JSON response 
        //of the created scan entry
        try {
            const { target_path, analysis_type } = req.body;
            const result = await scanService.initiateScan(target_path, analysis_type);
            res.status(201).json(result);
        } catch (error) {
            next(error);
        }   
    },

    //handles the request to list all scans
    listAllScans: async (req, res, next) => {
        try {
            const result = await scanService.getAllScans();
            res.json(result);
        } catch (error) {
            next(error);
        }
    },

    // handles the request to get a scan by its ID
    getScan: async (req, res, next) => {
        try {
            const scan_id = req.params.id;
            const result = await scanService.getScanById(scan_id);
            res.json(result);
        } catch (error) {
            next(error);
        }   
    },

    // handles the request to get detections for a specific scan ID
    getDetections: async (req, res, next) => {
        try {
            const scan_id = req.params.id;
            const result = await scanService.getDetectionsByScanId(scan_id);
            res.json(result);
        } catch (error) {
            next(error);
        }
    },

};
