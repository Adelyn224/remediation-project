/**
 * it handles the incoming requests related to scans
 * and based on the type of request, delegates the business logic to 
 * the scan service by calling the appropriate functions.
 */

const scan_service = require('../services/scan_service');

module.exports = {
    // handles the request to starts a new scan
    startNewScan: async (req, res, next) => {
        //it reads the target_path and analysis_type from the request body,
        //then tries to initiate a new scan using the scan service
        //and sends back the result as a JSON response 
        //of the created scan entry
        try {
            const {target_path} = req.body;
            if (!target_path) {
                return res.status(400).json({ message: 'the target_path is required' });
            } else {
                const result = await scan_service.initiateScan(target_path);
                res.status(201).json(result); //201 status code to indicate that a new resource has been successfully created
            }
        } catch (error) {
            next(error);
        }   
    },


    //handles the request to list all scans
    listAllScans: async (req, res, next) => {
        try {
            const result = await scan_service.getAllScans();
            res.json(result);
        } catch (error) {
            next(error);
        }
    },


    // handles the request to get a scan by its ID
    getScan: async (req, res, next) => {
        try {
            const scan_id = req.params.id;
            const result = await scan_service.getScanById(scan_id);
            if (!result) {
                return res.status(404).json({ message: 'Scan entry not found' });
            } else {
                res.json(result);
            }
        } catch (error) {
            next(error);
        }   
    },


    // handles the request to retrieve detections for a specific scan ID
    getDetections: async (req, res, next) => {
        try {
            const scan_id = req.params.id;
            const result = await scan_service.getDetectionsByScanId(scan_id);
            if (!result) {
                return res.status(404).json({ message: 'Detections not found for the specified scan' });
            } else {
                res.json(result);
            }
        } catch (error) {
            next(error);
        }
    },


    // it submits a new detection entry for a specific scan ID
    submitDetections: async (req, res, next) => {
        try {
            const scan_id = req.params.id;
            const {detections} = req.body;
            if (!detections || !Array.isArray(detections)) {
                return res.status(400).json({ message: 'detections must be a non-empty array' });
            }
            const result = await scan_service.saveDetections(scan_id, detections);
            res.status(201).json(result);
        } catch (error) {
            next(error);
        }
    },
};