/**
 * imports necessary repositories to allow access
 * to scan repository functions,
 * and defines service functions
 */

const scan_repository = require('../repositories/scan_repository');
const detection_repository = require('../repositories/detection_repository');

//
module.exports = {
    // initiates a new scan and returns the created scan entry
    initiateScan: async (target_path, analysis_type) => {

        const scan = await scan_repository.createScan("Queued");

        //TODO: Add the python logic to actually start the scanning process asynchronously

        return {
            id: scan.scan_id,
            started_at: scan.started_at,
            ended_at: scan.ended_at,
            status: scan.status,
        }

    },

    // retrieves a scan by its ID
    getScanById: async (id) => {

        const scan = await scan_repository.findById(id);
        
        if (!scan) {
            const error = new Error('No scan match found');
            error.status = 404;
            throw error;
        }  

        return {
            id: scan.scan_id,
            started_at: scan.started_at,
            ended_at: scan.ended_at,
            status: scan.status,
        };

    },

    // retrieves all scans
    getAllScans: async () => {

        const all_scans = await scan_repository.findAll();
        return all_scans.map(scan => ({
            id: scan.scan_id,
            started_at: scan.started_at,
            ended_at: scan.ended_at,
            status: scan.status,
        }));

    },

    // retrieves all detections for a specific scan ID
    getDetectionsByScanId: async (id) => {
        const detections = await detection_repository.findByScanId(id);
        return detections.map(d => ({
            file_path: d.file.filepath,
            malware_name: d.malware.name,
            yara_rule_name: d.yara_rule.name,
            status: d.status,
        }));
    }

};
