/**
 * creates a database instance that connects
 * to the scan table 
 */
const database = require('../models');
const scan = database.scan;


module.exports = {
    // creates a new scan entry in the database
    createScan: async (target_path, status) => {
        const all_scans = await scan.findAll();
        const next_id = `s${(String(all_scans.length + 1)).padStart(3, '0')}`;


        return scan.create({
            scan_id: next_id,
            target_path: target_path,
            started_at: new Date(),
            status: status,
        });
    },


    //retrieves a scan by its ID
    findById: (id) => {
        return scan.findByPk(id);
    },


    // retrieves all scans from the database
    findAll: () => {
        return scan.findAll({order: [['scan_id', 'DESC']]});
    },


    // updates the status of a scan
    updateScanStatus: (scan_id, status) => {
        return scan.update(
            {status: status}, 
            {where: {scan_id: scan_id}}
        );
    },


    // updates the end time of a scan
    updateScanEndTime: (scan_id, end_time) => {
        return scan.update(
            {ended_at: end_time},
            {where: {scan_id: scan_id}}
        );
    },
};