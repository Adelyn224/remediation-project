/**
 * creates a database instance that connects
 * to the detection table
 */
const database = require('../models');


//grants access to the tables in the database
const detection = database.detection;
const file = database.file;
const malware = database.malware;
const yara_rule = database.yara_rule;

module.exports = {
    // retrieves all detections associated with a specific scan_id
    findByScanId: (id) => {
        return detection.findAll({
            where: { scan_id: id },
            include: [file, malware, yara_rule],
        });
    },

    
    // creates multiple detection entries in the database
    bulkCreate: async (detections) => {
        return detection.bulkCreate(detections);
    },


    // creates a single detection entry in the database
    createDetection: async (detection_reports) => {
        return detection.create(detection_reports);
    },


    // counts all detections in the database
    countAll: async () => {
        return detection.count();
    }
};