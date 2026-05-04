/**
 * creates a database instance that connects
 * to the remediation table
 */
const database = require('../models');
const remediation = database.remediation;


module.exports = {
    // retrieves all remediations associated with a specific malware_id
    findByMalwareId: (id) => {
        return remediation.findAll({where: { malware_id: id }});
    },
};