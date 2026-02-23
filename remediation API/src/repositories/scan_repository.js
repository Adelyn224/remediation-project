/**
 * this create a database instance that connects
 * to the scan table
 */
const database = require('../models');

const scan = database.scan;

module.exports = {
  // creates a new scan entry in the database
  createScan: async (status) => {
    return scan.create ({
        started_at: new Date(),
        status: status, // e.g., 'queued', 'in_progress', 'completed', 'failed'
    });
  },

  //retrieves a Scan by its id
  findById: (id) => {
    return scan.findByPk(id);
  },

  // retrieves all scans from the database
  findAll: () => {
    return scan.findAll({order: [["scan_id", "DESC"]]});
  },

};
