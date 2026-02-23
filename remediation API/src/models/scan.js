/**
 *defines the "scan" model representing the 
 *scan table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const scan = sequelize.define('scan', {
        scan_id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        
        started_at: {
            type: DataTypes.DATE,
        },

        ended_at: {
            type: DataTypes.DATE,
        },

        status: {
            type: DataTypes.STRING,
        },
        
    }, {
        // Defines the table name and disable timestamps if not needed
        tableName: 'scans',
        timestamps: false,
    });

    return scan;
}
    