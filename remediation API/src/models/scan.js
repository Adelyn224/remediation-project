/**
 *defines the "scan" model representing the 
 *scan table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const scan = sequelize.define('scan', {
        scan_id: {
            type: DataTypes.CHAR(4),
            primaryKey: true,
        },

        target_path: {
            type: DataTypes.STRING,
            allowNull: false,
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
        // defines the table name and disable timestamps if not needed
        tableName: 'scan',
        timestamps: false,
    });

    return scan;
}  