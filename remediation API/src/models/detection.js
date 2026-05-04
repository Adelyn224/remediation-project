/**
 * defines the "detection" model representing the 
 * detection table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const detection = sequelize.define('detection', {
        detection_id: {
            type: DataTypes.CHAR(4),
            primaryKey: true,
        },

        scan_id: {
            type: DataTypes.CHAR(4),
            allowNull: false,
        },

        file_id: {
            type: DataTypes.CHAR(4),
            allowNull: false,
        },

        malware_id: {
            type: DataTypes.CHAR(4),
            allowNull: false,
        },

        rule_id: {
            type: DataTypes.CHAR(4),
            allowNull: false,
        },

        time_detected: {
            type: DataTypes.DATE,
            allowNull: false,
        },

        status: {
            type: DataTypes.STRING, // e.g., 'quarantined', 'deleted', 'ignored'
            allowNull: false,
        },

    }, {
        // Defines the table name and disable timestamps if not needed
        tableName: 'detection',
        timestamps: false,
    });

    return detection;
}