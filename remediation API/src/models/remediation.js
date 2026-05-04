/**
 * defines the "remediation" model representing the 
 * remediation table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const remediation = sequelize.define('remediation', {
        remediation_id: {
            type: DataTypes.CHAR(6),
            primaryKey: true,
        },
        
        malware_id: {
            type: DataTypes.CHAR(4),
            allowNull: false,
        },

        remediation_name: {
            type: DataTypes.STRING,
            allowNull: false,
        },

        remediation_steps: {
            type: DataTypes.TEXT,
            allowNull: false,
        },

        resource_link: {
            type: DataTypes.STRING,
            allowNull: true,
        },

    }, {
        // defines the table name and disable timestamps if not needed
        tableName: 'remediation',
        timestamps: false,
    });

    return remediation;
}