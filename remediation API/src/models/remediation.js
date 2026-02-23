/**
 * defines the "remediation" model representing the 
 * remediation table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const remediation = sequelize.define('remediation', {
        remediation_id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        
        malware_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
        },

        title: {
            type: DataTypes.STRING,
            allowNull: false,
        },

        steps: {
            type: DataTypes.TEXT,
            allowNull: false,
        },

        source_URL: {
            type: DataTypes.STRING,
            allowNull: true,
        },

    }, {
        // Defines the table name and disable timestamps if not needed
        tableName: 'remediations',
        timestamps: false,
    });

    return remediation;
}