/**
 * defines the yara_rule model representing the 
 * yara_rules table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const yara_rule = sequelize.define('yara_rule', {
        
        rule_id: {
            type: DataTypes.CHAR(4),
            primaryKey: true,
        }, 

        malware_id: {
            type: DataTypes.CHAR(4),
            allowNull: false,
        },

        rule_name: {
            type: DataTypes.STRING,
        },

        rule_strings: {
            type: DataTypes.TEXT,
        },

    }, {
        // defines the table name and disable timestamps if not needed
        tableName: 'yara_rule',
        timestamps: false,
    });

    return yara_rule;
}