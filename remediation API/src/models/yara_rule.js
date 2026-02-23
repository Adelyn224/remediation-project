/**
 * defines the yara_rule model representing the 
 * yara_rules table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const yara_rule = sequelize.define('yara_rule', {
        
        rule_id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        }, 

        malware_id: {
            type: DataTypes.INTEGER,
            allowNull: false,
        },

        name: {
            type: DataTypes.STRING,
        },

        rule_text_for_pattern_matching: {
            type: DataTypes.TEXT,
        },

    }, {
        // Defines the table name and disable timestamps if not needed
        tableName: 'yara_rule',
        timestamps: false,
    });

    return yara_rule;
}
