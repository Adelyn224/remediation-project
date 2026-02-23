/**
 *defines the file model representing the 
 *file table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const file = sequelize.define('file', {

        file_id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },

        filepath: {
            type: DataTypes.STRING,
            allowNull: false,
        },

    }, {

        // Defines the table name and disable timestamps if not needed
        tableName: 'files',
        timestamps: false,

    });

    return file;
};