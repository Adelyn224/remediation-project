/**
 *defines the file model representing the 
 *file table in the malware detection system.
 */
module.exports = (sequelize, DataTypes) => {
    const file = sequelize.define('file', {

        file_id: {
            type: DataTypes.CHAR(4),
            primaryKey: true,
        },

        file_path: {
            type: DataTypes.STRING,
            allowNull: false,
        },

    }, {
        // defines the table name and disable timestamps if not needed
        tableName: 'file',
        timestamps: false,

    });

    return file;
};