/**
 * creates a database instance that connects
 * to the file table
 */
const database = require('../models');
const file = database.file;


module.exports = {
    // retrieves a file entry by its ID
    findById: (id) => {
        return file.findByPk(id);
    },


    // retrieves a file entry by its filepath
    findByFilepath: (file_path) => {
        return file.findOne({ where: { file_path: file_path } });
    },


    // creates a new file entry if the filepath does not already exist,
    // otherwise returns the existing entry
    findOrCreateByFilepath: async (file_path) => {
        const [entry, created] = await file.findOrCreate({
            where: { file_path: file_path },
            defaults: { file_path: file_path },
        });
        return entry;
    },


    // retrieves all file entries
    findAll: () => {
        return file.findAll();
    },


    //creates a new file entry using the file_id and filepath
    createFile: (file_id, file_path) => {
        return file.create({ file_id, file_path: file_path });
    },
};