/**
 * imports the file repository to allow access to file-related database functions,
 * defines service functions for file-related operations.
 */
const file_repository = require('../repositories/file_repository');

// generates the next file ID in the correct sequence e.g. f001, f002
const generateFileId = async () => {
    const all_files = await file_repository.findAll();
    const next_id = all_files.length + 1;
    return `f${String(next_id).padStart(3, '0')}`;
};


module.exports = {
    // adds a file path to the database, creating a new entry if it does not already exist
    registerFile: async (file_path) => {
        const existing = await file_repository.findByFilepath(file_path);
        if (existing) {
            return {
                file_id: existing.file_id,
                file_path: existing.file_path,
                message: 'File already registered',
            };
        }

        const file_id = await generateFileId();
        const new_file = await file_repository.createFile(file_id, file_path);
        return {
            file_id: new_file.file_id,
            file_path: new_file.file_path,
        };
    },


    // retrieves a file entry by its path
    getFileByPath: async (file_path) => {
        return file_repository.findByFilepath(file_path);
    },
};