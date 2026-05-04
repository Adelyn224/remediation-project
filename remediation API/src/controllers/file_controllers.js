/**
 * it handles the incoming requests related to file paths
 * and based on the type of request, delegates the business logic to 
 * the file service by calling the appropriate functions and sends back JSON responses.
 */
const file_service = require('../services/file_service');


module.exports = {
    // it adds a new file path to the database and returns the created entry as a JSON response
    addFilePath: async (req, res, next) => {
        try {
            const { filepath } = req.body;
            if (!filepath) {
                return res.status(400).json({ message: 'filepath is required' });
            }
            const result = await file_service.addFilePath(filepath);
            res.status(201).json(result);
        } catch (error) {
            next(error);
        }
    },
};