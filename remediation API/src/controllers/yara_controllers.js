/**
 * it handles the incoming requests related to yara rule entries
 * and based on the type of request, delegates the business logic to 
 * the yara service by calling the appropriate functions and sends back JSON responses.
 */
const yara_service = require('../services/yara_service');


module.exports = {
    // it stores a triggered YARA rule entry
    createYaraRule: async (req, res, next) => {
        try {
            const { name, malware_id, rule_strings } = req.body;
            if (!name || !malware_id || !rule_strings) {
                return res.status(400).json({ message: 'the name, malware_id and rule_strings are required' });
            } else {
                const result = await yara_service.createYaraRule(name, malware_id, rule_strings);
                res.status(201).json(result);
            }
        } catch (error) {
            next(error);
        }
    },


    // it lists all YARA rules associated with a specific malware ID
    getRulesByMalware: async (req, res, next) => {
        try {
            const { malware_id } = req.params;
            const result = await yara_service.getRulesByMalwareId(malware_id);
            if (!result || result.length === 0) {
                return res.status(404).json({ message: 'No YARA rules found for the specified malware' });
            } else {
                res.json(result);
            }
        } catch (error) {
            next(error);
        }
    },
};