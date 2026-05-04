/**
 * creates a database instance that connects
 * to the yara_rule table
 */
const database = require('../models');
const yara_rule = database.yara_rule;


module.exports = {
    // retrieves a yara rule entry by its ID
    findById: (id) => {
        return yara_rule.findByPk(id);
    },


    // retrieves all yara rules associated with a specific malware ID
    findByMalwareId: (malware_id) => {
        return yara_rule.findAll({ where: { malware_id: malware_id } });
    },


    // retrieves the rule_strings associated with a specific yara rule ID
    findRuleStringsById: (id) => {
        return yara_rule.findOne({
            where: { rule_id: id },
            attributes: ['rule_name', 'rule_strings'],
        });
    },

    
    // creates a new yara rule entry, used by the Python engine
    // when a rule is triggered during a scan
    createYaraRule: async (rule_id, rule_name, malware_id, rule_strings) => {
        return yara_rule.create({
            rule_id: rule_id,
            rule_name: rule_name,
            malware_id: malware_id,
            rule_strings: rule_strings,
        });
    },


    // retrieves all yara rules entries
    findAll: () => {
        return yara_rule.findAll();
    },


    // retrieves a yara rule entry by its name
    findByName: (rule_name) => {
        return yara_rule.findOne({ where: { rule_name: rule_name } });
    },
};