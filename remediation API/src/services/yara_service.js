/**
 * imports the yara repository to allow access
 * to its respective database functions,
 * and defines service functions
 */
const yara_repository = require('../repositories/yara_repository');


// generates the next rule ID in the correctsequence e.g. r001, r002
const generateRuleId = async () => {
    const all_rules = await yara_repository.findAll();
    const next_id = all_rules.length + 1;
    return `r${String(next_id).padStart(3, '0')}`;
};


module.exports = {
    // creates a new YARA rule entry triggered during a scan
    createYaraRule: async (rule_name, malware_id, rule_strings) => {
        const rule_id = await generateRuleId();
        const rule = await yara_repository.createYaraRule(rule_id, rule_name, malware_id, rule_strings);
        return {
            rule_id: rule.rule_id,
            rule_name: rule.rule_name,
            malware_id: rule.malware_id,
            rule_strings: rule.rule_strings,
        };
    },


    // retrieves all YARA rules associated with a specific malware ID
    getRulesByMalwareId: async (malware_id) => {
        const rules = await yara_repository.findByMalwareId(malware_id);
        return rules.map(r => ({
            rule_id: r.rule_id,
            rule_name: r.rule_name,
            rule_strings: r.rule_strings,
        }));
    },


    // retrieves a rule by its name — used internally during detection saving
    getRuleByName: async (rule_name) => {
        return yara_repository.findByName(rule_name);
    },
};