/**
 * database model definitions and relationships setup using Sequelize Object Relational Mapping (ORM).
 * it loads the Sequelize library and initializes a connection to a PostgreSQL 
 * database named "malware_database" using the provided credentials.
 * sequelize transalate the JS code into SQL queries that mach the choosen database dialect (in this case, PostgreSQL).
 */
require('dotenv').config();
const {Sequelize} = require('sequelize');

const sequelize = new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
        host: process.env.DB_HOST,
        dialect: 'postgres'
    }
);


//defines the database object and imports 
//various models representing different
//entities in the malware detection system.
const database = {};
database.Sequelize = Sequelize;
database.sequelize = sequelize;


database.detection = require('./detection')(sequelize, Sequelize);
database.file = require('./file')(sequelize, Sequelize);
database.malware = require('./malware')(sequelize, Sequelize);
database.remediation = require('./remediation')(sequelize, Sequelize);
database.scan = require('./scan')(sequelize, Sequelize);
database.yara_rule = require('./yara_rule')(sequelize, Sequelize);


//this maps the relationships between the different models in the database.
//similar to the mapping in the database schema.
database.scan.hasMany(database.detection, {foreignKey: 'scan_id'});
database.detection.belongsTo(database.scan, {foreignKey: 'scan_id'});

database.file.hasMany(database.detection, {foreignKey: 'file_id'});
database.detection.belongsTo(database.file, {foreignKey: 'file_id'});

database.malware.hasMany(database.detection, {foreignKey: 'malware_id'});
database.detection.belongsTo(database.malware, {foreignKey: 'malware_id'});

database.malware.hasMany(database.remediation, {foreignKey: 'malware_id'});
database.remediation.belongsTo(database.malware, {foreignKey: 'malware_id'});

database.yara_rule.hasMany(database.detection, {foreignKey: 'rule_id'});
database.detection.belongsTo(database.yara_rule, {foreignKey: 'rule_id'});

database.malware.hasMany(database.yara_rule, {foreignKey: 'malware_id'});
database.yara_rule.belongsTo(database.malware, {foreignKey: 'malware_id'});


//exports the database object for use in other parts of the application.
module.exports = database;