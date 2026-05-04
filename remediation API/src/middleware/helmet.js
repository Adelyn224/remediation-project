/**
 * Helmet middleware configuration.
 * Sets security-related HTTP headers on every response
 * to protect the API from common vulnerabilities.
 */
const helmet = require('helmet');

module.exports = helmet();