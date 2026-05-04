/**
 * CORS middleware configuration.
 * Allows the React front-end to make requests to this API
 * from a different origin (port or domain).
 */
const cors = require('cors');

const corsSetup = {
    origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};

module.exports = cors(corsSetup);