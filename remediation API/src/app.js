/**
 * Main application file that configures the Express server
 * and defines the health check endpoint.
 */
const express = require('express');
const cors = require('./middleware/cors');
const helmet = require('./middleware/helmet');


//status code meanings:
//200 OK: The request was successful.
//201 Created: The request was successful, and a new resource has been created as a result.
//400 Bad Request: The server cannot process the request due to errors e.g missing required fields.
//404 Not Found: The requested resource could not be found on the server.
//500 Internal Server Error: An unexpected error occurred on the server while processing the request.
const app = express();


app.use(helmet); //imports and uses the Helmet middleware to enhance security by setting various HTTP headers
app.use(cors); //imports and uses the CORS middleware to enable cross-origin requests
app.use(express.json()); //it allows the app to parse JSON requests


//health check endpoint to verify that the server is running and responsive
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'OK', message: 'The server is running smoothly' });
});


//importing and using the defined routes
app.use("/api/v1", require("./v1/routes/scan_routes"));
app.use("/api/v1", require("./v1/routes/malware_routes"));
app.use("/api/v1", require("./v1/routes/file_routes"));
app.use("/api/v1", require("./v1/routes/yara_routes"));


//handles any errors that occur when the request does not match any defined routes
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});


//handles any errors that occur during request processing
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
});


//the server is deployed using the environment variable PORT if defined
//if one is not defined, the server starts on port 3000
//and the app listens to requests on port 3000
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});