/**
 * Main application file that configures the Express server
 * and defines the health check endpoint.
 */
const express = require('express');
const app = express();


//it allows the app to parse JSON requests
app.use(express.json());

//importing and using the scan routes
app.use("/api/v1", require("./v1/routes/scan_routes"));

//importing and using the malware routes
app.use("/api/v1", require("./v1/routes/malware_routes"));


//the server is deployed using the environment variable PORT if defined
//if one is not defined, the server starts on port 3000
//and the app listens to requests on port 3000
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});