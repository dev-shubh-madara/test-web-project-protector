// Old Node server. Never started by the demo; it only exists so CipherBloom has risky JavaScript to find.
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(cors({ origin: "*" }));

app.get('/ping', (req, res) => {
  require('child_process').exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.listen(3000);
