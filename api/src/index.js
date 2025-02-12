// express starter
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const { KEYCLOAK_URL, KEYCLOAK_REALM } = process.env;

const port = 8000;
const app = express();
app.use(cors());

/*
  > curl -X GET http://localhost:8000/reports \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
*/

app.get('/reports', async (req, res) => {

  const token = req.headers.authorization.split(' ')[1];

  const keycloackEndpoint = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}`

  const realmsRes = await axios.get(keycloackEndpoint);

  const dataOfToken = jwt.decode(token);

  if (dataOfToken.realm_access.roles[0] !== "prothetic_user") {
    res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    jwt.verify(token, `-----BEGIN PUBLIC KEY-----\n${realmsRes.data.public_key}\n-----END PUBLIC KEY-----\n`, { algorithms: ['RS256'] });
  } catch (error) {
    console.log(error)
    res.status(403).json({ error: 'Invalid token' });
    return
  }

  res.status(200).json({ reports: [{ id: 1, name: 'Report 1' }, { id: 2, name: 'Report 2' }] });
});

app.listen(port, () => {
  console.log(`Api app listening at http://localhost:${port}`);
});

