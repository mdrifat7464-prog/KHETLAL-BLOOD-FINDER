const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const app = express();
app.use(cors());
app.use(express.json());

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
    }),
    databaseURL: "https://khetlal-blood-donor-finder-default-rtdb.firebaseio.com"
  });
}

const db = admin.database();
const rpName = 'Khetlal Blood Finder';

app.get('/', (req, res) => {
  res.send('Khetlal Blood Finder Backend is Running smoothly! 🚀');
});

app.post('/generate-registration-options', async (req, res) => {
  try {
    const { uid, email, name, rpID } = req.body;
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: uid,
      userName: email,
      userDisplayName: name,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
    });
    await db.ref(`passkey_challenges/${uid}`).set(options.challenge);
    res.json(options);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/verify-registration', async (req, res) => {
  try {
    const { uid, response, rpID } = req.body;
    const challengeSnap = await db.ref(`passkey_challenges/${uid}`).once('value');
    const expectedChallenge = challengeSnap.val();
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: req.headers.origin,
      expectedRPID: rpID,
    });
    if (verification.verified) {
      const { registrationInfo } = verification;
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      const credentialIDBase64 = Buffer.from(credentialID).toString('base64url');
      const publicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64url');
      const newPasskey = {
        credentialID: credentialIDBase64,
        credentialPublicKey: publicKeyBase64,
        counter,
        transports: response.response.transports || [],
        uid
      };
      await db.ref(`passkey_map/${credentialIDBase64}`).set(newPasskey);
      await db.ref(`passkey_challenges/${uid}`).remove();
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/generate-authentication-options', async (req, res) => {
  try {
    const { rpID } = req.body;
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
    });
    await db.ref(`auth_challenges/${options.challenge}`).set(true);
    res.json(options);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/verify-authentication', async (req, res) => {
  try {
    const { response, expectedChallenge, rpID } = req.body;
    const challengeSnap = await db.ref(`auth_challenges/${expectedChallenge}`).once('value');
    if (!challengeSnap.exists()) {
      return res.status(400).json({ error: 'Invalid challenge' });
    }
    await db.ref(`auth_challenges/${expectedChallenge}`).remove();
    const credentialIDBase64 = response.id;
    const passkeySnap = await db.ref(`passkey_map/${credentialIDBase64}`).once('value');
    if (!passkeySnap.exists()) {
      return res.status(404).json({ error: 'Passkey not found' });
    }
    const passkey = passkeySnap.val();
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: req.headers.origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: Buffer.from(passkey.credentialPublicKey, 'base64url'),
        credentialID: Buffer.from(passkey.credentialID, 'base64url'),
        counter: passkey.counter,
        transports: passkey.transports || [],
      },
    });
    if (verification.verified) {
      await db.ref(`passkey_map/${credentialIDBase64}`).update({
        counter: verification.authenticationInfo.newCounter
      });
      const customToken = await admin.auth().createCustomToken(passkey.uid);
      res.json({ verified: true, token: customToken });
    } else {
      res.status(400).json({ verified: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {});
module.exports = app;
