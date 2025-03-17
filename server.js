import express from 'express';
import cors from 'cors';
import { 
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse 
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));
app.use(express.static('public'));

// Server configuration
const port = 3000;
const rpID = 'localhost';
const rpName = 'WebAuthn Demo';
const expectedOrigin = `http://${rpID}:${port}`;

// In-memory storage (in a real app, you'd use a database)
const users = new Map();
const authenticators = new Map();
const challenges = new Map();
const signedData = new Map();

// Helper function to generate random user ID
function generateUserId() {
  return crypto.randomBytes(16).toString('hex');
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create a new user and generate registration options
app.post('/api/register/begin', async (req, res) => {
  try {
    const userId = generateUserId();
    const userName = req.body.username || `user_${userId.substring(0, 6)}`;
    
    // Store the user
    users.set(userId, {
      id: userId,
      name: userName,
      displayName: userName,
    });
    
    // Generate registration options

    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: userId,
        userName,
        timeout: 60000,
        attestationType: 'direct',
        excludeCredentials: [],
        authenticatorSelection: {
            residentKey: 'preferred',
        },
        // Support for the two most common algorithms: ES256, and RS256
        supportedAlgorithmIDs: [-7, -257],
    });
    
    // Store the challenge for verification later
    challenges.set(userId, options.challenge);
    
    res.json({ options, userId });
  } catch (error) {
    console.error('Error generating registration options:', error);
    res.status(500).json({ error: error.message });
  }
});

// Verify registration response
app.post('/api/register/complete', async (req, res) => {
  try {
    const { userId, attestationResponse } = req.body;
    
    const user = users.get(userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const expectedChallenge = challenges.get(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found' });
    }
    
    // Verify the attestation
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
    
    const { verified, registrationInfo } = verification;
    
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Verification failed' });
    }
    
    // Store the authenticator
    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    
    const newAuthenticator = {
      credentialID: isoBase64URL.fromBuffer(credentialID),
      credentialPublicKey: isoBase64URL.fromBuffer(credentialPublicKey),
      counter,
      userId,
    };
    
    if (!authenticators.has(userId)) {
      authenticators.set(userId, []);
    }
    authenticators.get(userId).push(newAuthenticator);
    
    // Clean up the challenge
    challenges.delete(userId);
    
    res.json({ 
      verified, 
      authenticator: {
        credentialID: newAuthenticator.credentialID,
        userId
      }
    });
  } catch (error) {
    console.error('Error verifying registration:', error);
    res.status(500).json({ error: error.message });
  }
});

// Generate authentication options
app.post('/api/authenticate/begin', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = users.get(userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const userAuthenticators = authenticators.get(userId) || [];
    if (userAuthenticators.length === 0) {
      return res.status(400).json({ error: 'No authenticators found for user' });
    }
    
    // Generate authentication options
    const options = await generateAuthenticationOptions({
        timeout: 60000,
        allowCredentials: [],
        userVerification: 'required',
        rpID,
    });
    
    // Store the challenge for verification later
    challenges.set(userId, options.challenge);
    
    res.json({ options });
  } catch (error) {
    console.error('Error generating authentication options:', error);
    res.status(500).json({ error: error.message });
  }
});

// Verify authentication response
app.post('/api/authenticate/complete', async (req, res) => {
  try {
    const { userId, assertionResponse } = req.body;
    
    const user = users.get(userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const expectedChallenge = challenges.get(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found' });
    }
    
    const userAuthenticators = authenticators.get(userId) || [];
    const authenticator = userAuthenticators.find(
      auth => auth.credentialID === assertionResponse.id
    );
    
    if (!authenticator) {
      return res.status(400).json({ error: 'Authenticator not found' });
    }
    
    // Verify the assertion
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
        credentialPublicKey: isoBase64URL.toBuffer(authenticator.credentialPublicKey),
        counter: authenticator.counter,
      },
    });
    
    const { verified, authenticationInfo } = verification;
    
    if (!verified) {
      return res.status(400).json({ error: 'Authentication failed' });
    }
    
    // Update the authenticator counter
    authenticator.counter = authenticationInfo.newCounter;
    
    // Clean up the challenge
    challenges.delete(userId);
    
    res.json({ verified, userId });
  } catch (error) {
    console.error('Error verifying authentication:', error);
    res.status(500).json({ error: error.message });
  }
});

// Generate options for signing data
app.post('/api/sign/begin', async (req, res) => {
  try {
    const { userId, data } = req.body;
    
    if (!data) {
      return res.status(400).json({ error: 'No data provided to sign' });
    }
    
    const user = users.get(userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const userAuthenticators = authenticators.get(userId) || [];
    if (userAuthenticators.length === 0) {
      return res.status(400).json({ error: 'No authenticators found for user' });
    }
    
    // Generate authentication options for signing
    // We'll use the data as part of the challenge
    const dataBuffer = Buffer.from(data);
    const dataHash = crypto.createHash('sha256').update(dataBuffer).digest();
    const challenge = isoBase64URL.fromBuffer(dataHash);
    
    const options = await generateAuthenticationOptions({
        timeout: 60000,
        allowCredentials: [],
        userVerification: 'required',
        rpID,
        challenge
    });
    
    
    // Store the challenge and data for verification later
    challenges.set(userId, options.challenge);
    signedData.set(userId, data);
    
    res.json({ options });
  } catch (error) {
    console.error('Error generating signing options:', error);
    res.status(500).json({ error: error.message });
  }
});

// Verify signed data
app.post('/api/sign/complete', async (req, res) => {
  try {
    const { userId, assertionResponse } = req.body;
    
    const user = users.get(userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }
    
    const expectedChallenge = challenges.get(userId);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge not found' });
    }
    
    const data = signedData.get(userId);
    if (!data) {
      return res.status(400).json({ error: 'No data found to verify' });
    }
    
    const userAuthenticators = authenticators.get(userId) || [];
    const authenticator = userAuthenticators.find(
      auth => auth.credentialID === assertionResponse.id
    );
    
    if (!authenticator) {
      return res.status(400).json({ error: 'Authenticator not found' });
    }
    
    // Verify the assertion (signature)
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: isoBase64URL.toBuffer(authenticator.credentialID),
        credentialPublicKey: isoBase64URL.toBuffer(authenticator.credentialPublicKey),
        counter: authenticator.counter,
      },
    });
    
    const { verified, authenticationInfo } = verification;
    
    if (!verified) {
      return res.status(400).json({ error: 'Signature verification failed' });
    }
    
    // Update the authenticator counter
    authenticator.counter = authenticationInfo.newCounter;
    
    // Clean up
    challenges.delete(userId);
    signedData.delete(userId);
    
    res.json({ 
      verified, 
      data,
      signature: assertionResponse.response.signature,
      authenticatorData: assertionResponse.response.authenticatorData
    });
  } catch (error) {
    console.error('Error verifying signature:', error);
    res.status(500).json({ error: error.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
