const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser

  // DOM Elements
  const registerButton = document.getElementById('register-button');
  const authenticateButton = document.getElementById('authenticate-button');
  const signButton = document.getElementById('sign-button');
  const usernameInput = document.getElementById('username');
  const dataToSignInput = document.getElementById('data-to-sign');
  const registrationOutput = document.getElementById('registration-output');
  const authenticationOutput = document.getElementById('authentication-output');
  const signingOutput = document.getElementById('signing-output');
  const verificationOutput = document.getElementById('verification-output');
  
  // State
  let currentUserId = null;
  let currentCredentialId = null;
  
  // Helper function to display output
  function displayOutput(element, message, isError = false) {
    element.textContent = typeof message === 'object' 
      ? JSON.stringify(message, null, 2) 
      : message;
    
    element.classList.remove('hidden');
    
    if (isError) {
      element.classList.add('error');
      element.classList.remove('success');
    } else {
      element.classList.add('success');
      element.classList.remove('error');
    }
  }
  
  // Helper function to handle errors
  function handleError(element, error) {
    console.error(error);
    displayOutput(element, `Error: ${error.message || error}`, true);
  }
  
  // Register a new WebAuthn credential
  registerButton.addEventListener('click', async () => {
    try {
      const username = usernameInput.value.trim() || 'anonymous_user';
      
      // Step 1: Get registration options from the server
      displayOutput(registrationOutput, 'Requesting registration options...');
      
      const optionsResponse = await fetch('/api/register/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username }),
      });
      
      if (!optionsResponse.ok) {
        const error = await optionsResponse.json();
        throw new Error(error.error || 'Failed to get registration options');
      }
      
      const { options, userId } = await optionsResponse.json();
      currentUserId = userId;
      
      displayOutput(registrationOutput, 'Creating credential...');
      
      // Step 2: Create the credential
      const attestationResponse = await startRegistration(options);
      
      // Step 3: Verify the credential with the server
      displayOutput(registrationOutput, 'Verifying credential with server...');
      
      const verificationResponse = await fetch('/api/register/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId,
          attestationResponse,
        }),
      });
      
      if (!verificationResponse.ok) {
        const error = await verificationResponse.json();
        throw new Error(error.error || 'Failed to verify registration');
      }
      
      const verification = await verificationResponse.json();
      
      if (verification.verified) {
        currentCredentialId = verification.authenticator.credentialID;
        displayOutput(registrationOutput, 'Registration successful! You can now authenticate and sign data.');
        
        // Enable authentication
        authenticateButton.disabled = false;
      } else {
        throw new Error('Registration verification failed');
      }
    } catch (error) {
      handleError(registrationOutput, error);
    }
  });
  
  // Authenticate with a WebAuthn credential
  authenticateButton.addEventListener('click', async () => {
    try {
      if (!currentUserId) {
        throw new Error('No user registered. Please register first.');
      }
      
      // Step 1: Get authentication options from the server
      displayOutput(authenticationOutput, 'Requesting authentication options...');
      
      const optionsResponse = await fetch('/api/authenticate/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId: currentUserId }),
      });
      
      if (!optionsResponse.ok) {
        const error = await optionsResponse.json();
        throw new Error(error.error || 'Failed to get authentication options');
      }
      
      const { options } = await optionsResponse.json();
      
      displayOutput(authenticationOutput, 'Authenticating...');
      
      // Step 2: Perform the authentication
      const assertionResponse = await startAuthentication(options);
      
      // Step 3: Verify the authentication with the server
      displayOutput(authenticationOutput, 'Verifying authentication with server...');
      
      const verificationResponse = await fetch('/api/authenticate/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: currentUserId,
          assertionResponse,
        }),
      });
      
      if (!verificationResponse.ok) {
        const error = await verificationResponse.json();
        throw new Error(error.error || 'Failed to verify authentication');
      }
      
      const verification = await verificationResponse.json();
      
      if (verification.verified) {
        displayOutput(authenticationOutput, 'Authentication successful! You can now sign data.');
        
        // Enable data signing
        dataToSignInput.disabled = false;
        signButton.disabled = false;
      } else {
        throw new Error('Authentication verification failed');
      }
    } catch (error) {
      handleError(authenticationOutput, error);
    }
  });
  
  // Sign data with a WebAuthn credential
  signButton.addEventListener('click', async () => {
    try {
      if (!currentUserId) {
        throw new Error('No user registered. Please register first.');
      }
      
      const dataToSign = dataToSignInput.value.trim();
      if (!dataToSign) {
        throw new Error('Please enter data to sign');
      }
      
      // Step 1: Get signing options from the server
      displayOutput(signingOutput, 'Requesting signing options...');
      
      const optionsResponse = await fetch('/api/sign/begin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
          userId: currentUserId,
          data: dataToSign
        }),
      });
      
      if (!optionsResponse.ok) {
        const error = await optionsResponse.json();
        throw new Error(error.error || 'Failed to get signing options');
      }
      
      const { options } = await optionsResponse.json();
      
      displayOutput(signingOutput, 'Signing data...');
      
      // Step 2: Perform the signing operation (which is an authentication)
      const assertionResponse = await startAuthentication(options);
      
      // Step 3: Verify the signature with the server
      displayOutput(signingOutput, 'Verifying signature with server...');
      
      const verificationResponse = await fetch('/api/sign/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: currentUserId,
          assertionResponse,
        }),
      });
      
      if (!verificationResponse.ok) {
        const error = await verificationResponse.json();
        throw new Error(error.error || 'Failed to verify signature');
      }
      
      const verification = await verificationResponse.json();
      
      if (verification.verified) {
        displayOutput(signingOutput, 'Data signed successfully!');
        
        // Display verification details
        const details = {
          originalData: verification.data,
          signatureBase64: verification.signature,
          authenticatorDataBase64: verification.authenticatorData,
        };
        
        displayOutput(verificationOutput, details);
        verificationOutput.classList.remove('hidden');
      } else {
        throw new Error('Signature verification failed');
      }
    } catch (error) {
      handleError(signingOutput, error);
    }
  });
  