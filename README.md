# WebAuthn Signer Demo

This project demonstrates how to use WebAuthn for key generation and data signing in a web application.

## Features

- Register a new FIDO-based key
- Authenticate with the registered key
- Sign arbitrary data with the key
- Verify signatures

## Prerequisites

- Node.js 16+ installed
- A browser that supports WebAuthn (most modern browsers)
- A device with a platform authenticator (Windows Hello, Touch ID, etc.) or a FIDO2 security key

## Installation

1. Clone this repository
2. Install dependencies:

```bash
npm install
npm run start
