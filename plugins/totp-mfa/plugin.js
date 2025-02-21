const path = require('path');

// Dynamically load the 'speakeasy' and 'qrcode' modules
const speakeasy = require(path.join(process.cwd(), 'node_modules', 'speakeasy'));
const qrcode = require(path.join(process.cwd(), 'node_modules', 'qrcode'));

exports.description = "TOTP MFA Plugin";
exports.version = 1.0;
exports.apiRequired = [10.3];

exports.init = async function(api) {
  // Open the database for storing the secret
  const db = await api.openDb('totp-mfa');
  let secret = await db.get('secret');

  // If secret does not exist, create one and store it
  if (!secret) {
    const generatedSecret = speakeasy.generateSecret({ length: 20 });
    await db.put('secret', generatedSecret.base32);
    secret = generatedSecret.base32;
  }

  // Middleware to handle MFA setup
  exports.middleware = async ctx => {
    if (ctx.path === '/mfa-setup') {
      // Generate QR code for the secret
      const url = speakeasy.otpauthURL({ secret, label: 'HFS', issuer: 'HFS' });
      const qrCode = await qrcode.toDataURL(url);
      ctx.body = `<img src="${qrCode}">`;
      return;
    }

    // Proceed with normal request handling
    return ctx.next();
  };

  // Listen to the login event to verify the TOTP token
  api.events.on('attemptingLogin', async ({ ctx, username, password }) => {
    const token = ctx.request.body.token; // Assuming token is sent in the request body
    const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token });

    if (!verified) {
      ctx.body = 'MFA Failed';
      return api.events.preventDefault;
    }
  });

  return {
    unload: () => {
      // Cleanup if needed when the plugin is unloaded
    }
  };
};