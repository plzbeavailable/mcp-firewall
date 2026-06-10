// GitHub Device Flow authentication
// This script gets a token for creating repos and pushing code.

const CLIENT_ID = 'Iv23li41jTRXWP0kysVe'; // GitHub CLI client ID (public)

async function main() {
  // Step 1: Request device code
  const deviceResp = await fetch('https://github.com/login/device/code', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      scope: 'repo,workflow',
    }),
  });

  const deviceData = await deviceResp.json();

  if (deviceData.error) {
    console.error('Error getting device code:', deviceData);
    process.exit(1);
  }

  console.log('\n========================================');
  console.log('  GitHub Authentication Required');
  console.log('========================================');
  console.log(`\n  1. Open: ${deviceData.verification_uri}`);
  console.log(`  2. Enter code: ${deviceData.user_code}`);
  console.log('\n  Waiting for you to authorize...\n');

  // Step 2: Poll for token
  const interval = deviceData.interval || 5;
  const expiresAt = Date.now() + (deviceData.expires_in || 900) * 1000;

  while (Date.now() < expiresAt) {
    await new Promise(r => setTimeout(r, interval * 1000));

    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        device_code: deviceData.device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      }),
    });

    const tokenData = await tokenResp.json();

    if (tokenData.error) {
      if (tokenData.error === 'authorization_pending') {
        process.stdout.write('.');
        continue;
      }
      if (tokenData.error === 'slow_down') {
        await new Promise(r => setTimeout(r, (interval + 5) * 1000));
        continue;
      }
      console.error('\nError getting token:', tokenData);
      process.exit(1);
    }

    // Success!
    console.log('\n\n✅ Authenticated successfully!');
    console.log(`Token: ${tokenData.access_token.substring(0, 10)}...`);
    console.log(`Token type: ${tokenData.token_type}`);
    console.log(`Scope: ${tokenData.scope}`);

    // Save token to temp file
    const fs = await import('fs');
    fs.writeFileSync(new URL('../.github-token', import.meta.url), tokenData.access_token);
    console.log('\nToken saved to .github-token');
    process.exit(0);
  }

  console.error('\n⏰ Timed out waiting for authorization.');
  process.exit(1);
}

main().catch(err => { console.error(err); process.exit(1); });
