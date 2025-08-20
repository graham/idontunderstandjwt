import chalk from 'chalk';

export class Logger {
  static info(message: string): void {
    console.log(chalk.blue('ℹ️ '), message);
  }

  static success(message: string): void {
    console.log(chalk.green('✅'), message);
  }

  static error(message: string): void {
    console.log(chalk.red('❌'), message);
  }

  static warning(message: string): void {
    console.log(chalk.yellow('⚠️ '), message);
  }

  static section(title: string): void {
    console.log('\n' + chalk.bold.underline(title));
    console.log('═'.repeat(title.length));
  }

  static step(stepNumber: number, description: string): void {
    console.log(chalk.cyan(`📝 Step ${stepNumber}:`), description);
  }

  static explain(concept: string, explanation: string): void {
    console.log('\n' + chalk.bold.magenta('🎓 JWT Concept:'), chalk.bold(concept));
    console.log(chalk.gray('   '), explanation);
  }

  static debug(label: string, data: any): void {
    console.log(chalk.gray('🔍 Debug:'), chalk.bold(label));
    if (typeof data === 'object') {
      console.log(chalk.gray(JSON.stringify(data, null, 2)));
    } else {
      console.log(chalk.gray('   '), data);
    }
  }

  static keyValue(key: string, value: string): void {
    console.log(chalk.blue('   '), chalk.bold(key + ':'), value);
  }
}

export class JWTEducator {
  static explainJWTStructure(): void {
    Logger.explain(
      'JWT Structure',
      'A JWT token has 3 parts separated by dots (.): Header.Payload.Signature\n' +
      '   • Header: Contains algorithm info (alg) and token type (typ)\n' +
      '   • Payload: Contains the claims (data) you want to transmit\n' +
      '   • Signature: Proves the token hasn\'t been tampered with'
    );
  }

  static explainAlgorithm(algorithm: string): void {
    const explanations: Record<string, string> = {
      'RS256': 'RSA with SHA-256. Uses public/private key pairs. Private key signs, public key verifies.',
      'HS256': 'HMAC with SHA-256. Uses a shared secret key for both signing and verification.',
      'ES256': 'ECDSA with SHA-256. Uses elliptic curve cryptography - more efficient than RSA.',
      'Ed25519': 'EdDSA with Ed25519 curve. Fast and secure modern algorithm.',
    };

    const explanation = explanations[algorithm] || `Algorithm: ${algorithm}`;
    Logger.explain(`Algorithm: ${algorithm}`, explanation);
  }

  static explainKeyPairs(): void {
    Logger.explain(
      'Public/Private Key Pairs',
      'Asymmetric cryptography uses two related keys:\n' +
      '   • Private Key: Keep secret! Used to SIGN tokens\n' +
      '   • Public Key: Share freely! Used to VERIFY tokens\n' +
      '   This allows anyone to verify tokens without being able to create fake ones.'
    );
  }

  static explainJWKS(): void {
    Logger.explain(
      'JWKS (JSON Web Key Set)',
      'A collection of cryptographic keys in JSON format:\n' +
      '   • Contains multiple public keys for token verification\n' +
      '   • Each key has a unique ID (kid) to identify which one to use\n' +
      '   • Allows key rotation without breaking existing tokens\n' +
      '   • Usually served at /.well-known/jwks.json endpoint'
    );
  }

  static explainTokenVerification(): void {
    Logger.explain(
      'Token Verification Process',
      'To verify a JWT token:\n' +
      '   1. Decode the header to find the key ID (kid)\n' +
      '   2. Look up the corresponding public key in the JWKS\n' +
      '   3. Verify the signature using that key\n' +
      '   4. Check claims like expiration (exp), issuer (iss), audience (aud)'
    );
  }

  static explainSecurity(): void {
    Logger.explain(
      'JWT Security Best Practices',
      '🔒 Important security considerations:\n' +
      '   • Always verify tokens on the server side\n' +
      '   • Use strong algorithms (avoid "none" algorithm)\n' +
      '   • Set appropriate expiration times\n' +
      '   • Validate issuer (iss) and audience (aud) claims\n' +
      '   • Keep private keys secure and rotate them regularly'
    );
  }
}

export function base64UrlDecode(input: string): string {
  // Add padding if needed
  const padded = input + '='.repeat((4 - input.length % 4) % 4);
  // Replace URL-safe characters
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  // Decode
  return Buffer.from(base64, 'base64').toString('utf-8');
}

export function parseJWTToken(token: string): { header: any; payload: any; signature: string } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT token format');
  }

  const [headerPart, payloadPart, signature] = parts;

  try {
    const header = JSON.parse(base64UrlDecode(headerPart || ''));
    const payload = JSON.parse(base64UrlDecode(payloadPart || ''));

    return { header, payload, signature: signature || '' };
  } catch (error) {
    throw new Error('Failed to parse JWT token');
  }
}

export function formatJWTToken(token: string): void {
  try {
    const { header, payload, signature } = parseJWTToken(token);
    
    Logger.section('🔍 JWT Token Breakdown');
    
    console.log(chalk.bold.yellow('📋 Header:'));
    console.log(JSON.stringify(header, null, 2));
    
    console.log(chalk.bold.blue('\n📦 Payload:'));
    console.log(JSON.stringify(payload, null, 2));
    
    console.log(chalk.bold.green('\n✍️  Signature:'));
    console.log(signature);
    
  } catch (error) {
    Logger.error(`Failed to parse token: ${error}`);
  }
}