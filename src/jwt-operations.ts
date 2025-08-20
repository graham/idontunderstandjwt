import * as jose from 'jose';
import { JWKSManager, StoredKeyPair } from './jwks-manager';
import { Logger, JWTEducator, formatJWTToken, parseJWTToken } from './utils';

export interface TokenPayload {
  sub?: string;  // Subject (user ID)
  iss?: string;  // Issuer
  aud?: string;  // Audience
  exp?: number;  // Expiration time
  iat?: number;  // Issued at
  nbf?: number;  // Not before
  jti?: string;  // JWT ID
  [key: string]: any; // Custom claims
}

export interface VerificationResult {
  success: boolean;
  keyId: string;
  algorithm: string;
  payload?: jose.JWTPayload;
  protectedHeader?: jose.JWTHeaderParameters;
  error?: string;
}

export class JWTOperations {
  constructor(private jwksManager: JWKSManager) {}

  async createToken(
    kid: string,
    payload: TokenPayload,
    expiresIn = '1h',
    explain = true
  ): Promise<string> {
    if (explain) {
      Logger.section('🎫 Creating JWT Token');
      JWTEducator.explainJWTStructure();
    }

    Logger.step(1, `Looking up key: ${kid}`);
    const keyPair = await this.jwksManager.getKeyPair(kid);
    
    if (!keyPair) {
      Logger.error(`Key not found: ${kid}`);
      throw new Error(`Key with ID ${kid} not found`);
    }

    Logger.success(`Found key: ${kid} (${keyPair.algorithm})`);
    Logger.keyValue('Algorithm', keyPair.algorithm);
    Logger.keyValue('Key Type', keyPair.jwk.kty);

    if (explain) {
      JWTEducator.explainAlgorithm(keyPair.algorithm);
    }

    Logger.step(2, 'Preparing JWT header');
    const header = {
      alg: keyPair.algorithm,
      typ: 'JWT',
      kid: kid
    };
    Logger.debug('JWT Header', header);

    Logger.step(3, 'Preparing JWT payload');
    const now = Math.floor(Date.now() / 1000);
    
    // Calculate expiration
    let expirationTime = now;
    if (expiresIn.endsWith('h')) {
      expirationTime += parseInt(expiresIn) * 3600;
    } else if (expiresIn.endsWith('m')) {
      expirationTime += parseInt(expiresIn) * 60;
    } else if (expiresIn.endsWith('d')) {
      expirationTime += parseInt(expiresIn) * 24 * 3600;
    } else {
      expirationTime += parseInt(expiresIn);
    }

    const finalPayload = {
      ...payload,
      iat: now,
      exp: expirationTime,
      jti: `jwt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    };

    Logger.debug('JWT Payload', finalPayload);
    Logger.keyValue('Issued At', new Date(now * 1000).toISOString());
    Logger.keyValue('Expires At', new Date(expirationTime * 1000).toISOString());
    Logger.keyValue('Valid For', expiresIn);

    try {
      Logger.step(4, 'Signing JWT token...');
      
      const jwt = await new jose.SignJWT(finalPayload)
        .setProtectedHeader(header)
        .sign(keyPair.privateKey);

      Logger.success('JWT token created successfully!');

      if (explain) {
        Logger.explain(
          'Token Creation Process',
          'Here\'s what happened:\n' +
          '   1. We looked up the private key using the key ID (kid)\n' +
          '   2. We created a header with algorithm info and key ID\n' +
          '   3. We prepared the payload with your data plus standard claims\n' +
          '   4. We signed everything using the private key\n' +
          '   The resulting token can be verified by anyone with the public key!'
        );

        formatJWTToken(jwt);
      }

      return jwt;

    } catch (error) {
      Logger.error(`Failed to create JWT: ${error}`);
      throw error;
    }
  }

  async verifyToken(
    token: string,
    issuer?: string,
    audience?: string,
    explain = true
  ): Promise<VerificationResult[]> {
    if (explain) {
      Logger.section('🔍 Verifying JWT Token');
      JWTEducator.explainTokenVerification();
      formatJWTToken(token);
    }

    const results: VerificationResult[] = [];
    const keyPairs = await this.jwksManager.getAllKeyPairs();

    if (keyPairs.length === 0) {
      Logger.warning('No keys available for verification!');
      return results;
    }

    // Try to get the kid from token header
    let tokenKid: string | undefined;
    try {
      const { header } = parseJWTToken(token);
      tokenKid = header.kid;
      if (tokenKid) {
        Logger.info(`Token specifies key ID: ${tokenKid}`);
      } else {
        Logger.info('Token does not specify a key ID, will try all available keys');
      }
    } catch (error) {
      Logger.warning('Could not parse token header');
    }

    Logger.step(1, `Testing against ${keyPairs.length} available key(s)`);

    for (const keyPair of keyPairs) {
      Logger.info(`\n🔑 Testing key: ${keyPair.kid} (${keyPair.algorithm})`);
      
      try {
        const verificationOptions: jose.JWTVerifyOptions = {};
        if (issuer) verificationOptions.issuer = issuer;
        if (audience) verificationOptions.audience = audience;

        Logger.debug('Verification options', verificationOptions);

        const { payload, protectedHeader } = await jose.jwtVerify(
          token,
          keyPair.publicKey,
          verificationOptions
        );

        Logger.success(`✅ Verification SUCCESS with key: ${keyPair.kid}`);
        Logger.keyValue('Algorithm matched', protectedHeader.alg || 'unknown');
        Logger.keyValue('Token expires', new Date((payload.exp || 0) * 1000).toISOString());
        
        if (explain && payload.sub) {
          Logger.keyValue('Subject (user)', payload.sub as string);
        }

        results.push({
          success: true,
          keyId: keyPair.kid,
          algorithm: keyPair.algorithm,
          payload,
          protectedHeader
        });

        if (tokenKid && tokenKid === keyPair.kid) {
          Logger.info('🎯 This was the key specified in the token header!');
        }

      } catch (error) {
        Logger.error(`❌ Verification FAILED with key: ${keyPair.kid}`);
        Logger.debug('Error details', error instanceof Error ? error.message : String(error));

        results.push({
          success: false,
          keyId: keyPair.kid,
          algorithm: keyPair.algorithm,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }

    // Summary
    const successCount = results.filter(r => r.success).length;
    Logger.step(2, 'Verification Summary');
    
    if (successCount > 0) {
      Logger.success(`Token verified successfully with ${successCount} key(s)`);
      
      if (successCount > 1) {
        Logger.warning(
          '⚠️  Multiple keys verified this token. In production, this might indicate:\n' +
          '   • Key rotation in progress\n' +
          '   • Multiple valid signing keys\n' +
          '   • Check the "kid" claim to identify the intended key'
        );
      }
    } else {
      Logger.error('❌ Token verification failed with ALL available keys');
      Logger.info('This could mean:');
      Logger.info('   • Token was signed with a different key');
      Logger.info('   • Token has been tampered with');
      Logger.info('   • Token has expired');
      Logger.info('   • Wrong issuer or audience claims');
    }

    if (explain) {
      JWTEducator.explainSecurity();
    }

    return results;
  }

  async createAccessRefreshTokenPair(
    kid: string,
    subject: string,
    payload: TokenPayload = {},
    accessTokenTTL = '15m',
    refreshTokenTTL = '7d',
    explain = true
  ): Promise<{ accessToken: string; refreshToken: string; sessionId: string }> {
    if (explain) {
      Logger.section('🔄 Creating Access & Refresh Token Pair');
      Logger.explain(
        'Access & Refresh Tokens',
        'A common pattern for secure authentication:\n' +
        '   • Access Token: Short-lived (15min), used for API requests\n' +
        '   • Refresh Token: Long-lived (7 days), used to get new access tokens\n' +
        '   This minimizes the time window if an access token is compromised.'
      );
    }

    const sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    Logger.step(1, 'Creating Access Token');
    const accessPayload = {
      ...payload,
      sub: subject,
      type: 'access',
      session_id: sessionId
    };

    const accessToken = await this.createToken(kid, accessPayload, accessTokenTTL, false);
    Logger.success(`Access token created (expires in ${accessTokenTTL})`);

    Logger.step(2, 'Creating Refresh Token');
    const refreshPayload = {
      sub: subject,
      type: 'refresh',
      session_id: sessionId
    };

    const refreshToken = await this.createToken(kid, refreshPayload, refreshTokenTTL, false);
    Logger.success(`Refresh token created (expires in ${refreshTokenTTL})`);

    if (explain) {
      Logger.explain(
        'Token Usage',
        'How to use these tokens:\n' +
        '   1. Use the access token for API requests (Authorization: Bearer <token>)\n' +
        '   2. When access token expires, use refresh token to get a new pair\n' +
        '   3. Store refresh token securely (httpOnly cookie recommended)\n' +
        `   4. Session ID: ${sessionId} tracks this login session`
      );
    }

    return { accessToken, refreshToken, sessionId };
  }

  async refreshAccessToken(
    refreshToken: string,
    kid: string,
    newAccessTokenTTL = '15m',
    explain = true
  ): Promise<{ accessToken: string; sessionId: string }> {
    if (explain) {
      Logger.section('🔄 Refreshing Access Token');
      Logger.explain(
        'Token Refresh Process',
        'Steps to refresh an access token:\n' +
        '   1. Verify the refresh token is valid and not expired\n' +
        '   2. Extract the subject and session info\n' +
        '   3. Create a new access token with the same claims\n' +
        '   4. The refresh token remains valid for future refreshes'
      );
    }

    Logger.step(1, 'Verifying refresh token');
    const verificationResults = await this.verifyToken(refreshToken, undefined, undefined, false);
    
    const validResult = verificationResults.find(r => r.success);
    if (!validResult || !validResult.payload) {
      Logger.error('Refresh token is invalid or expired');
      throw new Error('Invalid refresh token');
    }

    Logger.success('Refresh token is valid');

    // Check if it's actually a refresh token
    if (validResult.payload.type !== 'refresh') {
      Logger.error('Token is not a refresh token');
      throw new Error('Provided token is not a refresh token');
    }

    const subject = validResult.payload.sub as string;
    const sessionId = validResult.payload.session_id as string;

    Logger.keyValue('Subject', subject);
    Logger.keyValue('Session ID', sessionId);

    Logger.step(2, 'Creating new access token');
    const newAccessPayload = {
      sub: subject,
      type: 'access',
      session_id: sessionId
    };

    const accessToken = await this.createToken(kid, newAccessPayload, newAccessTokenTTL, false);
    Logger.success('New access token created successfully');

    if (explain) {
      Logger.explain(
        'Refresh Complete',
        'The old access token is now invalid (if it hadn\'t expired already).\n' +
        'Use this new access token for API requests.\n' +
        'The refresh token remains valid for future refreshes.'
      );
    }

    return { accessToken, sessionId };
  }
}