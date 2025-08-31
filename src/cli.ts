import { Command } from 'commander';
import { JWKSManager } from './jwks-manager';
import { JWTOperations } from './jwt-operations';
import { SessionManager } from './session-manager';
import { Logger, JWTEducator, formatJWTToken } from './utils';

const program = new Command();
const jwksManager = new JWKSManager();
const jwtOps = new JWTOperations(jwksManager);
const sessionManager = new SessionManager();

program
  .name('jwt-learner')
  .description('Educational JWT token management tool')
  .version('1.0.0');

// Generate Key Command
program
  .command('generate-key')
  .description('Generate a new key pair for JWT signing')
  .option('-a, --algorithm <algorithm>', 'Algorithm to use (RS256, ES256, Ed25519, etc.)', 'RS256')
  .option('-n, --name <name>', 'Custom name for this key (otherwise a creative name will be generated)')
  .option('-d, --description <description>', 'Description for this key')
  .option('-i, --issuer <issuer>', 'JWT issuer (iss) claim - who issued the token')
  .option('--audience <audience>', 'JWT audience (aud) claim - who the token is for')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      const kid = await jwksManager.generateKeyPair(
        options.algorithm,
        options.name,
        options.description,
        options.issuer,
        options.audience,
        options.explain
      );
      Logger.success(`\n🎉 Key generated successfully with ID: ${kid}`);
    } catch (error) {
      Logger.error(`Failed to generate key: ${error}`);
      process.exit(1);
    }
  });

// List Keys Command
program
  .command('list-keys')
  .description('List all available key pairs')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      await jwksManager.listKeys(options.explain);
    } catch (error) {
      Logger.error(`Failed to list keys: ${error}`);
      process.exit(1);
    }
  });

// Create Token Command
program
  .command('create-token')
  .description('Create a new JWT token')
  .requiredOption('-k, --kid <kid>', 'Key ID to use for signing')
  .option('-p, --payload <payload>', 'JSON payload for the token', '{}')
  .option('-s, --subject <subject>', 'Subject (user ID)')
  .option('-i, --issuer <issuer>', 'Token issuer')
  .option('-a, --audience <audience>', 'Token audience')
  .option('-e, --expires <expires>', 'Expiration time (1h, 30m, 7d, etc.)', '1h')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      let payload: any = {};
      
      if (options.payload !== '{}') {
        payload = JSON.parse(options.payload);
      }
      
      if (options.subject) payload.sub = options.subject;
      if (options.issuer) payload.iss = options.issuer;
      if (options.audience) payload.aud = options.audience;

      const token = await jwtOps.createToken(
        options.kid,
        payload,
        options.expires,
        options.explain
      );

      Logger.success('\n🎫 JWT Token Created:');
      console.log(token);

    } catch (error) {
      Logger.error(`Failed to create token: ${error}`);
      process.exit(1);
    }
  });

// Verify Token Command
program
  .command('verify-token')
  .description('Verify a JWT token against all available keys')
  .requiredOption('-t, --token <token>', 'JWT token to verify')
  .option('-i, --issuer <issuer>', 'Expected issuer')
  .option('-a, --audience <audience>', 'Expected audience')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      const results = await jwtOps.verifyToken(
        options.token,
        options.issuer,
        options.audience,
        options.explain
      );

      const successCount = results.filter(r => r.success).length;
      process.exit(successCount > 0 ? 0 : 1);

    } catch (error) {
      Logger.error(`Failed to verify token: ${error}`);
      process.exit(1);
    }
  });

// Parse Token Command (just decode without verification)
program
  .command('parse-token')
  .description('Parse and display JWT token structure without verification')
  .requiredOption('-t, --token <token>', 'JWT token to parse')
  .option('--no-explain', 'Skip educational explanations')
  .action((options) => {
    try {
      if (options.explain) {
        JWTEducator.explainJWTStructure();
      }
      formatJWTToken(options.token);
    } catch (error) {
      Logger.error(`Failed to parse token: ${error}`);
      process.exit(1);
    }
  });

// Export JWKS Command
program
  .command('export-jwks')
  .description('Export public JWKS for sharing')
  .option('-o, --output <file>', 'Output file path', './public-jwks.json')
  .option('--no-explain', 'Skip educational explanations')
  .action((options) => {
    try {
      jwksManager.exportPublicJWKS(options.output, options.explain);
    } catch (error) {
      Logger.error(`Failed to export JWKS: ${error}`);
      process.exit(1);
    }
  });

// Remove Key Command
program
  .command('remove-key')
  .description('Remove a key pair from the JWKS')
  .requiredOption('-k, --kid <kid>', 'Key ID to remove')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      const success = await jwksManager.removeKey(options.kid, options.explain);
      process.exit(success ? 0 : 1);
    } catch (error) {
      Logger.error(`Failed to remove key: ${error}`);
      process.exit(1);
    }
  });

// Session Management Commands

// Create Session Command
program
  .command('create-session')
  .description('Create a new authentication session with access and refresh tokens')
  .requiredOption('-n, --name <name>', 'Session name')
  .requiredOption('-s, --subject <subject>', 'Subject (user ID)')
  .requiredOption('-k, --kid <kid>', 'Key ID to use for signing')
  .option('-p, --payload <payload>', 'JSON payload for custom claims', '{}')
  .option('--access-ttl <ttl>', 'Access token TTL (15m, 1h, etc.)', '15m')
  .option('--refresh-ttl <ttl>', 'Refresh token TTL (7d, 30d, etc.)', '7d')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      let customClaims = {};
      if (options.payload !== '{}') {
        customClaims = JSON.parse(options.payload);
      }

      await sessionManager.createSession(
        options.name,
        options.subject,
        options.kid,
        jwtOps,
        customClaims,
        options.accessTtl,
        options.refreshTtl,
        options.explain
      );

    } catch (error) {
      Logger.error(`Failed to create session: ${error}`);
      process.exit(1);
    }
  });

// List Sessions Command
program
  .command('list-sessions')
  .description('List all authentication sessions')
  .option('--no-explain', 'Skip educational explanations')
  .action((options) => {
    sessionManager.listSessions(options.explain);
  });

// Session Status Command
program
  .command('session-status')
  .description('Show detailed status of an authentication session')
  .requiredOption('-n, --name <name>', 'Session name')
  .option('--no-explain', 'Skip educational explanations')
  .action((options) => {
    try {
      sessionManager.getSessionStatus(options.name, options.explain);
    } catch (error) {
      Logger.error(`Failed to get session status: ${error}`);
      process.exit(1);
    }
  });

// Refresh Session Command
program
  .command('refresh-session')
  .description('Refresh an authentication session to get a new access token')
  .requiredOption('-n, --name <name>', 'Session name')
  .option('--access-ttl <ttl>', 'New access token TTL', '15m')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      await sessionManager.refreshSession(
        options.name,
        jwtOps,
        options.accessTtl,
        options.explain
      );
    } catch (error) {
      Logger.error(`Failed to refresh session: ${error}`);
      process.exit(1);
    }
  });

// Get Session Token Command
program
  .command('get-session-token')
  .description('Get the current access token from a session')
  .requiredOption('-n, --name <name>', 'Session name')
  .option('-t, --type <type>', 'Token type (access or refresh)', 'access')
  .action((options) => {
    try {
      const sessionData = sessionManager.loadSession(options.name, false);
      
      const token = options.type === 'refresh' ? sessionData.refreshToken : sessionData.accessToken;
      const expiry = options.type === 'refresh' ? sessionData.refreshTokenExpiry : sessionData.accessTokenExpiry;
      
      Logger.info(`${options.type.toUpperCase()} token for session: ${options.name}`);
      Logger.keyValue('Expires', expiry.toLocaleString());
      
      const now = new Date();
      if (now >= expiry) {
        Logger.warning('⚠️  Token has expired!');
      } else {
        Logger.success('✅ Token is valid');
      }
      
      console.log('\nToken:');
      console.log(token);

    } catch (error) {
      Logger.error(`Failed to get session token: ${error}`);
      process.exit(1);
    }
  });

// Remove Session Command
program
  .command('remove-session')
  .description('Remove an authentication session')
  .requiredOption('-n, --name <name>', 'Session name')
  .option('--no-explain', 'Skip educational explanations')
  .action((options) => {
    try {
      const success = sessionManager.removeSession(options.name, options.explain);
      process.exit(success ? 0 : 1);
    } catch (error) {
      Logger.error(`Failed to remove session: ${error}`);
      process.exit(1);
    }
  });

// Configure Key Command
program
  .command('configure-key')
  .description('Configure issuer and audience for an existing key')
  .requiredOption('-k, --key <key>', 'Key to configure')
  .option('-i, --issuer <issuer>', 'JWT issuer (iss) claim - who issued the token')
  .option('-a, --audience <audience>', 'JWT audience (aud) claim - who the token is for')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      if (!options.issuer && !options.audience) {
        Logger.error('Please specify --issuer and/or --audience');
        process.exit(1);
      }

      await jwksManager.setKeyIssuerAudience(
        options.key,
        options.issuer,
        options.audience,
        options.explain
      );

    } catch (error) {
      Logger.error(`Failed to configure key: ${error}`);
      process.exit(1);
    }
  });

// Individual Export Commands
program
  .command('export')
  .description('Export individual JWT components (public-key, private-key, jwks)')
  .argument('<type>', 'What to export: public-key, private-key, or jwks')
  .requiredOption('-k, --key <key>', 'Key ID to export from')
  .option('--format <format>', 'Output format: pem (default) or raw', 'pem')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (type, options) => {
    try {
      const validTypes = ['public-key', 'private-key', 'jwks'];
      if (!validTypes.includes(type)) {
        console.error(`Error: Invalid export type: ${type}`);
        console.error('Valid types: public-key, private-key, jwks');
        process.exit(1);
      }

      // Temporarily suppress console output for clean piping
      const originalLog = console.log;
      const originalInfo = console.info;
      const originalError = console.error;
      
      // Redirect all console output to stderr or null during the operation
      console.log = () => {};
      console.info = () => {};
      console.error = () => {};

      let output = '';

      try {
        switch (type) {
          case 'public-key':
            output = await jwksManager.exportPublicKeyAsSPKI(options.key, false);
            break;

          case 'private-key':
            output = await jwksManager.exportPrivateKeyAsPKCS8(options.key, false);
            break;

          case 'jwks':
            if (options.format === 'raw') {
              // Export raw JWKS JSON for specific key
              output = await jwksManager.exportJWKSAsBase64([options.key], false);
              // Decode the base64 to get raw JSON
              const base64Data = output.replace('data:text/plain;charset=utf-8;base64,', '');
              const jwksJson = Buffer.from(base64Data, 'base64').toString('utf-8');
              output = JSON.stringify(JSON.parse(jwksJson), null, 2);
            } else {
              // Export base64-encoded JWKS (default)
              output = await jwksManager.exportJWKSAsBase64([options.key], false);
            }
            break;
        }
      } finally {
        // Restore console methods
        console.log = originalLog;
        console.info = originalInfo;
        console.error = originalError;
      }

      // Output only the raw content for piping
      console.log(output);

    } catch (error) {
      console.error(`Error: Failed to export ${type}: ${error}`);
      process.exit(1);
    }
  });

// Export Environment Variables Command
program
  .command('export-env')
  .description('Export JWT keys as environment variables for Convex')
  .option('-k, --key <key>', 'Specific key to export (exports both private key and JWKS)')
  .option('--jwks-only', 'Export only JWKS (all public keys) without private key')
  .option('--all-keys', 'Export JWKS containing all public keys')
  .option('-i, --issuer <issuer>', 'JWT issuer (iss) claim - who issued the token')
  .option('-a, --audience <audience>', 'JWT audience (aud) claim - who the token is for')
  .option('-f, --format <format>', 'Output format: console, file, or env-file', 'console')
  .option('-o, --output <file>', 'Output file path (when format is file or env-file)')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      if (!options.key && !options.jwksOnly && !options.allKeys) {
        Logger.error('Please specify --key <key-name>, --jwks-only, or --all-keys');
        Logger.info('Use "list-keys" to see available keys');
        process.exit(1);
      }

      let output = '';

      if (options.key) {
        // Export specific key (both private and public)
        const result = await jwksManager.exportForConvexEnv(options.key, options.issuer, options.audience, options.explain);
        
        if (options.format === 'env-file') {
          output = `JWT_PRIVATE_KEY="${result.privateKey}"\nJWT_PUBLIC_KEY="${result.publicKey}"\nJWKS="${result.jwks}"`;
          if (result.issuer) output += `\nCONVEX_JWT_ISSUER="${result.issuer}"`;
          if (result.audience) output += `\nCONVEX_JWT_AUDIENCE="${result.audience}"`;
          output += '\n';
        } else {
          output = `JWT_PRIVATE_KEY="${result.privateKey}"\nJWT_PUBLIC_KEY="${result.publicKey}"\nJWKS="${result.jwks}"`;
          if (result.issuer) output += `\nCONVEX_JWT_ISSUER="${result.issuer}"`;
          if (result.audience) output += `\nCONVEX_JWT_AUDIENCE="${result.audience}"`;
        }
      } else if (options.jwksOnly || options.allKeys) {
        // Export only JWKS (all public keys)
        const jwks = await jwksManager.exportJWKSAsBase64(undefined, options.explain);
        
        if (options.format === 'env-file') {
          output = `JWKS="${jwks}"\n`;
        } else {
          output = `JWKS="${jwks}"`;
        }
      }

      // Output handling
      if (options.format === 'file' || options.format === 'env-file') {
        if (!options.output) {
          Logger.error('Output file required when using --format file or env-file');
          process.exit(1);
        }
        
        const fs = require('fs');
        fs.writeFileSync(options.output, output);
        Logger.success(`Environment variables exported to: ${options.output}`);
      } else {
        // Console output
        Logger.section('🌍 Convex Environment Variables');
        console.log('\n' + output + '\n');
        
        if (options.explain) {
          Logger.info('Usage instructions:');
          Logger.info('1. Copy the above environment variables');
          Logger.info('2. Add them to your Convex dashboard or .env file');
          Logger.info('3. Configure your Convex auth to use these values');
        }
      }

    } catch (error) {
      Logger.error(`Failed to export environment variables: ${error}`);
      process.exit(1);
    }
  });

// Clear Command
program
  .command('clear')
  .description('Clear all generated keys and/or sessions')
  .option('--keys-only', 'Clear only keys, keep sessions')
  .option('--sessions-only', 'Clear only sessions, keep keys')
  .option('--include-backups', 'Also remove backup files')
  .option('--force', 'Skip confirmation prompt')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      const clearKeys = !options.sessionsOnly;
      const clearSessions = !options.keysOnly;
      
      if (options.explain) {
        Logger.section('🧹 Clear All Data');
        Logger.info('This command will remove:');
        if (clearKeys) Logger.info('  • All JWT keys and JWKS files');
        if (clearSessions) Logger.info('  • All authentication sessions');
        if (options.includeBackups) Logger.info('  • All backup files');
      }

      // Confirmation prompt unless --force is used
      if (!options.force) {
        const readline = require('readline');
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        });

        const answer = await new Promise<string>((resolve) => {
          rl.question('\n⚠️  Are you sure you want to clear this data? (yes/no): ', resolve);
        });
        rl.close();

        if (answer.toLowerCase() !== 'yes' && answer.toLowerCase() !== 'y') {
          Logger.info('Clear operation cancelled');
          return;
        }
      }

      let success = true;

      // Clear keys if requested
      if (clearKeys) {
        const keysSuccess = await jwksManager.clearAll(options.includeBackups, options.explain);
        success = success && keysSuccess;
      }

      // Clear sessions if requested
      if (clearSessions) {
        const sessionsSuccess = sessionManager.clearAllSessions(options.explain);
        success = success && sessionsSuccess;
      }

      if (success) {
        Logger.success('\n🎉 Clear operation completed successfully!');
        if (options.explain) {
          Logger.info('You now have a clean slate for learning and experimentation.');
        }
      } else {
        Logger.error('Some operations failed during clear');
        process.exit(1);
      }

    } catch (error) {
      Logger.error(`Failed to clear data: ${error}`);
      process.exit(1);
    }
  });

// Educational Commands

// JWT Basics Command
program
  .command('learn-basics')
  .description('Learn JWT basics and concepts')
  .action(() => {
    Logger.section('🎓 JWT Learning Module: Basics');
    JWTEducator.explainJWTStructure();
    JWTEducator.explainKeyPairs();
    JWTEducator.explainJWKS();
    JWTEducator.explainTokenVerification();
    JWTEducator.explainSecurity();
    
    Logger.section('🚀 Next Steps');
    Logger.info('Try these commands to get hands-on experience:');
    Logger.info('1. npm run cli -- generate-key');
    Logger.info('2. npm run cli -- create-token -k <key-id> -s user123');
    Logger.info('3. npm run cli -- verify-token -t <your-token>');
  });

// Algorithm Comparison Command
program
  .command('compare-algorithms')
  .description('Compare different JWT signing algorithms')
  .action(() => {
    Logger.section('🔒 JWT Algorithm Comparison');
    
    const algorithms = ['HS256', 'RS256', 'ES256', 'Ed25519'];
    algorithms.forEach(alg => {
      JWTEducator.explainAlgorithm(alg);
    });

    Logger.section('🤔 Which Algorithm Should I Use?');
    Logger.explain(
      'Algorithm Selection Guide',
      '• HS256 (HMAC): Simple, shared secret. Good for internal services.\n' +
      '• RS256 (RSA): Most common. Good compatibility, larger tokens.\n' +
      '• ES256 (ECDSA): Smaller keys and tokens, good performance.\n' +
      '• Ed25519 (EdDSA): Modern, fast, secure. Great choice for new projects.'
    );
  });

export { program };