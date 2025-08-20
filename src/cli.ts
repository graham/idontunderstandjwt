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
  .option('-d, --description <description>', 'Description for this key')
  .option('--no-explain', 'Skip educational explanations')
  .action(async (options) => {
    try {
      const kid = await jwksManager.generateKeyPair(
        options.algorithm,
        options.description,
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