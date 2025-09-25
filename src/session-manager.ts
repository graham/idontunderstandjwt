import * as fs from 'fs';
import * as path from 'path';
import { Logger, JWTEducator } from './utils';
import { JWTOperations } from './jwt-operations';

export interface SessionData {
  sessionId: string;
  sessionName: string;
  subject: string;
  keyId: string;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiry: Date;
  refreshTokenExpiry: Date;
  created: Date;
  lastRefreshed?: Date;
  customClaims?: Record<string, any>;
}

export class SessionManager {
  private sessionsDir: string;

  constructor(sessionsDir = './sessions') {
    this.sessionsDir = path.resolve(sessionsDir);
    this.ensureSessionsDirectory();
  }

  private ensureSessionsDirectory(): void {
    if (!fs.existsSync(this.sessionsDir)) {
      fs.mkdirSync(this.sessionsDir, { recursive: true });
      Logger.info(`Created sessions directory: ${this.sessionsDir}`);
    }
  }

  private getSessionFilePath(sessionName: string): string {
    return path.join(this.sessionsDir, `${sessionName}.json`);
  }

  async createSession(
    sessionName: string,
    subject: string,
    keyId: string,
    jwtOps: JWTOperations,
    customClaims: Record<string, any> = {},
    accessTokenTTL = '15m',
    refreshTokenTTL = '7d',
    explain = true
  ): Promise<SessionData> {
    if (explain) {
      Logger.section('📁 Creating Authentication Session');
      Logger.explain(
        'Session Management',
        'Sessions help manage user authentication state:\n' +
        '   • Store access and refresh tokens\n' +
        '   • Track expiration times\n' +
        '   • Enable token refreshing\n' +
        '   • Persist across CLI runs'
      );
    }

    Logger.step(1, `Creating session: ${sessionName}`);
    Logger.keyValue('Subject (User)', subject);
    Logger.keyValue('Key ID', keyId);
    Logger.keyValue('Access Token TTL', accessTokenTTL);
    Logger.keyValue('Refresh Token TTL', refreshTokenTTL);

    const sessionPath = this.getSessionFilePath(sessionName);
    
    if (fs.existsSync(sessionPath)) {
      Logger.warning(`Session file already exists: ${sessionName}`);
      Logger.info('Use refresh-session to update an existing session');
      throw new Error(`Session ${sessionName} already exists`);
    }

    Logger.step(2, 'Generating access and refresh token pair');
    const { accessToken, refreshToken, sessionId } = await jwtOps.createAccessRefreshTokenPair(
      keyId,
      subject,
      customClaims,
      accessTokenTTL,
      refreshTokenTTL,
      false // Don't explain here, we already did above
    );

    // Calculate expiry times
    const now = new Date();
    const accessExpiry = new Date(now.getTime() + this.parseTTL(accessTokenTTL) * 1000);
    const refreshExpiry = new Date(now.getTime() + this.parseTTL(refreshTokenTTL) * 1000);

    Logger.step(3, 'Creating session data');
    const sessionData: SessionData = {
      sessionId,
      sessionName,
      subject,
      keyId,
      accessToken,
      refreshToken,
      accessTokenExpiry: accessExpiry,
      refreshTokenExpiry: refreshExpiry,
      created: now,
      customClaims
    };

    Logger.step(4, 'Saving session to file');
    fs.writeFileSync(sessionPath, JSON.stringify(sessionData, null, 2));
    Logger.success(`Session saved: ${sessionPath}`);

    if (explain) {
      Logger.explain(
        'Session Created',
        `Session "${sessionName}" is now ready to use!\n` +
        `   • Access token expires: ${accessExpiry.toLocaleString()}\n` +
        `   • Refresh token expires: ${refreshExpiry.toLocaleString()}\n` +
        `   • Session file: ${sessionPath}`
      );
    }

    return sessionData;
  }

  async createSessionWithIssuerAudience(
    sessionName: string,
    subject: string,
    keyId: string,
    jwtOps: JWTOperations,
    customClaims: Record<string, any> = {},
    accessTokenTTL = '15m',
    refreshTokenTTL = '7d',
    issuer?: string,
    audience?: string,
    explain = true
  ): Promise<SessionData> {
    if (explain) {
      Logger.section('📁 Creating Authentication Session with Issuer/Audience');
      Logger.explain(
        'Session Management with Claims',
        'Creating a session with specific issuer and audience claims:\n' +
        '   • Issuer (iss): Who issued the tokens\n' +
        '   • Audience (aud): Who the tokens are intended for\n' +
        '   • These claims help verify token authenticity'
      );
    }

    Logger.step(1, `Creating session: ${sessionName}`);
    Logger.keyValue('Subject (User)', subject);
    Logger.keyValue('Key ID', keyId);
    if (issuer) Logger.keyValue('Issuer', issuer);
    if (audience) Logger.keyValue('Audience', audience);
    Logger.keyValue('Access Token TTL', accessTokenTTL);
    Logger.keyValue('Refresh Token TTL', refreshTokenTTL);

    const sessionPath = this.getSessionFilePath(sessionName);
    
    if (fs.existsSync(sessionPath)) {
      Logger.warning(`Session file already exists: ${sessionName}`);
      Logger.info('Use refresh-session to update an existing session');
      throw new Error(`Session ${sessionName} already exists`);
    }

    Logger.step(2, 'Generating access and refresh token pair with issuer/audience');
    const { accessToken, refreshToken, sessionId } = await jwtOps.createAccessRefreshTokenPairWithClaims(
      keyId,
      subject,
      customClaims,
      accessTokenTTL,
      refreshTokenTTL,
      issuer,
      audience,
      false // Don't explain here, we already did above
    );

    // Calculate expiry times
    const now = new Date();
    const accessExpiry = new Date(now.getTime() + this.parseTTL(accessTokenTTL) * 1000);
    const refreshExpiry = new Date(now.getTime() + this.parseTTL(refreshTokenTTL) * 1000);

    Logger.step(3, 'Creating session data');
    const sessionData: SessionData = {
      sessionId,
      sessionName,
      subject,
      keyId,
      accessToken,
      refreshToken,
      accessTokenExpiry: accessExpiry,
      refreshTokenExpiry: refreshExpiry,
      created: now,
      customClaims
    };

    Logger.step(4, 'Saving session to file');
    fs.writeFileSync(sessionPath, JSON.stringify(sessionData, null, 2));
    Logger.success(`Session saved: ${sessionPath}`);

    if (explain) {
      Logger.explain(
        'Session Created with Claims',
        `Session "${sessionName}" is now ready to use!\n` +
        `   • Access token expires: ${accessExpiry.toLocaleString()}\n` +
        `   • Refresh token expires: ${refreshExpiry.toLocaleString()}\n` +
        `   • Session file: ${sessionPath}` +
        (issuer ? `\n   • Issuer: ${issuer}` : '') +
        (audience ? `\n   • Audience: ${audience}` : '')
      );
    }

    return sessionData;
  }

  loadSession(sessionName: string, explain = true): SessionData {
    if (explain) {
      Logger.section('📂 Loading Authentication Session');
    }

    const sessionPath = this.getSessionFilePath(sessionName);
    
    if (!fs.existsSync(sessionPath)) {
      Logger.error(`Session not found: ${sessionName}`);
      throw new Error(`Session ${sessionName} does not exist`);
    }

    Logger.step(1, `Loading session: ${sessionName}`);
    
    try {
      const sessionContent = fs.readFileSync(sessionPath, 'utf8');
      const sessionData: SessionData = JSON.parse(sessionContent);
      
      // Convert date strings back to Date objects
      sessionData.created = new Date(sessionData.created);
      sessionData.accessTokenExpiry = new Date(sessionData.accessTokenExpiry);
      sessionData.refreshTokenExpiry = new Date(sessionData.refreshTokenExpiry);
      if (sessionData.lastRefreshed) {
        sessionData.lastRefreshed = new Date(sessionData.lastRefreshed);
      }

      Logger.success(`Session loaded: ${sessionName}`);
      Logger.keyValue('Subject', sessionData.subject);
      Logger.keyValue('Created', sessionData.created.toLocaleString());
      Logger.keyValue('Access Token Expires', sessionData.accessTokenExpiry.toLocaleString());
      Logger.keyValue('Refresh Token Expires', sessionData.refreshTokenExpiry.toLocaleString());

      // Check token status
      const now = new Date();
      const accessValid = now < sessionData.accessTokenExpiry;
      const refreshValid = now < sessionData.refreshTokenExpiry;

      if (!refreshValid) {
        Logger.error('🚨 Refresh token has expired! Session is no longer valid.');
      } else if (!accessValid) {
        Logger.warning('⏰ Access token has expired. Use refresh-session to get a new one.');
      } else {
        Logger.success('✅ Access token is still valid');
      }

      return sessionData;

    } catch (error) {
      Logger.error(`Failed to load session: ${error}`);
      throw error;
    }
  }

  async refreshSession(
    sessionName: string,
    jwtOps: JWTOperations,
    newAccessTokenTTL = '15m',
    explain = true
  ): Promise<SessionData> {
    if (explain) {
      Logger.section('🔄 Refreshing Authentication Session');
    }

    Logger.step(1, 'Loading existing session');
    const sessionData = this.loadSession(sessionName, false);

    // Check if refresh token is still valid
    const now = new Date();
    if (now >= sessionData.refreshTokenExpiry) {
      Logger.error('❌ Refresh token has expired. Create a new session.');
      throw new Error('Refresh token expired');
    }

    Logger.step(2, 'Using refresh token to get new access token');
    const { accessToken } = await jwtOps.refreshAccessToken(
      sessionData.refreshToken,
      sessionData.keyId,
      newAccessTokenTTL,
      false
    );

    Logger.step(3, 'Updating session data');
    sessionData.accessToken = accessToken;
    sessionData.accessTokenExpiry = new Date(now.getTime() + this.parseTTL(newAccessTokenTTL) * 1000);
    sessionData.lastRefreshed = now;

    Logger.step(4, 'Saving updated session');
    const sessionPath = this.getSessionFilePath(sessionName);
    fs.writeFileSync(sessionPath, JSON.stringify(sessionData, null, 2));

    Logger.success('Session refreshed successfully!');
    Logger.keyValue('New Access Token Expires', sessionData.accessTokenExpiry.toLocaleString());

    if (explain) {
      Logger.explain(
        'Session Refreshed',
        'Your session now has a fresh access token!\n' +
        '   • The old access token is no longer valid\n' +
        '   • The refresh token remains the same\n' +
        '   • Use the new access token for API requests'
      );
    }

    return sessionData;
  }

  listSessions(explain = true): string[] {
    if (explain) {
      Logger.section('📋 Authentication Sessions');
    }

    const sessionFiles = fs.readdirSync(this.sessionsDir)
      .filter(file => file.endsWith('.json'))
      .map(file => file.replace('.json', ''));

    if (sessionFiles.length === 0) {
      Logger.warning('No sessions found');
      Logger.info('Use "create-session" to create your first authentication session');
      return [];
    }

    Logger.info(`Found ${sessionFiles.length} session(s):`);

    sessionFiles.forEach((sessionName, index) => {
      try {
        const sessionData = this.loadSession(sessionName, false);
        const now = new Date();
        const accessValid = now < sessionData.accessTokenExpiry;
        const refreshValid = now < sessionData.refreshTokenExpiry;

        console.log(`\n${index + 1}. ${sessionName}`);
        Logger.keyValue('  Subject', sessionData.subject);
        Logger.keyValue('  Created', sessionData.created.toLocaleString());
        
        if (!refreshValid) {
          Logger.keyValue('  Status', '🚨 EXPIRED (refresh token)');
        } else if (!accessValid) {
          Logger.keyValue('  Status', '⏰ NEEDS REFRESH (access token)');
        } else {
          Logger.keyValue('  Status', '✅ ACTIVE');
        }

      } catch (error) {
        Logger.keyValue('  Status', '❌ ERROR loading session');
      }
    });

    return sessionFiles;
  }

  getSessionStatus(sessionName: string, explain = true): void {
    if (explain) {
      Logger.section('📊 Session Status');
    }

    const sessionData = this.loadSession(sessionName, false);
    const now = new Date();

    Logger.keyValue('Session Name', sessionData.sessionName);
    Logger.keyValue('Session ID', sessionData.sessionId);
    Logger.keyValue('Subject', sessionData.subject);
    Logger.keyValue('Key ID', sessionData.keyId);
    Logger.keyValue('Created', sessionData.created.toLocaleString());
    
    if (sessionData.lastRefreshed) {
      Logger.keyValue('Last Refreshed', sessionData.lastRefreshed.toLocaleString());
    }

    // Token status
    const accessValid = now < sessionData.accessTokenExpiry;
    const refreshValid = now < sessionData.refreshTokenExpiry;
    const accessTimeLeft = Math.max(0, sessionData.accessTokenExpiry.getTime() - now.getTime());
    const refreshTimeLeft = Math.max(0, sessionData.refreshTokenExpiry.getTime() - now.getTime());

    console.log('\n📊 Token Status:');
    Logger.keyValue('Access Token', accessValid ? '✅ Valid' : '❌ Expired');
    Logger.keyValue('Access Expires', sessionData.accessTokenExpiry.toLocaleString());
    if (accessValid) {
      Logger.keyValue('Time Left', this.formatDuration(accessTimeLeft));
    }

    Logger.keyValue('Refresh Token', refreshValid ? '✅ Valid' : '❌ Expired');
    Logger.keyValue('Refresh Expires', sessionData.refreshTokenExpiry.toLocaleString());
    if (refreshValid) {
      Logger.keyValue('Time Left', this.formatDuration(refreshTimeLeft));
    }

    if (sessionData.customClaims && Object.keys(sessionData.customClaims).length > 0) {
      console.log('\n📝 Custom Claims:');
      for (const [key, value] of Object.entries(sessionData.customClaims)) {
        Logger.keyValue(key, JSON.stringify(value));
      }
    }
  }

  removeSession(sessionName: string, explain = true): boolean {
    if (explain) {
      Logger.section('🗑️  Removing Session');
    }

    const sessionPath = this.getSessionFilePath(sessionName);
    
    if (!fs.existsSync(sessionPath)) {
      Logger.error(`Session not found: ${sessionName}`);
      return false;
    }

    Logger.step(1, `Removing session: ${sessionName}`);
    fs.unlinkSync(sessionPath);
    Logger.success(`Session ${sessionName} removed successfully`);

    if (explain) {
      Logger.warning(
        '⚠️  Session removed. All tokens from this session are now considered invalid.\n' +
        '   (Note: The actual JWT tokens don\'t know they\'re "invalid" until they expire)'
      );
    }

    return true;
  }

  clearAllSessions(explain = true): boolean {
    try {
      if (explain) {
        Logger.section('🧹 Clearing All Sessions');
        Logger.warning('This will remove all authentication sessions!');
      }

      const sessionNames = this.listSessions(false);
      
      if (sessionNames.length === 0) {
        if (explain) {
          Logger.info('No sessions found to clear');
        }
        return true;
      }

      let removedCount = 0;
      for (const sessionName of sessionNames) {
        if (this.removeSession(sessionName, false)) {
          removedCount++;
          if (explain) {
            Logger.success(`Removed session: ${sessionName}`);
          }
        }
      }

      if (explain) {
        Logger.success(`Cleared ${removedCount} sessions`);
        Logger.warning(
          '⚠️  All session tokens are now considered invalid.\n' +
          '   (Note: The actual JWT tokens don\'t know they\'re "invalid" until they expire)'
        );
      }

      return true;
    } catch (error) {
      Logger.error(`Failed to clear sessions: ${error}`);
      return false;
    }
  }

  private parseTTL(ttl: string): number {
    // Convert TTL string to seconds
    if (ttl.endsWith('h')) {
      return parseInt(ttl) * 3600;
    } else if (ttl.endsWith('m')) {
      return parseInt(ttl) * 60;
    } else if (ttl.endsWith('d')) {
      return parseInt(ttl) * 24 * 3600;
    } else {
      return parseInt(ttl);
    }
  }

  private formatDuration(milliseconds: number): string {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) {
      return `${days}d ${hours % 24}h ${minutes % 60}m`;
    } else if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }
}