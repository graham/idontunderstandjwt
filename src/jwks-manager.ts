import * as jose from 'jose';
import * as fs from 'fs';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { Logger, JWTEducator, generateCreativeName } from './utils';

export interface JWKSKey {
  kty: string;
  use: string;
  kid: string;
  alg: string;
  n?: string;
  e?: string;
  x?: string;
  y?: string;
  crv?: string;
  d?: string;
}

export interface JWKS {
  keys: JWKSKey[];
}

export interface StoredKeyPair {
  kid: string;
  algorithm: string;
  publicKey: any; // KeyLike from jose
  privateKey: any; // KeyLike from jose
  jwk: JWKSKey;
  created: string;
  description?: string;
  issuer?: string;
  audience?: string;
}

export class JWKSManager {
  private keysDir: string;
  private combinedJwksPath: string;
  private keyPairs: Map<string, StoredKeyPair> = new Map();

  constructor(jwksDir = './jwt-keys') {
    this.keysDir = path.resolve(jwksDir);
    
    // Ensure the jwt-keys directory exists
    if (!fs.existsSync(this.keysDir)) {
      fs.mkdirSync(this.keysDir, { recursive: true });
    }
    
    this.combinedJwksPath = path.join(this.keysDir, 'jwks.json');
    // Note: Can't await in constructor, keys will be loaded lazily
  }

  private getPublicKeyPath(kid: string): string {
    return path.join(this.keysDir, `${kid}.json`);
  }

  private getPrivateKeyPath(kid: string): string {
    return path.join(this.keysDir, `${kid}-private.json`);
  }

  private async ensureKeysLoaded(): Promise<void> {
    if (this.keyPairs.size === 0) {
      await this.loadJWKS();
    }
  }

  private async loadJWKS(): Promise<void> {
    try {
      // First check for migration from old shared files
      await this.migrateFromSharedFiles();
      
      // Load individual key files
      await this.loadIndividualKeyFiles();
      
      Logger.info(`Loaded ${this.keyPairs.size} key pairs in total`);
    } catch (error) {
      Logger.warning(`Could not load keys: ${error}`);
      Logger.info('Starting with empty key set');
    }
  }

  private async migrateFromSharedFiles(): Promise<void> {
    const oldJwksPath = path.join(this.keysDir, 'jwks.json');
    const oldPrivatePath = path.join(this.keysDir, 'jwks-private.json');
    
    if (fs.existsSync(oldJwksPath) && fs.existsSync(oldPrivatePath)) {
      try {
        Logger.info('Found old shared files, migrating to individual key files...');
        
        const jwksContent = fs.readFileSync(oldJwksPath, 'utf8');
        const jwks: JWKS = JSON.parse(jwksContent);
        
        const privateKeysContent = fs.readFileSync(oldPrivatePath, 'utf8');
        const privateKeysData = JSON.parse(privateKeysContent);
        
        let migratedCount = 0;
        
        // Migrate each key to individual files
        for (const publicJWK of jwks.keys) {
          if (publicJWK.kid && privateKeysData[publicJWK.kid]) {
            try {
              const keyData = privateKeysData[publicJWK.kid];
              
              // Save as individual files
              const publicKeyPath = this.getPublicKeyPath(publicJWK.kid);
              const privateKeyPath = this.getPrivateKeyPath(publicJWK.kid);
              
              // Only migrate if individual files don't already exist
              if (!fs.existsSync(publicKeyPath) && !fs.existsSync(privateKeyPath)) {
                fs.writeFileSync(publicKeyPath, JSON.stringify(publicJWK, null, 2));
                fs.writeFileSync(privateKeyPath, JSON.stringify(keyData, null, 2));
                migratedCount++;
              }
            } catch (error) {
              Logger.warning(`Could not migrate key ${publicJWK.kid}: ${error}`);
            }
          }
        }
        
        if (migratedCount > 0) {
          Logger.success(`Migrated ${migratedCount} keys to individual files`);
          
          // Backup old files before removing
          const backupSuffix = `-backup-${Date.now()}`;
          fs.renameSync(oldJwksPath, oldJwksPath.replace('.json', `${backupSuffix}.json`));
          fs.renameSync(oldPrivatePath, oldPrivatePath.replace('.json', `${backupSuffix}.json`));
          
          Logger.info('Old shared files backed up and removed');
        }
      } catch (error) {
        Logger.warning(`Migration failed: ${error}`);
      }
    }
  }

  private async loadIndividualKeyFiles(): Promise<void> {
    try {
      const files = fs.readdirSync(this.keysDir);
      const keyFiles = files.filter(file => file.endsWith('.json') && !file.endsWith('-private.json') && file !== 'jwks.json');
      
      Logger.info(`Found ${keyFiles.length} individual key files`);
      
      for (const publicKeyFile of keyFiles) {
        const kid = publicKeyFile.replace('.json', '');
        const publicKeyPath = this.getPublicKeyPath(kid);
        const privateKeyPath = this.getPrivateKeyPath(kid);
        
        if (fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath)) {
          try {
            const publicJWK = JSON.parse(fs.readFileSync(publicKeyPath, 'utf8'));
            const privateKeyData = JSON.parse(fs.readFileSync(privateKeyPath, 'utf8'));
            
            const publicKey = await jose.importJWK(publicJWK, publicJWK.alg, { extractable: true });
            const privateKey = await jose.importJWK(privateKeyData.privateJWK, publicJWK.alg, { extractable: true });
            
            const storedKey: StoredKeyPair = {
              kid: publicJWK.kid,
              algorithm: publicJWK.alg,
              publicKey,
              privateKey,
              jwk: publicJWK,
              created: privateKeyData.created,
              ...(privateKeyData.description && { description: privateKeyData.description }),
              ...(privateKeyData.issuer && { issuer: privateKeyData.issuer }),
              ...(privateKeyData.audience && { audience: privateKeyData.audience })
            };
            
            this.keyPairs.set(kid, storedKey);
            Logger.success(`Loaded key: ${kid}`);
          } catch (error) {
            Logger.warning(`Could not load key ${kid}: ${error}`);
          }
        }
      }
    } catch (error) {
      Logger.warning(`Could not scan for individual key files: ${error}`);
    }
  }

  private async saveKey(keyPair: StoredKeyPair): Promise<void> {
    try {
      // Save individual public key file
      const publicJWK = { ...keyPair.jwk };
      delete publicJWK.d; // Remove private key component
      
      const publicKeyPath = this.getPublicKeyPath(keyPair.kid);
      fs.writeFileSync(publicKeyPath, JSON.stringify(publicJWK, null, 2));
      
      // Save individual private key file
      const privateJWK = await jose.exportJWK(keyPair.privateKey);
      const privateKeyData = {
        privateJWK,
        created: keyPair.created,
        description: keyPair.description,
        issuer: keyPair.issuer,
        audience: keyPair.audience
      };
      
      const privateKeyPath = this.getPrivateKeyPath(keyPair.kid);
      fs.writeFileSync(privateKeyPath, JSON.stringify(privateKeyData, null, 2));
      
      Logger.success(`Key files saved: ${keyPair.kid}.json and ${keyPair.kid}-private.json`);
    } catch (error) {
      Logger.error(`Failed to save key ${keyPair.kid}: ${error}`);
      throw error;
    }
  }

  private async saveAllKeys(): Promise<void> {
    try {
      Logger.step(1, 'Saving individual key files');
      
      // Save each key as individual files
      for (const keyPair of this.keyPairs.values()) {
        await this.saveKey(keyPair);
      }
      
      // Also save combined JWKS for compatibility
      const publicJWKS: JWKS = {
        keys: Array.from(this.keyPairs.values()).map(keyPair => {
          const publicJWK = { ...keyPair.jwk };
          delete publicJWK.d; // Remove private key component
          return publicJWK;
        })
      };

      fs.writeFileSync(this.combinedJwksPath, JSON.stringify(publicJWKS, null, 2));
      Logger.success(`Combined JWKS saved to: ${this.combinedJwksPath}`);

    } catch (error) {
      Logger.error(`Failed to save keys: ${error}`);
      throw error;
    }
  }

  async generateKeyPair(algorithm: string, customName?: string, description?: string, issuer?: string, audience?: string, explain = true): Promise<string> {
    if (explain) {
      Logger.section('🔑 Generating New Key Pair');
      JWTEducator.explainKeyPairs();
      JWTEducator.explainAlgorithm(algorithm);
    }

    Logger.step(1, `Generating ${algorithm} key pair...`);
    
    try {
      const { publicKey, privateKey } = await jose.generateKeyPair(algorithm as any, { extractable: true });
      Logger.success('Key pair generated successfully!');

      Logger.step(2, 'Creating unique key identifier (kid)');
      const kid = customName || generateCreativeName();
      Logger.keyValue('Key ID (kid)', kid);

      Logger.step(3, 'Converting to JWK format');
      const publicJWK = await jose.exportJWK(publicKey);
      const privateJWK = await jose.exportJWK(privateKey);

      // Add required JWK fields
      const jwk: JWKSKey = {
        ...publicJWK,
        kid,
        alg: algorithm,
        use: 'sig',
        kty: publicJWK.kty!
      };

      if (explain) {
        Logger.debug('Generated JWK (public parts)', jwk);
      }

      Logger.step(4, 'Storing key pair in memory');
      const storedKey: StoredKeyPair = {
        kid,
        algorithm,
        publicKey,
        privateKey,
        jwk,
        created: new Date().toISOString(),
        ...(description && { description }),
        ...(issuer && { issuer }),
        ...(audience && { audience })
      };

      this.keyPairs.set(kid, storedKey);
      Logger.success(`Key pair stored with ID: ${kid}`);

      Logger.step(5, 'Saving key files');
      await this.saveAllKeys();

      if (explain) {
        Logger.explain(
          'What just happened?',
          `We created a new ${algorithm} key pair and:\n` +
          `   • Generated a unique ID (kid) to identify this key\n` +
          `   • Stored the private key in memory (for signing)\n` +
          `   • Added the public key to the JWKS (for verification)\n` +
          `   • Saved everything to ${this.keysDir}`
        );
      }

      return kid;

    } catch (error) {
      Logger.error(`Failed to generate key pair: ${error}`);
      throw error;
    }
  }

  async listKeys(explain = true): Promise<void> {
    await this.ensureKeysLoaded();
    if (explain) {
      Logger.section('📋 Key Inventory');
      if (this.keyPairs.size > 0) {
        JWTEducator.explainJWKS();
      }
    }

    if (this.keyPairs.size === 0) {
      Logger.warning('No keys found in the key store');
      Logger.info('Use "generate-key" command to create your first key pair');
      return;
    }

    Logger.info(`Found ${this.keyPairs.size} key pair(s):`);
    
    this.keyPairs.forEach((keyPair, index) => {
      console.log(`\n${index + 1}. ${keyPair.kid}`);
      Logger.keyValue('  Algorithm', keyPair.algorithm);
      Logger.keyValue('  Created', new Date(keyPair.created).toLocaleString());
      Logger.keyValue('  Key Type', keyPair.jwk.kty);
      if (keyPair.description) {
        Logger.keyValue('  Description', keyPair.description);
      }
    });

    if (explain) {
      Logger.explain(
        'Key Management',
        'Each key has a unique ID (kid) that identifies it in JWT tokens.\n' +
        'When verifying a token, we look at the "kid" in the token header\n' +
        'to know which public key to use for verification.'
      );
    }
  }

  getPublicJWKS(): JWKS {
    return {
      keys: Array.from(this.keyPairs.values()).map(keyPair => {
        const publicJWK = { ...keyPair.jwk };
        delete publicJWK.d; // Remove private key component
        return publicJWK;
      })
    };
  }

  async getKeyPair(kid: string): Promise<StoredKeyPair | undefined> {
    await this.ensureKeysLoaded();
    return this.keyPairs.get(kid);
  }

  async getAllKeyPairs(): Promise<StoredKeyPair[]> {
    await this.ensureKeysLoaded();
    return Array.from(this.keyPairs.values());
  }

  exportPublicJWKS(filePath?: string, explain = true): void {
    if (explain) {
      Logger.section('📤 Exporting Public JWKS');
      Logger.explain(
        'Public JWKS Export',
        'This creates a file containing only the PUBLIC keys.\n' +
        'This is what you would serve at your /.well-known/jwks.json endpoint\n' +
        'for other services to verify your JWT tokens.'
      );
    }

    const outputPath = filePath || './public-jwks.json';
    const publicJWKS = this.getPublicJWKS();

    Logger.step(1, 'Preparing public-only JWKS');
    Logger.debug('Public JWKS', publicJWKS);

    try {
      fs.writeFileSync(outputPath, JSON.stringify(publicJWKS, null, 2));
      Logger.success(`Public JWKS exported to: ${outputPath}`);
      
      if (explain) {
        Logger.info('🌐 This file is safe to share publicly and contains no secret information');
      }
    } catch (error) {
      Logger.error(`Failed to export JWKS: ${error}`);
      throw error;
    }
  }

  async removeKey(kid: string, explain = true): Promise<boolean> {
    await this.ensureKeysLoaded();
    if (explain) {
      Logger.section('🗑️  Removing Key');
    }

    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      Logger.error(`Key not found: ${kid}`);
      return false;
    }

    Logger.step(1, `Removing key: ${kid}`);
    Logger.keyValue('Algorithm', keyPair.algorithm);
    Logger.keyValue('Created', new Date(keyPair.created).toLocaleString());

    // Remove from memory
    this.keyPairs.delete(kid);
    
    Logger.step(2, 'Deleting individual key files');
    try {
      const publicKeyPath = this.getPublicKeyPath(kid);
      const privateKeyPath = this.getPrivateKeyPath(kid);
      
      if (fs.existsSync(publicKeyPath)) {
        fs.unlinkSync(publicKeyPath);
        Logger.success(`Deleted: ${kid}.json`);
      }
      
      if (fs.existsSync(privateKeyPath)) {
        fs.unlinkSync(privateKeyPath);
        Logger.success(`Deleted: ${kid}-private.json`);
      }
      
      // Update combined JWKS file
      await this.saveAllKeys();
      
    } catch (error) {
      Logger.error(`Failed to delete key files: ${error}`);
      return false;
    }

    Logger.success(`Key ${kid} removed successfully`);

    if (explain) {
      Logger.warning(
        '⚠️  Important: Any JWT tokens signed with this key can no longer be verified!\n' +
        '   Make sure all tokens using this key have expired before removing it.'
      );
    }

    return true;
  }

  async clearAll(includeBackups = false, explain = true): Promise<boolean> {
    try {
      if (explain) {
        Logger.section('🧹 Clearing All Keys');
        Logger.warning('This will remove all generated keys and JWKS files!');
      }

      // Clear in-memory keys first
      const keyCount = this.keyPairs.size;
      this.keyPairs.clear();

      // Remove all individual key files
      const files = fs.readdirSync(this.keysDir);
      let removedCount = 0;

      for (const file of files) {
        const filePath = path.join(this.keysDir, file);
        
        // Remove individual key files and combined JWKS
        if (file.endsWith('.json')) {
          const shouldRemove = 
            file.endsWith('-private.json') || // Private key files
            (!file.endsWith('-private.json') && !file.includes('backup') && file !== 'jwks.json') || // Public key files  
            file === 'jwks.json' || // Combined JWKS
            (includeBackups && file.includes('backup')); // Backup files if requested

          if (shouldRemove) {
            fs.unlinkSync(filePath);
            removedCount++;
            if (explain) {
              Logger.success(`Removed: ${file}`);
            }
          }
        }
      }

      if (explain) {
        Logger.success(`Cleared ${keyCount} keys from memory and ${removedCount} files from disk`);
        
        if (!includeBackups) {
          const backupFiles = files.filter(f => f.includes('backup'));
          if (backupFiles.length > 0) {
            Logger.info(`Kept ${backupFiles.length} backup files (use --include-backups to remove them)`);
          }
        }
      }

      return true;
    } catch (error) {
      Logger.error(`Failed to clear keys: ${error}`);
      return false;
    }
  }

  async exportPrivateKeyAsPKCS8(kid: string, explain = true): Promise<string> {
    await this.ensureKeysLoaded();
    
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      throw new Error(`Key not found: ${kid}`);
    }

    if (explain) {
      Logger.section('📤 Exporting Private Key as PKCS8');
      Logger.explain(
        'PKCS8 Format',
        'PKCS8 is a standard format for private keys used by Convex and many other systems.\n' +
        'It starts with "-----BEGIN PRIVATE KEY-----" and is base64 encoded.\n' +
        'For environment variables, newlines are replaced with spaces.'
      );
    }

    try {
      // Export the private key as PKCS8 PEM format
      const pkcs8Pem = await jose.exportPKCS8(keyPair.privateKey);
      
      if (explain) {
        Logger.success(`Private key for ${kid} exported as PKCS8`);
        Logger.info('This format is suitable for Convex JWT_PRIVATE_KEY environment variable');
      }
      
      return pkcs8Pem;
    } catch (error) {
      Logger.error(`Failed to export private key as PKCS8: ${error}`);
      throw error;
    }
  }

  async exportPublicKeyAsSPKI(kid: string, explain = true): Promise<string> {
    await this.ensureKeysLoaded();
    
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      throw new Error(`Key not found: ${kid}`);
    }

    if (explain) {
      Logger.section('📤 Exporting Public Key as SPKI');
      Logger.explain(
        'SPKI Format',
        'SPKI is a standard format for public keys.\n' +
        'It starts with "-----BEGIN PUBLIC KEY-----" and is base64 encoded.\n' +
        'This key can be shared publicly and is used for JWT verification.'
      );
    }

    try {
      // Export the public key as SPKI PEM format
      const spkiPem = await jose.exportSPKI(keyPair.publicKey);
      
      if (explain) {
        Logger.success(`Public key for ${kid} exported as SPKI`);
        Logger.info('This format can be shared publicly for JWT verification');
      }
      
      return spkiPem;
    } catch (error) {
      Logger.error(`Failed to export public key as SPKI: ${error}`);
      throw error;
    }
  }

  async exportJWKSAsBase64(kids?: string[], explain = true): Promise<string> {
    await this.ensureKeysLoaded();
    if (explain) {
      Logger.section('📤 Exporting JWKS as Base64');
      Logger.explain(
        'Base64 JWKS Data URI',
        'Creates a data URI with base64-encoded JWKS for use in environment variables.\n' +
        'Format: "data:text/plain;charset=utf-8;base64,{encoded-jwks}"\n' +
        'This allows Convex to load your public keys for JWT verification.'
      );
    }

    let jwks: JWKS;
    
    if (kids && kids.length > 0) {
      // Export specific keys
      const selectedKeys = kids.map(kid => {
        const keyPair = this.keyPairs.get(kid);
        if (!keyPair) {
          throw new Error(`Key not found: ${kid}`);
        }
        const publicJWK = { ...keyPair.jwk };
        delete publicJWK.d; // Remove private key component
        return publicJWK;
      });
      
      jwks = { keys: selectedKeys };
    } else {
      // Export all public keys
      jwks = this.getPublicJWKS();
    }

    // Convert to base64 data URI
    const jwksJson = JSON.stringify(jwks);
    const base64Jwks = Buffer.from(jwksJson, 'utf-8').toString('base64');
    const dataUri = `data:text/plain;charset=utf-8;base64,${base64Jwks}`;

    if (explain) {
      const keyCount = jwks.keys.length;
      Logger.success(`JWKS with ${keyCount} key(s) encoded as base64 data URI`);
      Logger.info('This format is suitable for Convex JWKS environment variable');
    }

    return dataUri;
  }

  async setKeyIssuerAudience(kid: string, issuer?: string, audience?: string, explain = true): Promise<boolean> {
    await this.ensureKeysLoaded();
    
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      throw new Error(`Key not found: ${kid}`);
    }

    if (explain) {
      Logger.section('⚙️  Configuring Key Issuer and Audience');
      Logger.explain(
        'JWT Issuer and Audience Claims',
        'Issuer (iss): Identifies who issued the JWT (e.g., "https://myapp.com")\n' +
        'Audience (aud): Identifies who the JWT is intended for (e.g., "convex" or "myapp-api")\n' +
        'These claims are crucial for security and must match your Convex auth configuration.'
      );
    }

    // Update the stored key pair
    keyPair.issuer = issuer;
    keyPair.audience = audience;

    // Save the updated key pair
    await this.saveKey(keyPair);

    if (explain) {
      Logger.success(`Updated key ${kid} configuration:`);
      if (issuer) Logger.keyValue('Issuer (iss)', issuer);
      if (audience) Logger.keyValue('Audience (aud)', audience);
    }

    return true;
  }

  async exportForConvexEnv(kid: string, issuer?: string, audience?: string, explain = true): Promise<{privateKey: string, publicKey: string, jwks: string, issuer?: string, audience?: string}> {
    await this.ensureKeysLoaded();
    
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      throw new Error(`Key not found: ${kid}`);
    }

    if (explain) {
      Logger.section('🔧 Exporting for Convex Environment Variables');
      Logger.info(`Preparing key "${kid}" for Convex deployment...`);
    }

    // Use provided issuer/audience or fall back to stored values
    const finalIssuer = issuer || keyPair.issuer;
    const finalAudience = audience || keyPair.audience;

    // Get PKCS8 private key
    const pkcs8 = await this.exportPrivateKeyAsPKCS8(kid, false);
    
    // Get SPKI public key
    const spki = await this.exportPublicKeyAsSPKI(kid, false);
    
    // Format for environment variable (replace newlines with spaces)
    const envPrivateKey = pkcs8.trimEnd().replace(/\n/g, ' ');
    const envPublicKey = spki.trimEnd().replace(/\n/g, ' ');
    
    // Get JWKS for this specific key
    const jwks = await this.exportJWKSAsBase64([kid], false);

    if (explain) {
      Logger.success('Environment variables prepared:');
      Logger.keyValue('JWT_PRIVATE_KEY', `"${envPrivateKey.substring(0, 60)}..."`);
      Logger.keyValue('JWT_PUBLIC_KEY', `"${envPublicKey.substring(0, 60)}..."`);
      Logger.keyValue('JWKS', `"${jwks.substring(0, 60)}..."`);
      if (finalIssuer) Logger.keyValue('Issuer', finalIssuer);
      if (finalAudience) Logger.keyValue('Audience', finalAudience);
      
      Logger.info('\nConvex Configuration:');
      Logger.info('Add these to your environment variables and create:');
      Logger.info('convex/auth.config.ts with:');
      if (finalIssuer || finalAudience) {
        console.log(`export default {
  providers: [
    {
      type: "customJwt",${finalAudience ? `\n      applicationID: "${finalAudience}",` : ''}${finalIssuer ? `\n      issuer: "${finalIssuer}",` : ''}
      jwks: process.env.JWKS,
    },
  ],
};`);
      }
    }

    return {
      privateKey: envPrivateKey,
      publicKey: envPublicKey,
      jwks: jwks,
      ...(finalIssuer && { issuer: finalIssuer }),
      ...(finalAudience && { audience: finalAudience })
    };
  }
}