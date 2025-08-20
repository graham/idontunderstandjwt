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
}

export class JWKSManager {
  private jwksPath: string;
  private privateKeysPath: string;
  private keyPairs: Map<string, StoredKeyPair> = new Map();

  constructor(jwksDir = './jwt-keys') {
    const keysDir = path.resolve(jwksDir);
    
    // Ensure the jwt-keys directory exists
    if (!fs.existsSync(keysDir)) {
      fs.mkdirSync(keysDir, { recursive: true });
    }
    
    this.jwksPath = path.join(keysDir, 'jwks.json');
    this.privateKeysPath = path.join(keysDir, 'jwks-private.json');
    // Note: Can't await in constructor, keys will be loaded lazily
  }

  private async ensureKeysLoaded(): Promise<void> {
    if (this.keyPairs.size === 0) {
      await this.loadJWKS();
    }
  }

  private async loadJWKS(): Promise<void> {
    try {
      if (fs.existsSync(this.jwksPath) && fs.existsSync(this.privateKeysPath)) {
        Logger.info(`Loading existing JWKS from: ${this.jwksPath}`);
        const jwksContent = fs.readFileSync(this.jwksPath, 'utf8');
        const jwks: JWKS = JSON.parse(jwksContent);
        
        const privateKeysContent = fs.readFileSync(this.privateKeysPath, 'utf8');
        const privateKeysData = JSON.parse(privateKeysContent);
        
        Logger.debug('Loaded JWKS', jwks);
        Logger.info(`Found ${jwks.keys.length} existing keys`);
        
        // Reconstruct key pairs from stored data
        for (const publicJWK of jwks.keys) {
          if (publicJWK.kid && privateKeysData[publicJWK.kid]) {
            try {
              const keyData = privateKeysData[publicJWK.kid];
              const publicKey = await jose.importJWK(publicJWK, publicJWK.alg);
              const privateKey = await jose.importJWK(keyData.privateJWK, publicJWK.alg);
              
              const storedKey: StoredKeyPair = {
                kid: publicJWK.kid,
                algorithm: publicJWK.alg,
                publicKey,
                privateKey,
                jwk: publicJWK,
                created: keyData.created,
                ...(keyData.description && { description: keyData.description })
              };
              
              this.keyPairs.set(publicJWK.kid, storedKey);
            } catch (error) {
              Logger.warning(`Could not reconstruct key ${publicJWK.kid}: ${error}`);
            }
          }
        }
        
        Logger.info(`Reconstructed ${this.keyPairs.size} key pairs in memory`);
      } else {
        Logger.info('No existing JWKS found, starting fresh');
      }
    } catch (error) {
      Logger.warning(`Could not load JWKS: ${error}`);
      Logger.info('Starting with empty key set');
    }
  }

  private async saveJWKS(): Promise<void> {
    try {
      const publicJWKS: JWKS = {
        keys: Array.from(this.keyPairs.values()).map(keyPair => {
          // Remove private key components for public JWKS
          const publicJWK = { ...keyPair.jwk };
          delete publicJWK.d; // Remove private key component
          return publicJWK;
        })
      };

      // Prepare private keys data
      const privateKeysData: Record<string, any> = {};
      for (const keyPair of this.keyPairs.values()) {
        const privateJWK = await jose.exportJWK(keyPair.privateKey);
        privateKeysData[keyPair.kid] = {
          privateJWK,
          created: keyPair.created,
          description: keyPair.description
        };
      }

      Logger.step(1, 'Preparing JWKS for storage');
      Logger.debug('Public JWKS to save', publicJWKS);

      fs.writeFileSync(this.jwksPath, JSON.stringify(publicJWKS, null, 2));
      Logger.success(`JWKS saved to: ${this.jwksPath}`);

      fs.writeFileSync(this.privateKeysPath, JSON.stringify(privateKeysData, null, 2));
      Logger.success(`Private keys saved to: ${this.privateKeysPath}`);

    } catch (error) {
      Logger.error(`Failed to save JWKS: ${error}`);
      throw error;
    }
  }

  async generateKeyPair(algorithm: string, customName?: string, description?: string, explain = true): Promise<string> {
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
        ...(description && { description })
      };

      this.keyPairs.set(kid, storedKey);
      Logger.success(`Key pair stored with ID: ${kid}`);

      Logger.step(5, 'Saving to JWKS file');
      await this.saveJWKS();

      if (explain) {
        Logger.explain(
          'What just happened?',
          `We created a new ${algorithm} key pair and:\n` +
          `   • Generated a unique ID (kid) to identify this key\n` +
          `   • Stored the private key in memory (for signing)\n` +
          `   • Added the public key to the JWKS (for verification)\n` +
          `   • Saved everything to ${this.jwksPath}`
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

    this.keyPairs.delete(kid);
    Logger.step(2, 'Updating JWKS file');
    await this.saveJWKS();

    Logger.success(`Key ${kid} removed successfully`);

    if (explain) {
      Logger.warning(
        '⚠️  Important: Any JWT tokens signed with this key can no longer be verified!\n' +
        '   Make sure all tokens using this key have expired before removing it.'
      );
    }

    return true;
  }
}