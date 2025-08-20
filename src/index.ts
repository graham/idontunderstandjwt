#!/usr/bin/env node

import { program } from './cli';
import { Logger } from './utils';

async function main() {
  try {
    // If no arguments provided, show help
    if (process.argv.length <= 2) {
      Logger.section('🎓 JWT Learning Tool');
      Logger.info('Welcome to the JWT educational tool!');
      Logger.info('');
      Logger.info('Start with these commands to learn JWT concepts:');
      Logger.info('  npm run cli -- learn-basics     # Learn JWT fundamentals');
      Logger.info('  npm run cli -- generate-key     # Create your first key pair');
      Logger.info('  npm run cli -- list-keys        # View your keys');
      Logger.info('');
      Logger.info('Use --help with any command for detailed options');
      Logger.info('Example: npm run cli -- create-token --help');
      Logger.info('');
      program.help();
      return;
    }

    await program.parseAsync(process.argv);
  } catch (error) {
    Logger.error(`Unexpected error: ${error}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}