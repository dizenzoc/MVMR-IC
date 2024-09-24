import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'io.ionic.starter',
  appName: 'MVMR_ionic_client',
  webDir: 'www',
  plugins: {
    Filesystem: {
      iosBasePath: 'Documents'
    }
  }
};

export default config;
