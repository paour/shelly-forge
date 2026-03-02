import axios from 'axios';
import * as crypto from 'crypto';

interface AuthChallenge {
  realm: string;
  nonce: number;
}

/**
 * Parses the WWW-Authenticate header from a Shelly 401 response.
 * Expected format: Digest realm="<realm>", nonce="<nonce>", algorithm=SHA-256
 */
function parseWWWAuthenticate(header: string): AuthChallenge {
  const realmMatch = header.match(/realm="([^"]+)"/);
  const nonceMatch = header.match(/nonce="?(\d+)"?/);
  if (!realmMatch || !nonceMatch) {
    throw new Error(`Cannot parse WWW-Authenticate header: ${header}`);
  }
  return {
    realm: realmMatch[1],
    nonce: parseInt(nonceMatch[1], 10),
  };
}

/**
 * Builds the Shelly Gen2 digest auth object for inclusion in the RPC request body.
 * Implements SHA-256 digest auth as defined in RFC7616 with Shelly-specific values.
 *
 * @param challenge - The auth challenge from the 401 response
 * @param password - The device password
 */
function buildShellyAuth(challenge: AuthChallenge, password: string): Record<string, unknown> {
  const username = 'admin';
  const cnonce = Math.floor(Math.random() * 0x100000000);
  const nc = 1; // nonce count is always 1 for stateless HTTP requests

  // HA1 = SHA256("admin:<realm>:<password>")
  const ha1 = crypto
    .createHash('sha256')
    .update(`${username}:${challenge.realm}:${password}`)
    .digest('hex');

  // HA2 = SHA256("dummy_method:dummy_uri") — Shelly-specific constant
  const ha2 = crypto
    .createHash('sha256')
    .update('dummy_method:dummy_uri')
    .digest('hex');

  // response = SHA256("<ha1>:<nonce>:<nc>:<cnonce>:auth:<ha2>")
  const response = crypto
    .createHash('sha256')
    .update(`${ha1}:${challenge.nonce}:${nc}:${cnonce}:auth:${ha2}`)
    .digest('hex');

  return {
    realm: challenge.realm,
    username,
    nonce: challenge.nonce,
    cnonce,
    response,
    algorithm: 'SHA-256',
  };
}

export class ShellyDevice {
  private readonly SYMBOLS_IN_CHUNK = 1024;
  private readonly password?: string;

  /**
   * @param ip - Device IP address or hostname
   * @param password - Device password. Falls back to SHELLY_AUTH_PASS env var if not provided.
   */
  constructor(private ip: string, password?: string) {
    this.password = password ?? process.env.SHELLY_AUTH_PASS;
  }

  /**
   * Posts to a Shelly RPC endpoint, automatically handling digest auth challenges.
   * On a 401, extracts the nonce/realm from WWW-Authenticate and retries with auth.
   */
  private async post(url: string, body: Record<string, unknown>, config?: object): Promise<any> {
    try {
      const response = await axios.post(url, body, config);
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 401 && this.password) {
        const wwwAuth: string = error.response.headers['www-authenticate'] ?? '';
        const challenge = parseWWWAuthenticate(wwwAuth);
        const auth = buildShellyAuth(challenge, this.password);
        const retryResponse = await axios.post(url, { ...body, auth }, config);
        return retryResponse.data;
      }

      throw error;
    }
  }

  async setDebug(enable: boolean): Promise<void> {
    try {
      await this.post(`http://${this.ip}/rpc`, {
        id: 1,
        method: 'Sys.SetConfig',
        params: {
          config: {
            debug: {
              websocket: {
                enable,
              },
            },
          },
        },
      });
      console.log(`Debug websocket ${enable ? 'enabled' : 'disabled'}`);
    } catch (error) {
      console.error('Error setting debug mode:', error);
      throw error;
    }
  }

  private async putChunk(scriptId: string, code: string, append: boolean = false): Promise<void> {
    try {
      const data = await this.post(
        `http://${this.ip}/rpc/Script.PutCode`,
        {
          id: scriptId,
          code,
          append,
        },
        { timeout: 2000 }
      );
      console.log('Chunk uploaded:', data);
    } catch (error) {
      console.error('Error uploading chunk:', error);
      throw error;
    }
  }

  async listScripts(): Promise<any[]> {
    try {
      const data = await this.post(`http://${this.ip}/rpc`, {
        id: 1,
        method: 'Script.List',
      });
      console.log('Scripts:', data);
      return data.result.scripts;
    } catch (error) {
      console.warn('Error listing scripts:', error);
      throw error;
    }
  }

  async stopScript(scriptId: string): Promise<void> {
    try {
      await this.post(`http://${this.ip}/rpc`, {
        id: 1,
        method: 'Script.Stop',
        params: { id: scriptId },
      });
    } catch (error) {
      console.warn('Error stopping script:', error);
      console.log('Script may not be running');
    }
  }

  private async createScript(name: string): Promise<any> {
    const data = await this.post(`http://${this.ip}/rpc`, {
      id: 1,
      method: 'Script.Create',
      params: { name },
    });
    return {
      id: data.result.id,
      name,
      enabled: false,
      running: false,
    };
  }

  private async setConfig(scriptId: string, name: string, enableOnBoot: boolean): Promise<void> {
    await this.post(`http://${this.ip}/rpc`, {
      id: 1,
      method: 'Script.SetConfig',
      params: { id: scriptId, name, enable: enableOnBoot },
    });
  }

  /**
   * Deploy a script to a Shelly device.
   * @param name - The name of the script.
   * @param code - The code of the script.
   * @param enableOnBoot - Whether to enable the script on boot.
   */
  async deploy(name: string, code: string, enableOnBoot: boolean): Promise<void> {
    try {
      const scripts = await this.listScripts();
      let script = scripts.find((script: any) => script.name === name);
      if (!script) {
        script = await this.createScript(name);
      }
      await this.setConfig(script.id, name, enableOnBoot);
      if (script.running) {
        console.log(`Script ${name} already exists, stopping it`);
        await this.stopScript(script.id);
      }

      console.log(`Uploading ${code.length} bytes`);

      // Upload in chunks
      for (let pos = 0; pos < code.length; pos += this.SYMBOLS_IN_CHUNK) {
        const chunk = code.slice(pos, pos + this.SYMBOLS_IN_CHUNK);
        await this.putChunk(script.id, chunk, pos > 0);
      }

      console.log('Script uploaded successfully');

      // Restart script
      await this.post(`http://${this.ip}/rpc`, {
        id: 1,
        method: 'Script.Start',
        params: { id: script.id },
      });
      console.log('Script restarted');
    } catch (error) {
      console.error('Error:', error);
      throw error;
    }
  }
}
