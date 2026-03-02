import chalk from 'chalk';
import WebSocket from 'ws';
import { SolutionsConfig } from '../solutions-config.js';
import { z } from 'zod';
import { logger } from '../utils/logger.js';

export const name = 'logs';

export const description = 'Stream logs from Shelly devices';

export const inputSchema: { [key: string]: z.ZodTypeAny } = {
    scriptName: z.string().optional().describe('Name of the script to stream logs from (optional)')
};

export async function callback(args: { scriptName?: string }) {
    return await logs(args.scriptName);
}

function connectDevice(device: string, prefix: string): WebSocket {
    // Force IPv4 — ws defaults to IPv6 which Shelly devices don't support
    const ws = new WebSocket(`ws://${device}/debug/log`);

    ws.on('open', () => {
        logger.log(chalk.green(`${prefix} Connected`));
    });

    ws.on('message', (data) => {
        const lines = data.toString().split('\n');
        lines.forEach((line) => {
            if (line.trim()) {
                logger.log(`${prefix} ${line.trim()}`);
            }
        });
    });

    ws.on('error', (error) => {
        logger.error(`${prefix} WebSocket error: ${error.message}`);
    });

    ws.on('close', () => {
        logger.log(chalk.yellow(`${prefix} Disconnected`));
    });

    return ws;
}

export default async function logs(scriptName?: string): Promise<string> {
    try {
        const config = new SolutionsConfig();
        await config.load();

        const sockets: WebSocket[] = [];

        if (scriptName) {
            const script = config.findScript(scriptName);
            if (!script) {
                throw new Error(`Script "${scriptName}" not found in solutions.config.json`);
            }

            const device = script.scriptConfig.device;
            logger.log(chalk.blue(`Streaming logs for script: ${scriptName} from ${script.solutionName} solution`));
            sockets.push(connectDevice(device, chalk.cyan(`[${device}]`)));
        } else {
            const uniqueDevices = new Set(config.getAllScripts().map((s) => s.scriptConfig.device));
            logger.log(chalk.blue(`Streaming logs from ${uniqueDevices.size} device(s)...`));

            for (const device of uniqueDevices) {
                sockets.push(connectDevice(device, chalk.cyan(`[${device}]`)));
            }
        }

        // Keep the process alive and clean up on Ctrl+C
        await new Promise<void>((resolve) => {
            process.on('SIGINT', () => {
                logger.log(chalk.yellow('\nClosing all log streams...'));
                sockets.forEach((ws) => ws.close());
                resolve();
            });
        });

        return 'Log streaming stopped.';
    } catch (error) {
        logger.error('Logs command failed', error);
        throw error;
    }
}
