#!/usr/bin/env node
/**
 * Zero terminal interface.
 *
 * The Rust engine owns evidence, symbols and caches; this process owns the
 * screen. On start it asks the engine for its identity, plugin registry and
 * settings, then renders the analysis workbench. Launch flags forwarded by `zero`
 * (image, symbols, system, pagefiles, hive, key) become the initial selection.
 */
import { render } from 'ink';
import React from 'react';
import { RpcEngine } from './rpc.js';
import { App, type LaunchOptions } from './app.js';
import { Root } from './views/root.js';
import type { Hello, Os } from './types.js';

interface Cli {
  image: string | null;
  symbols: string | null;
  offline: boolean;
  os: Os;
  arch: 'auto' | 'x86' | 'x64' | 'arm64';
  pagefiles: { index: number; path: string }[];
  swapfile: string | null;
  hive: string | null;
  key: string;
}

function parse(argv: string[]): Cli {
  const cli: Cli = {
    image: null,
    symbols: null,
    offline: false,
    os: 'auto',
    arch: 'auto',
    pagefiles: [],
    swapfile: null,
    hive: null,
    key: '',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    const value = (): string => {
      const next = argv[index + 1];
      if (next === undefined) {
        throw new Error(`${arg} 需要参数`);
      }
      index += 1;
      return next;
    };
    switch (arg) {
      case '--image':
        cli.image = value();
        break;
      case '--symbols':
        cli.symbols = value();
        break;
      case '--offline':
        cli.offline = true;
        break;
      case '--os': {
        const os = value();
        if (!['auto', 'linux', 'windows'].includes(os)) {
          throw new Error(`无效 --os ${os}`);
        }
        cli.os = os as Os;
        break;
      }
      case '--arch': {
        const arch = value();
        if (!['auto', 'x86', 'x64', 'arm64'].includes(arch)) {
          throw new Error(`无效 --arch ${arch}`);
        }
        cli.arch = arch as Cli['arch'];
        break;
      }
      case '--pagefile': {
        const raw = value();
        const at = raw.indexOf('=');
        if (at === -1) {
          throw new Error('--pagefile 需要 INDEX=PATH');
        }
        const pageIndex = Number(raw.slice(0, at));
        if (!Number.isInteger(pageIndex) || pageIndex < 0 || pageIndex > 15) {
          throw new Error('分页文件索引必须为 0..15');
        }
        cli.pagefiles.push({ index: pageIndex, path: raw.slice(at + 1) });
        break;
      }
      case '--swapfile':
        cli.swapfile = value();
        break;
      case '--hive': {
        const raw = value();
        const digits = raw.replace(/^0x/u, '');
        cli.hive = (raw.startsWith('0x') ? BigInt(`0x${digits}`) : BigInt(digits)).toString();
        break;
      }
      case '--key':
        cli.key = value();
        break;
      default:
        throw new Error(`未知参数 ${arg}`);
    }
  }
  return cli;
}

async function main(): Promise<void> {
  const cli = parse(process.argv.slice(2));
  const binary = process.env.ZERO_TUI_BACKEND ?? 'zero';
  const root = process.env.ZERO_ROOT ?? process.cwd();
  const engine = new RpcEngine(binary, root);
  let hello: Hello;
  try {
    hello = await engine.hello();
  } catch (error) {
    process.stderr.write(`无法连接分析引擎: ${(error as Error).message}\n`);
    await engine.close();
    process.exitCode = 1;
    return;
  }
  if (cli.offline) {
    hello.settings = { ...hello.settings, remote_symbols: false };
  }
  const launch: LaunchOptions = {
    image: cli.image,
    symbols: cli.symbols,
    offline: cli.offline,
    os: cli.os,
    arch: cli.arch,
    pagefiles: cli.pagefiles,
    swapfile: cli.swapfile,
    hive: cli.hive,
    key: cli.key,
  };
  const app = new App(engine, hello, launch);
  const instance = render(React.createElement(Root, { app }), {
    alternateScreen: true,
    exitOnCtrlC: false,
    patchConsole: false,
    incrementalRendering: true,
    maxFps: 30,
  });
  const shutdown = async (): Promise<void> => {
    await app.shutdown();
    instance.unmount();
  };
  process.on('SIGINT', () => {
    void shutdown();
  });
  process.on('SIGTERM', () => {
    void shutdown();
  });
  app.onQuit(() => {
    void shutdown();
  });
  await app.initialize();
}

main().catch((error: unknown) => {
  process.stderr.write(`${(error as Error).message}\n`);
  process.exitCode = 1;
});
