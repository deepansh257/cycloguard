/**
 * Shared logger factory for CycloGuard packages.
 * Package-local wrappers pass in their own pino dependency so we avoid
 * duplicating logger behavior while keeping package builds isolated.
 */
function createAppLogger({ pino }) {
  function buildBaseLogger() {
    const level = process.env.CYCLOGUARD_LOG_LEVEL || 'info';
    const format = (process.env.CYCLOGUARD_LOG_FORMAT || (process.env.CI ? 'json' : 'pretty')).toLowerCase();
    const destination = format === 'pretty'
      ? pino.transport({
        target: 'pino-pretty',
        options: {
          colorize: Boolean(process.stdout.isTTY),
          ignore: 'pid,hostname',
          translateTime: 'SYS:standard'
        }
      })
      : undefined;

    return pino({ level, base: undefined }, destination);
  }

  function writeRaw(message) {
    const output = message.endsWith('\n') ? message : `${message}\n`;
    process.stdout.write(output);
  }

  function wrapLogger(base) {
    return {
      info(message, meta) {
        if (meta) {
          base.info(meta, message);
          return;
        }
        base.info(message);
      },
      warn(message, meta) {
        if (meta) {
          base.warn(meta, message);
          return;
        }
        base.warn(message);
      },
      error(message, meta) {
        if (meta) {
          base.error(meta, message);
          return;
        }
        base.error(message);
      },
      debug(message, meta) {
        if (meta) {
          base.debug(meta, message);
          return;
        }
        base.debug(message);
      },
      raw(message) {
        writeRaw(message);
      },
      command(command) {
        base.info({ event: 'shell_command' }, `$ ${command}`);
      },
      child(component) {
        return wrapLogger(base.child({ component }));
      }
    };
  }

  return wrapLogger(buildBaseLogger());
}

module.exports = { createAppLogger };
