'use strict';

const { exec } = require('child_process');
const Adviser = require('adviser');

const SEVERITY_LEVEL = ['info', 'low', 'moderate', 'high', 'critical'];

class MinVulnerabilityAllow extends Adviser.Rule {
  constructor(context) {
    super(context);

    if (!this.context.options.level || SEVERITY_LEVEL.indexOf(this.context.options.level) < 0) {
      throw new Error(`Wrong level options, should be one of: 'info', 'low', 'moderate', 'high', 'critical'`);
    }

    if (!this.context.options.skip || !Array.isArray(this.context.options.skip)) {
      this.context.options.skip = [];
    }
  }

  run(sandbox) {
    return new Promise((resolve, reject) => {
      exec('npm audit --json=true', (_error, stdout, stderr) => {
        if (stdout) {
          let auditOutput = '';

          try {
            auditOutput = JSON.parse(stdout);
          } catch (error) {
            throw error;
          }

          const vulnerabilities = Object.keys(auditOutput.advisories).filter(
            item => this.context.options.skip.indexOf(item) < 0
          );

          const severityCounter = this.getSeverityCounter(vulnerabilities, auditOutput.advisories);

          if (Object.keys(severityCounter).length > 0) {
            const message = this.getMessage(severityCounter);

            sandbox.report({
              message
            });
          }
        }

        resolve();
      });
    });
  }

  getSeverityCounter(vulnerabilitiesIds, advisories) {
    const severityCounter = {};
    const minVulnerabilityIndex = SEVERITY_LEVEL.indexOf(this.context.options.level);

    vulnerabilitiesIds.forEach(vulnerability => {
      const vulnerabilitySeverity = advisories[vulnerability].severity;
      const vulnerabilitySeverityIndex = SEVERITY_LEVEL.indexOf(vulnerabilitySeverity);

      if (vulnerabilitySeverityIndex >= minVulnerabilityIndex) {
        severityCounter[vulnerabilitySeverity] =
          severityCounter[vulnerabilitySeverity] !== undefined ? severityCounter[vulnerabilitySeverity]++ : 1;
      }
    });

    return severityCounter;
  }

  getMessage(severityCounter) {
    let counterMessage = Object.keys(severityCounter).reduce((accu, item) => {
      return `${accu} ${severityCounter[item]} ${item},`;
    }, '');

    counterMessage = counterMessage.substr(0, counterMessage.length - 1);

    return `Found vulnerabilities above the value "${this.context.options.level}":${counterMessage}`;
  }
}

module.exports = MinVulnerabilityAllow;
