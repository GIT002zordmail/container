// SQL Injection Detection Module
class SQLInjectionDetector {
  constructor() {
    this.patterns = [
      { regex: /\bunion\s+select/i, type: 'union_select' },
      { regex: /\bselect\s+.*\bfrom/i, type: 'select_from' },
      { regex: /\binsert\s+into/i, type: 'insert_into' },
      { regex: /\bupdate\s+\w+\s+set/i, type: 'update_set' },
      { regex: /\bdelete\s+from/i, type: 'delete_from' },
      { regex: /\bdrop\s+table/i, type: 'drop_table' },
      { regex: /\balter\s+table/i, type: 'alter_table' },
      { regex: /\bcreate\s+table/i, type: 'create_table' },
      { regex: /\bexec(ute)?\s*\(/i, type: 'exec' },
      { regex: /;\s*(drop|delete|update|insert|create)/i, type: 'stacked_query' },
      { regex: /\/\*.*?\*\//s, type: 'comment' },
      { regex: /--\s*$|--\s*[\r\n]/m, type: 'comment' }
    ];
  }

  scan(payload) {
    const findings = [];

    const checkValue = (key, value) => {
      if (!value || typeof value !== 'string') return;
      
      for (const pattern of this.patterns) {
        if (pattern.regex.test(value)) {
          findings.push({
            field: key,
            type: pattern.type,
            reasons: [pattern.type]
          });
        }
      }
    };

    // Check object properties
    if (typeof payload === 'object') {
      for (const [key, value] of Object.entries(payload)) {
        checkValue(key, value);
      }
    } else if (typeof payload === 'string') {
      checkValue('input', payload);
    }

    return {
      suspicious: findings.length > 0,
      findings
    };
  }
}

module.exports = SQLInjectionDetector;
