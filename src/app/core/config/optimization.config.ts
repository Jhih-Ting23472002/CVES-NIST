/**
 * 儲存格式優化配置
 */

import { ProductNormalizationConfig, VersionRangeParsingConfig } from '../interfaces/optimized-storage.interface';

// 產品名稱正規化配置
export const PRODUCT_NORMALIZATION_CONFIG: ProductNormalizationConfig = {
  // 通用清理規則
  commonCleanupPatterns: [
    /_project$/i,     // 移除 "_project" 後綴
    /-js$/i,          // 移除 "-js" 後綴
    /-node$/i,        // 移除 "-node" 後綴
    /-npm$/i,         // 移除 "-npm" 後綴
    /^npm[-_]/i,      // 移除 "npm-" 或 "npm_" 前綴
    /^node[-_]/i,     // 移除 "node-" 或 "node_" 前綴
  ],

  // 生態系統特定規則
  ecosystemRules: {
    npm: {
      suffixesToRemove: ['_project', '-js', '-node', '-npm', '.js'],
      prefixesToRemove: ['node-', 'npm-'],
      nameVariations: {
        'form-data': ['form_data', 'formdata'],
        'lodash': ['lodash.js', 'lodash-node'],
        'express': ['express.js', 'expressjs'],
        'body-parser': ['body_parser', 'bodyparser'],
        'cookie-parser': ['cookie_parser', 'cookieparser'],
      }
    },
    pypi: {
      suffixesToRemove: ['-python', '_python', '.py'],
      prefixesToRemove: ['python-', 'py-'],
      nameVariations: {
        'django': ['Django', 'django-core'],
        'flask': ['Flask', 'flask-framework'],
        'requests': ['python-requests'],
      }
    },
    rubygems: {
      suffixesToRemove: ['-ruby', '_ruby', '-gem'],
      prefixesToRemove: ['ruby-'],
      nameVariations: {
        'rails': ['Ruby-on-Rails', 'ruby-on-rails', 'RubyOnRails'],
      }
    }
  },

  // 已知產品映射
  knownProductMappings: {
    'form-data': {
      standardName: 'form-data',
      ecosystem: 'npm',
      aliases: ['form_data', 'formdata', 'form-data_project']
    },
    'lodash': {
      standardName: 'lodash',
      ecosystem: 'npm',
      aliases: ['lodash.js', 'lodash-node', 'lodash_project']
    },
    'express': {
      standardName: 'express',
      ecosystem: 'npm',
      aliases: ['express.js', 'expressjs', 'express_project']
    },
    'react': {
      standardName: 'react',
      ecosystem: 'npm',
      aliases: ['react.js', 'reactjs', 'react_project']
    },
    'vue': {
      standardName: 'vue',
      ecosystem: 'npm',
      aliases: ['vue.js', 'vuejs', 'vue_project']
    },
    'angular': {
      standardName: '@angular/core',
      ecosystem: 'npm',
      aliases: ['angular.js', 'angularjs', 'angular_project']
    },
    'django': {
      standardName: 'django',
      ecosystem: 'pypi',
      aliases: ['Django', 'django-core', 'django_project']
    },
    'flask': {
      standardName: 'flask',
      ecosystem: 'pypi',
      aliases: ['Flask', 'flask-framework', 'flask_project']
    },
    'rails': {
      standardName: 'rails',
      ecosystem: 'rubygems',
      aliases: ['Ruby-on-Rails', 'ruby-on-rails', 'RubyOnRails']
    }
  }
};

// 版本範圍解析配置
export const VERSION_RANGE_PARSING_CONFIG: VersionRangeParsingConfig = {
  versionRangePatterns: {
    // 基本模式：影響的套件和版本
    // 例如："This issue affects form-data: < 2.5.4, 3.0.0 - 3.0.3."
    affectsPackagePattern: /(?:affects?|issue affects)\s+([\w\-@\/]+):\s*([^.\n]+(?:\.\d+(?:\s*-\s*\d+\.\d+)*[^.\n]*)*)/gi,

    versionConstraintPatterns: {
      // 小於：< 2.5.4
      lessThan: /\s*<\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
      
      // 小於等於：<= 2.5.4
      lessThanOrEqual: /\s*<=\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
      
      // 大於：> 1.0.0
      greaterThan: /\s*>\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
      
      // 大於等於：>= 1.0.0
      greaterThanOrEqual: /\s*>=\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
      
      // 範圍：3.0.0 - 3.0.3 或 1.0.0 to 2.0.0
      range: /([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)\s*(?:-|to)\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
      
      // 確切版本：= 1.2.3
      exactVersion: /\s*=\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g
    },

    // 套件名稱模式
    packageNamePatterns: [
      // 標準套件名稱
      /\b([@\w][\w\-\.\/]*[\w])\b/g,
      
      // 有作用域的套件名稱（如 @angular/core）
      /@[\w\-]+\/[\w\-\.]+/g,
      
      // 常見變體
      /\b[\w]+(?:[-_][\w]+)*\b/g
    ]
  },

  // 信心分數權重
  confidenceWeights: {
    cpeStructuredData: 0.9,       // 來自 CPE 結構化資料的信心分數
    descriptionDirectMatch: 0.8,   // 描述中直接匹配的信心分數
    descriptionFuzzyMatch: 0.6,    // 描述中模糊匹配的信心分數
    fallbackGuess: 0.3            // 備用猜測的信心分數
  }
};

// 預定義的描述解析模式
export const DESCRIPTION_PARSING_PATTERNS = {
  // 常見的漏洞描述模式
  vulnerabilityPatterns: [
    // "vulnerability in package-name"
    /(?:vulnerability|security issue|flaw|bug)\s+(?:was\s+)?(?:found\s+)?in\s+([\w\-@\/\.]+)/gi,
    
    // "package-name allows/enables/permits"
    /([\w\-@\/\.]+)\s+(?:allows?|enables?|permits?|causes?)/gi,
    
    // "issue in package-name"
    /issue\s+in\s+([\w\-@\/\.]+)/gi,
    
    // "package-name version constraint"
    /([\w\-@\/\.]+)\s+(?:version\s+)?([<>=!]+\s*[\d\.]+[^\s,]*(?:\s*,\s*[<>=!]*\s*[\d\.]+[^\s,]*)*)/gi,

    // 新增模式：支援更複雜的套件名稱格式
    // "author package-name up to version" - 如 "juliangruber brace-expansion up to 1.1.11"
    /(?:in\s+)?(?:[\w\-\.]+\s+)?([\w\-@\/\.]+)\s+up\s+to\s+([\d\.\/,\s]+)/gi,
    
    // "In package-name before version" - 如 "In http-proxy-middleware before 2.0.9"
    /In\s+([\w\-@\/\.]+)\s+before\s+([\d\.x\s,]+(?:and\s+[\d\.x\s]+before\s+[\d\.]+)?)/gi,
    
    // "package-name before version" - 如 "package-name before 2.0.9"
    /([\w\-@\/\.]+)\s+before\s+([\d\.x\s,]+)/gi,
    
    // "package-name prior to version" - 如 "package-name prior to 2.0.9"
    /([\w\-@\/\.]+)\s+prior\s+to\s+([\d\.x\s,]+)/gi,
    
    // "package-name through version" - 如 "package-name through 2.0.9"
    /([\w\-@\/\.]+)\s+through\s+([\d\.x\s,]+)/gi,

    // "upgrading to version" - 提取修復版本
    /(?:upgrading?\s+to\s+version\s*|fixed\s+in\s+version\s*)([\d\.]+(?:[,\s]+[\d\.]+)*)/gi,
    
    // "versions up to and including" - 如 "versions up to and including 2.4.6"
    /([\w\-@\/\.]+).*?versions?\s+up\s+to(?:\s+and\s+including)?\s+([\d\.]+)/gi,
  ],

  // 版本約束模式（更詳細）
  versionConstraintPatterns: [
    // 複雜版本範圍："< 2.5.4, 3.0.0 - 3.0.3, 4.0.0 - 4.0.3"
    /([<>=!]+\s*[\d\.]+[^\s,]*(?:\s*,\s*[<>=!]*\s*[\d\.]+[^\s,]*)*)/g,
    
    // 單一版本約束："< 2.5.4"
    /([<>=!]+)\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
    
    // 版本範圍："1.0.0 - 2.0.0"
    /([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)\s*(?:-|to|through)\s*([\d\.]+(?:[-+][a-zA-Z0-9\.]*)?)/g,
    
    // 複雜版本格式："1.1.11/2.0.1/3.0.0/4.0.0" - 多個版本用斜線分隔
    /([\d\.]+(?:\/[\d\.]+)*)/g,
    
    // "版本 x.y.z and a.b before c.d.e" 格式
    /([\d\.x]+)\s+(?:and\s+)?([\d\.x]+)\s+before\s+([\d\.]+)/g,
    
    // 修復版本格式："version 1.1.12, 2.0.2, 3.0.1 and 4.0.1"
    /version\s+([\d\.]+(?:\s*,\s*[\d\.]+)*(?:\s+and\s+[\d\.]+)?)/gi
  ],

  // 修復版本提取模式
  fixVersionPatterns: [
    // "Upgrading to version 1.1.12, 2.0.2, 3.0.1 and 4.0.1"
    /(?:upgrading?\s+to\s+version\s*|fixed\s+in\s+version\s*|upgrade\s+to\s*)([\d\.]+(?:\s*,\s*[\d\.]+)*(?:\s+and\s+[\d\.]+)?)/gi,
    
    // "version 1.1.12, 2.0.2, 3.0.1 and 4.0.1 is able to address"
    /version\s+([\d\.]+(?:\s*,\s*[\d\.]+)*(?:\s+and\s+[\d\.]+)?)\s+(?:is\s+able\s+to\s+address|addresses?|fixes?)/gi,
    
    // "fixed in 1.2.3"
    /(?:fixed\s+in|patched\s+in|resolved\s+in)\s+([\d\.]+)/gi
  ],

  // 套件名稱清理模式
  packageNameCleanupPatterns: [
    // 移除引號
    /^["']|["']$/g,
    
    // 移除多餘空白
    /\s+/g,
    
    // 移除非字母數字字符（保留 - _ . @ /）
    /[^a-zA-Z0-9\-_\.@\/]/g
  ]
};

// 生態系統檢測規則
export const ECOSYSTEM_DETECTION_RULES = {
  npm: {
    indicators: ['node', 'npm', 'javascript', 'js', '@'],
    fileExtensions: ['.js', '.ts', '.json'],
    commonPrefixes: ['@', 'node-', 'npm-'],
    commonSuffixes: ['-js', '-node', '.js']
  },
  
  pypi: {
    indicators: ['python', 'py', 'pip'],
    fileExtensions: ['.py', '.pyx'],
    commonPrefixes: ['python-', 'py-'],
    commonSuffixes: ['-python', '-py', '.py']
  },
  
  rubygems: {
    indicators: ['ruby', 'gem', 'rails'],
    fileExtensions: ['.rb', '.gem'],
    commonPrefixes: ['ruby-'],
    commonSuffixes: ['-ruby', '-gem', '-rails']
  },
  
  maven: {
    indicators: ['java', 'maven', 'spring'],
    fileExtensions: ['.jar', '.war'],
    commonPrefixes: [],
    commonSuffixes: ['-java', '-maven']
  },
  
  nuget: {
    indicators: ['csharp', 'dotnet', '.net'],
    fileExtensions: ['.dll', '.exe'],
    commonPrefixes: [],
    commonSuffixes: ['-dotnet', '-net']
  }
};

// 信心分數計算權重
export const CONFIDENCE_SCORE_WEIGHTS = {
  // 資料來源權重
  dataSource: {
    structuredCpe: 0.4,      // 40% - 來自結構化 CPE 資料
    descriptionParsing: 0.3,  // 30% - 來自描述解析
    knownMapping: 0.2,        // 20% - 來自已知產品映射
    heuristic: 0.1           // 10% - 來自啟發式推測
  },
  
  // 匹配品質權重
  matchQuality: {
    exactMatch: 1.0,         // 精確匹配
    aliasMatch: 0.9,         // 別名匹配
    fuzzyMatch: 0.7,         // 模糊匹配
    partialMatch: 0.5,       // 部分匹配
    heuristicMatch: 0.3      // 啟發式匹配
  },
  
  // 版本資訊完整性權重
  versionCompleteness: {
    fullRange: 1.0,          // 完整版本範圍
    partialRange: 0.8,       // 部分版本範圍
    singleConstraint: 0.6,   // 單一版本約束
    noVersion: 0.2           // 無版本資訊
  }
};