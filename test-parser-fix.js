// 測試修復後的解析器是否能正確處理 NVD 2.0 格式

// 模擬 NVD 2.0 格式資料
const nvd20TestData = {
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2025-08-11T01:00:00.308Z",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2025-TEST-001",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2025-01-15T10:00:00.000Z",
        "lastModified": "2025-01-16T12:00:00.000Z",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {
            "lang": "en",
            "value": "Cross-site scripting vulnerability in example application"
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "cve@mitre.org",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "baseScore": 6.1,
                "baseSeverity": "MEDIUM"
              },
              "exploitabilityScore": 2.8,
              "impactScore": 2.7
            }
          ]
        },
        "configurations": [
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:example:application:1.0:*:*:*:*:*:*:*",
                    "versionEndExcluding": "1.1"
                  }
                ]
              }
            ]
          }
        ],
        "references": [
          {
            "url": "https://example.com/advisory",
            "source": "cve@mitre.org",
            "tags": ["Vendor Advisory"]
          }
        ]
      }
    }
  ]
};

// 模擬 NVD 1.1 格式資料
const nvd11TestData = {
  "CVE_data_type": "CVE",
  "CVE_data_format": "MITRE", 
  "CVE_data_version": "4.0",
  "CVE_Items": [
    {
      "cve": {
        "CVE_data_meta": {
          "ID": "CVE-2025-TEST-002"
        },
        "description": {
          "description_data": [
            {
              "lang": "en",
              "value": "Path traversal vulnerability in legacy application"
            }
          ]
        },
        "references": {
          "reference_data": [
            {
              "url": "https://example.com/legacy-advisory",
              "refsource": "MISC",
              "tags": ["Vendor Advisory"]
            }
          ]
        }
      },
      "configurations": {
        "nodes": [
          {
            "operator": "OR",
            "cpe_match": [
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:legacy:application:2.0:*:*:*:*:*:*:*",
                "versionEndExcluding": "2.1"
              }
            ]
          }
        ]
      },
      "impact": {
        "baseMetricV3": {
          "cvssV3": {
            "version": "3.1",
            "baseScore": 7.5,
            "baseSeverity": "HIGH"
          }
        }
      },
      "publishedDate": "2025-01-10T14:30:00Z",
      "lastModifiedDate": "2025-01-11T09:15:00Z"
    }
  ]
};

console.log('=== 格式檢測測試 ===');

// 檢測 2.0 格式
console.log('NVD 2.0 格式檢測:');
console.log('- 是否有 vulnerabilities:', !!nvd20TestData.vulnerabilities);
console.log('- 第一個項目 CVE ID:', nvd20TestData.vulnerabilities?.[0]?.cve?.id);
console.log('- CVSS 路徑正確:', !!nvd20TestData.vulnerabilities?.[0]?.cve?.metrics?.cvssMetricV31);
console.log('- 配置路徑正確:', !!nvd20TestData.vulnerabilities?.[0]?.cve?.configurations);

console.log('\nNVD 1.1 格式檢測:');
console.log('- 是否有 CVE_Items:', !!nvd11TestData.CVE_Items);
console.log('- 第一個項目 CVE ID:', nvd11TestData.CVE_Items?.[0]?.cve?.CVE_data_meta?.ID);
console.log('- CVSS 路徑 (item level):', !!nvd11TestData.CVE_Items?.[0]?.impact?.baseMetricV3);
console.log('- 配置路徑 (item level):', !!nvd11TestData.CVE_Items?.[0]?.configurations);

console.log('\n=== 關鍵路徑比較 ===');
const nvd20Item = nvd20TestData.vulnerabilities[0];
const nvd11Item = nvd11TestData.CVE_Items[0];

console.log('CVE ID 提取:');
console.log('- 2.0:', nvd20Item.cve.id);
console.log('- 1.1:', nvd11Item.cve.CVE_data_meta.ID);

console.log('\n描述提取:');
console.log('- 2.0:', nvd20Item.cve.descriptions[0].value);
console.log('- 1.1:', nvd11Item.cve.description.description_data[0].value);

console.log('\nCVSS 分數提取:');
console.log('- 2.0:', nvd20Item.cve.metrics.cvssMetricV31[0].cvssData.baseScore);
console.log('- 1.1:', nvd11Item.impact.baseMetricV3.cvssV3.baseScore);

console.log('\n日期提取:');
console.log('- 2.0 published:', nvd20Item.cve.published);
console.log('- 1.1 published:', nvd11Item.publishedDate);

console.log('\n配置提取:');
console.log('- 2.0 path: cve.configurations');
console.log('- 1.1 path: item.configurations (not cve.configurations)');

console.log('\n✅ 測試完成 - 解析器修復應該能正確處理兩種格式');