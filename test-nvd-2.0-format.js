// NVD 2.0 格式測試 - 基於實際資料結構
const mockNvd20Data = {
  "resultsPerPage": 2,
  "startIndex": 0,
  "totalResults": 2,
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
        "cveTags": [],
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
                "baseSeverity": "MEDIUM",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "REQUIRED",
                "scope": "CHANGED",
                "confidentialityImpact": "LOW",
                "integrityImpact": "LOW",
                "availabilityImpact": "NONE"
              },
              "exploitabilityScore": 2.8,
              "impactScore": 2.7
            }
          ]
        },
        "weaknesses": [
          {
            "source": "cve@mitre.org",
            "type": "Primary",
            "description": [
              {
                "lang": "en",
                "value": "CWE-79"
              }
            ]
          }
        ],
        "configurations": [
          {
            "operator": "OR",
            "negate": false,
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:example:application:1.0:*:*:*:*:*:*:*",
                    "versionEndExcluding": "1.1",
                    "matchCriteriaId": "12345678-1234-1234-1234-123456789012"
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

// 格式比較測試
console.log('=== NVD 格式比較 ===');
console.log('1.1 格式特點:');
console.log('- 頂層: CVE_Items[]');
console.log('- CVE ID: item.cve.CVE_data_meta.ID');
console.log('- 描述: item.cve.description.description_data[]');
console.log('- CVSS: item.impact.baseMetricV3.cvssV3');
console.log('- 配置: item.configurations.nodes[]');
console.log('- 參考: item.cve.references.reference_data[]');

console.log('\n2.0 格式特點:');
console.log('- 頂層: vulnerabilities[]');
console.log('- CVE ID: item.cve.id');
console.log('- 描述: item.cve.descriptions[]');
console.log('- CVSS: item.cve.metrics.cvssMetricV31[]');
console.log('- 配置: item.cve.configurations[]');
console.log('- 參考: item.cve.references[]');

console.log('\n主要差異:');
console.log('1. 容器屬性名: CVE_Items → vulnerabilities');
console.log('2. CVE ID 路徑: cve.CVE_data_meta.ID → cve.id');
console.log('3. 描述結構: cve.description.description_data → cve.descriptions');
console.log('4. CVSS 路徑: impact.baseMetricV3 → cve.metrics.cvssMetricV31');
console.log('5. 配置路徑: configurations.nodes → cve.configurations');
console.log('6. 參考路徑: cve.references.reference_data → cve.references');
console.log('7. 日期路徑: publishedDate/lastModifiedDate → cve.published/lastModified');

// 測試解析
const vuln = mockNvd20Data.vulnerabilities[0];
const cve = vuln.cve;
console.log('\n=== 2.0 格式解析測試 ===');
console.log('CVE ID:', cve.id);
console.log('描述:', cve.descriptions?.[0]?.value);
console.log('CVSS 分數:', cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore);
console.log('嚴重程度:', cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity);
console.log('發布日期:', cve.published);
console.log('配置數量:', cve.configurations?.length || 0);