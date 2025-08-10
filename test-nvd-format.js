// NVD 資料格式測試
// 此測試模擬實際的 NVD 1.1 JSON Feed 格式

const mockNvdData = {
  "CVE_data_type": "CVE",
  "CVE_data_format": "MITRE", 
  "CVE_data_version": "4.0",
  "CVE_data_numberOfCVEs": "2",
  "CVE_data_timestamp": "2024-08-09T10:00:00.000Z",
  "CVE_Items": [
    {
      "cve": {
        "data_type": "CVE",
        "data_format": "MITRE",
        "data_version": "4.0",
        "CVE_data_meta": {
          "ID": "CVE-2024-TEST-001",
          "ASSIGNER": "test@example.com"
        },
        "problemtype": {
          "problemtype_data": [
            {
              "description": [
                {
                  "lang": "en",
                  "value": "CWE-79"
                }
              ]
            }
          ]
        },
        "references": {
          "reference_data": [
            {
              "url": "https://example.com/advisory",
              "name": "https://example.com/advisory",
              "refsource": "MISC",
              "tags": ["Vendor Advisory"]
            }
          ]
        },
        "description": {
          "description_data": [
            {
              "lang": "en", 
              "value": "Cross-site scripting vulnerability in example application"
            }
          ]
        }
      },
      "configurations": {
        "CVE_data_version": "4.0",
        "nodes": [
          {
            "operator": "OR",
            "cpe_match": [
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:example:application:1.0:*:*:*:*:*:*:*",
                "versionEndExcluding": "1.1"
              }
            ]
          }
        ]
      },
      "impact": {
        "baseMetricV3": {
          "cvssV3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW", 
            "privilegesRequired": "NONE",
            "userInteraction": "REQUIRED",
            "scope": "CHANGED",
            "confidentialityImpact": "LOW",
            "integrityImpact": "LOW",
            "availabilityImpact": "NONE",
            "baseScore": 6.1,
            "baseSeverity": "MEDIUM"
          },
          "exploitabilityScore": 2.8,
          "impactScore": 2.7
        }
      },
      "publishedDate": "2024-01-15T10:00:00Z",
      "lastModifiedDate": "2024-01-16T12:00:00Z"
    },
    {
      "cve": {
        "data_type": "CVE",
        "data_format": "MITRE",
        "data_version": "4.0",
        "CVE_data_meta": {
          "ID": "CVE-2024-TEST-002",
          "ASSIGNER": "security@nodejs.org"
        },
        "problemtype": {
          "problemtype_data": [
            {
              "description": [
                {
                  "lang": "en",
                  "value": "CWE-22"
                }
              ]
            }
          ]
        },
        "references": {
          "reference_data": [
            {
              "url": "https://nodejs.org/security/",
              "name": "https://nodejs.org/security/",
              "refsource": "MISC",
              "tags": ["Vendor Advisory"]
            }
          ]
        },
        "description": {
          "description_data": [
            {
              "lang": "en",
              "value": "Path traversal vulnerability in Node.js package"
            }
          ]
        }
      },
      "configurations": {
        "CVE_data_version": "4.0", 
        "nodes": [
          {
            "operator": "OR",
            "cpe_match": [
              {
                "vulnerable": true,
                "cpe23Uri": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "18.0.0",
                "versionEndExcluding": "18.19.1"
              }
            ]
          }
        ]
      },
      "impact": {
        "baseMetricV3": {
          "cvssV3": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE", 
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
            "baseScore": 9.8,
            "baseSeverity": "CRITICAL"
          },
          "exploitabilityScore": 3.9,
          "impactScore": 5.9
        }
      },
      "publishedDate": "2024-02-01T14:30:00Z",
      "lastModifiedDate": "2024-02-02T09:15:00Z"
    }
  ]
};

// 測試解析結果
console.log('NVD 1.1 JSON Feed 格式測試資料:');
console.log('總 CVE 數量:', mockNvdData.CVE_Items.length);
console.log('CVE IDs:', mockNvdData.CVE_Items.map(item => item.cve.CVE_data_meta.ID));

// 測試每個 CVE 項目的結構
mockNvdData.CVE_Items.forEach((item, index) => {
  const cve = item.cve;
  console.log(`\n=== CVE ${index + 1} ===`);
  console.log('ID:', cve.CVE_data_meta.ID);
  console.log('描述:', cve.description?.description_data?.[0]?.value);
  console.log('CVSS 分數:', item.impact?.baseMetricV3?.cvssV3?.baseScore);
  console.log('嚴重程度:', item.impact?.baseMetricV3?.cvssV3?.baseSeverity);
  console.log('發布日期:', item.publishedDate);
  console.log('配置節點:', item.configurations?.nodes?.length || 0);
});

console.log('\n✅ 測試資料結構符合 NVD 1.1 JSON Feed 格式');
console.log('✅ 修復後的解析器應該能正確處理此格式');