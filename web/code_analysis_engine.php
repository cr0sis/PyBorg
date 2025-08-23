<?php
/**
 * Code Analysis Engine for Code Reviewer Agent
 * 
 * Specialized analysis modules for comprehensive code review:
 * - Security vulnerability detection
 * - Performance bottleneck identification  
 * - Code quality metrics calculation
 * - IRC bot and PHP web application specific checks
 */

require_once 'security_config.php';

class CodeAnalysisEngine {
    
    private $analysisId;
    private $rulesDatabase;
    private $performanceProfiler;
    private $securityScanner;
    
    public function __construct($analysisId = null) {
        $this->analysisId = $analysisId ?: $this->generateAnalysisId();
        $this->initializeRulesDatabase();
        $this->initializeProfiler();
        $this->initializeSecurityScanner();
    }
    
    // ==================== SECURITY ANALYSIS ====================
    
    public function conductSecurityAnalysis($codeFiles) {
        $this->logAnalysis('Starting comprehensive security analysis', 'INFO');
        
        $results = [
            'vulnerability_scan' => $this->scanVulnerabilities($codeFiles),
            'injection_analysis' => $this->analyzeInjectionVulnerabilities($codeFiles),
            'authentication_review' => $this->reviewAuthenticationSecurity($codeFiles),
            'session_security' => $this->analyzeSessionSecurity($codeFiles),
            'input_validation' => $this->analyzeInputValidation($codeFiles),
            'output_encoding' => $this->analyzeOutputEncoding($codeFiles),
            'file_handling' => $this->analyzeFileHandlingSecurity($codeFiles),
            'crypto_review' => $this->reviewCryptographicUsage($codeFiles),
            'privilege_escalation' => $this->checkPrivilegeEscalation($codeFiles),
            'irc_specific_security' => $this->analyzeIrcSecurityPatterns($codeFiles)
        ];
        
        $overallScore = $this->calculateSecurityScore($results);
        $riskLevel = $this->determineRiskLevel($results);
        
        return [
            'analysis_id' => $this->analysisId,
            'overall_security_score' => $overallScore,
            'risk_level' => $riskLevel,
            'detailed_results' => $results,
            'critical_findings' => $this->extractCriticalFindings($results),
            'remediation_recommendations' => $this->generateSecurityRecommendations($results)
        ];
    }
    
    private function scanVulnerabilities($codeFiles) {
        $vulnerabilities = [];
        
        $vulnPatterns = [
            // SQL Injection patterns
            'sql_injection' => [
                '/\$_(GET|POST|REQUEST)\[.*?\].*?(mysql_query|mysqli_query|query|execute|prepare).*?\$/i',
                '/query.*?\$_(GET|POST|REQUEST)/i',
                '/execute\(.*?\$_(GET|POST|REQUEST)/i',
                '/SELECT.*?\$_(GET|POST|REQUEST)/i',
                '/INSERT.*?\$_(GET|POST|REQUEST)/i',
                '/UPDATE.*?\$_(GET|POST|REQUEST)/i',
                '/DELETE.*?\$_(GET|POST|REQUEST)/i'
            ],
            
            // XSS patterns
            'xss' => [
                '/echo.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                '/print.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                '/printf.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                '/<\?php.*?echo.*?\$_(GET|POST|REQUEST)/i',
                '/innerHTML.*?\$_(GET|POST|REQUEST)/i'
            ],
            
            // Command Injection patterns
            'command_injection' => [
                '/(exec|system|shell_exec|passthru|popen|proc_open)\(.*?\$_(GET|POST|REQUEST)/i',
                '/`.*?\$_(GET|POST|REQUEST).*?`/i',
                '/eval\(.*?\$_(GET|POST|REQUEST)/i'
            ],
            
            // Path Traversal patterns
            'path_traversal' => [
                '/file_get_contents\(.*?\$_(GET|POST|REQUEST)/i',
                '/include.*?\$_(GET|POST|REQUEST)/i',
                '/require.*?\$_(GET|POST|REQUEST)/i',
                '/fopen\(.*?\$_(GET|POST|REQUEST)/i',
                '/readfile\(.*?\$_(GET|POST|REQUEST)/i'
            ],
            
            // Insecure Deserialization
            'deserialization' => [
                '/unserialize\(.*?\$_(GET|POST|REQUEST)/i',
                '/json_decode\(.*?\$_(GET|POST|REQUEST).*?true\)/i'
            ],
            
            // Weak Cryptography
            'weak_crypto' => [
                '/md5\(.*?password/i',
                '/sha1\(.*?password/i',
                '/crypt\(.*?\$_(GET|POST)/i',
                '/mcrypt_/i',
                '/MCRYPT_/i'
            ]
        ];
        
        foreach ($codeFiles as $fileName => $content) {
            foreach ($vulnPatterns as $vulnType => $patterns) {
                foreach ($patterns as $pattern) {
                    if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                        foreach ($matches[0] as $match) {
                            $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                            
                            $vulnerabilities[] = [
                                'file' => $fileName,
                                'type' => $vulnType,
                                'severity' => $this->getVulnerabilitySeverity($vulnType),
                                'line' => $lineNumber,
                                'code_snippet' => trim($match[0]),
                                'pattern' => $pattern,
                                'description' => $this->getVulnerabilityDescription($vulnType),
                                'remediation' => $this->getVulnerabilityRemediation($vulnType)
                            ];
                        }
                    }
                }
            }
        }
        
        return [
            'total_vulnerabilities' => count($vulnerabilities),
            'by_severity' => $this->groupVulnerabilitiesBySeverity($vulnerabilities),
            'by_type' => $this->groupVulnerabilitiesByType($vulnerabilities),
            'details' => $vulnerabilities
        ];
    }
    
    private function analyzeIrcSecurityPatterns($codeFiles) {
        $ircVulns = [];
        
        $ircPatterns = [
            // IRC command injection
            'irc_command_injection' => [
                '/PRIVMSG.*?\$_(GET|POST|REQUEST)/i',
                '/NOTICE.*?\$_(GET|POST|REQUEST)/i',
                '/KICK.*?\$_(GET|POST|REQUEST)/i',
                '/MODE.*?\$_(GET|POST|REQUEST)/i'
            ],
            
            // Flood/spam vulnerabilities
            'flood_protection' => [
                '/send_message.*?foreach/i',
                '/privmsg.*?while/i',
                '/send.*?for\(/i'
            ],
            
            // Privilege escalation in IRC
            'irc_privilege_escalation' => [
                '/admin_only.*?false/i',
                '/is_admin.*?\$_(GET|POST)/i',
                '/channel_op.*?\$_/i'
            ],
            
            // Nickname spoofing/impersonation
            'nickname_security' => [
                '/nick.*?\$_(GET|POST)/i',
                '/realname.*?\$_(GET|POST)/i',
                '/ident.*?\$_(GET|POST)/i'
            ]
        ];
        
        foreach ($codeFiles as $fileName => $content) {
            if (strpos($fileName, 'plugins/') !== false || strpos($fileName, 'bot') !== false) {
                foreach ($ircPatterns as $vulnType => $patterns) {
                    foreach ($patterns as $pattern) {
                        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                            foreach ($matches[0] as $match) {
                                $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                                
                                $ircVulns[] = [
                                    'file' => $fileName,
                                    'type' => $vulnType,
                                    'severity' => 'HIGH',
                                    'line' => $lineNumber,
                                    'code_snippet' => trim($match[0]),
                                    'irc_specific' => true,
                                    'description' => $this->getIrcVulnerabilityDescription($vulnType)
                                ];
                            }
                        }
                    }
                }
            }
        }
        
        return [
            'irc_vulnerabilities_found' => count($ircVulns),
            'details' => $ircVulns,
            'network_isolation_check' => $this->checkNetworkIsolation($codeFiles),
            'rate_limiting_check' => $this->checkIrcRateLimiting($codeFiles)
        ];
    }
    
    // ==================== PERFORMANCE ANALYSIS ====================
    
    public function conductPerformanceAnalysis($codeFiles) {
        $this->logAnalysis('Starting performance analysis', 'INFO');
        
        $results = [
            'algorithm_complexity' => $this->analyzeAlgorithmComplexity($codeFiles),
            'database_performance' => $this->analyzeDatabasePerformance($codeFiles),
            'memory_usage' => $this->analyzeMemoryUsage($codeFiles),
            'io_operations' => $this->analyzeIOOperations($codeFiles),
            'loop_efficiency' => $this->analyzeLoopEfficiency($codeFiles),
            'function_complexity' => $this->analyzeFunctionComplexity($codeFiles),
            'caching_opportunities' => $this->identifyCachingOpportunities($codeFiles),
            'bottleneck_detection' => $this->detectBottlenecks($codeFiles)
        ];
        
        return [
            'analysis_id' => $this->analysisId,
            'overall_performance_score' => $this->calculatePerformanceScore($results),
            'detailed_results' => $results,
            'optimization_recommendations' => $this->generatePerformanceRecommendations($results)
        ];
    }
    
    private function analyzeDatabasePerformance($codeFiles) {
        $issues = [];
        
        $performancePatterns = [
            // N+1 query problem
            'n_plus_one' => '/foreach.*?query|for.*?query|while.*?query/i',
            
            // Missing prepared statements
            'unprepared_queries' => '/query\(.*?\$.*?\.|mysql_query\(.*?\$|mysqli_query\(.*?\$/i',
            
            // SELECT * usage
            'select_star' => '/SELECT \* FROM/i',
            
            // Missing LIMIT clauses
            'unlimited_queries' => '/SELECT.*?FROM.*?WHERE(?!.*LIMIT)/i',
            
            // Potential missing indexes
            'unindexed_queries' => '/WHERE.*?(timestamp|created_at|updated_at)(?!.*INDEX)/i',
            
            // Transaction issues
            'missing_transactions' => '/(INSERT|UPDATE|DELETE).*?(INSERT|UPDATE|DELETE)(?!.*BEGIN|START TRANSACTION)/i'
        ];
        
        foreach ($codeFiles as $fileName => $content) {
            foreach ($performancePatterns as $issueType => $pattern) {
                if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                    foreach ($matches[0] as $match) {
                        $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                        
                        $issues[] = [
                            'file' => $fileName,
                            'type' => $issueType,
                            'line' => $lineNumber,
                            'code_snippet' => trim($match[0]),
                            'performance_impact' => $this->getPerformanceImpact($issueType),
                            'recommendation' => $this->getPerformanceRecommendation($issueType)
                        ];
                    }
                }
            }
        }
        
        return [
            'total_issues' => count($issues),
            'by_impact' => $this->groupIssuesByImpact($issues),
            'details' => $issues
        ];
    }
    
    private function analyzeFunctionComplexity($codeFiles) {
        $complexityIssues = [];
        
        foreach ($codeFiles as $fileName => $content) {
            // Find all functions
            preg_match_all('/function\s+(\w+)\s*\([^)]*\)\s*\{([^{}]*\{[^{}]*\}[^{}]*)*[^{}]*\}/s', $content, $functions, PREG_OFFSET_CAPTURE);
            
            foreach ($functions[0] as $index => $match) {
                $functionName = $functions[1][$index][0];
                $functionBody = $match[0];
                $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                
                // Calculate cyclomatic complexity
                $complexity = $this->calculateCyclomaticComplexity($functionBody);
                
                // Calculate lines of code
                $linesOfCode = substr_count($functionBody, "\n");
                
                // Check for complexity issues
                if ($complexity > 10 || $linesOfCode > 50) {
                    $complexityIssues[] = [
                        'file' => $fileName,
                        'function' => $functionName,
                        'line' => $lineNumber,
                        'cyclomatic_complexity' => $complexity,
                        'lines_of_code' => $linesOfCode,
                        'severity' => $complexity > 15 ? 'HIGH' : ($complexity > 10 ? 'MEDIUM' : 'LOW'),
                        'recommendation' => $complexity > 15 ? 'Refactor immediately' : 'Consider refactoring'
                    ];
                }
            }
        }
        
        return [
            'complex_functions_found' => count($complexityIssues),
            'average_complexity' => $this->calculateAverageComplexity($complexityIssues),
            'details' => $complexityIssues
        ];
    }
    
    // ==================== CODE QUALITY ANALYSIS ====================
    
    public function conductCodeQualityAnalysis($codeFiles) {
        $this->logAnalysis('Starting code quality analysis', 'INFO');
        
        $results = [
            'coding_standards' => $this->analyzeCodingStandards($codeFiles),
            'documentation_coverage' => $this->analyzeDocumentationCoverage($codeFiles),
            'code_duplication' => $this->detectCodeDuplication($codeFiles),
            'naming_conventions' => $this->analyzeNamingConventions($codeFiles),
            'error_handling' => $this->analyzeErrorHandling($codeFiles),
            'test_coverage' => $this->analyzeTestCoverage($codeFiles),
            'maintainability_index' => $this->calculateMaintainabilityIndex($codeFiles),
            'technical_debt' => $this->assessTechnicalDebt($codeFiles)
        ];
        
        return [
            'analysis_id' => $this->analysisId,
            'overall_quality_score' => $this->calculateCodeQualityScore($results),
            'detailed_results' => $results,
            'improvement_recommendations' => $this->generateQualityRecommendations($results)
        ];
    }
    
    private function analyzeErrorHandling($codeFiles) {
        $issues = [];
        
        $errorPatterns = [
            // Missing try-catch blocks
            'missing_exception_handling' => [
                '/file_get_contents\((?!.*try)/i',
                '/mysqli_query\((?!.*try)/i',
                '/curl_exec\((?!.*try)/i',
                '/json_decode\((?!.*try)/i'
            ],
            
            // Generic exception catching
            'generic_catch' => '/catch\s*\(\s*Exception/i',
            
            // Missing error logging
            'missing_error_logging' => '/catch\s*\([^)]+\)\s*\{(?!.*error_log|.*logSecurityEvent)/i',
            
            // Suppressed errors without handling
            'suppressed_errors' => '/@(file_get_contents|fopen|mysqli_query|curl_exec)/i'
        ];
        
        foreach ($codeFiles as $fileName => $content) {
            foreach ($errorPatterns as $issueType => $patterns) {
                if (is_array($patterns)) {
                    foreach ($patterns as $pattern) {
                        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                            foreach ($matches[0] as $match) {
                                $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                                $issues[] = [
                                    'file' => $fileName,
                                    'type' => $issueType,
                                    'line' => $lineNumber,
                                    'severity' => $this->getErrorHandlingSeverity($issueType),
                                    'code_snippet' => trim($match[0])
                                ];
                            }
                        }
                    }
                } else {
                    if (preg_match_all($patterns, $content, $matches, PREG_OFFSET_CAPTURE)) {
                        foreach ($matches[0] as $match) {
                            $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;
                            $issues[] = [
                                'file' => $fileName,
                                'type' => $issueType,
                                'line' => $lineNumber,
                                'severity' => $this->getErrorHandlingSeverity($issueType),
                                'code_snippet' => trim($match[0])
                            ];
                        }
                    }
                }
            }
        }
        
        return [
            'error_handling_issues' => count($issues),
            'by_severity' => $this->groupIssuesBySeverity($issues),
            'details' => $issues
        ];
    }
    
    // ==================== UTILITY METHODS ====================
    
    private function calculateCyclomaticComplexity($functionBody) {
        // Count decision points (if, else, while, for, foreach, case, catch, &&, ||)
        $complexity = 1; // Base complexity
        
        $patterns = [
            '/\bif\s*\(/i',
            '/\belse\b/i',
            '/\belseif\s*\(/i',
            '/\bwhile\s*\(/i',
            '/\bfor\s*\(/i',
            '/\bforeach\s*\(/i',
            '/\bcase\s+/i',
            '/\bcatch\s*\(/i',
            '/&&/',
            '/\|\|/'
        ];
        
        foreach ($patterns as $pattern) {
            $complexity += preg_match_all($pattern, $functionBody);
        }
        
        return $complexity;
    }
    
    private function getVulnerabilitySeverity($vulnType) {
        $severityMap = [
            'sql_injection' => 'CRITICAL',
            'command_injection' => 'CRITICAL',
            'xss' => 'HIGH',
            'path_traversal' => 'HIGH',
            'deserialization' => 'HIGH',
            'weak_crypto' => 'MEDIUM'
        ];
        
        return $severityMap[$vulnType] ?? 'MEDIUM';
    }
    
    private function getVulnerabilityDescription($vulnType) {
        $descriptions = [
            'sql_injection' => 'SQL injection vulnerability detected. User input is directly used in SQL queries without proper sanitization.',
            'command_injection' => 'Command injection vulnerability detected. User input is passed to system commands without proper validation.',
            'xss' => 'Cross-Site Scripting vulnerability detected. User input is output without proper encoding.',
            'path_traversal' => 'Path traversal vulnerability detected. File operations use user input without proper validation.',
            'deserialization' => 'Insecure deserialization detected. User input is unserialized without validation.',
            'weak_crypto' => 'Weak cryptographic functions detected. Use stronger hashing algorithms for passwords.'
        ];
        
        return $descriptions[$vulnType] ?? 'Security vulnerability detected.';
    }
    
    private function getVulnerabilityRemediation($vulnType) {
        $remediations = [
            'sql_injection' => 'Use prepared statements with parameter binding. Validate and sanitize all user inputs.',
            'command_injection' => 'Avoid using user input in system commands. Use whitelisting and proper validation.',
            'xss' => 'Encode output using htmlspecialchars() or similar functions. Implement Content Security Policy.',
            'path_traversal' => 'Validate file paths against a whitelist. Use realpath() and check against allowed directories.',
            'deserialization' => 'Avoid unserializing user input. Use JSON or implement proper validation.',
            'weak_crypto' => 'Use password_hash() and password_verify() for passwords. Use stronger algorithms like bcrypt.'
        ];
        
        return $remediations[$vulnType] ?? 'Review and fix the security issue.';
    }
    
    private function logAnalysis($message, $level = 'INFO') {
        error_log("CODE_ANALYSIS_ENGINE: [$level] [{$this->analysisId}] $message");
    }
    
    private function generateAnalysisId() {
        return 'ANALYSIS_' . date('Ymd_His') . '_' . substr(md5(microtime()), 0, 8);
    }
    
    private function initializeRulesDatabase() {
        // Initialize security and quality rules database
        $this->rulesDatabase = [
            'security_rules' => [],
            'performance_rules' => [],
            'quality_rules' => []
        ];
    }
    
    private function initializeProfiler() {
        $this->performanceProfiler = new stdClass();
    }
    
    private function initializeSecurityScanner() {
        $this->securityScanner = new stdClass();
    }
    
    // Additional placeholder methods for complete implementation
    private function groupVulnerabilitiesBySeverity($vulnerabilities) {
        $grouped = ['CRITICAL' => [], 'HIGH' => [], 'MEDIUM' => [], 'LOW' => []];
        foreach ($vulnerabilities as $vuln) {
            $grouped[$vuln['severity']][] = $vuln;
        }
        return $grouped;
    }
    
    private function groupVulnerabilitiesByType($vulnerabilities) {
        $grouped = [];
        foreach ($vulnerabilities as $vuln) {
            $grouped[$vuln['type']][] = $vuln;
        }
        return $grouped;
    }
    
    private function extractCriticalFindings($results) {
        $critical = [];
        if (isset($results['vulnerability_scan']['by_severity']['CRITICAL'])) {
            $critical = array_merge($critical, $results['vulnerability_scan']['by_severity']['CRITICAL']);
        }
        return $critical;
    }
    
    // More placeholder methods would be implemented here...
    private function calculateSecurityScore($results) { return 0.75; }
    private function determineRiskLevel($results) { return 'MEDIUM'; }
    private function generateSecurityRecommendations($results) { return []; }
    private function checkNetworkIsolation($codeFiles) { return true; }
    private function checkIrcRateLimiting($codeFiles) { return true; }
    private function getIrcVulnerabilityDescription($vulnType) { return "IRC-specific security issue: $vulnType"; }
    private function analyzeAlgorithmComplexity($codeFiles) { return []; }
    private function analyzeMemoryUsage($codeFiles) { return []; }
    private function analyzeIOOperations($codeFiles) { return []; }
    private function analyzeLoopEfficiency($codeFiles) { return []; }
    private function identifyCachingOpportunities($codeFiles) { return []; }
    private function detectBottlenecks($codeFiles) { return []; }
    private function calculatePerformanceScore($results) { return 0.8; }
    private function generatePerformanceRecommendations($results) { return []; }
    private function getPerformanceImpact($issueType) { return 'MEDIUM'; }
    private function getPerformanceRecommendation($issueType) { return 'Optimize this pattern'; }
    private function groupIssuesByImpact($issues) { return []; }
    private function calculateAverageComplexity($issues) { return 5.0; }
    private function analyzeCodingStandards($codeFiles) { return []; }
    private function analyzeDocumentationCoverage($codeFiles) { return []; }
    private function detectCodeDuplication($codeFiles) { return []; }
    private function analyzeNamingConventions($codeFiles) { return []; }
    private function analyzeTestCoverage($codeFiles) { return []; }
    private function calculateMaintainabilityIndex($codeFiles) { return 0.8; }
    private function assessTechnicalDebt($codeFiles) { return []; }
    private function calculateCodeQualityScore($results) { return 0.85; }
    private function generateQualityRecommendations($results) { return []; }
    private function getErrorHandlingSeverity($issueType) { return 'MEDIUM'; }
    private function groupIssuesBySeverity($issues) { return []; }
}

// API endpoint for code analysis
if ($_SERVER['SCRIPT_NAME'] === '/code_analysis_engine.php') {
    initSecureSession();
    requireAdmin();
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $engine = new CodeAnalysisEngine();
        
        $result = match($input['analysis_type'] ?? '') {
            'security' => $engine->conductSecurityAnalysis($input['code_files'] ?? []),
            'performance' => $engine->conductPerformanceAnalysis($input['code_files'] ?? []),
            'quality' => $engine->conductCodeQualityAnalysis($input['code_files'] ?? []),
            'comprehensive' => [
                'security' => $engine->conductSecurityAnalysis($input['code_files'] ?? []),
                'performance' => $engine->conductPerformanceAnalysis($input['code_files'] ?? []),
                'quality' => $engine->conductCodeQualityAnalysis($input['code_files'] ?? [])
            ],
            default => ['error' => 'Invalid analysis type']
        };
        
        header('Content-Type: application/json');
        echo json_encode($result);
    } else {
        header('Content-Type: application/json');
        echo json_encode(['status' => 'Code Analysis Engine v1.0 Ready']);
    }
}
?>