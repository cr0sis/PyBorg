<?php
/**
 * Secure File Upload Handler - Phase 5: File System Security
 * Comprehensive file upload validation, scanning, and quarantine system
 */

require_once 'security_middleware.php';
require_once 'input_sanitizer.php';
require_once 'secure_error_handler.php';
require_once 'auth.php';

class SecureUploadHandler {
    
    private static $uploadDirectory = '/var/www/html/uploads/';
    private static $quarantineDirectory = '/var/www/html/quarantine/';
    private static $maxFileSize = 10485760; // 10MB
    private static $maxFilesPerRequest = 5;
    
    // Whitelist of allowed file types with MIME validation
    private static $allowedTypes = [
        'txt' => ['text/plain'],
        'json' => ['application/json', 'text/plain'],
        'csv' => ['text/csv', 'application/csv'],
        'log' => ['text/plain'],
        'md' => ['text/markdown', 'text/plain'],
        'sql' => ['text/plain', 'application/sql'],
        'xml' => ['text/xml', 'application/xml'],
        'yml' => ['text/yaml', 'application/yaml'],
        'yaml' => ['text/yaml', 'application/yaml']
    ];
    
    // Dangerous file patterns to always block
    private static $dangerousPatterns = [
        '/\.php\d*$/i',
        '/\.phtml$/i',
        '/\.jsp$/i',
        '/\.asp$/i',
        '/\.aspx$/i',
        '/\.exe$/i',
        '/\.bat$/i',
        '/\.cmd$/i',
        '/\.sh$/i',
        '/\.com$/i',
        '/\.scr$/i',
        '/\.vbs$/i',
        '/\.js$/i',
        '/\.jar$/i'
    ];
    
    // Suspicious content patterns
    private static $suspiciousContent = [
        '/<\?php/i',
        '/<script/i',
        '/eval\s*\(/i',
        '/exec\s*\(/i',
        '/system\s*\(/i',
        '/shell_exec/i',
        '/passthru/i',
        '/base64_decode/i',
        '/file_get_contents/i',
        '/fopen/i',
        '/fwrite/i',
        '/include/i',
        '/require/i'
    ];
    
    /**
     * Process file upload with comprehensive security checks
     */
    public static function processUpload($files, $allowedExtensions = null) {
        // Ensure user is authenticated
        if (!isUserLoggedIn()) {
            SecurityMiddleware::logSecurityEvent('UNAUTHORIZED_UPLOAD_ATTEMPT', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ], 'HIGH');
            return ['error' => 'Authentication required'];
        }
        
        // Initialize upload and quarantine directories
        self::initializeDirectories();
        
        // Validate request
        $validation = self::validateUploadRequest($files);
        if (isset($validation['error'])) {
            return $validation;
        }
        
        $results = [];
        $processedFiles = 0;
        
        // Process each file
        foreach ($files['name'] as $index => $filename) {
            if ($processedFiles >= self::$maxFilesPerRequest) {
                SecurityMiddleware::logSecurityEvent('TOO_MANY_FILES_UPLOAD', [
                    'attempted_count' => count($files['name']),
                    'max_allowed' => self::$maxFilesPerRequest,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ], 'MEDIUM');
                break;
            }
            
            $fileInfo = [
                'name' => $files['name'][$index],
                'type' => $files['type'][$index],
                'tmp_name' => $files['tmp_name'][$index],
                'error' => $files['error'][$index],
                'size' => $files['size'][$index]
            ];
            
            $result = self::processSingleFile($fileInfo, $allowedExtensions);
            $results[] = $result;
            $processedFiles++;
        }
        
        return [
            'success' => true,
            'files' => $results,
            'processed_count' => $processedFiles
        ];
    }
    
    /**
     * Process a single uploaded file
     */
    private static function processSingleFile($fileInfo, $allowedExtensions = null) {
        $filename = $fileInfo['name'];
        $tmpPath = $fileInfo['tmp_name'];
        
        // Check for upload errors
        if ($fileInfo['error'] !== UPLOAD_ERR_OK) {
            return [
                'filename' => $filename,
                'status' => 'error',
                'message' => self::getUploadErrorMessage($fileInfo['error'])
            ];
        }
        
        // Validate file size
        if ($fileInfo['size'] > self::$maxFileSize) {
            SecurityMiddleware::logSecurityEvent('OVERSIZED_FILE_UPLOAD', [
                'filename' => $filename,
                'size' => $fileInfo['size'],
                'max_allowed' => self::$maxFileSize,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'MEDIUM');
            
            return [
                'filename' => $filename,
                'status' => 'error',
                'message' => 'File too large (max: ' . self::formatBytes(self::$maxFileSize) . ')'
            ];
        }
        
        // Sanitize filename
        $safeFilename = self::sanitizeFilename($filename);
        if (!$safeFilename) {
            return [
                'filename' => $filename,
                'status' => 'error',
                'message' => 'Invalid filename'
            ];
        }
        
        // Validate file extension and type
        $extension = strtolower(pathinfo($safeFilename, PATHINFO_EXTENSION));
        $validation = self::validateFileType($safeFilename, $fileInfo['type'], $extension, $allowedExtensions);
        if (isset($validation['error'])) {
            return [
                'filename' => $filename,
                'status' => 'blocked',
                'message' => $validation['error']
            ];
        }
        
        // Read and scan file content
        $content = file_get_contents($tmpPath);
        if ($content === false) {
            return [
                'filename' => $filename,
                'status' => 'error',
                'message' => 'Failed to read uploaded file'
            ];
        }
        
        // Security scan
        $scanResult = self::scanFileContent($content, $safeFilename);
        if ($scanResult['quarantine']) {
            return self::quarantineFile($tmpPath, $safeFilename, $scanResult['threats']);
        }
        
        // Generate unique filename to prevent conflicts
        $finalFilename = self::generateUniqueFilename($safeFilename);
        $finalPath = self::$uploadDirectory . $finalFilename;
        
        // Move file to upload directory
        if (move_uploaded_file($tmpPath, $finalPath)) {
            // Set secure permissions
            chmod($finalPath, 0644);
            
            // Log successful upload
            SecurityMiddleware::logSecurityEvent('FILE_UPLOAD_SUCCESS', [
                'original_filename' => $filename,
                'saved_filename' => $finalFilename,
                'size' => $fileInfo['size'],
                'type' => $fileInfo['type'],
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_id' => $_SESSION['user_id'] ?? 'unknown'
            ], 'INFO');
            
            return [
                'filename' => $filename,
                'saved_as' => $finalFilename,
                'status' => 'success',
                'size' => $fileInfo['size'],
                'path' => $finalPath,
                'url' => '/uploads/' . $finalFilename
            ];
        } else {
            return [
                'filename' => $filename,
                'status' => 'error',
                'message' => 'Failed to save file'
            ];
        }
    }
    
    /**
     * Validate upload request
     */
    private static function validateUploadRequest($files) {
        if (!isset($files['name']) || !is_array($files['name'])) {
            return ['error' => 'No files uploaded'];
        }
        
        if (count($files['name']) > self::$maxFilesPerRequest) {
            return ['error' => 'Too many files (max: ' . self::$maxFilesPerRequest . ')'];
        }
        
        return ['success' => true];
    }
    
    /**
     * Validate file type and extension
     */
    private static function validateFileType($filename, $mimeType, $extension, $allowedExtensions = null) {
        // Check against dangerous patterns first
        foreach (self::$dangerousPatterns as $pattern) {
            if (preg_match($pattern, $filename)) {
                SecurityMiddleware::logSecurityEvent('DANGEROUS_FILE_UPLOAD_BLOCKED', [
                    'filename' => $filename,
                    'pattern' => $pattern,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ], 'HIGH');
                
                return ['error' => 'File type not allowed'];
            }
        }
        
        // Use custom allowed extensions if provided
        $typeMap = $allowedExtensions ? $allowedExtensions : self::$allowedTypes;
        
        // Check if extension is allowed
        if (!isset($typeMap[$extension])) {
            SecurityMiddleware::logSecurityEvent('UNALLOWED_EXTENSION_UPLOAD', [
                'filename' => $filename,
                'extension' => $extension,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'MEDIUM');
            
            return ['error' => "File extension '$extension' not allowed"];
        }
        
        // Validate MIME type
        $allowedMimes = $typeMap[$extension];
        if (!in_array($mimeType, $allowedMimes)) {
            SecurityMiddleware::logSecurityEvent('MIME_TYPE_MISMATCH', [
                'filename' => $filename,
                'reported_mime' => $mimeType,
                'expected_mimes' => $allowedMimes,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'HIGH');
            
            return ['error' => 'File type validation failed'];
        }
        
        return ['success' => true];
    }
    
    /**
     * Scan file content for suspicious patterns
     */
    private static function scanFileContent($content, $filename) {
        $threats = [];
        
        // Check for suspicious content patterns
        foreach (self::$suspiciousContent as $pattern) {
            if (preg_match($pattern, $content)) {
                $threats[] = "Suspicious pattern: $pattern";
            }
        }
        
        // Check for null bytes (often used in bypass attempts)
        if (strpos($content, "\0") !== false) {
            $threats[] = "Null byte detected";
        }
        
        // Check for extremely long lines (potential buffer overflow)
        $lines = explode("\n", $content);
        foreach ($lines as $line) {
            if (strlen($line) > 10000) {
                $threats[] = "Extremely long line detected";
                break;
            }
        }
        
        // Binary file detection for text file types
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (in_array($extension, ['txt', 'csv', 'log', 'md', 'sql', 'xml', 'yml', 'yaml'])) {
            if (!mb_check_encoding($content, 'UTF-8') && !mb_check_encoding($content, 'ASCII')) {
                $threats[] = "Binary content in text file";
            }
        }
        
        return [
            'quarantine' => !empty($threats),
            'threats' => $threats
        ];
    }
    
    /**
     * Quarantine suspicious file
     */
    private static function quarantineFile($tmpPath, $filename, $threats) {
        $quarantineFilename = date('Y-m-d_H-i-s') . '_' . $filename;
        $quarantinePath = self::$quarantineDirectory . $quarantineFilename;
        
        if (move_uploaded_file($tmpPath, $quarantinePath)) {
            chmod($quarantinePath, 0600); // Restricted permissions
            
            // Log quarantine event
            SecurityMiddleware::logSecurityEvent('FILE_QUARANTINED', [
                'original_filename' => $filename,
                'quarantine_filename' => $quarantineFilename,
                'threats' => $threats,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_id' => $_SESSION['user_id'] ?? 'unknown'
            ], 'HIGH');
            
            // Create threat report
            $reportPath = $quarantinePath . '.report.json';
            file_put_contents($reportPath, json_encode([
                'timestamp' => date('Y-m-d H:i:s'),
                'original_filename' => $filename,
                'threats' => $threats,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'user_id' => $_SESSION['user_id'] ?? 'unknown'
            ], JSON_PRETTY_PRINT));
            
            return [
                'filename' => $filename,
                'status' => 'quarantined',
                'message' => 'File quarantined due to security concerns',
                'threats' => $threats,
                'quarantine_id' => $quarantineFilename
            ];
        } else {
            return [
                'filename' => $filename,
                'status' => 'error',
                'message' => 'Failed to quarantine suspicious file'
            ];
        }
    }
    
    /**
     * Sanitize filename
     */
    private static function sanitizeFilename($filename) {
        // Remove directory traversal attempts
        $filename = basename($filename);
        
        // Remove or replace dangerous characters
        $filename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
        
        // Prevent hidden files
        $filename = ltrim($filename, '.');
        
        // Limit length
        if (strlen($filename) > 255) {
            $ext = pathinfo($filename, PATHINFO_EXTENSION);
            $name = substr(pathinfo($filename, PATHINFO_FILENAME), 0, 250 - strlen($ext));
            $filename = $name . '.' . $ext;
        }
        
        // Ensure filename is not empty
        if (empty($filename) || $filename === '.') {
            return false;
        }
        
        return $filename;
    }
    
    /**
     * Generate unique filename to prevent conflicts
     */
    private static function generateUniqueFilename($filename) {
        $name = pathinfo($filename, PATHINFO_FILENAME);
        $ext = pathinfo($filename, PATHINFO_EXTENSION);
        
        $counter = 1;
        $newFilename = $filename;
        
        while (file_exists(self::$uploadDirectory . $newFilename)) {
            $newFilename = $name . '_' . $counter . '.' . $ext;
            $counter++;
            
            // Prevent infinite loop
            if ($counter > 1000) {
                $newFilename = uniqid($name . '_') . '.' . $ext;
                break;
            }
        }
        
        return $newFilename;
    }
    
    /**
     * Initialize upload and quarantine directories
     */
    private static function initializeDirectories() {
        $directories = [
            self::$uploadDirectory,
            self::$quarantineDirectory
        ];
        
        foreach ($directories as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
                
                // Create .htaccess for upload directory
                if ($dir === self::$uploadDirectory) {
                    file_put_contents($dir . '.htaccess', 
                        "# Prevent PHP execution in uploads\n" .
                        "php_flag engine off\n" .
                        "AddType text/plain .php .phtml .php3 .php4 .php5 .php6\n" .
                        "# Block suspicious file types\n" .
                        "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php6|exe|bat|sh|com)$\">\n" .
                        "    Deny from all\n" .
                        "</FilesMatch>\n"
                    );
                }
                
                // Restrict access to quarantine directory
                if ($dir === self::$quarantineDirectory) {
                    file_put_contents($dir . '.htaccess', "Deny from all\n");
                }
            }
        }
    }
    
    /**
     * Get upload error message
     */
    private static function getUploadErrorMessage($errorCode) {
        switch ($errorCode) {
            case UPLOAD_ERR_INI_SIZE:
                return 'File exceeds upload_max_filesize directive';
            case UPLOAD_ERR_FORM_SIZE:
                return 'File exceeds MAX_FILE_SIZE directive';
            case UPLOAD_ERR_PARTIAL:
                return 'File was only partially uploaded';
            case UPLOAD_ERR_NO_FILE:
                return 'No file was uploaded';
            case UPLOAD_ERR_NO_TMP_DIR:
                return 'Missing temporary folder';
            case UPLOAD_ERR_CANT_WRITE:
                return 'Failed to write file to disk';
            case UPLOAD_ERR_EXTENSION:
                return 'File upload stopped by extension';
            default:
                return 'Unknown upload error';
        }
    }
    
    /**
     * Format bytes to human readable
     */
    private static function formatBytes($bytes) {
        $units = ['B', 'KB', 'MB', 'GB'];
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }
    
    /**
     * List uploaded files
     */
    public static function listUploads($limit = 50) {
        if (!isUserLoggedIn()) {
            return ['error' => 'Authentication required'];
        }
        
        $files = glob(self::$uploadDirectory . '*');
        $results = [];
        
        foreach (array_slice($files, -$limit) as $file) {
            if (is_file($file)) {
                $results[] = [
                    'filename' => basename($file),
                    'size' => filesize($file),
                    'size_human' => self::formatBytes(filesize($file)),
                    'modified' => filemtime($file),
                    'modified_human' => date('Y-m-d H:i:s', filemtime($file)),
                    'url' => '/uploads/' . basename($file)
                ];
            }
        }
        
        return [
            'success' => true,
            'files' => array_reverse($results),
            'count' => count($results)
        ];
    }
    
    /**
     * List quarantined files (admin only)
     */
    public static function listQuarantine() {
        if (!isUserLoggedIn() || !isUserAdmin()) {
            return ['error' => 'Admin access required'];
        }
        
        $files = glob(self::$quarantineDirectory . '*');
        $results = [];
        
        foreach ($files as $file) {
            if (is_file($file) && !str_ends_with($file, '.report.json')) {
                $reportFile = $file . '.report.json';
                $report = null;
                
                if (file_exists($reportFile)) {
                    $report = json_decode(file_get_contents($reportFile), true);
                }
                
                $results[] = [
                    'filename' => basename($file),
                    'size' => filesize($file),
                    'size_human' => self::formatBytes(filesize($file)),
                    'quarantined' => filemtime($file),
                    'quarantined_human' => date('Y-m-d H:i:s', filemtime($file)),
                    'report' => $report
                ];
            }
        }
        
        return [
            'success' => true,
            'files' => array_reverse($results),
            'count' => count($results)
        ];
    }
}
?>