<?php
/**
 * Path Traversal Protection - Phase 5: File System Security
 * Advanced protection against directory traversal and path manipulation attacks
 */

require_once 'security_middleware.php';
require_once 'file_access_logger.php';
require_once 'config_paths.php';

class PathTraversalProtection {
    
    // Allowed base directories for file operations
    private static $allowedBasePaths = [
        ConfigPaths::UPLOAD_DIR . '/',
        ConfigPaths::SHARED_STORAGE_DIR . '/',
        '/var/www/html/data/',
        ConfigPaths::BASE_LOG_DIR . '/',
        '/tmp/php_uploads/'
    ];
    
    // Dangerous path patterns to block
    private static $dangerousPatterns = [
        '/\.\./',           // Parent directory traversal
        '/\.\.\\\/',        // Windows-style parent directory
        '/\.\//',           // Current directory reference
        '/\/\.\./',         // Unix parent directory
        '/\\\\.\.\\\\/',    // Escaped parent directory
        '/%2e%2e%2f/',      // URL encoded ../
        '/%2e%2e/',         // URL encoded ..
        '/%252e%252e/',     // Double URL encoded ..
        '/\.\.%2f/',        // Mixed encoding
        '/\.\.%5c/',        // Backslash variant
        '/\x00/',           // Null byte injection
        '/\/\/+/',          // Multiple slashes
        '/\\\\+/',          // Multiple backslashes
    ];
    
    // System directories that should never be accessible
    private static $systemPaths = [
        '/etc/',
        '/bin/',
        '/sbin/',
        '/usr/bin/',
        '/usr/sbin/',
        '/lib/',
        '/lib64/',
        '/boot/',
        '/root/',
        '/proc/',
        '/sys/',
        '/dev/',
        '/var/log/',
        '/var/spool/',
        '/var/mail/',
        '/home/',
        '/opt/',
        '/.git/',
        '/.svn/',
        '/.htaccess',
        '/.htpasswd',
        '/.env',
        '/config/',
        '/private/',
        '/admin/',
        '/backup/'
    ];
    
    /**
     * Validate and sanitize file path
     */
    public static function validatePath($inputPath, $operation = 'READ') {
        // Initial null check
        if ($inputPath === null || $inputPath === '') {
            FileAccessLogger::logSuspiciousActivity('EMPTY_PATH', '', 
                'Empty or null path provided', 'MEDIUM');
            return false;
        }
        
        // Convert to string and trim
        $path = trim((string)$inputPath);
        
        // Check for dangerous patterns first
        foreach (self::$dangerousPatterns as $pattern) {
            if (preg_match($pattern, $path)) {
                FileAccessLogger::logSuspiciousActivity('DANGEROUS_PATTERN', $path, 
                    "Dangerous pattern detected: $pattern", 'HIGH');
                return false;
            }
        }
        
        // Check for null bytes (common in path traversal attacks)  
        if (strpos($path, "\0") !== false) {
            FileAccessLogger::logSuspiciousActivity('NULL_BYTE', $path,
                'Null byte detected in path', 'HIGH');
            return false;
        }
        
        // Normalize path separators
        $path = str_replace('\\', '/', $path);
        
        // URL decode to catch encoded traversal attempts
        $decodedPath = rawurldecode($path);
        if ($decodedPath !== $path) {
            // Check decoded path for dangerous patterns
            foreach (self::$dangerousPatterns as $pattern) {
                if (preg_match($pattern, $decodedPath)) {
                    FileAccessLogger::logSuspiciousActivity('ENCODED_TRAVERSAL', $path,
                        "Encoded path traversal detected: $decodedPath", 'HIGH');
                    return false;
                }
            }
            $path = $decodedPath;
        }
        
        // Resolve path to absolute path
        $resolvedPath = self::resolvePath($path);
        if (!$resolvedPath) {
            FileAccessLogger::logSuspiciousActivity('PATH_RESOLUTION_FAILED', $path,
                'Failed to resolve path', 'MEDIUM');
            return false;
        }
        
        // Check against system paths
        foreach (self::$systemPaths as $systemPath) {
            if (stripos($resolvedPath, $systemPath) === 0) {
                FileAccessLogger::logSuspiciousActivity('SYSTEM_PATH_ACCESS', $resolvedPath,
                    "Attempted access to system path: $systemPath", 'HIGH');
                return false;
            }
        }
        
        // For write operations, be more strict
        if (in_array($operation, ['WRITE', 'DELETE', 'UPLOAD', 'MOVE'])) {
            if (!self::isPathInAllowedDirectories($resolvedPath)) {
                FileAccessLogger::logSuspiciousActivity('UNAUTHORIZED_WRITE_PATH', $resolvedPath,
                    "Write operation attempted outside allowed directories", 'HIGH');
                return false;
            }
        }
        
        // Additional checks for read operations
        if ($operation === 'READ') {
            // Check file extension for read operations
            $extension = strtolower(pathinfo($resolvedPath, PATHINFO_EXTENSION));
            if (in_array($extension, ['php', 'phtml', 'php3', 'php4', 'php5'])) {
                FileAccessLogger::logSuspiciousActivity('PHP_FILE_READ', $resolvedPath,
                    'Attempted to read PHP file', 'MEDIUM');
                return false;
            }
        }
        
        // Log successful validation for audit
        FileAccessLogger::logAccess('PATH_VALIDATION', $resolvedPath, 'SUCCESS', [
            'original_path' => $inputPath,
            'operation' => $operation
        ]);
        
        return $resolvedPath;
    }
    
    /**
     * Resolve path to absolute path safely
     */
    private static function resolvePath($path) {
        // Handle absolute vs relative paths
        if ($path[0] !== '/') {
            // For relative paths, assume they're relative to the web root
            $path = '/var/www/html/' . ltrim($path, './');
        }
        
        // Split path into components
        $parts = explode('/', $path);
        $resolved = [];
        
        foreach ($parts as $part) {
            if ($part === '' || $part === '.') {
                // Skip empty parts and current directory references
                continue;
            } elseif ($part === '..') {
                // Parent directory - remove last component if exists
                if (!empty($resolved)) {
                    array_pop($resolved);
                }
                // Don't allow going above root
            } else {
                // Regular directory/file name
                $resolved[] = $part;
            }
        }
        
        // Reconstruct path
        $finalPath = '/' . implode('/', $resolved);
        
        // Additional safety check - use realpath if file exists
        if (file_exists($finalPath)) {
            $realPath = realpath($finalPath);
            if ($realPath) {
                return $realPath;
            }
        }
        
        return $finalPath;
    }
    
    /**
     * Check if path is within allowed directories
     */
    private static function isPathInAllowedDirectories($path) {
        foreach (self::$allowedBasePaths as $allowedPath) {
            // Normalize the allowed path
            $normalizedAllowed = rtrim(realpath($allowedPath) ?: $allowedPath, '/') . '/';
            
            // Check if the target path starts with the allowed path
            if (strpos($path . '/', $normalizedAllowed) === 0) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Secure file existence check
     */
    public static function safeFileExists($path) {
        $validatedPath = self::validatePath($path, 'READ');
        if (!$validatedPath) {
            return false;
        }
        
        $exists = file_exists($validatedPath);
        
        FileAccessLogger::logAccess('FILE_EXISTS_CHECK', $validatedPath, 
            $exists ? 'SUCCESS' : 'NOT_FOUND');
        
        return $exists;
    }
    
    /**
     * Secure file reading
     */
    public static function safeFileRead($path, $maxSize = 1048576) {
        $validatedPath = self::validatePath($path, 'READ');
        if (!$validatedPath) {
            return ['error' => 'Invalid or unsafe path'];
        }
        
        if (!file_exists($validatedPath)) {
            FileAccessLogger::logAccess('FILE_READ', $validatedPath, 'NOT_FOUND');
            return ['error' => 'File not found'];
        }
        
        $fileSize = filesize($validatedPath);
        if ($fileSize > $maxSize) {
            FileAccessLogger::logAccess('FILE_READ', $validatedPath, 'SIZE_EXCEEDED', [
                'file_size' => $fileSize,
                'max_size' => $maxSize
            ]);
            return ['error' => 'File too large'];
        }
        
        $content = file_get_contents($validatedPath);
        if ($content === false) {
            FileAccessLogger::logAccess('FILE_READ', $validatedPath, 'READ_ERROR');
            return ['error' => 'Read failed'];
        }
        
        FileAccessLogger::logAccess('FILE_READ', $validatedPath, 'SUCCESS', [
            'bytes_read' => strlen($content)
        ]);
        
        return [
            'success' => true,
            'content' => $content,
            'size' => strlen($content),
            'path' => $validatedPath
        ];
    }
    
    /**
     * Secure file writing
     */
    public static function safeFileWrite($path, $content, $append = false) {
        $validatedPath = self::validatePath($path, 'WRITE');
        if (!$validatedPath) {
            return ['error' => 'Invalid or unsafe path'];
        }
        
        // Create directory if it doesn't exist
        $directory = dirname($validatedPath);
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0755, true)) {
                FileAccessLogger::logAccess('FILE_WRITE', $validatedPath, 'MKDIR_FAILED');
                return ['error' => 'Failed to create directory'];
            }
        }
        
        $flags = $append ? FILE_APPEND | LOCK_EX : LOCK_EX;
        $bytesWritten = file_put_contents($validatedPath, $content, $flags);
        
        if ($bytesWritten === false) {
            FileAccessLogger::logAccess('FILE_WRITE', $validatedPath, 'WRITE_FAILED');
            return ['error' => 'Write failed'];
        }
        
        // Set secure permissions
        chmod($validatedPath, 0644);
        
        FileAccessLogger::logAccess('FILE_WRITE', $validatedPath, 'SUCCESS', [
            'bytes_written' => $bytesWritten,
            'append_mode' => $append
        ]);
        
        return [
            'success' => true,
            'bytes_written' => $bytesWritten,
            'path' => $validatedPath
        ];
    }
    
    /**
     * Secure file deletion
     */
    public static function safeFileDelete($path) {
        $validatedPath = self::validatePath($path, 'DELETE');
        if (!$validatedPath) {
            return ['error' => 'Invalid or unsafe path'];
        }
        
        if (!file_exists($validatedPath)) {
            FileAccessLogger::logAccess('FILE_DELETE', $validatedPath, 'NOT_FOUND');
            return ['error' => 'File not found'];
        }
        
        $fileSize = filesize($validatedPath);
        
        if (unlink($validatedPath)) {
            FileAccessLogger::logAccess('FILE_DELETE', $validatedPath, 'SUCCESS', [
                'file_size' => $fileSize
            ]);
            return ['success' => true, 'deleted_size' => $fileSize];
        } else {
            FileAccessLogger::logAccess('FILE_DELETE', $validatedPath, 'DELETE_FAILED');
            return ['error' => 'Delete failed'];
        }
    }
    
    /**
     * Secure directory listing
     */
    public static function safeDirectoryList($path, $pattern = '*') {
        $validatedPath = self::validatePath($path, 'READ');
        if (!$validatedPath) {
            return ['error' => 'Invalid or unsafe path'];
        }
        
        if (!is_dir($validatedPath)) {
            FileAccessLogger::logAccess('DIRECTORY_LIST', $validatedPath, 'NOT_DIRECTORY');
            return ['error' => 'Not a directory'];
        }
        
        // Sanitize pattern to prevent injection
        $pattern = preg_replace('/[^a-zA-Z0-9.*_-]/', '', $pattern);
        
        $files = glob($validatedPath . '/' . $pattern);
        $results = [];
        
        if ($files) {
            foreach ($files as $file) {
                // Double-check each file is safe
                if (self::validatePath($file, 'READ')) {
                    $results[] = [
                        'name' => basename($file),
                        'path' => $file,
                        'is_dir' => is_dir($file),
                        'is_file' => is_file($file),
                        'size' => is_file($file) ? filesize($file) : 0,
                        'modified' => filemtime($file)
                    ];
                }
            }
        }
        
        FileAccessLogger::logDirectoryAccess($validatedPath, $pattern, 'SUCCESS', count($results));
        
        return [
            'success' => true,
            'files' => $results,
            'count' => count($results)
        ];
    }
    
    /**
     * Add allowed base path (for extending functionality)
     */
    public static function addAllowedBasePath($path) {
        $realPath = realpath($path);
        if ($realPath && is_dir($realPath)) {
            self::$allowedBasePaths[] = rtrim($realPath, '/') . '/';
            return true;
        }
        return false;
    }
    
    /**
     * Get allowed base paths (for debugging)
     */
    public static function getAllowedBasePaths() {
        return self::$allowedBasePaths;
    }
    
    /**
     * Test path for traversal vulnerabilities (for security testing)
     */
    public static function testPathSecurity($testPaths) {
        $results = [];
        
        foreach ($testPaths as $testPath) {
            $result = self::validatePath($testPath, 'READ');
            $results[$testPath] = [
                'valid' => $result !== false,
                'resolved_path' => $result,
                'blocked' => $result === false
            ];
        }
        
        return $results;
    }
}
?>