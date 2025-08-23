<?php
/**
 * Test to reproduce the exact SecureGame HTTP 400 error
 */

// Simulate the exact request that the browser makes
function testSecureGameRequest() {
    echo "=== Testing Exact SecureGame Request ===\n";
    
    // This is the format the minified SecureGame.js sends based on the code analysis
    $secureGamePayload = [
        'op' => 'start_session',
        'game_type' => 'breakout',
        'player_name' => 'Anonymous'
    ];
    
    $postData = json_encode($secureGamePayload);
    
    echo "POST Data: $postData\n";
    
    // Set up the request exactly like the browser
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => [
                'Content-Type: application/json',
                'X-Requested-With: XMLHttpRequest',
                'X-Game-Client: secure-v3'
            ],
            'content' => $postData
        ]
    ]);
    
    // Make the request to the game proxy
    $response = file_get_contents('http://localhost/api/secure/game-proxy.php', false, $context);
    
    if ($response === false) {
        echo "Request failed\n";
        $error = error_get_last();
        echo "Error: " . print_r($error, true) . "\n";
    } else {
        echo "Response: $response\n";
        
        $responseData = json_decode($response, true);
        if ($responseData) {
            echo "Decoded response: " . print_r($responseData, true) . "\n";
        }
    }
    
    // Also check the HTTP response headers
    if (isset($http_response_header)) {
        echo "HTTP Headers:\n";
        foreach ($http_response_header as $header) {
            echo "  $header\n";
        }
    }
}

// Test with different payload formats to see which one works
function testDifferentPayloadFormats() {
    echo "\n=== Testing Different Payload Formats ===\n";
    
    $formats = [
        'direct' => [
            'op' => 'start_session',
            'game_type' => 'breakout', 
            'player_name' => 'Anonymous'
        ],
        'with_data_wrapper' => [
            'op' => 'start_session',
            'data' => [
                'game_type' => 'breakout',
                'player_name' => 'Anonymous'
            ]
        ],
        'full_secure_format' => [
            'op' => 'start_session',
            'data' => [
                'game_type' => 'breakout',
                'player_name' => 'Anonymous'
            ],
            'ts' => time(),
            'nonce' => 'test123',
            'sid' => null
        ]
    ];
    
    foreach ($formats as $name => $payload) {
        echo "\n--- Testing $name format ---\n";
        echo "Payload: " . json_encode($payload) . "\n";
        
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Content-Type: application/json',
                    'X-Requested-With: XMLHttpRequest',
                    'X-Game-Client: secure-v3'
                ],
                'content' => json_encode($payload)
            ]
        ]);
        
        $response = @file_get_contents('http://localhost/api/secure/game-proxy.php', false, $context);
        
        if ($response === false) {
            echo "Request failed\n";
            if (isset($http_response_header)) {
                echo "Status: " . $http_response_header[0] . "\n";
            }
        } else {
            echo "Success: $response\n";
        }
    }
}

// Run the tests
testSecureGameRequest();
testDifferentPayloadFormats();