"""Tests for database functionality"""

import pytest
import tempfile
import os
from core.database import BotDatabase

class TestBotDatabase:
    """Test database operations"""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        db = BotDatabase(path)
        yield db
        os.unlink(path)
    
    def test_link_tracking(self, temp_db):
        """Test link tracking functionality"""
        # First time storing a link
        result = temp_db.check_and_store_link("user1", "https://example.com", "#test")
        assert result is None
        
        # Same user posting same link
        result = temp_db.check_and_store_link("user1", "https://example.com", "#test")
        assert result is None
        
        # Different user posting same link
        result = temp_db.check_and_store_link("user2", "https://example.com", "#test")
        assert result is not None
        assert result['user'] == "user1"
    
    def test_user_scores(self, temp_db):
        """Test user score management"""
        # Initial score should be 0
        score = temp_db.get_user_score("testuser", "bet7")
        assert score['score'] == 0
        
        # Update score
        temp_db.update_user_score("testuser", 100, "bet7")
        score = temp_db.get_user_score("testuser", "bet7")
        assert score['score'] == 100
        
        # Get leaderboard
        leaderboard = temp_db.get_leaderboard("bet7")
        assert len(leaderboard) == 1
        assert leaderboard[0]['user'] == "testuser"
    
    def test_conversation_history(self, temp_db):
        """Test conversation history storage"""
        # Store conversation
        temp_db.store_conversation("user1", "Hello", "Hi there", {"context": "test"})
        
        # Retrieve history
        history = temp_db.get_conversation_history("user1")
        assert len(history) == 1
        assert history[0]['message'] == "Hello"
        
        # Clear history
        temp_db.clear_conversation_history("user1")
        history = temp_db.get_conversation_history("user1")
        assert len(history) == 0