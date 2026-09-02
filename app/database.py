# app/database.py
"""
Simulated Financial Database & Ledger.
Provides an in-memory data store for accounts, users, and transactions.
"""

from typing import Dict, Any, Optional

USERS_DB: Dict[int, Dict[str, Any]] = {
    101: {
        "id": 101,
        "username": "alice",
        "name": "Alice Wonderland",
        "email": "alice@finsec-guardian.internal",
        "balance": 50000.00,
        "is_admin": False,
        "role": "user",
        "password_hash": "$2b$12$e8Y6bF0Xb7qP0x9EwQGf9eK7xN5w4Z0v5vL5n7w8v9u1m2o3p4q5r" # Simulated bcrypt
    },
    102: {
        "id": 102,
        "username": "bob",
        "name": "Bob Builder",
        "email": "bob@finsec-guardian.internal",
        "balance": 150.00,
        "is_admin": False,
        "role": "user",
        "password_hash": "$2b$12$e8Y6bF0Xb7qP0x9EwQGf9eK7xN5w4Z0v5vL5n7w8v9u1m2o3p4q5r"
    },
    999: {
        "id": 999,
        "username": "admin",
        "name": "Security Officer",
        "email": "secops@finsec-guardian.internal",
        "balance": 1000000.00,
        "is_admin": True,
        "role": "admin",
        "password_hash": "$2b$12$e8Y6bF0Xb7qP0x9EwQGf9eK7xN5w4Z0v5vL5n7w8v9u1m2o3p4q5r"
    }
}

TRANSACTIONS_LOG = []

def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    return USERS_DB.get(user_id)

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    for user in USERS_DB.values():
        if user["username"].lower() == username.lower():
            return user
    return None

def reset_db_state():
    """Helper to reset in-memory records during automated test runs."""
    USERS_DB[101]["balance"] = 50000.00
    USERS_DB[101]["is_admin"] = False
    USERS_DB[102]["balance"] = 150.00
    USERS_DB[102]["is_admin"] = False
