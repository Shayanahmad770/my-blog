#!/usr/bin/env python3
"""
Run this once after deploying to Supabase
"""
import os
from app import app, init_db

print("="*60)
print("SUPABASE DATABASE INITIALIZATION")
print("="*60)

# Verify DATABASE_URL is set
if not os.environ.get('DATABASE_URL'):
    print("❌ ERROR: DATABASE_URL not found in environment!")
    print("Please add it to Secrets in Replit.")
    exit(1)

print("✅ DATABASE_URL found")

with app.app_context():
    try:
        print("Creating tables and indexes...")
        init_db()
        print("✅ Database initialized successfully!")
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)

print("="*60)
print("You can now run your Flask app")
print("="*60)