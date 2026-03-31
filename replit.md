# WAF Bypass Lab — Payload Encoder Framework

## Overview
A Flask-based web application for testing and demonstrating Web Application Firewall (WAF) bypass techniques. It includes payload encoding/decoding, mutation, a rule-based WAF engine, an AI-powered WAF engine (ML-based), and live testing capabilities.

## Project Structure
- `server.py` — Flask web server (main entry point, port 5000)
- `payload_encoder.py` — Payload encoding, decoding, and mutation logic
- `waf_engine.py` — Rule-based WAF engine
- `ai_waf_engine.py` — AI/ML-powered WAF using TF-IDF + Logistic Regression
- `live_tester.py` — Live target testing utility
- `templates/index.html` — Single-page frontend
- `static/app.js` — Frontend JavaScript
- `static/app.css` — Frontend styles
- `tests/` — Test files
- `requirements.txt` — Python dependencies

## Tech Stack
- **Language:** Python 3.12
- **Framework:** Flask
- **ML:** scikit-learn (TF-IDF + Logistic Regression)
- **HTTP:** requests
- **Production Server:** gunicorn

## Running the App
- **Development:** `python server.py` (runs on 0.0.0.0:5000)
- **Production:** `gunicorn --bind=0.0.0.0:5000 --reuse-port server:app`

## Key Notes
- The app runs on port 5000 with host 0.0.0.0 for Replit compatibility
- The AI WAF trains in-memory on startup using an inline dataset
- Debug mode is enabled in development (intentional for local tooling)
