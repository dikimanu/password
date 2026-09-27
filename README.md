# AI-Based Adaptive Authentication and Intelligent Attack Detection System

## Setup

```
pip install -r requirements.txt
```

## Run

```
python app.py
```

Visit http://127.0.0.1:5000/

The database (`database/app.db`) and ML models (`ml/trained_models/*.pkl`) are
created automatically on first run, using a synthetic dataset generated in
`ml/datasets/authentication_logs.csv`.

## Flow

1. Register at `/auth/register`
2. Log in at `/auth/login`
3. Based on the AI risk assessment of the login (frequency, IP/device change,
   time of day, failure ratio), the policy engine decides:
   - LOW risk → normal login
   - MEDIUM risk → additional verification flagged
   - HIGH risk → OTP required (check the server console for the code)
   - CRITICAL risk → account temporarily protected + OTP required
4. User dashboard: `/user/dashboard`
5. Admin dashboard: `/admin/dashboard` (requires a user with `is_admin = 1`
   in the `users` table — set this manually in SQLite for your admin account)

## Making a user an admin

```
python -c "from database.database import get_connection; c=get_connection(); c.execute(\"UPDATE users SET is_admin=1 WHERE username='youradminuser'\"); c.commit()"
```

## Retraining the ML model

```
python ml/train_model.py
```
