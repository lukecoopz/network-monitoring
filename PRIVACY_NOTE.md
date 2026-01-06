# Privacy Note

This repository contains network monitoring code. When you push this to GitHub/GitLab/etc., make sure to:

1. **Set the repository to Private** in your hosting platform settings
2. **Do not commit sensitive data** like:
   - API keys
   - Database files with real network data
   - Personal network information
   - Credentials

The `.gitignore` file is configured to exclude:
- Database files (`*.db`, `*.sqlite`, `*.sqlite3`)
- Virtual environments (`venv/`)
- Python cache files (`__pycache__/`)
- IDE files
- Log files

## Setting Repository to Private on GitHub

1. Go to your repository on GitHub
2. Click **Settings**
3. Scroll down to **Danger Zone**
4. Click **Change visibility**
5. Select **Make private**

## Setting Repository to Private on GitLab

1. Go to your project on GitLab
2. Click **Settings** → **General**
3. Expand **Visibility, project features, permissions**
4. Change **Project visibility** to **Private**

