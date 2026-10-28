# 🛡️ AI Phishing Email Analyzer

A beginner-friendly cybersecurity project built with **Python, Streamlit, and Google Gemini**. Paste email text to get an AI-assisted risk assessment, visible URL extraction, transparent heuristic checks, and recommended next steps.

## Features

- Paste email text into a clean Streamlit interface
- Extract visible HTTP/HTTPS and `www` URLs without visiting them
- Run transparent local checks for urgency, credential requests, and some suspicious URL patterns
- Ask Gemini for a cautious Low / Medium / High risk assessment
- Display warning signs, potentially reassuring signs, and safe next steps
- Download the result as JSON
- Configure the API key through environment variables or Streamlit Secrets

> **Limitations:** This is an educational triage aid, not a definitive phishing detector, malware scanner, URL reputation service, or replacement for a security team. It does not visit or verify links. False positives and false negatives are possible.

## Project files

```text
ai-phishing-email-analyzer/
├── app.py
├── requirements.txt
└── README.md
```

## 1. Get a Gemini API key

1. Visit [Google AI Studio](https://aistudio.google.com/).
2. Sign in and create an API key.
3. Keep the key private. Do not put it in source code, GitHub, screenshots, or this README.

Model access, quotas, and billing depend on Google's current account terms.

## 2. Run locally

Install Python 3.10 or newer.

Open a terminal in the project folder and create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

- **Windows PowerShell:** `.venv\Scripts\Activate.ps1`
- **Windows Command Prompt:** `.venv\Scripts\activate.bat`
- **macOS/Linux:** `source .venv/bin/activate`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Set the API key for the current terminal session:

**Windows PowerShell**
```powershell
$env:GEMINI_API_KEY="your_api_key_here"
```

**Windows Command Prompt**
```bat
set GEMINI_API_KEY=your_api_key_here
```

**macOS/Linux**
```bash
export GEMINI_API_KEY="your_api_key_here"
```

Run the app:

```bash
streamlit run app.py
```

Open the local URL printed in the terminal, usually `http://localhost:8501`.

## 3. Upload to GitHub using the browser (no terminal)

1. Go to [GitHub](https://github.com/) and sign in.
2. Click **+ → New repository**.
3. Name it `ai-phishing-email-analyzer`.
4. Choose Public if you want a simple public portfolio project. Click **Create repository**.
5. On the repository page, choose **Add file → Upload files**.
6. Drag in `app.py`, `requirements.txt`, and `README.md`.
7. Click **Commit changes**.
8. Verify all three files appear at the repository root.
9. Make sure you have not uploaded your API key, `.env` file, or any real/private emails.

You can also create each file with **Add file → Create new file** and paste its contents.

## 4. Deploy on Streamlit Community Cloud

1. Open [Streamlit Community Cloud](https://share.streamlit.io/).
2. Sign in with the GitHub account containing the repository.
3. Click **Create app** and select `ai-phishing-email-analyzer`.
4. Choose the `main` branch (or your default branch) and set the main file path to `app.py`.
5. Open the app's **Settings → Secrets** (or Advanced settings during deployment).
6. Add your key as TOML:

   ```toml
   GEMINI_API_KEY = "your_actual_api_key"
   ```

7. Save and deploy. Wait for the build to finish.
8. Test with a made-up sample email before sharing the public URL.

Streamlit's interface may change. Refer to the [official deployment documentation](https://docs.streamlit.io/deploy/streamlit-community-cloud) if menu labels differ.

## Privacy and security

- Email content entered by a user is sent to the configured Gemini API for analysis.
- Do not paste passwords, access tokens, confidential company messages, or other sensitive content.
- If the app is public, visitors may consume the owner's API quota. Monitor usage and consider authentication or rate limits before broad release.
- This app does not intentionally store email content in a database or write it to disk; Streamlit session state can retain results during the session.
- URL extraction is local and does not mean URLs are safe, active, or verified.
- A displayed risk rating is not proof that a message is malicious or safe.

## Troubleshooting

- **API key missing:** Set `GEMINI_API_KEY` locally or in Streamlit Secrets.
- **Analysis failed:** Check key validity, model access, quota, network connection, and deployment logs.
- **Module missing:** Ensure `requirements.txt` is committed at the repository root and redeploy.
- **Unexpected risk rating:** AI analysis can be wrong. Verify suspicious messages with your organization's security team or a trusted communication channel.

## Future improvements

Possible next steps include `.eml` upload support, unit tests, a small sample-email gallery, domain reputation checks using a trusted threat-intelligence API, and safer handling for public multi-user deployments.
