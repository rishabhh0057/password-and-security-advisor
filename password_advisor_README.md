# Password & Security Advisor — GenAI + Agentic AI

Same structure as your class's AI EDA Agent project, applied to password security.

## Files

- **password_security_advisor.ipynb** — Colab/Jupyter notebook. Run top to
  bottom. Builds each tool step by step (strength check, breach check, mini
  RAG, password generator), then wires them into an agent with
  `create_agent`, matching the pattern from your EDA agent notebooks.
- **app.py** — Streamlit deployment, same layout style as your flower
  classification app (title, image, sidebar, button, results panel).

## Setup

```bash
pip install langchain langchain-google-genai langchain-groq \
            langchain_community faiss-cpu sentence-transformers \
            requests streamlit
```

### For the notebook (Colab)
Store your key in Colab's Secrets tab (key icon, left sidebar) as
`GOOGLE_API_KEY` — do NOT paste it directly into a cell. The notebook reads
it with `userdata.get('GOOGLE_API_KEY')`.

### For the Streamlit app
Create `.streamlit/secrets.toml`:
```toml
GOOGLE_API_KEY = "your_key_here"
```
Then run:
```bash
streamlit run app.py
```

## What makes this "Agentic AI" vs just "GenAI"

- **GenAI part**: the LLM explains *why* a password is weak/strong and
  drafts the report text — this is generation grounded in tool output.
- **Agentic part**: the agent built with `create_agent` decides, on its own,
  *which* tools to call and in *what order* for a given question (strength
  check first, then breach check, then retrieve grounding guidance) rather
  than following a fixed script. For a fuller agentic story in your report,
  extend this with a scheduled monitor loop (perceive → decide → act →
  reflect) that checks tracked accounts periodically without being asked —
  ask me if you want that module added in the same notebook style.

## Security notes worth including in your report

- Passwords are never logged or stored in plaintext.
- The breach check uses HIBP's k-anonymity API — only 5 hex characters of a
  SHA-1 hash are sent, never the real password.
- API keys belong in secrets/env vars, never hardcoded in a notebook cell —
  worth a slide in your presentation on responsible AI project hygiene.
