# CIRA minimum version

CIRA scans folders on your computer, scores each file with a machine learning model, explains every
score, shows which fixes improve your device health the most, and can move risky files to a quarantine
you can undo. Everything runs locally. There is no login and no cloud in this version.

## Run it (Windows, Python 3.10 or newer)

```
pip install -r requirements.txt
python run.py
```

Your browser opens at http://127.0.0.1:8765. Pick folders, press **Start scan**.
Run the terminal as Administrator if you want CIRA to read the BitLocker state and all open ports.

The trained model is included. To retrain it: `pip install -r requirements-dev.txt` then `python train_model.py`.
To run the tests: `python -m pytest`.

## What is real and what is not

| Part | Status |
|---|---|
| File scanning (hash, entropy, file type, disguised programs, double extensions, program structure) | Works. Tested on Linux with sample files, including a real Windows .exe |
| Risk model (XGBoost) with per-file SHAP explanations | Works, but **trained on synthetic data** (see below) |
| Known-bad hash list | Works. Ships with the EICAR test file hash only |
| Health score, ranked fixes, what-if projection | Works. The projection is exact for the score formula |
| Quarantine and restore | Works. Only files inside your user folder, never system files, never deleted |
| Open ports and running programs | Works. Ports use fixed rules, not ML |
| Firewall, Defender and BitLocker checks | **Written for Windows but not run on Windows yet.** The output parser is unit tested |
| Report | Downloads as HTML. Use the browser's Print to save as PDF |
| Login, settings sync, permission pop-ups, firewall changes, site and plugin guard | Not in this version (v2) |

### About the model

`train_model.py` generates synthetic files from distributions written by hand, trains XGBoost on them,
and compares it with an equal-weight checklist. The reported AUC (about 0.85 against 0.76 for the
checklist) measures how well the model separates the generator's two groups. **It says nothing about real
malware detection.** Do not present it as a detection rate.

To get real results, replace `load_dataset()` in `train_model.py` with features extracted from a labelled
collection (EMBER, or samples from MalwareBazaar plus clean files) using `agent.scanner.extract_features`,
then retrain. The rest of the app does not change.

Monotonic constraints are used so that a red flag (double extension, disguised program, and so on) can never
lower a score. Scores above 40 are Medium and above 70 are High.

Use only the harmless EICAR test file or samples inside a virtual machine when testing. Never run real
malware on your own computer.

## Safety design (questions an examiner may ask)

- The agent listens on 127.0.0.1 only and rejects other Host headers (blocks DNS rebinding).
- Every API call needs a random per-launch token that only the served page contains. No CORS headers are sent.
- Quarantine takes a finding ID from the last scan, never a path typed by a client.
- Scans are read-only. Quarantine is a move, not a delete, and restore never overwrites an existing file.
- The page builds all text with `textContent`, so a malicious file name cannot inject HTML.

## Project layout

```
run.py                 start the app
train_model.py         build the synthetic dataset, train, evaluate against the baseline
agent/scanner.py       read-only file features
agent/model.py         XGBoost scoring and SHAP explanations
agent/system_info.py   ports, running programs, security settings, disk
agent/health.py        health score, ranked fixes, what-if
agent/quarantine.py    move to quarantine and restore
agent/engine.py        runs a scan end to end
agent/main.py          local web server and API
frontend/              dashboard (plain HTML, CSS and JavaScript, no build step)
models/                trained model, metrics, known-bad hashes
tests/                 unit and API tests
```

## Make a Windows installer (not tested yet)

```
pip install pyinstaller
pyinstaller --onefile --name CIRA --add-data "frontend;frontend" --add-data "models;models" run.py
```

An unsigned program shows a Windows SmartScreen warning and some antivirus tools may flag it.
Publish the file on GitHub Releases and link it from your YouTube video description.

## Next steps

1. Retrain on a real labelled dataset and report precision, recall and PR-AUC on a held-out set.
2. Run and fix the Windows checks on a real Windows machine.
3. v2: Supabase login and scan history, permission pop-ups, firewall rule manager, site and plugin guard.
