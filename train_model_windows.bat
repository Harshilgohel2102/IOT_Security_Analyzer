@echo off
setlocal
cd /d %~dp0server
if not exist .venv (
  py -3 -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python -c "from app.ml_engine import RiskModel; from pathlib import Path; model=RiskModel(Path('app/models')); model.train_bootstrap_model(); print(model.metrics)"
