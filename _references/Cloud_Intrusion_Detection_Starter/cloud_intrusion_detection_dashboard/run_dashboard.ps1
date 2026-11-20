# PowerShell launch script for Cloud-Based Intrusion Detection Dashboard
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$env:PATH = "C:\Users\Hp\AppData\Local\Python\bin;C:\Users\Hp\AppData\Local\Python\pythoncore-3.15-64\Scripts;" + $env:PATH

Write-Host "🛡️ Launching Cloud-Based Intrusion Detection Dashboard..." -ForegroundColor Cyan

if (Get-Command streamlit -ErrorAction SilentlyContinue) {
    streamlit run app.py
} else {
    & "C:\Users\Hp\AppData\Local\Python\bin\python.exe" -m streamlit run app.py
}
