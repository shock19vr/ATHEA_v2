# Wazuh-ATHEA Startup Scripts

# === Start Backend ===
Write-Host "Starting Wazuh-ATHEA Backend (FastAPI)..." -ForegroundColor Cyan
$backendPath = Join-Path $PSScriptRoot "backend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backendPath'; .\\.venv\\Scripts\\python -m uvicorn main:app --host 0.0.0.0 --port 8000"

Start-Sleep -Seconds 3

# === Start Frontend ===
Write-Host "Starting Wazuh-ATHEA Frontend (Next.js)..." -ForegroundColor Cyan
$frontendPath = Join-Path $PSScriptRoot "frontend"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$frontendPath'; npm run dev -- --hostname 0.0.0.0"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " Wazuh-ATHEA is starting up!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host " Backend API : http://localhost:8000" -ForegroundColor Yellow
Write-Host " API Docs    : http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host " Dashboard   : http://localhost:3000" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "First pipeline run takes ~5-10 seconds for ML." -ForegroundColor Gray
Write-Host "Press CTRL+C in each terminal to stop." -ForegroundColor Gray
