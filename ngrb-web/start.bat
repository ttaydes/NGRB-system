@echo off
echo Starting NGRB System...

REM 创建必要的目录
if not exist "server\data" mkdir server\data

REM 初始化数据库
echo Initializing database...
python server\init_db.py

REM 启动后端服务器
echo Starting backend server...
start cmd /k "python server\app.py"

REM 等待后端服务器启动
timeout /t 5

REM 启动流量收集器
echo Starting traffic collector...
start cmd /k "python Agent\trafficcollection.py"

echo System started successfully!
echo Backend URL: http://localhost:5000
echo Frontend URL: http://localhost:8080 