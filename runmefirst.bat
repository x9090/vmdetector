@echo off
cd %~d0
del /Q /F c:\windows\system32\drivers\VMDetectorSys.sys > NUL
del /Q /F c:\windows\system32\drivers\wmifiler.sys > NUL
move VMDetectorSys.sys c:\windows\system32\drivers\VMDetectorSys.sys
move wmifilter.sys c:\windows\system32\drivers\wmifilter.sys